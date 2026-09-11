package acmeserver

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmeauth"
	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
)

func (s *Server) restore() error {
	info, err := os.Lstat(s.cfg.StateFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect ACME state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("ACME state must be a regular file with permissions 0600")
	}
	if info.Size() > 64<<20 {
		return errors.New("ACME state exceeds 64 MiB")
	}
	f, err := os.Open(s.cfg.StateFile)
	if err != nil {
		return fmt.Errorf("open ACME state: %w", err)
	}
	defer f.Close()
	var loaded state
	dec := json.NewDecoder(io.LimitReader(f, 64<<20+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&loaded); err != nil {
		return fmt.Errorf("decode ACME state: %w", err)
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("trailing data in ACME state")
	}
	if err := s.validateState(loaded); err != nil {
		return fmt.Errorf("validate ACME state: %w", err)
	}
	// An interrupted outbound validation proves nothing. Clients may retry it.
	for id, auth := range loaded.Authorizations {
		if auth.ChallengeStatus == "processing" {
			auth.ChallengeStatus = "pending"
			loaded.Authorizations[id] = auth
		}
	}
	s.state = loaded
	return nil
}

func (s *Server) validateState(st state) error {
	if st.Version != 1 || st.Domain != s.cfg.Domain || st.RootFingerprint != s.state.RootFingerprint {
		return errors.New("state version, domain, or root CA does not match configuration")
	}
	if st.Accounts == nil || st.Orders == nil || st.Authorizations == nil || st.Certificates == nil ||
		len(st.Accounts) > maxAccounts || len(st.Orders) > maxRecords || len(st.Authorizations) > maxRecords || len(st.Certificates) > maxRecords {
		return errors.New("invalid or oversized state collections")
	}
	keys := make(map[string]bool)
	for id, a := range st.Accounts {
		thumb, err := acmeauth.Thumbprint(a.Key)
		if err != nil || !a.Key.IsPublic() || a.ID != id || !validID(id) ||
			thumb != a.Thumbprint || keys[thumb] || (a.Status != "valid" && a.Status != "deactivated") {
			return errors.New("invalid or duplicate account")
		}
		keys[thumb] = true
	}
	for id, o := range st.Orders {
		if id != o.ID || !validID(id) || o.Expires.IsZero() || len(o.Identifiers) == 0 || len(o.Identifiers) > maxIdentifiers || len(o.AuthIDs) != len(o.Identifiers) {
			return errors.New("invalid order")
		}
		if _, ok := st.Accounts[o.AccountID]; !ok {
			return errors.New("order references missing account")
		}
		if o.Status != "pending" && o.Status != "ready" && o.Status != "valid" && o.Status != "invalid" {
			return errors.New("invalid order status")
		}
		seen := make(map[string]bool)
		for i, name := range o.Identifiers {
			if name.Type != "dns" || !s.allowedName(name.Value) || seen[name.Value] {
				return errors.New("invalid order identifiers")
			}
			seen[name.Value] = true
			a, ok := st.Authorizations[o.AuthIDs[i]]
			if !ok || a.OrderID != id || a.AccountID != o.AccountID || a.Name != name.Value {
				return errors.New("order authorization mismatch")
			}
		}
		if o.Status == "valid" {
			c, ok := st.Certificates[o.CertificateID]
			if !ok || c.OrderID != id || len(o.CSR) == 0 {
				return errors.New("valid order lacks certificate")
			}
		}
	}
	for id, a := range st.Authorizations {
		if id != a.ID || !validID(id) || !validID(a.Token) || a.Expires.IsZero() || !s.allowedName(a.Name) {
			return errors.New("invalid authorization")
		}
		o, ok := st.Orders[a.OrderID]
		if !ok || o.AccountID != a.AccountID {
			return errors.New("authorization references missing order")
		}
		if a.Status != "pending" && a.Status != "valid" && a.Status != "invalid" && a.Status != "deactivated" && a.Status != "expired" {
			return errors.New("invalid authorization status")
		}
		if a.ChallengeStatus != "pending" && a.ChallengeStatus != "processing" && a.ChallengeStatus != "valid" && a.ChallengeStatus != "invalid" {
			return errors.New("invalid challenge status")
		}
		if a.Status == "valid" && (a.Validated == nil || !a.Target.IP.Is4() || a.Target.ClientID == "" || a.ChallengeStatus != "valid") {
			return errors.New("valid authorization lacks proof")
		}
	}
	serials := make(map[string]bool)
	for id, c := range st.Certificates {
		leaf, err := parseLeaf(c.PEM)
		if err != nil || id != c.ID || !validID(id) || leaf.SerialNumber.String() != c.Serial || serials[c.Serial] || !leaf.NotAfter.Equal(c.NotAfter) || leaf.IsCA {
			return errors.New("invalid issued certificate")
		}
		if err := leaf.CheckSignatureFrom(s.root); err != nil {
			return errors.New("issued certificate is not signed by this CA")
		}
		o, ok := st.Orders[c.OrderID]
		if !ok || o.AccountID != c.AccountID || o.CertificateID != id || o.Status != "valid" {
			return errors.New("certificate references wrong order")
		}
		if c.RevokedAt != nil && !validRevocationReason(c.Reason) {
			return errors.New("invalid revocation reason")
		}
		serials[c.Serial] = true
	}
	if len(st.CRL) != 0 {
		list, err := x509.ParseRevocationList(st.CRL)
		if err != nil || list.Number == nil || list.Number.Int64() != st.CRLNumber || !list.NextUpdate.Equal(st.CRLNextUpdate) {
			return errors.New("invalid stored CRL")
		}
		if err := list.CheckSignatureFrom(s.root); err != nil {
			return errors.New("invalid stored CRL signature")
		}
	}
	return nil
}

func validID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func (s *Server) commit(next state) error {
	data, err := json.Marshal(next)
	if err != nil {
		return fmt.Errorf("encode ACME state: %w", err)
	}
	if len(data) > 64<<20 {
		return errors.New("ACME state exceeds 64 MiB capacity")
	}
	dir := filepath.Dir(s.cfg.StateFile)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create ACME state directory: %w", err)
	}
	f, err := os.CreateTemp(dir, ".acme-state-*")
	if err != nil {
		return fmt.Errorf("create ACME state snapshot: %w", err)
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return fmt.Errorf("write ACME state: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("sync ACME state: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close ACME state: %w", err)
	}
	if err := os.Rename(f.Name(), s.cfg.StateFile); err != nil {
		return fmt.Errorf("replace ACME state: %w", err)
	}
	// Rename is the commit point. Keep memory aligned with disk even if the
	// directory cannot be synced; still report that durability failure upstream.
	s.state = next
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open ACME directory: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync ACME directory: %w", err)
	}
	return nil
}

func parseLeaf(chain []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(chain)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate chain")
	}
	return x509.ParseCertificate(block.Bytes)
}

func (s *Server) allowedName(name string) bool {
	for _, c := range name {
		if c > 127 {
			return false
		}
	}
	return strings.Contains(name, ".") && name == strings.TrimSuffix(lease.NormalizeHostname(name, s.cfg.Domain), ".") &&
		name != "gateway."+s.cfg.Domain && name != "ns."+s.cfg.Domain
}

// Remove expired orders with their dependent records before applying capacity
// limits. Issued orders remain available until their certificate expires.
func (s *Server) prune(st *state) {
	for id, o := range st.Orders {
		if s.now().Before(o.Expires) {
			continue
		}
		for _, authID := range o.AuthIDs {
			delete(st.Authorizations, authID)
		}
		delete(st.Certificates, o.CertificateID)
		delete(st.Orders, id)
	}
}

func sameCSR(a, b []byte) bool { return bytes.Equal(a, b) }
