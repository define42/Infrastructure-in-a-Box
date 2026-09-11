package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
)

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

// ErrInvalidCSR identifies a malformed or unauthorized certificate request.
var ErrInvalidCSR = errors.New("invalid CSR")

// SignCSR signs a TLS server certificate for an already authorized set of DNS
// names. The caller must establish control of every name before calling it.
// Only the client's public key and validated DNS names are copied from the CSR;
// its private key stays with the client. The result is a leaf-first PEM chain.
func (m *Manager) SignCSR(csrDER []byte, authorizedNames []string) ([]byte, error) {
	if len(csrDER) == 0 || len(csrDER) > 64*1024 {
		return nil, fmt.Errorf("%w: CSR must contain between 1 and 65536 bytes", ErrInvalidCSR)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("%w: parse CSR: %w", ErrInvalidCSR, err)
	}
	if err := validateCSRKey(csr.PublicKey); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCSR, err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("%w: verify CSR signature: %w", ErrInvalidCSR, err)
	}
	if err := validateCSRExtensions(csr.Extensions); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCSR, err)
	}
	names, err := m.csrNames(csr, authorizedNames)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCSR, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if err := m.validateRoot(now); err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	notBefore, notAfter := now.Add(-clockSkew), now.Add(leafLifetime)
	if notBefore.Before(m.root.Leaf.NotBefore) {
		notBefore = m.root.Leaf.NotBefore
	}
	if notAfter.After(m.root.Leaf.NotAfter) {
		notAfter = m.root.Leaf.NotAfter
	}
	template := &x509.Certificate{
		SerialNumber:          serial.Add(serial, big.NewInt(1)),
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              names,
	}
	if _, ok := csr.PublicKey.(*rsa.PublicKey); ok {
		template.KeyUsage |= x509.KeyUsageKeyEncipherment
	}
	if m.cfg.CRLURL != "" {
		template.CRLDistributionPoints = []string{m.cfg.CRLURL}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, m.root.Leaf, csr.PublicKey, m.root.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("sign CSR: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse issued certificate: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(m.root.Leaf)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: now}); err != nil {
		return nil, fmt.Errorf("verify issued certificate chain: %w", err)
	}
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return append(chain, m.rootPEM...), nil
}

func validateCSRKey(key crypto.PublicKey) error {
	switch key := key.(type) {
	case *rsa.PublicKey:
		if key == nil || key.N == nil || key.N.Sign() <= 0 || key.N.Bit(0) == 0 ||
			key.N.BitLen() < 2048 || key.N.BitLen() > 8192 || key.E < 3 || key.E > 1<<31-1 || key.E%2 == 0 {
			return errors.New("CSR requires an RSA key between 2048 and 8192 bits with a valid exponent")
		}
	case *ecdsa.PublicKey:
		if key == nil || (key.Curve != elliptic.P256() && key.Curve != elliptic.P384() && key.Curve != elliptic.P521()) {
			return errors.New("CSR requires ECDSA P-256, P-384, or P-521")
		}
		if key.X == nil || key.Y == nil { //nolint:staticcheck // PublicKey.Bytes panics on nil coordinates in Go 1.26.
			return errors.New("CSR contains an invalid ECDSA point")
		}
		if _, err := key.Bytes(); err != nil {
			return errors.New("CSR contains an invalid ECDSA point")
		}
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return errors.New("CSR contains an invalid Ed25519 key")
		}
	default:
		return errors.New("CSR key type is unsupported")
	}
	return nil
}

func validateCSRExtensions(extensions []pkix.Extension) error {
	for _, ext := range extensions {
		if !ext.Id.Equal(oidSubjectAltName) {
			if ext.Critical {
				return fmt.Errorf("CSR contains an unsupported critical extension: %s", ext.Id)
			}
			// Noncritical requests cannot override this CA's TLS-only profile.
			continue
		}
		// crypto/x509 ignores unknown GeneralName types. Inspect the raw SAN
		// sequence too, so otherName and directoryName cannot escape validation.
		var sequence asn1.RawValue
		rest, err := asn1.Unmarshal(ext.Value, &sequence)
		if err != nil || len(rest) != 0 || sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
			return errors.New("CSR contains a malformed subject alternative name extension")
		}
		for data := sequence.Bytes; len(data) != 0; {
			var name asn1.RawValue
			data, err = asn1.Unmarshal(data, &name)
			if err != nil {
				return fmt.Errorf("parse CSR subject alternative name: %w", err)
			}
			if name.Class != asn1.ClassContextSpecific || name.Tag != 2 || name.IsCompound {
				return errors.New("CSR subject alternative names must contain only DNS names")
			}
		}
	}
	return nil
}

func (m *Manager) csrNames(csr *x509.CertificateRequest, authorizedNames []string) ([]string, error) {
	if len(authorizedNames) == 0 || len(authorizedNames) > 100 || len(csr.DNSNames) != len(authorizedNames) {
		return nil, errors.New("CSR DNS names must exactly match the authorized names (1 to 100 names)")
	}
	authorized := make(map[string]bool, len(authorizedNames))
	for _, name := range authorizedNames {
		canonical := m.certificateName(name)
		if canonical == "" || authorized[canonical] {
			return nil, fmt.Errorf("invalid or duplicate authorized DNS name %q", name)
		}
		authorized[canonical] = true
	}
	names := make([]string, 0, len(csr.DNSNames))
	for _, name := range csr.DNSNames {
		canonical := m.certificateName(name)
		if canonical == "" || !authorized[canonical] {
			return nil, fmt.Errorf("CSR DNS name %q does not match the authorized names", name)
		}
		names = append(names, canonical)
		delete(authorized, canonical)
	}
	for _, attribute := range csr.Subject.Names {
		if attribute.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
			cn, ok := attribute.Value.(string)
			if !ok || !slices.Contains(names, m.certificateName(cn)) {
				return nil, errors.New("CSR common name must match an authorized DNS name")
			}
		}
	}
	// Certificate identity is deterministic regardless of SAN ordering in a CSR.
	slices.Sort(names)
	return names, nil
}

func (m *Manager) certificateName(name string) string {
	for _, c := range name {
		if c > 127 {
			return ""
		}
	}
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if _, err := netip.ParseAddr(name); err == nil {
		return ""
	}
	canonical := strings.TrimSuffix(lease.NormalizeHostname(name, m.cfg.Domain), ".")
	domain := strings.TrimPrefix(m.hostname, "gateway.")
	if name == "" || canonical != name || name == m.hostname || name == "ns."+domain ||
		name == "ldap."+domain {
		return ""
	}
	return canonical
}

// CreateCRL signs a DER revocation list for certificates issued by this CA. The
// caller owns durable revocation records and must increase number for each list.
func (m *Manager) CreateCRL(entries []x509.RevocationListEntry, number int64) ([]byte, error) {
	if number <= 0 {
		return nil, errors.New("CRL number must be positive")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	if err := m.validateRoot(now); err != nil {
		return nil, err
	}
	clean := make([]x509.RevocationListEntry, 0, len(entries))
	seen := make(map[string]bool, len(entries))
	for _, entry := range entries {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 || seen[entry.SerialNumber.String()] {
			return nil, errors.New("CRL entries require distinct positive serial numbers")
		}
		if entry.RevocationTime.IsZero() || entry.RevocationTime.After(now) || entry.ReasonCode < 0 || entry.ReasonCode > 10 || entry.ReasonCode == 7 {
			return nil, errors.New("CRL entry has an invalid revocation time or reason")
		}
		seen[entry.SerialNumber.String()] = true
		clean = append(clean, x509.RevocationListEntry{
			SerialNumber:   new(big.Int).Set(entry.SerialNumber),
			RevocationTime: entry.RevocationTime,
			ReasonCode:     entry.ReasonCode,
		})
	}
	next := now.Add(24 * time.Hour)
	if next.After(m.root.Leaf.NotAfter) {
		next = m.root.Leaf.NotAfter
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(number),
		ThisUpdate:                now,
		NextUpdate:                next,
		RevokedCertificateEntries: clean,
	}, m.root.Leaf, m.root.PrivateKey.(crypto.Signer))
	if err != nil {
		return nil, fmt.Errorf("sign CRL: %w", err)
	}
	return der, nil
}
