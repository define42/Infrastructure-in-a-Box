package acmeserver

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/big"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmeauth"
	"github.com/go-jose/go-jose/v4"
)

func (s *Server) revokeCertificate(w http.ResponseWriter, signed *acmeauth.Request) {
	var payload struct {
		Certificate string `json:"certificate"`
		Reason      int    `json:"reason"`
	}
	if err := decodePayload(signed.Payload, &payload); err != nil {
		s.writeProblem(w, failure(http.StatusBadRequest, "malformed", "invalid certificate revocation payload"))
		return
	}
	if !validRevocationReason(payload.Reason) {
		s.writeProblem(w, failure(http.StatusBadRequest, "badRevocationReason", "unsupported certificate revocation reason"))
		return
	}
	der, err := base64.RawURLEncoding.Strict().DecodeString(payload.Certificate)
	if err != nil || len(der) == 0 || base64.RawURLEncoding.EncodeToString(der) != payload.Certificate {
		s.writeProblem(w, failure(http.StatusBadRequest, "malformed", "certificate must be unpadded base64url DER"))
		return
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		s.writeProblem(w, failure(http.StatusBadRequest, "malformed", "invalid certificate DER"))
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	var issued certificate
	for _, candidate := range s.state.Certificates {
		if candidate.Serial != leaf.SerialNumber.String() {
			continue
		}
		stored, err := parseLeaf(candidate.PEM)
		if err != nil {
			s.internalError(w, fmt.Errorf("read issued certificate: %w", err))
			return
		}
		if bytes.Equal(stored.Raw, der) {
			issued = candidate
			break
		}
	}
	if issued.ID == "" {
		s.writeProblem(w, failure(http.StatusBadRequest, "malformed", "certificate was not issued by this ACME service"))
		return
	}
	if !s.canRevoke(signed, issued, leaf) {
		s.writeProblem(w, failure(http.StatusForbidden, "unauthorized", "revocation requires the issuing account, certificate private key, or current authorizations for every certificate name"))
		return
	}
	if issued.RevokedAt != nil {
		s.writeProblem(w, failure(http.StatusBadRequest, "alreadyRevoked", "certificate has already been revoked"))
		return
	}
	now := s.now()
	issued.RevokedAt, issued.Reason = &now, payload.Reason
	next := s.state.clone()
	next.Certificates[issued.ID] = issued
	if err := s.refreshCRL(&next); err != nil {
		s.internalError(w, err)
		return
	}
	if err := s.commit(next); err != nil {
		s.internalError(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// canRevoke runs under s.mu so a concurrent rollover or deactivation cannot
// authorize a request using an account key that is no longer current.
func (s *Server) canRevoke(signed *acmeauth.Request, issued certificate, leaf *x509.Certificate) bool {
	if signed.KeyID != "" {
		accountID := strings.TrimPrefix(signed.KeyID, s.url("/account/"))
		a, p := s.activeAccount(signed, accountID)
		if p != nil {
			return false
		}
		return a.ID == issued.AccountID || s.authorizedForCertificate(a.ID, leaf)
	}
	thumbprint, err := acmeauth.Thumbprint(jose.JSONWebKey{Key: leaf.PublicKey})
	return err == nil && thumbprint == signed.Thumbprint
}

// RFC 8555 section 7.6 also permits an account that has proved control of every
// certificate identifier. A DHCP reassignment must invalidate the old proof.
func (s *Server) authorizedForCertificate(accountID string, leaf *x509.Certificate) bool {
	if len(leaf.DNSNames) == 0 || len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs) != 0 {
		return false
	}
	now := s.now()
	for _, name := range leaf.DNSNames {
		target, err := s.validator.Lookup(name)
		if err != nil {
			return false
		}
		found := false
		for _, a := range s.state.Authorizations {
			if a.AccountID == accountID && a.Name == name && a.Status == "valid" && a.ChallengeStatus == "valid" &&
				a.Validated != nil && !a.Validated.After(now) && a.Expires.After(now) && a.Target == target {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func validRevocationReason(reason int) bool {
	return reason >= 0 && reason <= 6 || reason == 9 || reason == 10
}

func (s *Server) serveCRL(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if len(s.state.CRL) == 0 || !s.state.CRLNextUpdate.After(s.now().Add(time.Minute)) {
		next := s.state.clone()
		if err := s.refreshCRL(&next); err != nil {
			s.mu.Unlock()
			s.internalError(w, err)
			return
		}
		if err := s.commit(next); err != nil {
			s.mu.Unlock()
			s.internalError(w, err)
			return
		}
	}
	der := bytes.Clone(s.state.CRL)
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Length", strconv.Itoa(len(der)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodHead {
		return
	}
	if _, err := w.Write(der); err != nil {
		s.logger.Debug("write ACME revocation list", "error", err)
	}
}

// refreshCRL runs under s.mu and modifies only the prospective snapshot. The
// caller must durably commit it before publishing a successful response.
func (s *Server) refreshCRL(next *state) error {
	if next.CRLNumber < 0 || next.CRLNumber == math.MaxInt64 {
		return errors.New("CRL number cannot be incremented")
	}
	now := s.now()
	entries := make([]x509.RevocationListEntry, 0)
	for _, cert := range next.Certificates {
		if cert.RevokedAt == nil || !cert.NotAfter.After(now) {
			continue
		}
		serial, ok := new(big.Int).SetString(cert.Serial, 10)
		if !ok || serial.Sign() <= 0 {
			return errors.New("revoked certificate has an invalid serial number")
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber: serial, RevocationTime: *cert.RevokedAt, ReasonCode: cert.Reason,
		})
	}
	slices.SortFunc(entries, func(a, b x509.RevocationListEntry) int {
		return a.SerialNumber.Cmp(b.SerialNumber)
	})
	number := next.CRLNumber + 1
	der, err := s.ca.CreateCRL(entries, number)
	if err != nil {
		return fmt.Errorf("create ACME revocation list: %w", err)
	}
	list, err := x509.ParseRevocationList(der)
	if err != nil {
		return fmt.Errorf("parse ACME revocation list: %w", err)
	}
	if list.Number == nil || list.Number.Cmp(big.NewInt(number)) != 0 || !list.NextUpdate.After(now) {
		return errors.New("certificate authority returned an invalid CRL number or expiry")
	}
	if err := list.CheckSignatureFrom(s.root); err != nil {
		return fmt.Errorf("verify ACME revocation list: %w", err)
	}
	next.CRL, next.CRLNumber, next.CRLNextUpdate = der, number, list.NextUpdate
	return nil
}
