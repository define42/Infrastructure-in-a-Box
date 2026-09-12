package acmeserver

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmeauth"
	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
	"github.com/go-jose/go-jose/v4"
)

// Server shares the gateway's HTTPS listener. It owns the state file and uses
// immutable snapshots so failed persistence never publishes successful changes.
type Server struct {
	mu          sync.Mutex
	activity    map[string]time.Time
	cfg         Config
	ca          Authority
	validator   Validator
	logger      *slog.Logger
	auth        *acmeauth.Verifier
	state       state
	now         func() time.Time
	validations chan struct{}
	root        *x509.Certificate
}

// New restores accounts, orders and certificates without opening any listeners.
func New(cfg Config, ca Authority, validator Validator, logger *slog.Logger) (*Server, error) {
	base, err := url.Parse(cfg.BaseURL)
	if err != nil || base.Scheme != "https" || base.Host == "" || base.User != nil ||
		base.Path != "/acme" || base.RawPath != "" || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("ACME base URL must be an absolute HTTPS URL ending in /acme")
	}
	cfg.Domain = strings.ToLower(strings.TrimSuffix(cfg.Domain, "."))
	if lease.NormalizeHostname("gateway", cfg.Domain) == "" || cfg.StateFile == "" {
		return nil, errors.New("ACME requires a valid domain and persistent state file")
	}
	if cfg.Leases == nil {
		return nil, errors.New("ACME requires a source lease registry")
	}
	if ca == nil || validator == nil {
		return nil, errors.New("ACME requires a signing authority and challenge validator")
	}
	if logger == nil {
		logger = slog.Default()
	}
	block, _ := pem.Decode(ca.RootPEM())
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid ACME root certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ACME root: %w", err)
	}
	hash := sha256.Sum256(root.Raw)
	s := &Server{
		cfg: cfg, ca: ca, validator: validator, logger: logger, now: time.Now, root: root,
		validations: make(chan struct{}, 32),
		state: state{Version: 1, Domain: cfg.Domain, RootFingerprint: hex.EncodeToString(hash[:]),
			Accounts: make(map[string]account), Orders: make(map[string]order),
			Authorizations: make(map[string]authorization), Certificates: make(map[string]certificate)},
	}
	if err := s.restore(); err != nil {
		return nil, err
	}
	// Fail at startup if accounts and issued certificates cannot be persisted.
	// This also saves recovery of interrupted challenge validations.
	if err := s.commit(s.state); err != nil {
		return nil, err
	}
	s.auth = acmeauth.New(s.lookupKey)
	return s, nil
}

func (s *Server) lookupKey(kid string) (jose.JSONWebKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := strings.TrimPrefix(kid, s.url("/account/"))
	if a, ok := s.state.Accounts[id]; ok && kid == s.url("/account/"+id) {
		return a.Key, nil
	}
	return jose.JSONWebKey{}, acmeauth.ErrUnknownAccount
}

func (s *Server) url(path string) string { return s.cfg.BaseURL + path }

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Link", "<"+s.url("/directory")+">;rel=\"index\"")
	nonce, err := s.auth.Nonce()
	if err != nil {
		s.internalError(w, err)
		return
	}
	w.Header().Set("Replay-Nonce", nonce)
	if r.URL.RawQuery != "" || r.URL.RawPath != "" || !strings.HasPrefix(r.URL.Path, "/acme/") {
		s.writeProblem(w, failure(404, "malformed", "unknown ACME resource"))
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/acme")
	if path == "/directory" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		s.directory(w)
		return
	}
	if path == "/new-nonce" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		status := http.StatusNoContent
		if r.Method == http.MethodHead {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		return
	}
	if path == "/crl" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		s.serveCRL(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		s.writeProblem(w, failure(405, "malformed", "this ACME resource requires a signed POST"))
		return
	}
	source := ""
	if path == "/new-account" || path == "/new-order" {
		var p *problem
		source, p = s.sourceLease(r)
		if p != nil {
			s.writeProblem(w, p)
			return
		}
	}
	signed, err := s.auth.Verify(r, s.url(path))
	if err != nil {
		var authErr *acmeauth.Error
		if errors.As(err, &authErr) {
			s.writeProblem(w, failure(authErr.Status, authErr.Type, authErr.Detail))
		} else {
			s.internalError(w, err)
		}
		return
	}
	if path == "/new-account" {
		s.newAccount(w, signed, source)
		return
	}
	if path == "/revoke-cert" {
		s.revokeCertificate(w, signed)
		return
	}
	if signed.KeyID == "" {
		s.writeProblem(w, failure(400, "malformed", "this request requires an account URL in kid"))
		return
	}
	accountID := strings.TrimPrefix(signed.KeyID, s.url("/account/"))
	s.mu.Lock()
	a, ok := s.state.Accounts[accountID]
	s.mu.Unlock()
	if !ok || a.Status != "valid" || a.Thumbprint != signed.Thumbprint {
		s.writeProblem(w, failure(403, "unauthorized", "account is not active or its key has changed"))
		return
	}
	if path == "/directory" || path == "/new-nonce" {
		if !s.postAsGet(w, signed) {
			return
		}
		if path == "/directory" {
			s.directory(w)
		} else {
			w.WriteHeader(http.StatusOK)
		}
		return
	}
	switch {
	case path == "/new-order":
		s.newOrder(w, signed, accountID, source)
	case path == "/key-change":
		s.keyChange(w, signed, accountID)
	case strings.HasPrefix(path, "/account/"):
		s.account(w, signed, accountID, strings.TrimPrefix(path, "/account/"))
	case strings.HasPrefix(path, "/orders/"):
		s.accountOrders(w, signed, accountID, strings.TrimPrefix(path, "/orders/"))
	case strings.HasPrefix(path, "/order/"):
		s.getOrder(w, signed, accountID, strings.TrimPrefix(path, "/order/"))
	case strings.HasPrefix(path, "/authz/"):
		s.getAuthorization(w, signed, accountID, strings.TrimPrefix(path, "/authz/"))
	case strings.HasPrefix(path, "/challenge/"):
		s.challenge(w, r, signed, accountID, strings.TrimPrefix(path, "/challenge/"))
	case strings.HasPrefix(path, "/finalize/"):
		s.finalize(w, signed, accountID, strings.TrimPrefix(path, "/finalize/"))
	case strings.HasPrefix(path, "/certificate/"):
		s.getCertificate(w, signed, accountID, strings.TrimPrefix(path, "/certificate/"))
	default:
		s.writeProblem(w, failure(404, "malformed", "unknown ACME resource"))
	}
}

func (s *Server) directory(w http.ResponseWriter) {
	s.writeJSON(w, http.StatusOK, map[string]any{
		"newNonce": s.url("/new-nonce"), "newAccount": s.url("/new-account"),
		"newOrder": s.url("/new-order"), "revokeCert": s.url("/revoke-cert"),
		"keyChange": s.url("/key-change"), "meta": map[string]any{"externalAccountRequired": false},
	})
}

func decodePayload(data []byte, target any) error {
	if len(data) == 0 {
		return errors.New("a JSON payload is required")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(target); err != nil {
		return err
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return errors.New("unexpected trailing JSON")
	}
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return errors.New("a JSON object is required")
	}
	return nil
}

func (s *Server) postAsGet(w http.ResponseWriter, signed *acmeauth.Request) bool {
	if len(signed.Payload) != 0 {
		s.writeProblem(w, failure(400, "malformed", "POST-as-GET requires an empty payload"))
		return false
	}
	return true
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		s.logger.Debug("write ACME response", "error", err)
	}
}

func (s *Server) writeProblem(w http.ResponseWriter, p *problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	if err := json.NewEncoder(w).Encode(p); err != nil {
		s.logger.Debug("write ACME problem", "error", err)
	}
}

func (s *Server) internalError(w http.ResponseWriter, err error) {
	s.logger.Error("ACME operation failed", "error", err)
	s.writeProblem(w, failure(500, "serverInternal", "the certificate authority could not complete the operation"))
}

func randomID() (string, error) {
	data := make([]byte, 24)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
