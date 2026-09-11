package acmeserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmeauth"
	"github.com/define42/Infrastructure-in-a-Box/internal/acmevalidate"
	"github.com/define42/Infrastructure-in-a-Box/internal/pki"
	"github.com/go-jose/go-jose/v4"
)

type orderValidator struct {
	mu      sync.Mutex
	target  acmevalidate.Target
	fail    error
	started chan struct{}
	resume  chan struct{}
}

func (v *orderValidator) Lookup(string) (acmevalidate.Target, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.target, v.fail
}

func (v *orderValidator) Validate(ctx context.Context, name, token, proof string) (acmevalidate.Target, error) {
	if !strings.HasPrefix(proof, token+".") {
		return acmevalidate.Target{}, errors.New("invalid proof")
	}
	if v.started != nil {
		close(v.started)
		select {
		case <-v.resume:
		case <-ctx.Done():
			return acmevalidate.Target{}, ctx.Err()
		}
	}
	return v.Lookup(name)
}

type orderFixture struct {
	s  *Server
	v  *orderValidator
	a  account
	ca *pki.Manager
}

func setupOrders(t *testing.T) orderFixture {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.Open(pki.Config{Directory: filepath.Join(dir, "ca"), Domain: "home.arpa", ServerIP: netip.MustParseAddr("192.0.2.1")})
	if err != nil {
		t.Fatal(err)
	}
	v := &orderValidator{target: acmevalidate.Target{IP: netip.MustParseAddr("192.0.2.10"), ClientID: "device-1"}}
	s, err := New(Config{BaseURL: "https://gateway.home.arpa/acme", Domain: "home.arpa", StateFile: filepath.Join(dir, "acme.json")}, ca, v, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jose.JSONWebKey{Key: &key.PublicKey}
	thumb, err := acmeauth.Thumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	s.newAccount(rec, &acmeauth.Request{Key: jwk, Thumbprint: thumb, Payload: []byte("{}")})
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: %d %s", rec.Code, rec.Body.String())
	}
	for _, a := range s.state.Accounts {
		return orderFixture{s: s, v: v, a: a, ca: ca}
	}
	t.Fatal("no account")
	return orderFixture{}
}

func (f orderFixture) request(t *testing.T, payload any) *acmeauth.Request {
	t.Helper()
	var data []byte
	if payload != nil {
		var err error
		data, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	return &acmeauth.Request{Payload: data, Key: f.a.Key, KeyID: f.s.url("/account/" + f.a.ID), Thumbprint: f.a.Thumbprint}
}

func (f orderFixture) create(t *testing.T, names ...string) order {
	t.Helper()
	ids := make([]identifier, 0, len(names))
	for _, name := range names {
		ids = append(ids, identifier{Type: "dns", Value: name})
	}
	rec := httptest.NewRecorder()
	f.s.newOrder(rec, f.request(t, map[string]any{"identifiers": ids}), f.a.ID)
	if rec.Code != http.StatusCreated {
		t.Fatalf("new order: %d %s", rec.Code, rec.Body.String())
	}
	id := strings.TrimPrefix(rec.Header().Get("Location"), f.s.url("/order/"))
	return f.s.state.Orders[id]
}

func (f orderFixture) accept(t *testing.T, o order) {
	t.Helper()
	for _, id := range o.AuthIDs {
		rec := httptest.NewRecorder()
		f.s.challenge(rec, httptest.NewRequest(http.MethodPost, f.s.url("/challenge/"+id), nil), f.request(t, map[string]any{}), f.a.ID, id)
		if rec.Code != http.StatusOK {
			t.Fatalf("accept: %d %s", rec.Code, rec.Body.String())
		}
	}
}

func orderCSR(t *testing.T, names ...string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func (f orderFixture) finalize(t *testing.T, o order, der []byte) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	f.s.finalize(rec, f.request(t, map[string]any{"csr": base64.RawURLEncoding.EncodeToString(der)}), f.a.ID, o.ID)
	return rec
}

func TestOrderEnforcesAllAuthorizationsAndExactCSR(t *testing.T) {
	f := setupOrders(t)
	o := f.create(t, "host.home.arpa", "alias.home.arpa")
	csr := orderCSR(t, "host.home.arpa", "alias.home.arpa")
	if rec := f.finalize(t, o, csr); rec.Code != http.StatusForbidden {
		t.Fatalf("unvalidated finalize: %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	f.s.challenge(rec, httptest.NewRequest("POST", "/", nil), f.request(t, map[string]any{}), f.a.ID, o.AuthIDs[0])
	if f.s.state.Orders[o.ID].Status != "pending" {
		t.Fatal("one of two proofs made order ready")
	}
	f.accept(t, o)
	if rec := f.finalize(t, o, orderCSR(t, "host.home.arpa", "intruder.home.arpa")); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "badCSR") {
		t.Fatalf("extra SAN accepted: %d %s", rec.Code, rec.Body.String())
	}
	if rec := f.finalize(t, o, csr); rec.Code != http.StatusOK {
		t.Fatalf("finalize: %d %s", rec.Code, rec.Body.String())
	}
	first := f.s.state.Orders[o.ID].CertificateID
	if rec := f.finalize(t, o, csr); rec.Code != http.StatusOK || f.s.state.Orders[o.ID].CertificateID != first || len(f.s.state.Certificates) != 1 {
		t.Fatal("finalize retry created another certificate")
	}
	if rec := f.finalize(t, o, orderCSR(t, "host.home.arpa", "alias.home.arpa")); rec.Code == http.StatusOK {
		t.Fatal("reused valid order with different CSR")
	}
	leaf, err := parseLeaf(f.s.state.Certificates[first].PEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.CheckSignatureFrom(f.s.root); err != nil {
		t.Fatal(err)
	}
}

func TestOrderRejectsIdentifierPolicy(t *testing.T) {
	for _, name := range []string{"host", "outside.example", "*.home.arpa", "home.arpa", "gateway.home.arpa", "ns.home.arpa", "192.0.2.10", "K.home.arpa", "host.home.arpa.."} {
		t.Run(name, func(t *testing.T) {
			f := setupOrders(t)
			rec := httptest.NewRecorder()
			f.s.newOrder(rec, f.request(t, map[string]any{"identifiers": []identifier{{Type: "dns", Value: name}}}), f.a.ID)
			if rec.Code != http.StatusBadRequest || len(f.s.state.Orders) != 0 {
				t.Fatalf("identifier accepted: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestOrderRejectsLeaseChangesAndExpiry(t *testing.T) {
	for _, change := range []string{"ip", "client", "missing", "expired"} {
		t.Run(change, func(t *testing.T) {
			f := setupOrders(t)
			o := f.create(t, "host.home.arpa")
			f.accept(t, o)
			switch change {
			case "ip":
				f.v.target.IP = netip.MustParseAddr("192.0.2.11")
			case "client":
				f.v.target.ClientID = "replacement-device"
			case "missing":
				f.v.fail = acmevalidate.ErrRejectedIdentifier
			case "expired":
				now := o.Expires.Add(time.Second)
				f.s.now = func() time.Time { return now }
			}
			if rec := f.finalize(t, o, orderCSR(t, "host.home.arpa")); rec.Code != http.StatusForbidden {
				t.Fatalf("changed lease finalized: %d %s", rec.Code, rec.Body.String())
			}
			if len(f.s.state.Certificates) != 0 {
				t.Fatal("issued certificate without current authorization")
			}
		})
	}
}

func TestOrderResourcesAreAccountOwned(t *testing.T) {
	f := setupOrders(t)
	o := f.create(t, "host.home.arpa")
	f.accept(t, o)
	if rec := f.finalize(t, o, orderCSR(t, "host.home.arpa")); rec.Code != http.StatusOK {
		t.Fatal(rec.Body.String())
	}
	other := f.a
	other.ID, _ = randomID()
	f.s.state.Accounts[other.ID] = other
	foreign := f
	foreign.a = other
	reads := []func(*httptest.ResponseRecorder){
		func(w *httptest.ResponseRecorder) { f.s.getOrder(w, foreign.request(t, nil), other.ID, o.ID) },
		func(w *httptest.ResponseRecorder) {
			f.s.getAuthorization(w, foreign.request(t, nil), other.ID, o.AuthIDs[0])
		},
		func(w *httptest.ResponseRecorder) {
			f.s.getCertificate(w, foreign.request(t, nil), other.ID, f.s.state.Orders[o.ID].CertificateID)
		},
		func(w *httptest.ResponseRecorder) {
			f.s.challenge(w, httptest.NewRequest("POST", "/", nil), foreign.request(t, map[string]any{}), other.ID, o.AuthIDs[0])
		},
	}
	for _, read := range reads {
		rec := httptest.NewRecorder()
		read(rec)
		if rec.Code != 404 {
			t.Fatalf("foreign resource: %d", rec.Code)
		}
	}
}

func TestInFlightValidationDiscardsProofAcrossKeyChange(t *testing.T) {
	f := setupOrders(t)
	f.v.started, f.v.resume = make(chan struct{}), make(chan struct{})
	o := f.create(t, "host.home.arpa")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	request := f.request(t, map[string]any{})
	go func() {
		defer close(done)
		f.s.challenge(rec, httptest.NewRequest("POST", "/", nil), request, f.a.ID, o.AuthIDs[0])
	}()
	<-f.v.started
	f.s.mu.Lock()
	a := f.s.state.Accounts[f.a.ID]
	a.Thumbprint = "different-key"
	f.s.state.Accounts[a.ID] = a
	f.s.mu.Unlock()
	close(f.v.resume)
	<-done
	if f.s.state.Orders[o.ID].Status != "pending" || f.s.state.Authorizations[o.AuthIDs[0]].Status != "pending" ||
		f.s.state.Authorizations[o.AuthIDs[0]].ChallengeStatus != "pending" {
		t.Fatal("rollover must discard the stale proof and preserve the pending order")
	}
	f.a = a
	f.v.started, f.v.resume = nil, nil
	f.accept(t, o)
	if f.s.state.Orders[o.ID].Status != "ready" {
		t.Fatal("new account key could not complete the pending order")
	}
}

func TestPersistenceFailureDoesNotPublishOrder(t *testing.T) {
	f := setupOrders(t)
	f.s.cfg.StateFile = filepath.Join(f.s.cfg.StateFile, "not-a-directory")
	rec := httptest.NewRecorder()
	f.s.newOrder(rec, f.request(t, map[string]any{"identifiers": []identifier{{Type: "dns", Value: "host.home.arpa"}}}), f.a.ID)
	if rec.Code != http.StatusInternalServerError || len(f.s.state.Orders) != 0 {
		t.Fatalf("failed snapshot published: %d", rec.Code)
	}
}

func TestChallengeCanRetryAfterResultPersistenceFails(t *testing.T) {
	f := setupOrders(t)
	f.v.started, f.v.resume = make(chan struct{}), make(chan struct{})
	o := f.create(t, "host.home.arpa")
	rec := httptest.NewRecorder()
	done := make(chan struct{})
	request := f.request(t, map[string]any{})
	go func() {
		defer close(done)
		f.s.challenge(rec, httptest.NewRequest("POST", "/", nil), request, f.a.ID, o.AuthIDs[0])
	}()
	<-f.v.started
	f.s.mu.Lock()
	path := f.s.cfg.StateFile
	f.s.cfg.StateFile = filepath.Join(path, "invalid-directory")
	f.s.mu.Unlock()
	close(f.v.resume)
	<-done
	if rec.Code != 500 || f.s.state.Authorizations[o.AuthIDs[0]].ChallengeStatus != "pending" {
		t.Fatalf("failed validation snapshot stranded challenge: %d %s", rec.Code, rec.Body.String())
	}
	f.s.cfg.StateFile = path
	f.v.started, f.v.resume = nil, nil
	f.accept(t, o)
	if f.s.state.Orders[o.ID].Status != "ready" {
		t.Fatal("challenge did not recover after storage recovered")
	}
}

func TestStateRecoveryAndCorruption(t *testing.T) {
	f := setupOrders(t)
	o := f.create(t, "host.home.arpa")
	a := f.s.state.Authorizations[o.AuthIDs[0]]
	a.ChallengeStatus = "processing"
	next := f.s.state.clone()
	next.Authorizations[a.ID] = a
	if err := f.s.commit(next); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(f.s.cfg, f.ca, f.v, f.s.logger)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.state.Authorizations[a.ID].ChallengeStatus != "pending" {
		t.Fatal("interrupted proof retained")
	}
	info, err := os.Stat(f.s.cfg.StateFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state permissions: %v %v", info, err)
	}
	for _, mutation := range []string{"root", "domain", "proof", "reference", "key"} {
		t.Run(mutation, func(t *testing.T) {
			bad := restarted.state.clone()
			switch mutation {
			case "root":
				bad.RootFingerprint = "wrong"
			case "domain":
				bad.Domain = "other.arpa"
			case "proof":
				a := bad.Authorizations[o.AuthIDs[0]]
				a.Status = "valid"
				bad.Authorizations[a.ID] = a
			case "reference":
				delete(bad.Accounts, f.a.ID)
			case "key":
				a := bad.Accounts[f.a.ID]
				a.Thumbprint = "wrong"
				bad.Accounts[a.ID] = a
			}
			if err := restarted.validateState(bad); err == nil {
				t.Fatal("corrupt state accepted")
			}
		})
	}
	if err := os.WriteFile(f.s.cfg.StateFile, []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(f.s.cfg, f.ca, f.v, f.s.logger); err == nil {
		t.Fatal("corrupt state silently replaced")
	}
}
