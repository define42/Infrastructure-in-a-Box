package acmeserver

import (
	"bytes"
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
	"math"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmeauth"
	"github.com/define42/Infrastructure-in-a-Box/internal/acmevalidate"
	"github.com/define42/Infrastructure-in-a-Box/internal/pki"
	"github.com/go-jose/go-jose/v4"
)

type revocationValidator struct {
	targets map[string]acmevalidate.Target
}

func (v revocationValidator) Lookup(name string) (acmevalidate.Target, error) {
	if target, ok := v.targets[name]; ok {
		return target, nil
	}
	return acmevalidate.Target{}, errors.New("no active lease")
}

func (revocationValidator) Validate(context.Context, string, string, string) (acmevalidate.Target, error) {
	return acmevalidate.Target{}, errors.New("unexpected HTTP validation")
}

type revocationFixture struct {
	server      *Server
	ca          *pki.Manager
	leaf        *x509.Certificate
	certificate certificate
	owner       account
	other       account
}

func revocationKey(t *testing.T) jose.JSONWebKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return jose.JSONWebKey{Key: key}
}

func revocationID(t *testing.T) string {
	t.Helper()
	id, err := randomID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newRevocationFixture(t *testing.T, names ...string) *revocationFixture {
	t.Helper()
	if len(names) == 0 {
		names = []string{"app.home.arpa"}
	}
	dir := t.TempDir()
	ca, err := pki.Open(pki.Config{
		Directory: filepath.Join(dir, "ca"), Domain: "home.arpa", ServerIP: netip.MustParseAddr("127.0.0.1"),
		CRLURL: "https://gateway.home.arpa/acme/crl",
	})
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		BaseURL: "https://gateway.home.arpa/acme", Domain: "home.arpa", StateFile: filepath.Join(dir, "acme.json"),
	}, ca, revocationValidator{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	makeAccount := func() account {
		privateKey := revocationKey(t)
		key := privateKey.Public()
		thumbprint, err := acmeauth.Thumbprint(key)
		if err != nil {
			t.Fatal(err)
		}
		return account{ID: revocationID(t), Key: key, Thumbprint: thumbprint, Status: "valid"}
	}
	owner, other := makeAccount(), makeAccount()
	key := revocationKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: names}, key.Key)
	if err != nil {
		t.Fatal(err)
	}
	chain, err := ca.SignCSR(csr, names)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := parseLeaf(chain)
	if err != nil {
		t.Fatal(err)
	}
	cert := certificate{
		ID: revocationID(t), AccountID: owner.ID, OrderID: revocationID(t), PEM: chain,
		Serial: leaf.SerialNumber.String(), NotAfter: leaf.NotAfter,
	}
	now := time.Now()
	s.state.Accounts[owner.ID], s.state.Accounts[other.ID] = owner, other
	o := order{
		ID: cert.OrderID, AccountID: owner.ID, Status: "valid", Expires: now.Add(time.Hour),
		CertificateID: cert.ID, CSR: csr,
	}
	for _, name := range names {
		auth := authorization{
			ID: revocationID(t), AccountID: owner.ID, OrderID: cert.OrderID, Name: name,
			Status: "valid", Expires: o.Expires, Token: revocationID(t), ChallengeStatus: "valid", Validated: &now,
			Target: acmevalidate.Target{IP: netip.MustParseAddr("127.0.0.2"), ClientID: "client-one"},
		}
		s.state.Authorizations[auth.ID] = auth
		o.AuthIDs = append(o.AuthIDs, auth.ID)
		o.Identifiers = append(o.Identifiers, identifier{Type: "dns", Value: name})
	}
	s.state.Orders[o.ID] = o
	s.state.Certificates[cert.ID] = cert
	if err := s.commit(s.state.clone()); err != nil {
		t.Fatal(err)
	}
	return &revocationFixture{server: s, ca: ca, leaf: leaf, certificate: cert, owner: owner, other: other}
}

func (f *revocationFixture) request(t *testing.T, certificateKey bool) *acmeauth.Request {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"certificate": base64.RawURLEncoding.EncodeToString(f.leaf.Raw), "reason": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := &acmeauth.Request{
		Payload: payload, Key: f.owner.Key, KeyID: f.server.url("/account/" + f.owner.ID), Thumbprint: f.owner.Thumbprint,
	}
	if certificateKey {
		request.Key = jose.JSONWebKey{Key: f.leaf.PublicKey}
		request.KeyID = ""
		request.Thumbprint, err = acmeauth.Thumbprint(request.Key)
		if err != nil {
			t.Fatal(err)
		}
	}
	return request
}

func TestRevokeCertificatePublishesPersistentCRL(t *testing.T) {
	t.Parallel()
	for _, certificateKey := range []bool{false, true} {
		t.Run(strconv.FormatBool(certificateKey), func(t *testing.T) {
			t.Parallel()
			f := newRevocationFixture(t)
			signed := f.request(t, certificateKey)
			response := httptest.NewRecorder()
			f.server.revokeCertificate(response, signed)
			if response.Code != http.StatusOK || response.Body.Len() != 0 {
				t.Fatalf("revocation = %d %s", response.Code, response.Body)
			}
			if f.server.state.Certificates[f.certificate.ID].RevokedAt == nil {
				t.Fatal("revocation was not committed")
			}
			crlResponse := httptest.NewRecorder()
			f.server.ServeHTTP(crlResponse, httptest.NewRequest(http.MethodGet, "/acme/crl", nil))
			if crlResponse.Code != http.StatusOK || crlResponse.Header().Get("Content-Type") != "application/pkix-crl" {
				t.Fatalf("CRL response = %d %s", crlResponse.Code, crlResponse.Body)
			}
			crl, err := x509.ParseRevocationList(crlResponse.Body.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			if err := crl.CheckSignatureFrom(f.server.root); err != nil {
				t.Fatal(err)
			}
			if crl.Number.Int64() != 1 || len(crl.RevokedCertificateEntries) != 1 ||
				crl.RevokedCertificateEntries[0].SerialNumber.Cmp(f.leaf.SerialNumber) != 0 || crl.RevokedCertificateEntries[0].ReasonCode != 1 {
				t.Fatal("published CRL does not contain the revoked certificate")
			}
			reopened, err := New(f.server.cfg, f.ca, revocationValidator{}, f.server.logger)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(reopened.state.CRL, crlResponse.Body.Bytes()) || reopened.state.Certificates[f.certificate.ID].RevokedAt == nil {
				t.Fatal("restart lost the CRL or revocation")
			}
			head := httptest.NewRecorder()
			reopened.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "/acme/crl", nil))
			if head.Code != http.StatusOK || head.Body.Len() != 0 || head.Header().Get("Content-Length") != strconv.Itoa(crlResponse.Body.Len()) {
				t.Fatal("HEAD did not describe the downloadable CRL")
			}
			repeated := httptest.NewRecorder()
			reopened.revokeCertificate(repeated, signed)
			var p problem
			if err := json.Unmarshal(repeated.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			if repeated.Code != http.StatusBadRequest || p.Type != problemPrefix+"alreadyRevoked" || reopened.state.CRLNumber != 1 {
				t.Fatal("repeated revocation changed the list or returned the wrong error")
			}
		})
	}
}

func TestRevokeCertificateRejectsUnauthorizedRequests(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		change func(*revocationFixture, *acmeauth.Request)
	}{
		{name: "different account", change: func(f *revocationFixture, r *acmeauth.Request) {
			r.KeyID, r.Key, r.Thumbprint = f.server.url("/account/"+f.other.ID), f.other.Key, f.other.Thumbprint
		}},
		{name: "different embedded key", change: func(f *revocationFixture, r *acmeauth.Request) {
			r.KeyID, r.Key, r.Thumbprint = "", f.other.Key, f.other.Thumbprint
		}},
		{name: "deactivated account", change: func(f *revocationFixture, r *acmeauth.Request) {
			owner := f.owner
			owner.Status = "deactivated"
			f.server.state.Accounts[owner.ID] = owner
		}},
		{name: "rolled over key", change: func(f *revocationFixture, r *acmeauth.Request) {
			owner := f.owner
			owner.Key, owner.Thumbprint = f.other.Key, f.other.Thumbprint
			f.server.state.Accounts[owner.ID] = owner
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newRevocationFixture(t)
			r := f.request(t, false)
			tc.change(f, r)
			response := httptest.NewRecorder()
			f.server.revokeCertificate(response, r)
			if response.Code != http.StatusForbidden || f.server.state.Certificates[f.certificate.ID].RevokedAt != nil || len(f.server.state.CRL) != 0 {
				t.Fatalf("unauthorized revocation changed state or returned %d", response.Code)
			}
		})
	}
}

func TestRevokeCertificateRejectsMalformedRequests(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		payload string
	}{
		{name: "empty"},
		{name: "null", payload: "null"},
		{name: "invalid JSON", payload: "{"},
		{name: "missing certificate", payload: "{}"},
		{name: "invalid encoding", payload: `{"certificate":"+++="}`},
		{name: "invalid DER", payload: `{"certificate":"YQ"}`},
		{name: "negative reason", payload: `{"reason":-1}`},
		{name: "unused reason", payload: `{"reason":7}`},
		{name: "remove from CRL", payload: `{"reason":8}`},
		{name: "unknown reason", payload: `{"reason":11}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newRevocationFixture(t)
			r := f.request(t, false)
			r.Payload = []byte(tc.payload)
			response := httptest.NewRecorder()
			f.server.revokeCertificate(response, r)
			if response.Code != http.StatusBadRequest || f.server.state.Certificates[f.certificate.ID].RevokedAt != nil {
				t.Fatalf("invalid revocation changed state or returned %d", response.Code)
			}
		})
	}
	t.Run("untracked certificate", func(t *testing.T) {
		t.Parallel()
		f := newRevocationFixture(t)
		r := f.request(t, true)
		delete(f.server.state.Certificates, f.certificate.ID)
		response := httptest.NewRecorder()
		f.server.revokeCertificate(response, r)
		if response.Code != http.StatusBadRequest || len(f.server.state.CRL) != 0 {
			t.Fatal("untracked certificate was accepted for revocation")
		}
	})
}

func TestRevokeCertificateWithCurrentNameAuthorizations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		change func(*authorization, map[string]acmevalidate.Target, *account, *acmeauth.Request)
		want   int
	}{
		{name: "all certificate names authorized", want: http.StatusOK},
		{name: "incomplete proof", want: http.StatusForbidden, change: func(a *authorization, _ map[string]acmevalidate.Target, _ *account, _ *acmeauth.Request) {
			a.Status, a.ChallengeStatus, a.Validated = "pending", "pending", nil
		}},
		{name: "expired proof", want: http.StatusForbidden, change: func(a *authorization, _ map[string]acmevalidate.Target, _ *account, _ *acmeauth.Request) {
			a.Expires = time.Now().Add(-time.Second)
		}},
		{name: "deactivated proof", want: http.StatusForbidden, change: func(a *authorization, _ map[string]acmevalidate.Target, _ *account, _ *acmeauth.Request) {
			a.Status = "deactivated"
		}},
		{name: "lease owner changed", want: http.StatusForbidden, change: func(a *authorization, targets map[string]acmevalidate.Target, _ *account, _ *acmeauth.Request) {
			target := targets[a.Name]
			target.ClientID = "new-owner"
			targets[a.Name] = target
		}},
		{name: "lease address changed", want: http.StatusForbidden, change: func(a *authorization, targets map[string]acmevalidate.Target, _ *account, _ *acmeauth.Request) {
			target := targets[a.Name]
			target.IP = netip.MustParseAddr("127.0.0.3")
			targets[a.Name] = target
		}},
		{name: "lease gone", want: http.StatusForbidden, change: func(a *authorization, targets map[string]acmevalidate.Target, _ *account, _ *acmeauth.Request) {
			delete(targets, a.Name)
		}},
		{name: "deactivated account", want: http.StatusForbidden, change: func(_ *authorization, _ map[string]acmevalidate.Target, a *account, _ *acmeauth.Request) {
			a.Status = "deactivated"
		}},
		{name: "stale account key", want: http.StatusForbidden, change: func(_ *authorization, _ map[string]acmevalidate.Target, _ *account, r *acmeauth.Request) {
			r.Thumbprint = "obsolete-key"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newRevocationFixture(t, "app.home.arpa", "second.home.arpa")
			source := f.server.state.Orders[f.certificate.OrderID]
			proofOrder := order{
				ID: revocationID(t), AccountID: f.other.ID, Status: "ready", Expires: time.Now().Add(time.Hour),
				Identifiers: source.Identifiers,
			}
			targets := make(map[string]acmevalidate.Target)
			for _, authID := range source.AuthIDs {
				proof := f.server.state.Authorizations[authID]
				proof.ID, proof.AccountID, proof.OrderID = revocationID(t), f.other.ID, proofOrder.ID
				f.server.state.Authorizations[proof.ID] = proof
				proofOrder.AuthIDs = append(proofOrder.AuthIDs, proof.ID)
				targets[proof.Name] = proof.Target
			}
			f.server.state.Orders[proofOrder.ID] = proofOrder
			f.server.validator = revocationValidator{targets: targets}
			r := f.request(t, false)
			r.Key, r.KeyID, r.Thumbprint = f.other.Key, f.server.url("/account/"+f.other.ID), f.other.Thumbprint
			lastID := proofOrder.AuthIDs[len(proofOrder.AuthIDs)-1]
			proof, actor := f.server.state.Authorizations[lastID], f.other
			if tc.change != nil {
				tc.change(&proof, targets, &actor, r)
				f.server.state.Authorizations[proof.ID] = proof
				f.server.state.Accounts[actor.ID] = actor
			}
			response := httptest.NewRecorder()
			f.server.revokeCertificate(response, r)
			if response.Code != tc.want {
				t.Fatalf("revocation = %d %s; want %d", response.Code, response.Body, tc.want)
			}
			revoked := f.server.state.Certificates[f.certificate.ID].RevokedAt != nil
			if revoked != (tc.want == http.StatusOK) {
				t.Fatal("revocation state does not match authorization result")
			}
			if revoked {
				if _, err := New(f.server.cfg, f.ca, f.server.validator, f.server.logger); err != nil {
					t.Fatalf("restore third-party revocation: %v", err)
				}
			}
		})
	}
}

func TestRevocationPersistenceFailure(t *testing.T) {
	t.Parallel()
	for _, revoke := range []bool{true, false} {
		t.Run(strconv.FormatBool(revoke), func(t *testing.T) {
			t.Parallel()
			f := newRevocationFixture(t)
			if err := os.Remove(f.server.cfg.StateFile); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(f.server.cfg.StateFile, 0o700); err != nil {
				t.Fatal(err)
			}
			response := httptest.NewRecorder()
			if revoke {
				f.server.revokeCertificate(response, f.request(t, false))
			} else {
				f.server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/acme/crl", nil))
			}
			if response.Code != http.StatusInternalServerError || f.server.state.Certificates[f.certificate.ID].RevokedAt != nil || len(f.server.state.CRL) != 0 || f.server.state.CRLNumber != 0 {
				t.Fatal("failed persistence published a successful revocation or CRL")
			}
		})
	}
}

func TestServeCRLRefreshesAndDropsExpiredCertificates(t *testing.T) {
	t.Parallel()
	f := newRevocationFixture(t)
	response := httptest.NewRecorder()
	f.server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/acme/crl", nil))
	if response.Code != http.StatusOK || f.server.state.CRLNumber != 1 {
		t.Fatalf("initial CRL = %d %s", response.Code, response.Body)
	}
	initial := bytes.Clone(response.Body.Bytes())
	response = httptest.NewRecorder()
	f.server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/acme/crl", nil))
	if response.Code != http.StatusOK || !bytes.Equal(initial, response.Body.Bytes()) || f.server.state.CRLNumber != 1 {
		t.Fatal("unexpired CRL was unnecessarily regenerated")
	}
	now := time.Now().Add(-time.Hour)
	expired := f.certificate
	expired.NotAfter, expired.RevokedAt, expired.Reason = now, &now, 1
	f.server.state.Certificates[expired.ID] = expired
	f.server.state.CRLNextUpdate = time.Now().Add(30 * time.Second)
	response = httptest.NewRecorder()
	f.server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/acme/crl", nil))
	if response.Code != http.StatusOK || f.server.state.CRLNumber != 2 {
		t.Fatalf("refresh CRL = %d %s", response.Code, response.Body)
	}
	crl, err := x509.ParseRevocationList(response.Body.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Fatal("CRL retained an expired certificate")
	}
	f.server.state.CRLNumber = math.MaxInt64
	f.server.state.CRLNextUpdate = time.Now()
	response = httptest.NewRecorder()
	f.server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/acme/crl", nil))
	if response.Code != http.StatusInternalServerError {
		t.Fatal("CRL number overflow was accepted")
	}
}
