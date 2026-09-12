package acmeserver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmeauth"
	"github.com/go-jose/go-jose/v4"
)

func TestNewAccountPersistsAndFindsExistingAccount(t *testing.T) {
	t.Parallel()
	s := accountTestServer(t)
	key := accountTestKey(t)
	signed := accountTestRequest(t, key, "", `{"contact":["mailto:admin@example.org"]}`)
	w := httptest.NewRecorder()
	s.newAccount(w, signed, "test-device")
	if w.Code != http.StatusCreated || len(s.state.Accounts) != 1 {
		t.Fatalf("create account: status %d, body %s", w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	id := strings.TrimPrefix(location, s.url("/account/"))
	if !validID(id) || s.state.Accounts[id].Contact[0] != "mailto:admin@example.org" {
		t.Fatalf("incorrect stored account: %+v", s.state.Accounts[id])
	}
	var view map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view["key"] != nil || view["orders"] == nil {
		t.Fatalf("incorrect account response fields: %s", w.Body.String())
	}
	info, err := os.Stat(s.cfg.StateFile)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("account state file permissions: %v, %v", info, err)
	}
	restored := accountTestServer(t)
	restored.cfg.StateFile = s.cfg.StateFile
	if err := restored.restore(); err != nil {
		t.Fatal(err)
	}
	if restored.state.Accounts[id].Thumbprint != signed.Thumbprint {
		t.Fatal("account key did not survive restart")
	}
	signed.Payload = []byte(`{"onlyReturnExisting":true,"contact":["unsupported:ignored"]}`)
	w = httptest.NewRecorder()
	s.newAccount(w, signed, "test-device")
	if w.Code != http.StatusOK || w.Header().Get("Location") != location || len(s.state.Accounts) != 1 ||
		s.state.Accounts[id].Contact[0] != "mailto:admin@example.org" {
		t.Fatalf("existing account lookup changed account: status %d, body %s", w.Code, w.Body.String())
	}
	unknown := accountTestRequest(t, accountTestKey(t), "", `{"onlyReturnExisting":true}`)
	w = httptest.NewRecorder()
	s.newAccount(w, unknown, "test-device")
	accountTestProblem(t, w, http.StatusBadRequest, "accountDoesNotExist")
}

func TestAccountUpdateEnforcesOwnershipAndPersistentChanges(t *testing.T) {
	t.Parallel()
	s := accountTestServer(t)
	key := accountTestKey(t)
	id := accountTestRegister(t, s, key)
	kid := s.url("/account/" + id)
	signed := accountTestRequest(t, key, kid, `{"contact":["mailto:new@example.org"]}`)
	w := httptest.NewRecorder()
	s.account(w, signed, id, "somebody-else")
	accountTestProblem(t, w, http.StatusForbidden, "unauthorized")
	original := s.state
	w = httptest.NewRecorder()
	s.account(w, signed, id, id)
	if w.Code != 200 || s.state.Accounts[id].Contact[0] != "mailto:new@example.org" || len(original.Accounts[id].Contact) != 0 {
		t.Fatalf("account update failed or mutated previous snapshot: status %d, body %s", w.Code, w.Body.String())
	}
	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.cfg.StateFile = filepath.Join(blocker, "state.json")
	signed.Payload = []byte(`{"contact":[]}`)
	w = httptest.NewRecorder()
	s.account(w, signed, id, id)
	accountTestProblem(t, w, http.StatusInternalServerError, "serverInternal")
	if s.state.Accounts[id].Contact[0] != "mailto:new@example.org" {
		t.Fatal("failed persistence published an account update")
	}
}

func TestAccountDeactivationCancelsOutstandingRequests(t *testing.T) {
	t.Parallel()
	s := accountTestServer(t)
	key := accountTestKey(t)
	id := accountTestRegister(t, s, key)
	s.state.Orders["pending"] = order{ID: "pending", AccountID: id, Status: "pending", Expires: s.now().Add(time.Hour), AuthIDs: []string{"auth"}}
	s.state.Orders["issued"] = order{ID: "issued", AccountID: id, Status: "valid", Expires: s.now().Add(time.Hour)}
	s.state.Authorizations["auth"] = authorization{ID: "auth", AccountID: id, Status: "pending", ChallengeStatus: "processing"}
	signed := accountTestRequest(t, key, s.url("/account/"+id), `{"status":"deactivated"}`)
	w := httptest.NewRecorder()
	s.account(w, signed, id, id)
	if w.Code != 200 || s.state.Accounts[id].Status != "deactivated" || len(s.state.Orders) != 1 ||
		len(s.state.Authorizations) != 0 || s.state.Orders["issued"].Status != "valid" {
		t.Fatalf("account deactivation failed: status %d, body %s", w.Code, w.Body.String())
	}
	signed.Payload = []byte(`{"status":"valid"}`)
	w = httptest.NewRecorder()
	s.account(w, signed, id, id)
	accountTestProblem(t, w, http.StatusForbidden, "unauthorized")
}

func TestAccountOrdersFiltersInvalidExpiredAndOtherAccounts(t *testing.T) {
	t.Parallel()
	s := accountTestServer(t)
	key := accountTestKey(t)
	id := accountTestRegister(t, s, key)
	for _, o := range []order{
		{ID: "pending", AccountID: id, Status: "pending", Expires: time.Now().Add(time.Hour)},
		{ID: "invalid", AccountID: id, Status: "invalid", Expires: time.Now().Add(time.Hour)},
		{ID: "expired", AccountID: id, Status: "ready", Expires: time.Now().Add(-time.Hour)},
		{ID: "foreign", AccountID: "another-account", Status: "pending", Expires: time.Now().Add(time.Hour)},
	} {
		s.state.Orders[o.ID] = o
	}
	signed := accountTestRequest(t, key, s.url("/account/"+id), "")
	w := httptest.NewRecorder()
	s.accountOrders(w, signed, id, id)
	var listing struct {
		Orders []string `json:"orders"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &listing); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || len(listing.Orders) != 1 || listing.Orders[0] != s.url("/order/pending") {
		t.Fatalf("unexpected account orders: status %d, body %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.accountOrders(w, signed, id, "another-account")
	accountTestProblem(t, w, http.StatusForbidden, "unauthorized")
	signed.Payload = []byte(`{}`)
	w = httptest.NewRecorder()
	s.accountOrders(w, signed, id, id)
	accountTestProblem(t, w, http.StatusBadRequest, "malformed")
}

func TestKeyChangeRequiresBothKeysAndPreservesAccount(t *testing.T) {
	t.Parallel()
	s := accountTestServer(t)
	oldKey := accountTestKey(t)
	newKey := accountTestKey(t)
	id := accountTestRegister(t, s, oldKey)
	kid := s.url("/account/" + id)
	signed := accountTestRequest(t, oldKey, kid, "")
	signed.Payload = accountTestRollover(t, s, newKey, kid, &oldKey.PublicKey)
	w := httptest.NewRecorder()
	s.keyChange(w, signed, id)
	newSigned := accountTestRequest(t, newKey, kid, "")
	if w.Code != 200 || s.state.Accounts[id].Thumbprint != newSigned.Thumbprint || s.state.Accounts[id].ID != id {
		t.Fatalf("key rollover failed: status %d, body %s", w.Code, w.Body.String())
	}
	signed.Payload = nil
	w = httptest.NewRecorder()
	s.account(w, signed, id, id)
	accountTestProblem(t, w, http.StatusForbidden, "unauthorized")
	w = httptest.NewRecorder()
	s.account(w, newSigned, id, id)
	if w.Code != 200 {
		t.Fatalf("new key cannot access existing account: %s", w.Body.String())
	}
	restored := accountTestServer(t)
	restored.cfg.StateFile = s.cfg.StateFile
	if err := restored.restore(); err != nil {
		t.Fatal(err)
	}
	if restored.state.Accounts[id].Thumbprint != newSigned.Thumbprint {
		t.Fatal("rolled account key was not persisted")
	}
}

func TestKeyChangeRejectsMismatchedIdentityAndExistingKey(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		wrongOld   bool
		wrongID    bool
		existing   bool
		statusCode int
	}{
		{name: "wrong old key", wrongOld: true, statusCode: 400},
		{name: "wrong account", wrongID: true, statusCode: 400},
		{name: "existing new key", existing: true, statusCode: 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := accountTestServer(t)
			oldKey := accountTestKey(t)
			newKey := accountTestKey(t)
			id := accountTestRegister(t, s, oldKey)
			kid := s.url("/account/" + id)
			existingID := ""
			if tc.existing {
				existingID = accountTestRegister(t, s, newKey)
			}
			payloadID := kid
			if tc.wrongID {
				payloadID += "/wrong"
			}
			oldPublic := &oldKey.PublicKey
			if tc.wrongOld {
				oldPublic = &newKey.PublicKey
			}
			signed := accountTestRequest(t, oldKey, kid, "")
			signed.Payload = accountTestRollover(t, s, newKey, payloadID, oldPublic)
			w := httptest.NewRecorder()
			s.keyChange(w, signed, id)
			accountTestProblem(t, w, tc.statusCode, "malformed")
			if s.state.Accounts[id].Thumbprint != signed.Thumbprint {
				t.Fatal("failed rollover modified account key")
			}
			if tc.existing && w.Header().Get("Location") != s.url("/account/"+existingID) {
				t.Fatal("key collision did not identify existing account")
			}
		})
	}
}

func TestAccountContactsRejectInvalidURLs(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		data string
		kind string
	}{
		{"null", `null`, "invalidContact"},
		{"string", `"mailto:a@example.org"`, "invalidContact"},
		{"unsupported scheme", `["https://example.org"]`, "unsupportedContact"},
		{"headers", `["mailto:a@example.org?subject=hi"]`, "invalidContact"},
		{"empty headers", `["mailto:a@example.org?"]`, "invalidContact"},
		{"multiple recipients", `["mailto:a@example.org,b@example.org"]`, "invalidContact"},
		{"not an email", `["mailto:nope"]`, "invalidContact"},
		{"display name", `["mailto:Admin%20%3Ca@example.org%3E"]`, "invalidContact"},
		{"line break", `["mailto:a@example.org%0a"]`, "invalidContact"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, p := accountContacts(json.RawMessage(tc.data))
			if p == nil || p.Type != problemPrefix+tc.kind {
				t.Fatalf("got %v; want %s", p, tc.kind)
			}
		})
	}
	for _, data := range []string{`[]`, `["mailto:admin@example.org"]`, `["mailto:admin+certs%40example.org"]`} {
		if _, p := accountContacts(json.RawMessage(data)); p != nil {
			t.Fatalf("valid contact rejected: %v", p)
		}
	}
}

func accountTestServer(t *testing.T) *Server {
	t.Helper()
	return &Server{
		cfg:    Config{BaseURL: "https://gateway.home.arpa/acme", Domain: "home.arpa", StateFile: filepath.Join(t.TempDir(), "acme.json")},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		now:    time.Now,
		state: state{Version: 1, Domain: "home.arpa", RootFingerprint: "test-ca", Accounts: make(map[string]account),
			Orders: make(map[string]order), Authorizations: make(map[string]authorization), Certificates: make(map[string]certificate)},
	}
}

func accountTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func accountTestRequest(t *testing.T, key *ecdsa.PrivateKey, kid, payload string) *acmeauth.Request {
	t.Helper()
	public := jose.JSONWebKey{Key: &key.PublicKey}
	thumbprint, err := acmeauth.Thumbprint(public)
	if err != nil {
		t.Fatal(err)
	}
	return &acmeauth.Request{Payload: []byte(payload), Key: public, KeyID: kid, Thumbprint: thumbprint}
}

func accountTestRegister(t *testing.T, s *Server, key *ecdsa.PrivateKey) string {
	t.Helper()
	w := httptest.NewRecorder()
	s.newAccount(w, accountTestRequest(t, key, "", `{}`), "test-device")
	if w.Code != 201 {
		t.Fatalf("register account: status %d, body %s", w.Code, w.Body.String())
	}
	return strings.TrimPrefix(w.Header().Get("Location"), s.url("/account/"))
}

func accountTestRollover(t *testing.T, s *Server, newKey *ecdsa.PrivateKey, kid string, oldKey *ecdsa.PublicKey) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"account": kid, "oldKey": jose.JSONWebKey{Key: oldKey}})
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: newKey},
		(&jose.SignerOptions{EmbedJWK: true}).WithHeader("url", s.url("/key-change")))
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(signed.FullSerialize())
}

func accountTestProblem(t *testing.T, w *httptest.ResponseRecorder, status int, kind string) {
	t.Helper()
	var p problem
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if w.Code != status || p.Type != problemPrefix+kind {
		t.Errorf("got status %d, body %s; want %d %s", w.Code, w.Body.String(), status, kind)
	}
}
