package acmeserver

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmeauth"
	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
	"github.com/go-jose/go-jose/v4"
)

type testSourceRegistry map[netip.Addr]lease.Lease

func (r testSourceRegistry) LookupIP(ip netip.Addr) (lease.Lease, bool) {
	current, ok := r[ip]
	return current, ok
}

func TestAccountCapacityReclaimsIdleAccounts(t *testing.T) {
	t.Parallel()
	s := accountTestServer(t)
	now := s.now()
	s.now = func() time.Time { return now }
	for i := range maxAccounts {
		storedKey := accountTestRequest(t, accountTestKey(t), "", `{}`)
		id := fmt.Sprintf("%032d", i)
		s.state.Accounts[id] = account{ID: id, Status: "valid", LastActive: now, Key: storedKey.Key, Thumbprint: storedKey.Thumbprint}
	}
	signed := accountTestRequest(t, accountTestKey(t), "", `{}`)
	w := httptest.NewRecorder()
	s.newAccount(w, signed, "new-device")
	accountTestProblem(t, w, 429, "rateLimited")
	if w.Header().Get("Retry-After") == "" {
		t.Fatal("missing retry delay")
	}
	id := fmt.Sprintf("%032d", 0)
	a := s.state.Accounts[id]
	a.LastActive = now.Add(-accountIdleLifetime)
	s.state.Accounts[id] = a
	w = httptest.NewRecorder()
	s.newAccount(w, signed, "new-device")
	if w.Code != 201 || len(s.state.Accounts) != maxAccounts {
		t.Fatalf("idle account did not free capacity: %d %s", w.Code, w.Body.String())
	}
	if _, exists := s.state.Accounts[id]; exists {
		t.Fatal("idle account retained")
	}
}

func TestOrderCapacity(t *testing.T) {
	t.Parallel()
	for _, kind := range []string{"pending", "ready", "orders", "authorizations"} {
		t.Run(kind, func(t *testing.T) {
			f := setupOrders(t)
			count := maxAccountOrders
			if kind == "orders" || kind == "authorizations" {
				count = maxRecords
			}
			for i := range count {
				id := fmt.Sprintf("%032d", i)
				owner, status := f.a.ID, kind
				if kind == "orders" || kind == "authorizations" {
					owner, status = "another-account", "pending"
				}
				f.s.state.Orders[id] = order{ID: id, AccountID: owner, Status: status, Expires: f.s.now().Add(time.Hour)}
				if kind == "authorizations" {
					// Fewer orders than the global cap, but no room for another authorization.
					delete(f.s.state.Orders, id)
					f.s.state.Authorizations[id] = authorization{ID: id}
				}
			}
			w := httptest.NewRecorder()
			f.s.newOrder(w, f.request(t, map[string]any{"identifiers": []identifier{{Type: "dns", Value: "host.home.arpa"}}}), f.a.ID, "source")
			accountTestProblem(t, w, 429, "rateLimited")
			if len(f.s.state.LeaseLimits["source"].Orders) != 0 {
				t.Fatal("rejection consumed creation quota")
			}
		})
	}
}

func TestInvalidOrdersArePrunedButStillCountAfterRestart(t *testing.T) {
	t.Parallel()
	f := setupOrders(t)
	now := f.s.now()
	f.s.now = func() time.Time { return now }
	for range maxAccountOrders {
		o := f.create(t, "host.home.arpa")
		w := httptest.NewRecorder()
		f.s.getAuthorization(w, f.request(t, map[string]any{"status": "deactivated"}), f.a.ID, o.AuthIDs[0])
		if w.Code != 200 || len(f.s.state.Orders) != 0 || len(f.s.state.Authorizations) != 0 {
			t.Fatalf("invalid order retained: %d %s", w.Code, w.Body.String())
		}
	}
	restarted, err := New(f.s.cfg, f.ca, f.v, f.s.logger)
	if err != nil {
		t.Fatal(err)
	}
	f.s = restarted
	f.s.now = func() time.Time { return now }
	if len(f.s.state.Orders) != 0 || len(f.s.state.Accounts[f.a.ID].RecentOrders) != maxAccountOrders {
		t.Fatal("restart restored invalid orders or lost quota history")
	}
	// Another source bypasses the lease quota, but must still hit the account quota.
	payload := map[string]any{"identifiers": []identifier{{Type: "dns", Value: "host.home.arpa"}}}
	w := httptest.NewRecorder()
	f.s.newOrder(w, f.request(t, payload), f.a.ID, "other-device")
	accountTestProblem(t, w, 429, "rateLimited")
	now = now.Add(orderLifetime)
	w = httptest.NewRecorder()
	f.s.newOrder(w, f.request(t, payload), f.a.ID, "other-device")
	if w.Code != 201 {
		t.Fatalf("quota did not expire: %d %s", w.Code, w.Body.String())
	}
}

func sourceTestPost(t *testing.T, s *Server, key *ecdsa.PrivateKey, kid, path, peer, payload string) *httptest.ResponseRecorder {
	t.Helper()
	nonce, err := s.auth.Nonce()
	if err != nil {
		t.Fatal(err)
	}
	opts := (&jose.SignerOptions{EmbedJWK: kid == ""}).WithHeader("nonce", nonce).WithHeader("url", s.url(path))
	if kid != "" {
		opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := signer.Sign([]byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, s.url(path), strings.NewReader(signed.FullSerialize()))
	r.Header.Set("Content-Type", "application/jose+json")
	r.Header.Set("X-Forwarded-For", "192.0.2.20")
	r.Header.Set("Forwarded", "for=192.0.2.20")
	r.RemoteAddr = peer
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

func TestSourceLeaseAccountLimit(t *testing.T) {
	t.Parallel()
	s := accountTestServer(t)
	now := s.now()
	s.now = func() time.Time { return now }
	s.auth = acmeauth.New(s.lookupKey)
	first, second := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")
	registry := testSourceRegistry{
		first:  {IP: first, ClientID: "first", ExpiresAt: now.Add(7 * 24 * time.Hour)},
		second: {IP: second, ClientID: "second", ExpiresAt: now.Add(7 * 24 * time.Hour)},
	}
	s.cfg.Leases = registry
	var existing *ecdsa.PrivateKey
	for range maxLeaseAccounts {
		existing = accountTestKey(t)
		w := sourceTestPost(t, s, existing, "", "/new-account", first.String()+":1234", `{}`)
		if w.Code != 201 {
			t.Fatalf("account creation: %d %s", w.Code, w.Body.String())
		}
	}
	path := s.cfg.StateFile
	restarted := accountTestServer(t)
	restarted.cfg = s.cfg
	restarted.now = s.now
	if err := restarted.restore(); err != nil {
		t.Fatal(err)
	}
	restarted.auth = acmeauth.New(restarted.lookupKey)
	s = restarted
	beforeInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	w := sourceTestPost(t, s, accountTestKey(t), "", "/new-account", "[::ffff:192.0.2.10]:9999", `{}`)
	accountTestProblem(t, w, 429, "rateLimited")
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) || !os.SameFile(beforeInfo, afterInfo) || !beforeInfo.ModTime().Equal(afterInfo.ModTime()) {
		t.Fatal("rate-limited request rewrote state")
	}
	w = sourceTestPost(t, s, existing, "", "/new-account", first.String()+":1234", `{"onlyReturnExisting":true}`)
	if w.Code != 200 {
		t.Fatalf("existing account blocked: %d", w.Code)
	}
	moved := netip.MustParseAddr("192.0.2.11")
	registry[moved] = lease.Lease{IP: moved, ClientID: "first", ExpiresAt: now.Add(7 * 24 * time.Hour)}
	w = sourceTestPost(t, s, accountTestKey(t), "", "/new-account", moved.String()+":1234", `{}`)
	accountTestProblem(t, w, 429, "rateLimited")
	w = sourceTestPost(t, s, accountTestKey(t), "", "/new-account", second.String()+":1234", `{}`)
	if w.Code != 201 {
		t.Fatalf("other lease blocked: %d %s", w.Code, w.Body.String())
	}
	now = now.Add(accountRateWindow)
	w = sourceTestPost(t, s, accountTestKey(t), "", "/new-account", first.String()+":1234", `{}`)
	if w.Code != 201 {
		t.Fatalf("expired quota retained: %d %s", w.Code, w.Body.String())
	}
	for _, peer := range []string{"bad", "192.0.2.99:1234", "[::1]:1234"} {
		w = sourceTestPost(t, s, accountTestKey(t), "", "/new-account", peer, `{}`)
		accountTestProblem(t, w, 403, "unauthorized")
	}
	registry[first] = lease.Lease{IP: first, ClientID: "first", ExpiresAt: now}
	w = sourceTestPost(t, s, accountTestKey(t), "", "/new-account", first.String()+":1234", `{}`)
	accountTestProblem(t, w, 403, "unauthorized")
}

func TestSourceLeaseOrderLimitAcrossAccounts(t *testing.T) {
	t.Parallel()
	f := setupOrders(t)
	now := f.s.now()
	f.s.now = func() time.Time { return now }
	keys := []*ecdsa.PrivateKey{accountTestKey(t), accountTestKey(t)}
	kids := make([]string, len(keys))
	for i, key := range keys {
		kids[i] = f.s.url("/account/" + accountTestRegister(t, f.s, key))
	}
	first, second := netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("192.0.2.20")
	f.s.cfg.Leases = testSourceRegistry{
		first:  {IP: first, ClientID: "first", ExpiresAt: now.Add(24 * time.Hour)},
		second: {IP: second, ClientID: "second", ExpiresAt: now.Add(24 * time.Hour)},
	}
	for i := range maxLeaseOrders {
		// Changing both the account and requested hostname still spends the source's quota.
		payload := fmt.Sprintf(`{"identifiers":[{"type":"dns","value":"host%d.home.arpa"}]}`, i)
		w := sourceTestPost(t, f.s, keys[i%2], kids[i%2], "/new-order", first.String()+":1234", payload)
		if w.Code != 201 {
			t.Fatalf("order: %d %s", w.Code, w.Body.String())
		}
	}
	payload := `{"identifiers":[{"type":"dns","value":"other.home.arpa"}]}`
	restarted, err := New(f.s.cfg, f.ca, f.v, f.s.logger)
	if err != nil {
		t.Fatal(err)
	}
	f.s = restarted
	f.s.now = func() time.Time { return now }
	w := sourceTestPost(t, f.s, keys[0], kids[0], "/new-order", first.String()+":4567", payload)
	accountTestProblem(t, w, 429, "rateLimited")
	w = sourceTestPost(t, f.s, keys[0], kids[0], "/new-order", second.String()+":4567", payload)
	if w.Code != 201 {
		t.Fatalf("other source blocked: %d %s", w.Code, w.Body.String())
	}
	now = now.Add(orderRateWindow)
	w = sourceTestPost(t, f.s, keys[0], kids[0], "/new-order", first.String()+":4567", payload)
	if w.Code != 201 {
		t.Fatalf("source window did not expire: %d %s", w.Code, w.Body.String())
	}
}

func TestConcurrentAccountCreationHonorsSourceLimit(t *testing.T) {
	t.Parallel()
	s := accountTestServer(t)
	var wg sync.WaitGroup
	codes := make(chan int, maxLeaseAccounts*2)
	for range cap(codes) {
		request := accountTestRequest(t, accountTestKey(t), "", `{}`)
		wg.Go(func() {
			w := httptest.NewRecorder()
			s.newAccount(w, request, "one-device")
			codes <- w.Code
		})
	}
	wg.Wait()
	close(codes)
	created := 0
	for code := range codes {
		if code == 201 {
			created++
		} else if code != 429 {
			t.Fatalf("unexpected response %d", code)
		}
	}
	if created != maxLeaseAccounts || len(s.state.Accounts) != maxLeaseAccounts {
		t.Fatal("concurrent creation exceeded quota")
	}
}

func TestPruneKeepsReferencedAndActiveAccounts(t *testing.T) {
	t.Parallel()
	f := setupOrders(t)
	o := f.create(t, "host.home.arpa")
	f.accept(t, o)
	if w := f.finalize(t, o, orderCSR(t, "host.home.arpa")); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	idleKey, activeKey := accountTestKey(t), accountTestKey(t)
	idle := accountTestRegister(t, f.s, idleKey)
	active := accountTestRegister(t, f.s, activeKey)
	now := f.s.now().Add(accountIdleLifetime)
	f.s.now = func() time.Time { return now }
	w := httptest.NewRecorder()
	f.s.account(w, accountTestRequest(t, activeKey, f.s.url("/account/"+active), ""), active, active)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if err := f.s.commit(f.s.state.clone()); err != nil {
		t.Fatal(err)
	}
	if _, exists := f.s.state.Accounts[idle]; exists {
		t.Fatal("idle account retained")
	}
	if len(f.s.state.Accounts) != 2 || len(f.s.state.Certificates) != 1 {
		t.Fatal("pruning lost active account or certificate owner")
	}
	if !f.s.state.Accounts[active].LastActive.Equal(now) {
		t.Fatal("read activity was not checkpointed")
	}
	restarted, err := New(f.s.cfg, f.ca, f.v, f.s.logger)
	if err != nil {
		t.Fatal(err)
	}
	if len(restarted.state.Certificates) != 1 {
		t.Fatal("retained certificate did not restore")
	}
}

func TestLegacyAccountExpiryUsesSnapshotTimestamp(t *testing.T) {
	t.Parallel()
	s := accountTestServer(t)
	id := accountTestRegister(t, s, accountTestKey(t))
	a := s.state.Accounts[id]
	a.LastActive = time.Time{}
	s.state.Accounts[id] = a
	data, err := json.Marshal(s.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.cfg.StateFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	old := s.now().Add(-accountIdleLifetime - time.Hour)
	if err := os.Chtimes(s.cfg.StateFile, old, old); err != nil {
		t.Fatal(err)
	}
	if err := s.restore(); err != nil {
		t.Fatal(err)
	}
	if !s.state.Accounts[id].LastActive.Equal(old) {
		t.Fatal("legacy account age was reset")
	}
	if err := s.commit(s.state.clone()); err != nil {
		t.Fatal(err)
	}
	if len(s.state.Accounts) != 0 {
		t.Fatal("legacy idle account retained")
	}
}

func TestOrderCapacityReclaimsInvalidAndExpiredOrders(t *testing.T) {
	t.Parallel()
	for _, status := range []string{"invalid", "pending"} {
		t.Run(status, func(t *testing.T) {
			f := setupOrders(t)
			expires := f.s.now().Add(time.Hour)
			if status == "pending" {
				expires = f.s.now().Add(-time.Hour)
			}
			for i := range maxRecords {
				id := fmt.Sprintf("%032d", i)
				f.s.state.Orders[id] = order{ID: id, AccountID: f.a.ID, Status: status, Expires: expires, AuthIDs: []string{id}}
				f.s.state.Authorizations[id] = authorization{ID: id, OrderID: id}
			}
			f.create(t, "host.home.arpa")
			if len(f.s.state.Orders) != 1 || len(f.s.state.Authorizations) != 1 {
				t.Fatal("full expired/invalid table was not reclaimed before capacity checks")
			}
		})
	}
}

func TestInvalidOrderCleanupIsAtomicWithPersistence(t *testing.T) {
	t.Parallel()
	f := setupOrders(t)
	o := f.create(t, "host.home.arpa")
	path := f.s.cfg.StateFile
	f.s.cfg.StateFile = path + "/not-a-directory"
	w := httptest.NewRecorder()
	request := f.request(t, map[string]any{"status": "deactivated"})
	f.s.getAuthorization(w, request, f.a.ID, o.AuthIDs[0])
	accountTestProblem(t, w, 500, "serverInternal")
	if f.s.state.Orders[o.ID].Status != "pending" || f.s.state.Authorizations[o.AuthIDs[0]].Status != "pending" {
		t.Fatal("failed commit published pruning")
	}
	before, err := json.Marshal(f.s.state)
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	f.s.newOrder(w, f.request(t, map[string]any{"identifiers": []identifier{{Type: "dns", Value: "host.home.arpa"}}}), f.a.ID, "test-device")
	accountTestProblem(t, w, 500, "serverInternal")
	after, err := json.Marshal(f.s.state)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("failed creation changed state or quota history")
	}
	f.s.cfg.StateFile = path
	w = httptest.NewRecorder()
	f.s.getAuthorization(w, request, f.a.ID, o.AuthIDs[0])
	if w.Code != 200 || len(f.s.state.Orders) != 0 || len(f.s.state.Authorizations) != 0 {
		t.Fatal("cleanup could not recover after persistence recovered")
	}
}

func TestFailedChallengePrunesOrder(t *testing.T) {
	t.Parallel()
	f := setupOrders(t)
	o := f.create(t, "host.home.arpa")
	f.v.fail = fmt.Errorf("challenge failed")
	f.accept(t, o)
	if len(f.s.state.Orders) != 0 || len(f.s.state.Authorizations) != 0 || len(f.s.state.Accounts[f.a.ID].RecentOrders) != 1 {
		t.Fatal("failed challenge retained order or forgot its creation")
	}
}

func TestLegacyInvalidOrdersRetainAccountQuota(t *testing.T) {
	t.Parallel()
	f := setupOrders(t)
	for range maxAccountOrders {
		f.create(t, "host.home.arpa")
	}
	for id, o := range f.s.state.Orders {
		o.Status = "invalid"
		f.s.state.Orders[id] = o
	}
	a := f.s.state.Accounts[f.a.ID]
	a.LastActive, a.RecentOrders = time.Time{}, nil
	f.s.state.Accounts[a.ID] = a
	f.s.state.LeaseLimits = nil
	data, err := json.Marshal(f.s.state)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.s.cfg.StateFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	restarted, err := New(f.s.cfg, f.ca, f.v, f.s.logger)
	if err != nil {
		t.Fatal(err)
	}
	f.s = restarted
	if len(f.s.state.Orders) != 0 || len(f.s.state.Authorizations) != 0 {
		t.Fatal("startup retained legacy invalid orders")
	}
	w := httptest.NewRecorder()
	f.s.newOrder(w, f.request(t, map[string]any{"identifiers": []identifier{{Type: "dns", Value: "host.home.arpa"}}}), f.a.ID, "new-device")
	accountTestProblem(t, w, 429, "rateLimited")
}

func TestSourceQuotaStorageIsBoundedAndExpires(t *testing.T) {
	t.Parallel()
	s := accountTestServer(t)
	now := s.now()
	s.now = func() time.Time { return now }
	s.state.LeaseLimits = make(map[string]leaseLimit)
	for i := range maxRecords {
		s.state.LeaseLimits[fmt.Sprint(i)] = leaseLimit{Accounts: []time.Time{now}}
	}
	signed := accountTestRequest(t, accountTestKey(t), "", `{}`)
	w := httptest.NewRecorder()
	s.newAccount(w, signed, "new-device")
	accountTestProblem(t, w, 429, "rateLimited")
	s.state.LeaseLimits["0"] = leaseLimit{Accounts: []time.Time{now.Add(-accountRateWindow)}}
	w = httptest.NewRecorder()
	s.newAccount(w, signed, "new-device")
	if w.Code != 201 || len(s.state.LeaseLimits) != maxRecords {
		t.Fatalf("expired quota blocked creation: %d %s", w.Code, w.Body.String())
	}
	now = now.Add(accountRateWindow)
	if err := s.commit(s.state.clone()); err != nil {
		t.Fatal(err)
	}
	if len(s.state.LeaseLimits) != 0 {
		t.Fatal("expired source quota history retained")
	}
}
