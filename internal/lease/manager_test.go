package lease

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		PoolStart:       netip.MustParseAddr("192.0.2.10"),
		PoolEnd:         netip.MustParseAddr("192.0.2.12"),
		Domain:          "home.arpa",
		LeaseDuration:   time.Hour,
		OfferDuration:   time.Minute,
		DeclineDuration: 5 * time.Minute,
	}
}

func testManager(t *testing.T, cfg Config) (*Manager, *time.Time) {
	t.Helper()
	now := time.Date(2030, time.January, 1, 12, 0, 0, 0, time.UTC)
	m, err := newManager(cfg, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return m, &now
}

func TestNewValidatesConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		change func(*Config)
	}{
		{"missing pool start", func(c *Config) { c.PoolStart = netip.Addr{} }},
		{"IPv6 pool", func(c *Config) { c.PoolEnd = netip.MustParseAddr("2001:db8::1") }},
		{"reversed pool", func(c *Config) { c.PoolStart, c.PoolEnd = c.PoolEnd, c.PoolStart }},
		{"missing domain", func(c *Config) { c.Domain = "" }},
		{"invalid domain", func(c *Config) { c.Domain = "bad..domain" }},
		{"missing lease duration", func(c *Config) { c.LeaseDuration = 0 }},
		{"negative lease duration", func(c *Config) { c.LeaseDuration = -time.Second }},
		{"negative offer duration", func(c *Config) { c.OfferDuration = -time.Second }},
		{"negative decline duration", func(c *Config) { c.DeclineDuration = -time.Second }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig()
			tc.change(&cfg)
			if _, err := New(cfg); err == nil {
				t.Fatal("New accepted invalid configuration")
			}
		})
	}
}

func TestOfferReservesWithoutPublishingDNS(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.PoolEnd = cfg.PoolStart.Next()
	m, now := testManager(t, cfg)
	wanted := cfg.PoolEnd
	first, err := m.Offer("first", wanted, "LAPTOP")
	if err != nil {
		t.Fatal(err)
	}
	if first.IP != wanted || first.Hostname != "laptop.home.arpa." || !first.ExpiresAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected first offer: %+v", first)
	}
	if _, ok := m.LookupName("laptop"); ok {
		t.Fatal("uncommitted offer appeared in DNS")
	}
	if _, ok := m.LookupIP(wanted); ok {
		t.Fatal("uncommitted offer appeared in reverse lookup")
	}
	repeated, err := m.Offer("first", cfg.PoolStart, "")
	if err != nil || repeated.IP != wanted || repeated.Hostname != first.Hostname {
		t.Fatalf("repeated offer changed assignment: %+v, %v", repeated, err)
	}
	second, err := m.Offer("second", wanted, "second")
	if err != nil || second.IP != cfg.PoolStart {
		t.Fatalf("second client did not get remaining address: %+v, %v", second, err)
	}
	if _, err := m.Offer("third", netip.Addr{}, "third"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("full pool error = %v, want ErrPoolExhausted", err)
	}
	if _, err := m.Commit("third", wanted, "third"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("another client stole an offer: %v", err)
	}

	*now = now.Add(time.Minute)
	third, err := m.Offer("third", wanted, "third")
	if err != nil || third.IP != wanted {
		t.Fatalf("expired offer was not reusable: %+v, %v", third, err)
	}
	if _, err := m.Commit("first", wanted, "first"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expired reservation stole new offer: %v", err)
	}
}

func TestOfferPrefersCurrentLeaseAndCarriesHostname(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	m, _ := testManager(t, cfg)
	offer, err := m.Offer("client", cfg.PoolStart, "discover-only")
	if err != nil {
		t.Fatal(err)
	}
	current, err := m.Commit("client", offer.IP, "")
	if err != nil || current.Hostname != "discover-only.home.arpa." {
		t.Fatalf("DISCOVER hostname was lost: %+v, %v", current, err)
	}
	offer, err = m.Offer("client", cfg.PoolEnd, "renamed")
	if err != nil || offer.IP != current.IP {
		t.Fatalf("existing allocation was not preferred: %+v, %v", offer, err)
	}
	renewed, err := m.Commit("client", offer.IP, "")
	if err != nil || renewed.Hostname != "renamed.home.arpa." {
		t.Fatalf("updated DISCOVER hostname was lost: %+v, %v", renewed, err)
	}
	if _, ok := m.LookupName("discover-only"); ok {
		t.Fatal("previous DNS name survived the rename")
	}
}

func TestOfferInvalidHostnameClearsPreviousDNSOnCommit(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	m, _ := testManager(t, cfg)
	current, err := m.Commit("client", cfg.PoolStart, "previous")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Offer("client", current.IP, "bad_name"); err != nil {
		t.Fatal(err)
	}
	// A retransmitted DISCOVER and the REQUEST may both omit the hostname.
	// They must preserve the explicit clearing instruction from the first one.
	if _, err := m.Offer("client", current.IP, ""); err != nil {
		t.Fatal(err)
	}
	renewed, err := m.Commit("client", current.IP, "")
	if err != nil || renewed.Hostname != "" {
		t.Fatalf("invalid offered name restored previous registration: %+v, %v", renewed, err)
	}
	if _, ok := m.LookupName("previous"); ok {
		t.Fatal("previous DNS name survived explicit invalid hostname")
	}
}

func TestCommitRenewsAndExpiresDNS(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	m, now := testManager(t, cfg)
	first, err := m.Commit("client", cfg.PoolStart, "LAPTOP.Home.ARPA.")
	if err != nil {
		t.Fatal(err)
	}
	if first.Hostname != "laptop.home.arpa." || !first.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("unexpected committed lease: %+v", first)
	}
	for _, name := range []string{"laptop", "LAPTOP.HOME.ARPA", "laptop.home.arpa."} {
		if got, ok := m.LookupName(name); !ok || got != first {
			t.Errorf("LookupName(%q) = %+v, %v; want %+v", name, got, ok, first)
		}
	}
	*now = now.Add(30 * time.Minute)
	renewed, err := m.Commit("client", first.IP, "")
	if err != nil || renewed.Hostname != first.Hostname || !renewed.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("renewal did not retain name and extend expiry: %+v, %v", renewed, err)
	}
	*now = first.ExpiresAt
	if _, ok := m.LookupName("laptop"); !ok {
		t.Fatal("renewed lease expired at its original deadline")
	}
	*now = renewed.ExpiresAt
	if _, ok := m.LookupName("laptop"); ok {
		t.Fatal("expired lease remained in DNS")
	}
	if _, ok := m.LookupIP(first.IP); ok {
		t.Fatal("expired lease remained in reverse lookup")
	}
	if offer, err := m.Offer("replacement", first.IP, "replacement"); err != nil || offer.IP != first.IP {
		t.Fatalf("expired address was not recycled: %+v, %v", offer, err)
	}
}

func TestCommitProtectsOtherClientsAndReplacesOwnAddress(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	m, _ := testManager(t, cfg)
	first, err := m.Commit("first", cfg.PoolStart, "first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Commit("second", cfg.PoolStart.Next(), "second")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Commit("second", first.IP, "first"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("another client's committed address was taken: %v", err)
	}
	if got, ok := m.LookupIP(second.IP); !ok || got != second {
		t.Fatalf("failed reassignment changed original lease: %+v, %v", got, ok)
	}
	moved, err := m.Commit("first", cfg.PoolEnd, "")
	if err != nil || moved.Hostname != first.Hostname {
		t.Fatalf("free requested IP could not replace client's allocation: %+v, %v", moved, err)
	}
	if _, ok := m.LookupIP(first.IP); ok {
		t.Fatal("client retained two addresses")
	}
	if got, ok := m.LookupName("first"); !ok || got.IP != moved.IP {
		t.Fatalf("DNS did not follow address change: %+v, %v", got, ok)
	}
	if offer, err := m.Offer("third", first.IP, "third"); err != nil || offer.IP != first.IP {
		t.Fatalf("old allocation was not freed: %+v, %v", offer, err)
	}
}

func TestCommitSuppressesConflictingInvalidAndReservedNames(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		hostname string
	}{
		{"collision", "existing"},
		{"invalid label", "bad_name"},
		{"outside domain", "attacker.example.org"},
		{"reserved nameserver", "NS.HOME.ARPA."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig()
			m, _ := testManager(t, cfg)
			original, err := m.Commit("original", cfg.PoolStart, "existing")
			if err != nil {
				t.Fatal(err)
			}
			second, err := m.Commit("second", cfg.PoolEnd, tc.hostname)
			if err != nil || second.Hostname != "" {
				t.Fatalf("name should be suppressed without denying lease: %+v, %v", second, err)
			}
			if got, ok := m.LookupIP(second.IP); !ok || got.Hostname != "" {
				t.Fatalf("unnamed lease should remain active: %+v, %v", got, ok)
			}
			if got, ok := m.LookupName("existing"); !ok || got != original {
				t.Fatalf("another client's DNS registration changed: %+v, %v", got, ok)
			}
		})
	}
}

func TestCommitRejectsInvalidClientAndAddress(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		clientID string
		ip       netip.Addr
	}{
		{"empty client", "", netip.MustParseAddr("192.0.2.10")},
		{"invalid UTF-8 client", string([]byte{0xff}), netip.MustParseAddr("192.0.2.10")},
		{"missing address", "client", netip.Addr{}},
		{"IPv6 address", "client", netip.MustParseAddr("2001:db8::1")},
		{"address outside pool", "client", netip.MustParseAddr("192.0.2.100")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m, _ := testManager(t, testConfig())
			if _, err := m.Commit(tc.clientID, tc.ip, "client"); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("invalid request error = %v, want ErrUnavailable", err)
			}
		})
	}
}

func TestReleaseChecksOwnershipAndRemovesDNS(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	m, _ := testManager(t, cfg)
	current, err := m.Commit("owner", cfg.PoolStart, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Release("other", current.IP); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("another client released address: %v", err)
	}
	if _, ok := m.LookupName("laptop"); !ok {
		t.Fatal("failed release removed DNS entry")
	}
	if err := m.Release("owner", current.IP); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.LookupName("laptop"); ok {
		t.Fatal("released lease remained in DNS")
	}
	if _, ok := m.LookupIP(current.IP); ok {
		t.Fatal("released lease remained in reverse lookup")
	}
	if offer, err := m.Offer("replacement", current.IP, "laptop"); err != nil || offer.IP != current.IP {
		t.Fatalf("released address was not reusable: %+v, %v", offer, err)
	}
}

func TestDeclineQuarantinesOnlyOwnedAddresses(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.PoolEnd = cfg.PoolStart
	m, now := testManager(t, cfg)
	current, err := m.Commit("owner", cfg.PoolStart, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Decline("other", current.IP); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("another client declined address: %v", err)
	}
	if _, ok := m.LookupName("laptop"); !ok {
		t.Fatal("failed decline removed DNS entry")
	}
	if err := m.Decline("owner", current.IP); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.LookupName("laptop"); ok {
		t.Fatal("declined lease remained in DNS")
	}
	if _, err := m.Offer("replacement", current.IP, "new"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("quarantined address was offered: %v", err)
	}
	if _, err := m.Commit("replacement", current.IP, "new"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("quarantined address was committed: %v", err)
	}
	*now = now.Add(cfg.DeclineDuration)
	offer, err := m.Offer("replacement", current.IP, "new")
	if err != nil || offer.IP != current.IP {
		t.Fatalf("expired quarantine was not reusable: %+v, %v", offer, err)
	}
	if err := m.Decline("replacement", offer.IP); err != nil {
		t.Fatalf("client could not decline its own offer: %v", err)
	}
}

func TestConcurrentAllocationNeverDuplicatesAddresses(t *testing.T) {
	t.Parallel()
	const poolSize = 32
	const clients = 64
	cfg := testConfig()
	cfg.PoolStart = netip.MustParseAddr("192.0.2.1")
	cfg.PoolEnd = netip.MustParseAddr("192.0.2.32")
	m, _ := testManager(t, cfg)
	type result struct {
		lease Lease
		err   error
	}
	results := make(chan result, clients)
	var wg sync.WaitGroup
	for i := range clients {
		wg.Go(func() {
			clientID := fmt.Sprintf("client-%d", i)
			offer, err := m.Offer(clientID, cfg.PoolStart, clientID)
			if err != nil {
				results <- result{err: err}
				return
			}
			current, err := m.Commit(clientID, offer.IP, "")
			if err == nil {
				if found, ok := m.LookupName(clientID); !ok || found.IP != current.IP {
					err = fmt.Errorf("DNS lookup did not match allocation for %s", clientID)
				}
			}
			results <- result{lease: current, err: err}
		})
	}
	wg.Wait()
	close(results)
	addresses := make(map[netip.Addr]bool)
	exhausted := 0
	for got := range results {
		if errors.Is(got.err, ErrPoolExhausted) {
			exhausted++
			continue
		}
		if got.err != nil {
			t.Fatal(got.err)
		}
		if addresses[got.lease.IP] {
			t.Fatalf("address %s was committed to multiple clients", got.lease.IP)
		}
		addresses[got.lease.IP] = true
	}
	if len(addresses) != poolSize || exhausted != clients-poolSize {
		t.Fatalf("allocated %d addresses, exhausted %d clients; want %d and %d", len(addresses), exhausted, poolSize, clients-poolSize)
	}
}
