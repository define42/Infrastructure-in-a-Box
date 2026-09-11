package lease

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReservedNamesAllowAddressAssignmentWithoutDNS(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		offerName    string
		requestName  string
		repeatOffer  bool
		initialLease bool
	}{
		{name: "direct request", requestName: "PRINTER.HOME.ARPA."},
		{name: "name from offer", offerName: "printer"},
		{name: "name from repeated offer", offerName: "printer", repeatOffer: true},
		{name: "renewal", initialLease: true, requestName: "printer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig()
			cfg.ReservedNames = []string{"PrInTeR"}
			m, now := testManager(t, cfg)
			if tc.initialLease {
				if _, err := m.Commit("client", cfg.PoolStart, "previous"); err != nil {
					t.Fatal(err)
				}
				*now = now.Add(time.Minute)
			}
			if tc.offerName != "" {
				if _, err := m.Offer("client", cfg.PoolStart, tc.offerName); err != nil {
					t.Fatal(err)
				}
			}
			if tc.repeatOffer {
				if _, err := m.Offer("client", cfg.PoolStart, ""); err != nil {
					t.Fatal(err)
				}
			}
			current, err := m.Commit("client", cfg.PoolStart, tc.requestName)
			if err != nil {
				t.Fatal(err)
			}
			if current.IP != cfg.PoolStart || current.ClientID != "client" || current.Hostname != "" {
				t.Fatalf("reserved name changed address assignment or registered DNS: %+v", current)
			}
			if !current.ExpiresAt.Equal(now.Add(cfg.LeaseDuration)) {
				t.Fatalf("reserved name changed lease duration: %v", current.ExpiresAt)
			}
			if _, ok := m.LookupName("PRINTER.HOME.ARPA."); ok {
				t.Fatal("reserved hostname was registered")
			}
			if _, ok := m.LookupName("previous"); ok {
				t.Fatal("renewal left the previous DNS name registered")
			}
			if _, err := m.Commit("client", current.IP, ""); err != nil {
				t.Fatalf("renewing the unnamed lease failed: %v", err)
			}
		})
	}
}

func TestReservedNamesValidateAndCopyConfiguration(t *testing.T) {
	t.Parallel()
	invalid := []string{
		"", "home.arpa", "HOME.ARPA.", "external.example", "bad..name", "bad_name",
		" name", "name ", "*.home.arpa", "192.0.2.1", "Kelvin", "\xff",
		strings.Repeat("a", 64),
	}
	for _, name := range invalid {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig()
			cfg.ReservedNames = []string{name}
			if _, err := New(cfg); err == nil {
				t.Fatalf("New accepted reserved name %q", name)
			}
		})
	}
	for _, name := range []string{"printer", "PRINTER.HOME.ARPA.", "printer.home.arpa", "printer."} {
		t.Run("copy "+name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig()
			cfg.ReservedNames = []string{name}
			m, _ := testManager(t, cfg)
			cfg.ReservedNames[0] = "other"
			printer, err := m.Commit("printer", cfg.PoolStart, "printer")
			if err != nil || printer.Hostname != "" {
				t.Fatalf("reservation was lost after caller changed configuration: %+v, %v", printer, err)
			}
			other, err := m.Commit("other", cfg.PoolStart.Next(), "other")
			if err != nil || other.Hostname != "other.home.arpa." {
				t.Fatalf("caller changed the manager's reserved names: %+v, %v", other, err)
			}
		})
	}
	for _, name := range []string{"lan", "LAN."} {
		cfg := testConfig()
		cfg.Domain = "lan"
		cfg.ReservedNames = []string{name}
		if _, err := New(cfg); err == nil {
			t.Fatalf("New accepted a single-label domain apex %q", name)
		}
	}
}

func TestRestoreClearsNewlyReservedNameAndPreservesLease(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.File = filepath.Join(t.TempDir(), "leases.json")
	m, now := testManager(t, cfg)
	original, err := m.Commit("printer", cfg.PoolStart, "printer")
	if err != nil {
		t.Fatal(err)
	}
	cfg.ReservedNames = []string{"PRINTER.HOME.ARPA."}
	restored, err := newManager(cfg, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	want := original
	want.Hostname = ""
	if current, ok := restored.LookupIP(original.IP); !ok || current != want {
		t.Fatalf("restoring a reserved name changed the lease: %+v, %v; want %+v", current, ok, want)
	}
	if _, ok := restored.LookupName("printer"); ok {
		t.Fatal("restoring a lease re-registered the reserved hostname")
	}
	renewed, err := restored.Commit(original.ClientID, original.IP, "")
	if err != nil || renewed.Hostname != "" {
		t.Fatalf("renewal recovered a reserved hostname: %+v, %v", renewed, err)
	}
	if err := restored.Release(original.ClientID, original.IP); err != nil {
		t.Fatal(err)
	}
	cfg.ReservedNames = nil
	unreserved, err := newManager(cfg, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := unreserved.Commit("replacement", original.IP, "printer")
	if err != nil || replacement.Hostname != original.Hostname {
		t.Fatalf("removing reservation did not allow a future registration: %+v, %v", replacement, err)
	}
	if current, ok := unreserved.LookupName("printer"); !ok || current.ClientID != "replacement" {
		t.Fatalf("new owner was not registered after removing reservation: %+v, %v", current, ok)
	}
}
