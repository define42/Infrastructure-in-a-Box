package lease

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistenceRestoresLeasesAndQuarantineButNotOffers(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.File = filepath.Join(t.TempDir(), "nested", "leases.json")
	m, now := testManager(t, cfg)
	active, err := m.Commit("active", cfg.PoolStart, "desk")
	if err != nil {
		t.Fatal(err)
	}
	declined, err := m.Offer("declined", cfg.PoolStart.Next(), "bad-address")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Decline("declined", declined.IP); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Offer("uncommitted", cfg.PoolEnd, "pending"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(cfg.File)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("lease file permissions = %o, want 600", info.Mode().Perm())
	}
	readDir, err := os.ReadDir(filepath.Dir(cfg.File))
	if err != nil {
		t.Fatal(err)
	}
	if len(readDir) != 1 || readDir[0].Name() != "leases.json" {
		t.Fatalf("unexpected files after atomic save: %v", readDir)
	}

	restored, err := newManager(cfg, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := restored.LookupName("desk"); !ok || got != active {
		t.Fatalf("persisted DNS lease was not restored: %+v, %v", got, ok)
	}
	if got, ok := restored.LookupIP(active.IP); !ok || got.Hostname != active.Hostname {
		t.Fatalf("persisted reverse DNS was not restored: %+v, %v", got, ok)
	}
	if _, err := restored.Commit("other", declined.IP, "other"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("decline quarantine was lost on restart: %v", err)
	}
	if offer, err := restored.Offer("new-client", cfg.PoolEnd, "new-client"); err != nil || offer.IP != cfg.PoolEnd {
		t.Fatalf("temporary offer survived restart: %+v, %v", offer, err)
	}
	if _, ok := restored.LookupName("pending"); ok {
		t.Fatal("uncommitted hostname appeared after restart")
	}

	*now = now.Add(cfg.LeaseDuration)
	expired, err := newManager(cfg, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := expired.LookupName("desk"); ok {
		t.Fatal("expired persisted lease was restored")
	}
	if _, err := expired.Commit("new-owner", declined.IP, "new-owner"); err != nil {
		t.Fatalf("expired persisted quarantine blocked assignment: %v", err)
	}
}

func TestReleaseIsPersisted(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.File = filepath.Join(t.TempDir(), "leases.json")
	m, now := testManager(t, cfg)
	current, err := m.Commit("client", cfg.PoolStart, "client")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Release("client", current.IP); err != nil {
		t.Fatal(err)
	}
	restored, err := newManager(cfg, func() time.Time { return *now })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.LookupName("client"); ok {
		t.Fatal("released DNS name returned after restart")
	}
	if _, err := restored.Commit("replacement", current.IP, "client"); err != nil {
		t.Fatalf("released lease returned after restart: %v", err)
	}
}

func TestPersistenceFailureDoesNotPublishNewLease(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.PoolEnd = cfg.PoolStart
	cfg.File = filepath.Join(t.TempDir(), "blocked", "leases.json")
	m, _ := testManager(t, cfg)
	if err := os.WriteFile(filepath.Dir(cfg.File), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	offer, err := m.Offer("client", cfg.PoolStart, "client")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Commit("client", offer.IP, ""); err == nil {
		t.Fatal("commit succeeded despite unwritable persistence path")
	}
	if _, ok := m.LookupName("client"); ok {
		t.Fatal("failed commit published DNS record")
	}
	if _, ok := m.LookupIP(offer.IP); ok {
		t.Fatal("failed commit published address assignment")
	}
	if _, err := m.Offer("other", offer.IP, "other"); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("failed commit lost the original reservation: %v", err)
	}
	if err := os.Remove(filepath.Dir(cfg.File)); err != nil {
		t.Fatal(err)
	}
	if current, err := m.Commit("client", offer.IP, ""); err != nil || current.Hostname != "client.home.arpa." {
		t.Fatalf("retry did not retain offer and name: %+v, %v", current, err)
	}
}

func TestPersistenceFailureRollsBackMutations(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*Manager, Lease) error
	}{
		{"renew", func(m *Manager, current Lease) error {
			_, err := m.Commit(current.ClientID, current.IP, "renamed")
			return err
		}},
		{"move", func(m *Manager, current Lease) error {
			_, err := m.Commit(current.ClientID, current.IP.Next(), "renamed")
			return err
		}},
		{"release", func(m *Manager, current Lease) error {
			return m.Release(current.ClientID, current.IP)
		}},
		{"decline", func(m *Manager, current Lease) error {
			return m.Decline(current.ClientID, current.IP)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig()
			cfg.File = filepath.Join(t.TempDir(), "leases.json")
			m, now := testManager(t, cfg)
			original, err := m.Commit("client", cfg.PoolStart, "original")
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(cfg.File)
			if err != nil {
				t.Fatal(err)
			}
			backup := cfg.File + ".backup"
			if err := os.Rename(cfg.File, backup); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(cfg.File, 0o700); err != nil {
				t.Fatal(err)
			}
			*now = now.Add(time.Minute)
			if err := tc.mutate(m, original); err == nil {
				t.Fatal("mutation succeeded although atomic rename was blocked")
			}
			if got, ok := m.LookupName("original"); !ok || got != original {
				t.Fatalf("failed mutation changed original lease: %+v, %v", got, ok)
			}
			if _, ok := m.LookupName("renamed"); ok {
				t.Fatal("failed mutation published new DNS name")
			}
			after, err := os.ReadFile(backup)
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Fatal("failed mutation changed the previous snapshot")
			}
			if err := os.Remove(cfg.File); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(backup, cfg.File); err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(filepath.Dir(cfg.File))
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 1 {
				t.Fatalf("failed save left temporary files behind: %v", entries)
			}
			restored, err := newManager(cfg, func() time.Time { return *now })
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := restored.LookupName("original"); !ok || got != original {
				t.Fatalf("restart after failed mutation changed lease: %+v, %v", got, ok)
			}
		})
	}
}

func TestRestoreRejectsMalformedFiles(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		data string
	}{
		{"malformed JSON", "{"},
		{"empty file", ""},
		{"unsupported version", `{"version":2,"leases":[]}`},
		{"trailing object", `{"version":1,"leases":[]} {}`},
		{"unknown field", `{"version":1,"leases":[],"typo":true}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig()
			cfg.File = filepath.Join(t.TempDir(), "leases.json")
			if err := os.WriteFile(cfg.File, []byte(tc.data), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := New(cfg); err == nil {
				t.Fatal("invalid lease file was accepted")
			}
		})
	}
}

func TestRestoreValidatesAssignments(t *testing.T) {
	t.Parallel()
	valid := Lease{
		ClientID:  "client",
		IP:        netip.MustParseAddr("192.0.2.10"),
		Hostname:  "client.home.arpa.",
		ExpiresAt: time.Date(2030, time.January, 1, 13, 0, 0, 0, time.UTC),
	}
	other := Lease{
		ClientID:  "other",
		IP:        netip.MustParseAddr("192.0.2.11"),
		Hostname:  "other.home.arpa.",
		ExpiresAt: valid.ExpiresAt,
	}
	cases := []struct {
		name   string
		change func(*persistedState)
	}{
		{"empty client", func(s *persistedState) { s.Leases[0].ClientID = "" }},
		{"out of pool", func(s *persistedState) { s.Leases[0].IP = netip.MustParseAddr("192.0.2.99") }},
		{"missing expiry", func(s *persistedState) { s.Leases[0].ExpiresAt = time.Time{} }},
		{"outside domain", func(s *persistedState) { s.Leases[0].Hostname = "client.example.org." }},
		{"invalid hostname", func(s *persistedState) { s.Leases[0].Hostname = "bad_name.home.arpa." }},
		{"reserved hostname", func(s *persistedState) { s.Leases[0].Hostname = "ns.home.arpa." }},
		{"duplicate client", func(s *persistedState) { s.Leases[1].ClientID = valid.ClientID }},
		{"duplicate address", func(s *persistedState) { s.Leases[1].IP = valid.IP }},
		{"duplicate hostname", func(s *persistedState) { s.Leases[1].Hostname = valid.Hostname }},
		{"duplicate legacy gateway hostname", func(s *persistedState) {
			s.Leases[0].Hostname = "gateway.home.arpa."
			s.Leases[1].Hostname = "gateway.home.arpa."
		}},
		{"active quarantine", func(s *persistedState) {
			s.Declined = []declinedAddress{{IP: valid.IP, ExpiresAt: valid.ExpiresAt}}
		}},
		{"invalid quarantine", func(s *persistedState) {
			s.Declined = []declinedAddress{{IP: netip.MustParseAddr("192.0.2.99"), ExpiresAt: valid.ExpiresAt}}
		}},
		{"missing quarantine expiry", func(s *persistedState) {
			s.Declined = []declinedAddress{{IP: netip.MustParseAddr("192.0.2.12")}}
		}},
		{"duplicate quarantine", func(s *persistedState) {
			declined := declinedAddress{IP: netip.MustParseAddr("192.0.2.12"), ExpiresAt: valid.ExpiresAt}
			s.Declined = []declinedAddress{declined, declined}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig()
			cfg.File = filepath.Join(t.TempDir(), "leases.json")
			saved := persistedState{Version: 1, Leases: []Lease{valid, other}}
			tc.change(&saved)
			data, err := json.Marshal(saved)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(cfg.File, data, 0o600); err != nil {
				t.Fatal(err)
			}
			now := valid.ExpiresAt.Add(-time.Hour)
			if _, err := newManager(cfg, func() time.Time { return now }); err == nil {
				t.Fatal("invalid saved assignment was accepted")
			}
		})
	}
}

func TestRestoreMigratesLegacyGatewayLease(t *testing.T) {
	t.Parallel()
	cfg := testConfig()
	cfg.File = filepath.Join(t.TempDir(), "leases.json")
	current := Lease{
		ClientID:  "old-gateway-client",
		IP:        cfg.PoolStart,
		Hostname:  "gateway.home.arpa.",
		ExpiresAt: time.Date(2030, time.January, 1, 13, 0, 0, 0, time.UTC),
	}
	data, err := json.Marshal(persistedState{Version: 1, Leases: []Lease{current}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg.File, data, 0o600); err != nil {
		t.Fatal(err)
	}
	now := current.ExpiresAt.Add(-time.Hour)
	m, err := newManager(cfg, func() time.Time { return now })
	if err != nil {
		t.Fatalf("legacy gateway lease prevented startup: %v", err)
	}
	want := current
	want.Hostname = ""
	if got, ok := m.LookupIP(current.IP); !ok || got != want {
		t.Fatalf("legacy gateway migration changed allocation: %+v, %v; want %+v", got, ok, want)
	}
	if _, ok := m.LookupName("GATEWAY.HOME.ARPA."); ok {
		t.Fatal("legacy gateway hostname remained registered")
	}
	if _, err := m.Commit("other", current.IP, "other"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("migration freed an active client's address: %v", err)
	}
	renewed, err := m.Commit(current.ClientID, current.IP, "")
	if err != nil || renewed != want {
		t.Fatalf("renewal restored reserved hostname: %+v, %v", renewed, err)
	}
	restarted, err := newManager(cfg, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := restarted.LookupIP(current.IP); !ok || got != want {
		t.Fatalf("migrated lease was not persisted: %+v, %v", got, ok)
	}
	now = current.ExpiresAt
	if _, ok := restarted.LookupIP(current.IP); ok {
		t.Fatal("migrated lease outlived its original expiration")
	}
	expired, err := newManager(cfg, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := expired.LookupIP(current.IP); ok {
		t.Fatal("expired migrated lease was restored")
	}
}
