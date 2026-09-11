package acmevalidate

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
)

const testName = "device.home.arpa"

type testRegistry struct {
	mu    sync.Mutex
	lease lease.Lease
	found bool
}

func (r *testRegistry) LookupName(string) (lease.Lease, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lease, r.found
}

func (r *testRegistry) update(fn func(*lease.Lease)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fn(&r.lease)
}

func newTestValidator(t *testing.T) (*Validator, *testRegistry) {
	t.Helper()
	registry := &testRegistry{
		found: true,
		lease: lease.Lease{
			ClientID:  "client-1",
			IP:        netip.MustParseAddr("192.168.50.10"),
			Hostname:  testName + ".",
			ExpiresAt: time.Now().Add(time.Hour),
		},
	}
	validator, err := New(Config{Domain: "home.arpa", Subnet: netip.MustParsePrefix("192.168.50.0/24")}, registry)
	if err != nil {
		t.Fatal(err)
	}
	return validator, registry
}

func challengeValues() (string, string) {
	token := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("t", 32)))
	thumbprint := base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("k", 32)))
	return token, token + "." + thumbprint
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		domain string
		subnet string
	}{
		{name: "empty domain", domain: "", subnet: "192.168.50.0/24"},
		{name: "wildcard domain", domain: "*.home.arpa", subnet: "192.168.50.0/24"},
		{name: "noncanonical subnet", domain: "home.arpa", subnet: "192.168.50.1/24"},
		{name: "ipv6 subnet", domain: "home.arpa", subnet: "fd00::/64"},
		{name: "no host addresses", domain: "home.arpa", subnet: "192.168.50.0/31"},
		{name: "invalid subnet", domain: "home.arpa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			subnet, _ := netip.ParsePrefix(tc.subnet)
			if _, err := New(Config{Domain: tc.domain, Subnet: subnet}, &testRegistry{}); err == nil {
				t.Fatal("invalid config accepted")
			}
		})
	}
	if _, err := New(Config{Domain: "home.arpa", Subnet: netip.MustParsePrefix("192.168.50.0/24")}, nil); err == nil {
		t.Fatal("nil registry accepted")
	}
}

func TestLookupIdentifierPolicy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		identifier string
		wantOK     bool
	}{
		{name: "hostname", identifier: testName, wantOK: true},
		{name: "canonical spelling", identifier: "DEVICE.HOME.ARPA.", wantOK: true},
		{name: "relative name", identifier: "device"},
		{name: "empty name"},
		{name: "zone apex", identifier: "home.arpa"},
		{name: "gateway", identifier: "GATEWAY.home.arpa."},
		{name: "nameserver", identifier: "ns.home.arpa"},
		{name: "LDAP service", identifier: "ldap.home.arpa"},
		{name: "LDAP service canonical spelling", identifier: "LDAP.HOME.ARPA."},
		{name: "external zone", identifier: "device.example.org"},
		{name: "suffix confusion", identifier: "device.not-home.arpa"},
		{name: "wildcard", identifier: "*.home.arpa"},
		{name: "ipv4", identifier: "192.168.50.10"},
		{name: "ipv6", identifier: "::1"},
		{name: "url", identifier: "http://device.home.arpa"},
		{name: "userinfo", identifier: "user@device.home.arpa"},
		{name: "port", identifier: "device.home.arpa:80"},
		{name: "unicode", identifier: "dévîce.home.arpa"},
		{name: "unicode case fold", identifier: "\u212Aey.home.arpa"},
		{name: "space", identifier: "device.home.arpa "},
		{name: "underscore", identifier: "my_device.home.arpa"},
		{name: "empty label", identifier: "device..home.arpa"},
		{name: "two final dots", identifier: "device.home.arpa.."},
		{name: "hyphen prefix", identifier: "-device.home.arpa"},
		{name: "long label", identifier: strings.Repeat("a", 64) + ".home.arpa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			validator, registry := newTestValidator(t)
			// Ensure rejection tests exercise name policy, not a missing record.
			registry.lease.Hostname = tc.identifier
			target, err := validator.Lookup(tc.identifier)
			if tc.wantOK {
				if err != nil || target.IP != registry.lease.IP || target.ClientID != registry.lease.ClientID {
					t.Fatalf("Lookup = %v, %v", target, err)
				}
			} else if !errors.Is(err, ErrRejectedIdentifier) {
				t.Fatalf("Lookup error = %v, want ErrRejectedIdentifier", err)
			}
		})
	}
}

func TestLookupLeasePolicy(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		edit func(*testRegistry)
	}{
		{name: "unregistered", edit: func(r *testRegistry) { r.found = false }},
		{name: "expired", edit: func(r *testRegistry) { r.lease.ExpiresAt = time.Now().Add(-time.Second) }},
		{name: "no client", edit: func(r *testRegistry) { r.lease.ClientID = "" }},
		{name: "wrong hostname", edit: func(r *testRegistry) { r.lease.Hostname = "other.home.arpa." }},
		{name: "no address", edit: func(r *testRegistry) { r.lease.IP = netip.Addr{} }},
		{name: "outside subnet", edit: func(r *testRegistry) { r.lease.IP = netip.MustParseAddr("192.168.51.10") }},
		{name: "network", edit: func(r *testRegistry) { r.lease.IP = netip.MustParseAddr("192.168.50.0") }},
		{name: "broadcast", edit: func(r *testRegistry) { r.lease.IP = netip.MustParseAddr("192.168.50.255") }},
		{name: "multicast", edit: func(r *testRegistry) { r.lease.IP = netip.MustParseAddr("224.0.0.1") }},
		{name: "unspecified", edit: func(r *testRegistry) { r.lease.IP = netip.MustParseAddr("0.0.0.0") }},
		{name: "ipv6", edit: func(r *testRegistry) { r.lease.IP = netip.MustParseAddr("fd00::1") }},
		{name: "mapped ipv6", edit: func(r *testRegistry) { r.lease.IP = netip.MustParseAddr("::ffff:192.168.50.10") }},
		{name: "loopback outside subnet", edit: func(r *testRegistry) { r.lease.IP = netip.MustParseAddr("127.0.0.1") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			validator, registry := newTestValidator(t)
			tc.edit(registry)
			if _, err := validator.Lookup(testName); !errors.Is(err, ErrRejectedIdentifier) {
				t.Fatalf("Lookup error = %v, want ErrRejectedIdentifier", err)
			}
		})
	}
}

func TestLookupCommittedLeaseLifecycle(t *testing.T) {
	t.Parallel()
	registry, err := lease.New(lease.Config{
		Domain: "home.arpa", PoolStart: netip.MustParseAddr("192.168.50.10"),
		PoolEnd: netip.MustParseAddr("192.168.50.20"), LeaseDuration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	validator, err := New(Config{Domain: "home.arpa", Subnet: netip.MustParsePrefix("192.168.50.0/24")}, registry)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := registry.Offer("client-1", netip.Addr{}, "device")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Lookup(testName); !errors.Is(err, ErrRejectedIdentifier) {
		t.Fatalf("offer can authorize certificates: %v", err)
	}
	if _, err := registry.Commit("client-1", offer.IP, "device"); err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Lookup(testName); err != nil {
		t.Fatalf("committed lease rejected: %v", err)
	}
	if err := registry.Release("client-1", offer.IP); err != nil {
		t.Fatal(err)
	}
	if _, err := validator.Lookup(testName); !errors.Is(err, ErrRejectedIdentifier) {
		t.Fatalf("released lease can authorize certificates: %v", err)
	}
}

func TestValidateRejectsInvalidInputsBeforeDial(t *testing.T) {
	t.Parallel()
	token, authorization := challengeValues()
	cases := []struct {
		name          string
		token         string
		authorization string
	}{
		{name: "short token", token: "abc", authorization: "abc." + strings.Repeat("A", 43)},
		{name: "path traversal", token: "../" + token, authorization: "../" + authorization},
		{name: "padded token", token: token + "=", authorization: authorization},
		{name: "line break", token: token + "\n", authorization: authorization},
		{name: "wrong token prefix", token: token, authorization: "a" + authorization},
		{name: "missing thumbprint", token: token, authorization: token + "."},
		{name: "invalid thumbprint", token: token, authorization: token + "." + strings.Repeat("!", 43)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			validator, _ := newTestValidator(t)
			validator.dialContext = func(context.Context, string, string) (net.Conn, error) {
				t.Error("invalid input attempted a connection")
				return nil, errors.New("unexpected connection")
			}
			if _, err := validator.Validate(t.Context(), testName, tc.token, tc.authorization); !errors.Is(err, ErrChallengeFailed) {
				t.Fatalf("Validate error = %v, want ErrChallengeFailed", err)
			}
		})
	}
}

func TestValidateCancellation(t *testing.T) {
	t.Parallel()
	validator, _ := newTestValidator(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	token, authorization := challengeValues()
	if _, err := validator.Validate(ctx, testName, token, authorization); !errors.Is(err, context.Canceled) {
		t.Fatalf("Validate error = %v, want context.Canceled", err)
	}
}

func TestValidateHasBoundedTimeout(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		validator, _ := newTestValidator(t)
		validator.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		token, authorization := challengeValues()
		started := time.Now()
		_, err := validator.Validate(t.Context(), testName, token, authorization)
		if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) != 5*time.Second {
			t.Fatalf("Validate = %v after %s, want deadline exceeded after 5s", err, time.Since(started))
		}
	})
}
