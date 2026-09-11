package lease

import (
	"strings"
	"testing"
)

func TestNormalizeHostname(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		hostname string
		domain   string
		want     string
	}{
		{"single label", "LAPTOP", "home.arpa", "laptop.home.arpa."},
		{"qualified", "Laptop.Home.ARPA.", "home.arpa", "laptop.home.arpa."},
		{"subdomain", "host.office.home.arpa", "home.arpa", "host.office.home.arpa."},
		{"canonical domain", "host", " HOME.ARPA. ", "host.home.arpa."},
		{"hyphens and digits", "test-42", "home.arpa", "test-42.home.arpa."},
		{"maximum label", strings.Repeat("a", 63), "home.arpa", strings.Repeat("a", 63) + ".home.arpa."},
		{"empty", "", "home.arpa", ""},
		{"empty domain", "host", "", ""},
		{"outside domain", "host.example.org", "home.arpa", ""},
		{"misleading domain suffix", "host.evilhome.arpa", "home.arpa", ""},
		{"domain apex", "home.arpa", "home.arpa", ""},
		{"leading whitespace", " host", "home.arpa", ""},
		{"underscore", "bad_name", "home.arpa", ""},
		{"Unicode", "bærbar", "home.arpa", ""},
		{"wildcard", "*.home.arpa", "home.arpa", ""},
		{"escaped characters", `host\046other`, "home.arpa", ""},
		{"empty label", "host..home.arpa", "home.arpa", ""},
		{"multiple trailing dots", "host.home.arpa..", "home.arpa", ""},
		{"leading hyphen", "-host", "home.arpa", ""},
		{"trailing hyphen", "host-", "home.arpa", ""},
		{"long label", strings.Repeat("a", 64), "home.arpa", ""},
		{"long name", strings.Repeat(strings.Repeat("a", 63)+".", 4) + "home.arpa", "home.arpa", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := NormalizeHostname(tc.hostname, tc.domain); got != tc.want {
				t.Errorf("NormalizeHostname(%q, %q) = %q, want %q", tc.hostname, tc.domain, got, tc.want)
			}
		})
	}
}
