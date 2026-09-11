package config_test

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func TestParseDefaults(t *testing.T) {
	t.Parallel()
	cfg, err := config.Parse(validArgs(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	expected := config.Config{
		Interface:     "eth0",
		DHCPAddress:   ":67",
		DNSAddress:    "192.168.50.2:53",
		ServerIP:      netip.MustParseAddr("192.168.50.2"),
		Subnet:        netip.MustParsePrefix("192.168.50.0/24"),
		PoolStart:     netip.MustParseAddr("192.168.50.100"),
		PoolEnd:       netip.MustParseAddr("192.168.50.200"),
		Domain:        "home.arpa",
		LeaseDuration: 12 * time.Hour,
		LeaseFile:     "leases.json",
		DNSTTL:        time.Minute,
		HTTPSAddress:  "192.168.50.2:443",
		CADirectory:   "pki",
		ACMEStateFile: filepath.Join("pki", "acme.json"),
	}
	if cfg != expected {
		t.Errorf("Parse() = %+v, want %+v", cfg, expected)
	}
}

func TestParseOverrides(t *testing.T) {
	t.Parallel()
	args := append(validArgs(),
		"-router", "192.168.50.1",
		"-domain", "LAB.Example.",
		"-lease-duration", "2h",
		"-lease-file", "",
		"-dns-ttl", "10s",
		"-dns-listen", ":1053",
		"-dhcp-listen", "192.168.50.2:1067",
		"-upstream", "127.0.0.1:53",
		"-https-listen", ":8443",
		"-ca-dir", "/var/lib/infra-box/pki",
	)
	cfg, err := config.Parse(args, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Router != netip.MustParseAddr("192.168.50.1") || cfg.Domain != "lab.example" {
		t.Errorf("incorrect router/domain: %+v", cfg)
	}
	if cfg.LeaseFile != "" || cfg.LeaseDuration != 2*time.Hour || cfg.DNSTTL != 10*time.Second {
		t.Errorf("incorrect lease/ttl settings: %+v", cfg)
	}
	if cfg.DNSAddress != ":1053" || cfg.DHCPAddress != "192.168.50.2:1067" || cfg.Upstream != "127.0.0.1:53" {
		t.Errorf("incorrect listener settings: %+v", cfg)
	}
	if cfg.HTTPSAddress != ":8443" || cfg.CADirectory != "/var/lib/infra-box/pki" {
		t.Errorf("incorrect HTTPS/CA settings: %+v", cfg)
	}
	if cfg.ACMEStateFile != "/var/lib/infra-box/pki/acme.json" {
		t.Errorf("ACME default did not follow custom CA directory: %q", cfg.ACMEStateFile)
	}
}

func TestParseACMEStateOverride(t *testing.T) {
	t.Parallel()
	cfg, err := config.Parse(append(validArgs(), "-acme-state", "/var/lib/infra-box/acme.json"), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ACMEStateFile != "/var/lib/infra-box/acme.json" {
		t.Errorf("ACME state file = %q", cfg.ACMEStateFile)
	}
}

func TestParseRejectsACMEStateCollisions(t *testing.T) {
	t.Parallel()
	leasePath, err := filepath.Abs("leases.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"leases.json", leasePath, "./pki/../leases.json", "pki",
		"pki/root-ca-bundle.pem", "pki/gateway-bundle.pem", "pki/root-ca.pem",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			_, err := config.Parse(append(validArgs(), "-acme-state", path), io.Discard)
			if err == nil || !strings.Contains(err.Error(), "-acme-state must differ") {
				t.Fatalf("Parse error = %v, want ACME state collision", err)
			}
		})
	}
	_, err = config.Parse(append(validArgs(), "-lease-file", "pki/acme.json"), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "-acme-state must differ") {
		t.Fatalf("default ACME state collision error = %v", err)
	}
}

func TestParseRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing interface",
			args: []string{"-interface", ""},
			want: "-interface is required",
		},
		{
			name: "missing server",
			args: []string{"-server-ip", ""},
			want: "-server-ip is required",
		},
		{
			name: "ipv6 server",
			args: []string{"-server-ip", "::1"},
			want: "-server-ip",
		},
		{
			name: "mapped server",
			args: []string{"-server-ip", "::ffff:192.168.50.2"},
			want: "-server-ip",
		},
		{
			name: "multicast server",
			args: []string{"-server-ip", "224.0.0.2"},
			want: "unicast",
		},
		{
			name: "server outside subnet",
			args: []string{"-server-ip", "192.168.51.2"},
			want: "belong to subnet",
		},
		{
			name: "server in pool",
			args: []string{"-server-ip", "192.168.50.100"},
			want: "must not include -server-ip",
		},
		{
			name: "missing subnet",
			args: []string{"-subnet", ""},
			want: "-subnet",
		},
		{
			name: "ipv6 subnet",
			args: []string{"-subnet", "fd00::/64"},
			want: "-subnet",
		},
		{
			name: "subnet has host bits",
			args: []string{"-subnet", "192.168.50.2/24"},
			want: "canonical",
		},
		{
			name: "point to point subnet",
			args: []string{"-subnet", "192.168.50.0/31"},
			want: "usable host",
		},
		{
			name: "host subnet",
			args: []string{"-subnet", "192.168.50.2/32"},
			want: "usable host",
		},
		{
			name: "missing pool start",
			args: []string{"-pool-start", ""},
			want: "-pool-start is required",
		},
		{
			name: "missing pool end",
			args: []string{"-pool-end", ""},
			want: "-pool-end is required",
		},
		{
			name: "pool outside subnet",
			args: []string{"-pool-end", "192.168.51.200"},
			want: "belong to subnet",
		},
		{
			name: "pool is reversed",
			args: []string{"-pool-start", "192.168.50.201"},
			want: "less than or equal",
		},
		{
			name: "pool includes network",
			args: []string{"-pool-start", "192.168.50.0"},
			want: "network or broadcast",
		},
		{
			name: "pool includes broadcast",
			args: []string{"-pool-end", "192.168.50.255"},
			want: "network or broadcast",
		},
		{
			name: "pool includes server",
			args: []string{"-pool-start", "192.168.50.1"},
			want: "must not include -server-ip",
		},
		{
			name: "invalid router",
			args: []string{"-router", "router"},
			want: "-router",
		},
		{
			name: "router outside subnet",
			args: []string{"-router", "192.168.51.1"},
			want: "belong to subnet",
		},
		{
			name: "router in pool",
			args: []string{"-router", "192.168.50.200"},
			want: "must not include -router",
		},
		{
			name: "router broadcast",
			args: []string{"-router", "192.168.50.255"},
			want: "network or broadcast",
		},
		{
			name: "empty domain",
			args: []string{"-domain", ""},
			want: "-domain",
		},
		{
			name: "root domain",
			args: []string{"-domain", "."},
			want: "-domain",
		},
		{
			name: "empty domain label",
			args: []string{"-domain", "home..arpa"},
			want: "labels",
		},
		{
			name: "long domain label",
			args: []string{"-domain", strings.Repeat("a", 64)},
			want: "labels",
		},
		{
			name: "domain too long for soa mailbox",
			args: []string{"-domain", strings.Repeat("abcd.", 48) + "abc"},
			want: "242",
		},
		{
			name: "leading label hyphen",
			args: []string{"-domain", "-home.arpa"},
			want: "hyphen",
		},
		{
			name: "trailing label hyphen",
			args: []string{"-domain", "home-.arpa"},
			want: "hyphen",
		},
		{
			name: "invalid domain character",
			args: []string{"-domain", "home_arpa"},
			want: "ascii",
		},
		{
			name: "unicode domain",
			args: []string{"-domain", "høme.arpa"},
			want: "ascii",
		},
		{
			name: "short lease",
			args: []string{"-lease-duration", "59s"},
			want: "at least 1m",
		},
		{
			name: "fractional lease",
			args: []string{"-lease-duration", "1m500ms"},
			want: "whole number",
		},
		{
			name: "lease overflows dhcp field",
			args: []string{"-lease-duration", "4294967296s"},
			want: "cannot exceed",
		},
		{
			name: "zero ttl",
			args: []string{"-dns-ttl", "0s"},
			want: "at least 1s",
		},
		{
			name: "fractional ttl",
			args: []string{"-dns-ttl", "1500ms"},
			want: "whole number",
		},
		{
			name: "ttl overflows dns field",
			args: []string{"-dns-ttl", "4294967296s"},
			want: "cannot exceed",
		},
		{
			name: "invalid dns host",
			args: []string{"-dns-listen", "localhost:53"},
			want: "numeric ipv4",
		},
		{
			name: "ipv6 dns listener",
			args: []string{"-dns-listen", "[::]:53"},
			want: "numeric ipv4",
		},
		{
			name: "dns listener not advertised",
			args: []string{"-dns-listen", "127.0.0.1:53"},
			want: "-dns-listen must bind",
		},
		{
			name: "dhcp listener wrong interface",
			args: []string{"-dhcp-listen", "192.168.51.2:67"},
			want: "-dhcp-listen must bind",
		},
		{
			name: "same udp listener",
			args: []string{"-dhcp-listen", ":53"},
			want: "different udp ports",
		},
		{
			name: "https and dns tcp conflict",
			args: []string{"-https-listen", ":53"},
			want: "different tcp ports",
		},
		{
			name: "https hostname needs resolution",
			args: []string{"-https-listen", "gateway.home.arpa:443"},
			want: "numeric ipv4",
		},
		{
			name: "https not advertised server",
			args: []string{"-https-listen", "192.168.50.3:443"},
			want: "-https-listen must bind",
		},
		{
			name: "zero https port",
			args: []string{"-https-listen", ":0"},
			want: "between 1 and 65535",
		},
		{
			name: "large https port",
			args: []string{"-https-listen", ":65536"},
			want: "between 1 and 65535",
		},
		{
			name: "ipv6 https listener",
			args: []string{"-https-listen", "[::]:443"},
			want: "numeric ipv4",
		},
		{
			name: "empty CA directory",
			args: []string{"-ca-dir", ""},
			want: "persistent directory",
		},
		{
			name: "blank CA directory",
			args: []string{"-ca-dir", " "},
			want: "persistent directory",
		},
		{
			name: "blank ACME state file",
			args: []string{"-acme-state", " "},
			want: "persistent file",
		},
		{
			name: "zero dns port",
			args: []string{"-dns-listen", ":0"},
			want: "between 1 and 65535",
		},
		{
			name: "large dns port",
			args: []string{"-dns-listen", ":65536"},
			want: "between 1 and 65535",
		},
		{
			name: "named dns port",
			args: []string{"-dns-listen", ":domain"},
			want: "between 1 and 65535",
		},
		{
			name: "upstream lacks port",
			args: []string{"-upstream", "1.1.1.1"},
			want: "ipv4:port",
		},
		{
			name: "upstream needs resolution",
			args: []string{"-upstream", "resolver.example:53"},
			want: "numeric ipv4",
		},
		{
			name: "empty upstream host",
			args: []string{"-upstream", ":53"},
			want: "numeric ipv4",
		},
		{
			name: "wildcard upstream",
			args: []string{"-upstream", "0.0.0.0:53"},
			want: "unicast",
		},
		{
			name: "multicast upstream",
			args: []string{"-upstream", "224.0.0.1:53"},
			want: "unicast",
		},
		{
			name: "broadcast upstream",
			args: []string{"-upstream", "255.255.255.255:53"},
			want: "unicast",
		},
		{
			name: "upstream points to listener",
			args: []string{"-upstream", "192.168.50.2:53"},
			want: "point back",
		},
		{
			name: "loopback points to wildcard",
			args: []string{"-dns-listen", ":53", "-upstream", "127.0.0.1:53"},
			want: "point back",
		},
		{
			name: "positional argument",
			args: []string{"serve"},
			want: "positional argument",
		},
		{
			name: "unknown flag",
			args: []string{"-unknown"},
			want: "flag provided but not defined",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Parse(append(validArgs(), tt.args...), io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Parse() error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestParseBoundaryValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{
			name: "single address pool",
			args: []string{"-pool-end", "192.168.50.100"},
		},
		{
			name: "minimum durations",
			args: []string{"-lease-duration", "1m", "-dns-ttl", "1s"},
		},
		{
			name: "maximum durations",
			args: []string{"-lease-duration", "4294967295s", "-dns-ttl", "4294967295s"},
		},
		{
			name: "router is server",
			args: []string{"-router", "192.168.50.2"},
		},
		{
			name: "long valid domain",
			args: []string{"-domain", strings.Repeat("abcd.", 48) + "ab"},
		},
		{
			name: "wildcard listeners",
			args: []string{"-dhcp-listen", "0.0.0.0:67", "-dns-listen", "0.0.0.0:53", "-https-listen", "0.0.0.0:443"},
		},
		{
			name: "dhcp and https use separate transports",
			args: []string{"-https-listen", ":67"},
		},
		{
			name: "upstream same server different port",
			args: []string{"-upstream", "192.168.50.2:1053"},
		},
		{
			name: "loopback upstream separate binding",
			args: []string{"-upstream", "127.0.0.1:53"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := config.Parse(append(validArgs(), tt.args...), io.Discard); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestParseHelp(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	_, err := config.Parse([]string{"-h"}, &output)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("Parse(-h) error = %v, want flag.ErrHelp", err)
	}
	if !strings.Contains(output.String(), "-server-ip") {
		t.Errorf("help did not list flags: %s", output.String())
	}
}

func validArgs() []string {
	return []string{
		"-interface", "eth0",
		"-server-ip", "192.168.50.2",
		"-subnet", "192.168.50.0/24",
		"-pool-start", "192.168.50.100",
		"-pool-end", "192.168.50.200",
	}
}
