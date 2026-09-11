package config_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func TestParseConfigFile(t *testing.T) {
	t.Parallel()
	path := writeConfig(t, "domain", "lab.example")
	cfg, err := config.Parse([]string{"-config", path}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Domain != "lab.example" {
		t.Errorf("Parse() domain = %q, want lab.example", cfg.Domain)
	}
}

func TestParseDefaultConfigFile(t *testing.T) {
	path := writeConfig(t)
	t.Chdir(filepath.Dir(path))
	cfg, err := config.Parse(nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interface != "eth0" || cfg.LeaseFile != filepath.Join(filepath.Dir(path), "leases.json") {
		t.Errorf("Parse() did not load config.json: %+v", cfg)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Parse(nil, io.Discard); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Parse() missing config error = %v, want os.ErrNotExist", err)
	}
}

func TestParseRejectsArguments(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "positional", args: []string{"serve"}, want: "positional argument"},
		{name: "config as positional", args: []string{"other.json"}, want: "positional argument"},
		{name: "unknown flag", args: []string{"-unknown"}, want: "flag provided but not defined"},
		{name: "missing path", args: []string{"-config"}, want: "flag needs an argument"},
	}
	for _, key := range configKeys() {
		tests = append(tests, struct {
			name string
			args []string
			want string
		}{
			name: "legacy " + key,
			args: []string{"-" + strings.ReplaceAll(key, "_", "-"), "value"},
			want: "flag provided but not defined",
		})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			args := append([]string{"-config", writeConfig(t)}, tt.args...)
			_, err := config.Parse(args, io.Discard)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Parse() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestParseHelp(t *testing.T) {
	t.Parallel()
	var output bytes.Buffer
	missing := filepath.Join(t.TempDir(), "missing.json")
	_, err := config.Parse([]string{"-config", missing, "-h"}, &output)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("Parse(-h) error = %v, want flag.ErrHelp", err)
	}
	if !strings.Contains(output.String(), "-config") || !strings.Contains(output.String(), "config.json") {
		t.Errorf("help did not describe the configuration file: %s", output.String())
	}
	if strings.Contains(output.String(), "-server-ip") {
		t.Errorf("help still advertises removed flags: %s", output.String())
	}
}

func TestLoadDefaults(t *testing.T) {
	t.Parallel()
	path := writeConfig(t)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
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
		LeaseFile:     filepath.Join(dir, "leases.json"),
		DNSTTL:        time.Minute,
		HTTPSAddress:  "192.168.50.2:443",
		CADirectory:   filepath.Join(dir, "pki"),
		ACMEStateFile: filepath.Join(dir, "pki", "acme.json"),
	}
	if cfg != expected {
		t.Errorf("Load() = %+v, want %+v", cfg, expected)
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Parallel()
	path := writeConfig(t,
		"router", "192.168.50.1",
		"domain", "LAB.Example.",
		"lease_duration", "2h",
		"lease_file", "",
		"dns_ttl", "10s",
		"dns_listen", ":1053",
		"dhcp_listen", "192.168.50.2:1067",
		"upstream", "127.0.0.1:53",
		"https_listen", ":8443",
		"ca_dir", "/var/lib/infra-box/pki",
	)
	cfg, err := config.Load(path)
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

func TestLoadPersistencePaths(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		lease, ca, acme string
	}{
		{name: "relative", lease: "state/leases.json", ca: "keys/../pki", acme: "state/acme.json"},
		{name: "absolute", lease: "/var/lib/infra-box/leases.json", ca: "/var/lib/infra-box/pki", acme: "/var/lib/infra-box/acme.json"},
		{name: "outside config directory", lease: "../state/leases.json", ca: "../pki", acme: "../state/acme.json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeConfig(t, "lease_file", tt.lease, "ca_dir", tt.ca, "acme_state", tt.acme)
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			checks := []struct{ name, got, value string }{
				{name: "lease_file", got: cfg.LeaseFile, value: tt.lease},
				{name: "ca_dir", got: cfg.CADirectory, value: tt.ca},
				{name: "acme_state", got: cfg.ACMEStateFile, value: tt.acme},
			}
			for _, check := range checks {
				want := filepath.Clean(check.value)
				if !filepath.IsAbs(want) {
					want = filepath.Join(filepath.Dir(path), want)
				}
				if check.got != want {
					t.Errorf("%s = %q, want %q", check.name, check.got, want)
				}
			}
		})
	}
}

func TestLoadOptionalEmptyValues(t *testing.T) {
	t.Parallel()
	path := writeConfig(t,
		"router", "", "upstream", "", "lease_file", "",
		"dns_listen", "", "https_listen", "", "acme_state", "",
	)
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Router.IsValid() || cfg.Upstream != "" || cfg.LeaseFile != "" {
		t.Errorf("optional empty values did not disable their features: %+v", cfg)
	}
	if cfg.DNSAddress != "192.168.50.2:53" || cfg.HTTPSAddress != "192.168.50.2:443" {
		t.Errorf("empty listeners did not derive server addresses: %+v", cfg)
	}
	if cfg.ACMEStateFile != filepath.Join(filepath.Dir(path), "pki", "acme.json") {
		t.Errorf("empty acme_state did not derive the default: %q", cfg.ACMEStateFile)
	}
}

func TestLoadRejectsACMEStateCollisions(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"leases.json", "./pki/../leases.json", "pki",
		"pki/root-ca-bundle.pem", "pki/gateway-bundle.pem", "pki/root-ca.pem",
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			_, err := config.Load(writeConfig(t, "acme_state", value))
			if err == nil || !strings.Contains(err.Error(), "acme_state must differ") {
				t.Fatalf("Load() error = %v, want ACME state collision", err)
			}
		})
	}
	_, err := config.Load(writeConfig(t, "lease_file", "pki/acme.json"))
	if err == nil || !strings.Contains(err.Error(), "acme_state must differ") {
		t.Fatalf("default ACME state collision error = %v", err)
	}
}

func TestLoadRejectsLeaseFileCollisions(t *testing.T) {
	t.Parallel()
	for _, value := range []string{
		"pki", "pki/root-ca-bundle.pem", "pki/gateway-bundle.pem", "pki/root-ca.pem",
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			_, err := config.Load(writeConfig(t, "lease_file", value))
			if err == nil || !strings.Contains(err.Error(), "lease_file must differ") {
				t.Fatalf("Load() error = %v, want lease file collision", err)
			}
		})
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{
			name:   "missing interface",
			values: []string{"interface", ""},
			want:   "interface is required",
		},
		{
			name:   "missing server",
			values: []string{"server_ip", ""},
			want:   "server_ip is required",
		},
		{
			name:   "ipv6 server",
			values: []string{"server_ip", "::1"},
			want:   "server_ip",
		},
		{
			name:   "mapped server",
			values: []string{"server_ip", "::ffff:192.168.50.2"},
			want:   "server_ip",
		},
		{
			name:   "multicast server",
			values: []string{"server_ip", "224.0.0.2"},
			want:   "unicast",
		},
		{
			name:   "server outside subnet",
			values: []string{"server_ip", "192.168.51.2"},
			want:   "belong to subnet",
		},
		{
			name:   "server in pool",
			values: []string{"server_ip", "192.168.50.100"},
			want:   "must not include server_ip",
		},
		{
			name:   "missing subnet",
			values: []string{"subnet", ""},
			want:   "subnet",
		},
		{
			name:   "ipv6 subnet",
			values: []string{"subnet", "fd00::/64"},
			want:   "subnet",
		},
		{
			name:   "subnet has host bits",
			values: []string{"subnet", "192.168.50.2/24"},
			want:   "canonical",
		},
		{
			name:   "point to point subnet",
			values: []string{"subnet", "192.168.50.0/31"},
			want:   "usable host",
		},
		{
			name:   "host subnet",
			values: []string{"subnet", "192.168.50.2/32"},
			want:   "usable host",
		},
		{
			name:   "missing pool start",
			values: []string{"pool_start", ""},
			want:   "pool_start is required",
		},
		{
			name:   "missing pool end",
			values: []string{"pool_end", ""},
			want:   "pool_end is required",
		},
		{
			name:   "pool outside subnet",
			values: []string{"pool_end", "192.168.51.200"},
			want:   "belong to subnet",
		},
		{
			name:   "pool is reversed",
			values: []string{"pool_start", "192.168.50.201"},
			want:   "less than or equal",
		},
		{
			name:   "pool includes network",
			values: []string{"pool_start", "192.168.50.0"},
			want:   "network or broadcast",
		},
		{
			name:   "pool includes broadcast",
			values: []string{"pool_end", "192.168.50.255"},
			want:   "network or broadcast",
		},
		{
			name:   "pool includes server",
			values: []string{"pool_start", "192.168.50.1"},
			want:   "must not include server_ip",
		},
		{
			name:   "invalid router",
			values: []string{"router", "router"},
			want:   "router",
		},
		{
			name:   "router outside subnet",
			values: []string{"router", "192.168.51.1"},
			want:   "belong to subnet",
		},
		{
			name:   "router in pool",
			values: []string{"router", "192.168.50.200"},
			want:   "must not include router",
		},
		{
			name:   "router broadcast",
			values: []string{"router", "192.168.50.255"},
			want:   "network or broadcast",
		},
		{
			name:   "empty domain",
			values: []string{"domain", ""},
			want:   "domain",
		},
		{
			name:   "root domain",
			values: []string{"domain", "."},
			want:   "domain",
		},
		{
			name:   "empty domain label",
			values: []string{"domain", "home..arpa"},
			want:   "labels",
		},
		{
			name:   "long domain label",
			values: []string{"domain", strings.Repeat("a", 64)},
			want:   "labels",
		},
		{
			name:   "domain too long for soa mailbox",
			values: []string{"domain", strings.Repeat("abcd.", 48) + "abc"},
			want:   "242",
		},
		{
			name:   "leading label hyphen",
			values: []string{"domain", "-home.arpa"},
			want:   "hyphen",
		},
		{
			name:   "trailing label hyphen",
			values: []string{"domain", "home-.arpa"},
			want:   "hyphen",
		},
		{
			name:   "invalid domain character",
			values: []string{"domain", "home_arpa"},
			want:   "ascii",
		},
		{
			name:   "unicode domain",
			values: []string{"domain", "høme.arpa"},
			want:   "ascii",
		},
		{
			name:   "unicode domain with ascii case fold",
			values: []string{"domain", "K.home.arpa"},
			want:   "ascii",
		},
		{
			name:   "empty lease duration",
			values: []string{"lease_duration", ""},
			want:   "lease_duration",
		},
		{
			name:   "invalid lease duration",
			values: []string{"lease_duration", "twelve hours"},
			want:   "lease_duration",
		},
		{
			name:   "short lease",
			values: []string{"lease_duration", "59s"},
			want:   "at least 1m",
		},
		{
			name:   "fractional lease",
			values: []string{"lease_duration", "1m500ms"},
			want:   "whole number",
		},
		{
			name:   "lease overflows dhcp field",
			values: []string{"lease_duration", "4294967296s"},
			want:   "cannot exceed",
		},
		{
			name:   "empty ttl",
			values: []string{"dns_ttl", ""},
			want:   "dns_ttl",
		},
		{
			name:   "invalid ttl",
			values: []string{"dns_ttl", "60"},
			want:   "dns_ttl",
		},
		{
			name:   "zero ttl",
			values: []string{"dns_ttl", "0s"},
			want:   "at least 1s",
		},
		{
			name:   "fractional ttl",
			values: []string{"dns_ttl", "1500ms"},
			want:   "whole number",
		},
		{
			name:   "ttl overflows dns field",
			values: []string{"dns_ttl", "4294967296s"},
			want:   "cannot exceed",
		},
		{
			name:   "empty dhcp listener",
			values: []string{"dhcp_listen", ""},
			want:   "dhcp_listen",
		},
		{
			name:   "invalid dns host",
			values: []string{"dns_listen", "localhost:53"},
			want:   "numeric ipv4",
		},
		{
			name:   "ipv6 dns listener",
			values: []string{"dns_listen", "[::]:53"},
			want:   "numeric ipv4",
		},
		{
			name:   "dns listener not advertised",
			values: []string{"dns_listen", "127.0.0.1:53"},
			want:   "dns_listen must bind",
		},
		{
			name:   "dhcp listener wrong interface",
			values: []string{"dhcp_listen", "192.168.51.2:67"},
			want:   "dhcp_listen must bind",
		},
		{
			name:   "same udp listener",
			values: []string{"dhcp_listen", ":53"},
			want:   "different udp ports",
		},
		{
			name:   "https and dns tcp conflict",
			values: []string{"https_listen", ":53"},
			want:   "different tcp ports",
		},
		{
			name:   "https hostname needs resolution",
			values: []string{"https_listen", "gateway.home.arpa:443"},
			want:   "numeric ipv4",
		},
		{
			name:   "https not advertised server",
			values: []string{"https_listen", "192.168.50.3:443"},
			want:   "https_listen must bind",
		},
		{
			name:   "zero https port",
			values: []string{"https_listen", ":0"},
			want:   "between 1 and 65535",
		},
		{
			name:   "large https port",
			values: []string{"https_listen", ":65536"},
			want:   "between 1 and 65535",
		},
		{
			name:   "ipv6 https listener",
			values: []string{"https_listen", "[::]:443"},
			want:   "numeric ipv4",
		},
		{
			name:   "empty CA directory",
			values: []string{"ca_dir", ""},
			want:   "persistent directory",
		},
		{
			name:   "blank CA directory",
			values: []string{"ca_dir", " "},
			want:   "persistent directory",
		},
		{
			name:   "blank ACME state file",
			values: []string{"acme_state", " "},
			want:   "persistent file",
		},
		{
			name:   "zero dns port",
			values: []string{"dns_listen", ":0"},
			want:   "between 1 and 65535",
		},
		{
			name:   "large dns port",
			values: []string{"dns_listen", ":65536"},
			want:   "between 1 and 65535",
		},
		{
			name:   "named dns port",
			values: []string{"dns_listen", ":domain"},
			want:   "between 1 and 65535",
		},
		{
			name:   "upstream lacks port",
			values: []string{"upstream", "1.1.1.1"},
			want:   "ipv4:port",
		},
		{
			name:   "upstream needs resolution",
			values: []string{"upstream", "resolver.example:53"},
			want:   "numeric ipv4",
		},
		{
			name:   "empty upstream host",
			values: []string{"upstream", ":53"},
			want:   "numeric ipv4",
		},
		{
			name:   "wildcard upstream",
			values: []string{"upstream", "0.0.0.0:53"},
			want:   "unicast",
		},
		{
			name:   "multicast upstream",
			values: []string{"upstream", "224.0.0.1:53"},
			want:   "unicast",
		},
		{
			name:   "broadcast upstream",
			values: []string{"upstream", "255.255.255.255:53"},
			want:   "unicast",
		},
		{
			name:   "upstream points to listener",
			values: []string{"upstream", "192.168.50.2:53"},
			want:   "point back",
		},
		{
			name:   "loopback points to wildcard",
			values: []string{"dns_listen", ":53", "upstream", "127.0.0.1:53"},
			want:   "point back",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Load(writeConfig(t, tt.values...))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Load() error = %v, want error containing %q", err, tt.want)
			}
		})
	}
}

func TestLoadBoundaryValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		values []string
	}{
		{
			name:   "single address pool",
			values: []string{"pool_end", "192.168.50.100"},
		},
		{
			name:   "minimum durations",
			values: []string{"lease_duration", "1m", "dns_ttl", "1s"},
		},
		{
			name:   "maximum durations",
			values: []string{"lease_duration", "4294967295s", "dns_ttl", "4294967295s"},
		},
		{
			name:   "router is server",
			values: []string{"router", "192.168.50.2"},
		},
		{
			name:   "long valid domain",
			values: []string{"domain", strings.Repeat("abcd.", 48) + "ab"},
		},
		{
			name:   "wildcard listeners",
			values: []string{"dhcp_listen", "0.0.0.0:67", "dns_listen", "0.0.0.0:53", "https_listen", "0.0.0.0:443"},
		},
		{
			name:   "dhcp and https use separate transports",
			values: []string{"https_listen", ":67"},
		},
		{
			name:   "upstream same server different port",
			values: []string{"upstream", "192.168.50.2:1053"},
		},
		{
			name:   "loopback upstream separate binding",
			values: []string{"upstream", "127.0.0.1:53"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := config.Load(writeConfig(t, tt.values...)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoadRequiresFields(t *testing.T) {
	t.Parallel()
	for _, key := range []string{"interface", "server_ip", "subnet", "pool_start", "pool_end"} {
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			values := validValues()
			delete(values, key)
			data, err := json.Marshal(values)
			if err != nil {
				t.Fatal(err)
			}
			_, err = config.Load(writeRawConfig(t, string(data)))
			if err == nil || !strings.Contains(err.Error(), key) {
				t.Errorf("missing %s error = %v", key, err)
			}
		})
	}
}

func TestLoadRejectsInvalidJSON(t *testing.T) {
	t.Parallel()
	base, err := json.Marshal(validValues())
	if err != nil {
		t.Fatal(err)
	}
	valid := string(base)
	withField := func(field string) string { return strings.TrimSuffix(valid, "}") + "," + field + "}" }
	tests := []struct{ name, data string }{
		{name: "empty", data: ""},
		{name: "whitespace", data: " \n\t"},
		{name: "null document", data: "null"},
		{name: "array document", data: "[" + valid + "]"},
		{name: "string document", data: `"config"`},
		{name: "number document", data: "42"},
		{name: "invalid UTF-8", data: withField("\"lease_file\":\"\xff\"")},
		{name: "truncated", data: strings.TrimSuffix(valid, "}")},
		{name: "unknown key", data: withField(`"bogus":"value"`)},
		{name: "case alias", data: withField(`"Interface":"eth1"`)},
		{name: "uppercase alias", data: withField(`"SERVER_IP":"192.168.50.3"`)},
		{name: "legacy key", data: withField(`"server-ip":"192.168.50.3"`)},
		{name: "duplicate key", data: withField(`"interface":"eth0"`)},
		{name: "escaped duplicate key", data: withField(`"interfa\u0063e":"eth0"`)},
		{name: "second document", data: valid + valid},
		{name: "trailing null", data: valid + " null"},
		{name: "trailing junk", data: valid + " junk"},
		{name: "line comment", data: "// config\n" + valid},
		{name: "block comment", data: "/* config */" + valid},
		{name: "trailing comma", data: strings.TrimSuffix(valid, "}") + ",}"},
		{name: "number value", data: withField(`"dns_ttl":60`)},
		{name: "boolean value", data: withField(`"upstream":false`)},
		{name: "array value", data: withField(`"upstream":[]`)},
		{name: "object value", data: withField(`"upstream":{}`)},
	}
	for _, key := range configKeys() {
		values := make(map[string]any)
		for name, value := range validValues() {
			values[name] = value
		}
		values[key] = nil
		data, err := json.Marshal(values)
		if err != nil {
			t.Fatal(err)
		}
		tests = append(tests, struct{ name, data string }{name: "null " + key, data: string(data)})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := config.Load(writeRawConfig(t, tt.data)); err == nil {
				t.Errorf("Load() accepted invalid JSON: %s", tt.data)
			}
		})
	}
}

func TestLoadRejectsReadErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	tests := []struct{ name, path string }{
		{name: "empty path", path: ""},
		{name: "missing file", path: filepath.Join(dir, "missing.json")},
		{name: "directory", path: dir},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := config.Load(tt.path); err == nil {
				t.Error("Load() accepted an unreadable configuration file")
			}
		})
	}
	missing := filepath.Join(dir, "missing.json")
	_, err := config.Parse([]string{"-config", missing}, io.Discard)
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Parse() missing config error = %v, want os.ErrNotExist", err)
	}
}

func TestLoadFileSizeLimit(t *testing.T) {
	t.Parallel()
	data, err := json.Marshal(validValues())
	if err != nil {
		t.Fatal(err)
	}
	const limit = 1 << 20
	exact := string(data) + strings.Repeat(" ", limit-len(data))
	if _, err := config.Load(writeRawConfig(t, exact)); err != nil {
		t.Errorf("Load() rejected a configuration at the size limit: %v", err)
	}
	if _, err := config.Load(writeRawConfig(t, exact+" ")); err == nil {
		t.Error("Load() accepted a configuration above the size limit")
	}
}

func TestLoadRejectsConfigOverwrite(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, filename, key, value string }{
		{name: "lease file", filename: "config.json", key: "lease_file", value: "config.json"},
		{name: "acme state", filename: "config.json", key: "acme_state", value: "config.json"},
		{name: "CA directory", filename: "config.json", key: "ca_dir", value: "config.json"},
		{name: "public root", filename: "root-ca.pem", key: "ca_dir", value: "."},
		{name: "private root", filename: "root-ca-bundle.pem", key: "ca_dir", value: "."},
		{name: "gateway bundle", filename: "gateway-bundle.pem", key: "ca_dir", value: "."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := writeConfig(t, tt.key, tt.value)
			renamed := filepath.Join(filepath.Dir(path), tt.filename)
			if path != renamed {
				if err := os.Rename(path, renamed); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := config.Load(renamed); err == nil {
				t.Error("Load() allows a state or certificate write to overwrite its configuration")
			}
		})
	}
}

func configKeys() []string {
	return []string{
		"interface", "server_ip", "subnet", "pool_start", "pool_end", "router",
		"domain", "lease_duration", "lease_file", "dns_listen", "dhcp_listen",
		"upstream", "dns_ttl", "https_listen", "ca_dir", "acme_state",
	}
}

func TestLoadExampleConfiguration(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(filepath.Join("..", "..", "config.example.json"))
	if err != nil {
		t.Fatalf("documented example configuration is invalid: %v", err)
	}
	if cfg.Interface != "eth0" || cfg.ServerIP != netip.MustParseAddr("192.168.50.2") {
		t.Errorf("unexpected example network: %+v", cfg)
	}
}

func validValues() map[string]string {
	return map[string]string{
		"interface":  "eth0",
		"server_ip":  "192.168.50.2",
		"subnet":     "192.168.50.0/24",
		"pool_start": "192.168.50.100",
		"pool_end":   "192.168.50.200",
	}
}

func writeConfig(t *testing.T, overrides ...string) string {
	t.Helper()
	values := validValues()
	if len(overrides)%2 != 0 {
		t.Fatal("configuration overrides must be key/value pairs")
	}
	for i := 0; i < len(overrides); i += 2 {
		values[overrides[i]] = overrides[i+1]
	}
	data, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	return writeRawConfig(t, string(data))
}

func writeRawConfig(t *testing.T, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
