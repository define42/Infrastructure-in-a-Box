package dnsserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
	"github.com/miekg/dns"
)

type testRegistry struct{ entries []lease.Lease }

func (r testRegistry) LookupName(name string) (lease.Lease, bool) {
	for _, entry := range r.entries {
		if entry.Hostname == name {
			return entry, true
		}
	}
	return lease.Lease{}, false
}

func (r testRegistry) LookupIP(ip netip.Addr) (lease.Lease, bool) {
	for _, entry := range r.entries {
		if entry.IP == ip {
			return entry, true
		}
	}
	return lease.Lease{}, false
}

func (r testRegistry) HasName(name string) bool {
	for _, entry := range r.entries {
		if time.Now().Before(entry.ExpiresAt) && (entry.Hostname == name || strings.HasSuffix(entry.Hostname, "."+name)) {
			return true
		}
	}
	return false
}

func testConfig() Config {
	return Config{
		Address: "127.0.0.1:0", Domain: "home.arpa",
		ServerIP: netip.MustParseAddr("192.168.1.1"),
		Subnet:   netip.MustParsePrefix("192.168.1.0/24"), TTL: time.Minute,
	}
}

func newTestServer(t *testing.T, config Config, entries ...lease.Lease) *Server {
	t.Helper()
	server, err := New(config, testRegistry{entries}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestNew(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		edit func(*Config)
	}{
		{"missing address", func(c *Config) { c.Address = "" }},
		{"named listen host", func(c *Config) { c.Address = "localhost:53" }},
		{"invalid port", func(c *Config) { c.Address = "127.0.0.1:65536" }},
		{"root domain", func(c *Config) { c.Domain = "." }},
		{"invalid domain", func(c *Config) { c.Domain = "bad_.arpa" }},
		{"long domain", func(c *Config) { c.Domain = strings.Repeat("a.", 125) }},
		{"IPv6 server", func(c *Config) { c.ServerIP = netip.IPv6Loopback() }},
		{"IPv6 subnet", func(c *Config) { c.Subnet = netip.MustParsePrefix("::/0") }},
		{"server outside subnet", func(c *Config) { c.ServerIP = netip.MustParseAddr("10.0.0.1") }},
		{"negative TTL", func(c *Config) { c.TTL = -time.Second }},
		{"huge TTL", func(c *Config) { c.TTL = (1 << 32) * time.Second }},
		{"upstream without port", func(c *Config) { c.Upstream = "1.1.1.1" }},
		{"named upstream", func(c *Config) { c.Upstream = "dns.example:53" }},
		{"wildcard upstream", func(c *Config) { c.Upstream = "0.0.0.0:53" }},
		{"self upstream", func(c *Config) { c.Address, c.Upstream = "127.0.0.1:53", "127.0.0.1:53" }},
		{"wildcard self upstream", func(c *Config) { c.Address, c.Upstream = ":53", "192.168.1.1:53" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := testConfig()
			test.edit(&config)
			if _, err := New(config, testRegistry{}, nil); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	if _, err := New(testConfig(), nil, nil); err == nil {
		t.Fatal("nil registry accepted")
	}
}

func TestNewARecords(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name    string
		records map[string]netip.Addr
	}{
		{"empty hostname", map[string]netip.Addr{"": netip.MustParseAddr("192.168.1.10")}},
		{"partial wildcard", map[string]netip.Addr{"nas*.home.arpa": netip.MustParseAddr("192.168.1.10")}},
		{"external hostname", map[string]netip.Addr{"nas.example.org": netip.MustParseAddr("192.168.1.10")}},
		{"domain suffix confusion", map[string]netip.Addr{"nothome.arpa": netip.MustParseAddr("192.168.1.10")}},
		{"underscore", map[string]netip.Addr{"my_nas": netip.MustParseAddr("192.168.1.10")}},
		{"leading whitespace", map[string]netip.Addr{" nas": netip.MustParseAddr("192.168.1.10")}},
		{"Unicode case fold", map[string]netip.Addr{"\u212aelvin": netip.MustParseAddr("192.168.1.10")}},
		{"escaped name", map[string]netip.Addr{`n\097s`: netip.MustParseAddr("192.168.1.10")}},
		{"invalid label", map[string]netip.Addr{"-nas": netip.MustParseAddr("192.168.1.10")}},
		{"long label", map[string]netip.Addr{strings.Repeat("a", 64): netip.MustParseAddr("192.168.1.10")}},
		{"reserved NS", map[string]netip.Addr{"NS.HOME.ARPA.": netip.MustParseAddr("192.168.1.10")}},
		{"reserved gateway", map[string]netip.Addr{"gateway": netip.MustParseAddr("192.168.1.10")}},
		{"duplicate hostname", map[string]netip.Addr{
			"nas": netip.MustParseAddr("192.168.1.10"), "NAS.HOME.ARPA.": netip.MustParseAddr("192.168.1.11"),
		}},
		{"duplicate apex", map[string]netip.Addr{
			"@": netip.MustParseAddr("192.168.1.10"), "HOME.ARPA.": netip.MustParseAddr("192.168.1.11"),
		}},
		{"invalid address", map[string]netip.Addr{"nas": {}}},
		{"IPv6", map[string]netip.Addr{"nas": netip.MustParseAddr("2001:db8::1")}},
		{"mapped IPv4", map[string]netip.Addr{"nas": netip.MustParseAddr("::ffff:192.168.1.10")}},
		{"unspecified", map[string]netip.Addr{"nas": netip.MustParseAddr("0.0.0.0")}},
		{"loopback", map[string]netip.Addr{"nas": netip.MustParseAddr("127.0.0.1")}},
		{"link local", map[string]netip.Addr{"nas": netip.MustParseAddr("169.254.0.1")}},
		{"multicast", map[string]netip.Addr{"nas": netip.MustParseAddr("224.0.0.1")}},
		{"broadcast", map[string]netip.Addr{"nas": netip.MustParseAddr("255.255.255.255")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			config := testConfig()
			config.ARecords = test.records
			if _, err := New(config, testRegistry{}, nil); err == nil {
				t.Fatal("invalid static A record accepted")
			}
		})
	}
}

func TestNewCopiesARecords(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.ARecords = map[string]netip.Addr{"nas.home.arpa.": netip.MustParseAddr("192.168.1.10")}
	server := newTestServer(t, config)
	config.ARecords["nas.home.arpa."] = netip.MustParseAddr("192.168.1.20")
	config.ARecords["added.home.arpa."] = netip.MustParseAddr("192.168.1.30")
	response := queryServer(t, server, new(dns.Msg).SetQuestion("nas.home.arpa.", dns.TypeA))
	if len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "192.168.1.10" {
		t.Fatalf("caller map mutation changed static answer: %s", response)
	}
	response = queryServer(t, server, new(dns.Msg).SetQuestion("added.home.arpa.", dns.TypeA))
	if response.Rcode != dns.RcodeNameError {
		t.Fatalf("caller map mutation added a static answer: %s", response)
	}
}

func TestRunCancelled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := newTestServer(t, testConfig()).Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestServeDNSLeaseRecords(t *testing.T) {
	t.Parallel()
	entry := lease.Lease{Hostname: "laptop.home.arpa.", IP: netip.MustParseAddr("192.168.1.100"), ExpiresAt: time.Now().Add(20 * time.Second)}
	server := newTestServer(t, testConfig(), entry,
		lease.Lease{Hostname: "expired.home.arpa.", IP: netip.MustParseAddr("192.168.1.101"), ExpiresAt: time.Now().Add(-time.Second)})
	for _, test := range []struct {
		name       string
		query      string
		kind       uint16
		code       int
		authority  bool
		answerKind uint16
		value      string
	}{
		{"lease A", "laptop.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, dns.TypeA, "192.168.1.100"},
		{"case insensitive", "LaPtOp.HoMe.ArPa.", dns.TypeA, dns.RcodeSuccess, true, dns.TypeA, "192.168.1.100"},
		{"lease PTR", "100.1.168.192.in-addr.arpa.", dns.TypePTR, dns.RcodeSuccess, true, dns.TypePTR, "laptop.home.arpa."},
		{"known host without IPv6", "laptop.home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, true, 0, ""},
		{"known PTR without A", "100.1.168.192.in-addr.arpa.", dns.TypeA, dns.RcodeSuccess, true, 0, ""},
		{"missing host", "missing.home.arpa.", dns.TypeA, dns.RcodeNameError, true, 0, ""},
		{"missing PTR", "111.1.168.192.in-addr.arpa.", dns.TypePTR, dns.RcodeNameError, true, 0, ""},
		{"expired host", "expired.home.arpa.", dns.TypeA, dns.RcodeNameError, true, 0, ""},
		{"expired PTR", "101.1.168.192.in-addr.arpa.", dns.TypePTR, dns.RcodeNameError, true, 0, ""},
		{"server A", "ns.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, dns.TypeA, "192.168.1.1"},
		{"gateway A", "gateway.home.arpa.", dns.TypeA, dns.RcodeSuccess, true, dns.TypeA, "192.168.1.1"},
		{"gateway case insensitive", "GaTeWaY.HoMe.ArPa.", dns.TypeA, dns.RcodeSuccess, true, dns.TypeA, "192.168.1.1"},
		{"gateway without IPv6", "gateway.home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, true, 0, ""},
		{"server PTR", "1.1.168.192.in-addr.arpa.", dns.TypePTR, dns.RcodeSuccess, true, dns.TypePTR, "ns.home.arpa."},
		{"forward SOA", "home.arpa.", dns.TypeSOA, dns.RcodeSuccess, true, dns.TypeSOA, ""},
		{"forward NS", "home.arpa.", dns.TypeNS, dns.RcodeSuccess, true, dns.TypeNS, "ns.home.arpa."},
		{"reverse SOA", "1.168.192.in-addr.arpa.", dns.TypeSOA, dns.RcodeSuccess, true, dns.TypeSOA, ""},
		{"reverse NS", "1.168.192.in-addr.arpa.", dns.TypeNS, dns.RcodeSuccess, true, dns.TypeNS, "ns.home.arpa."},
		{"apex NODATA", "home.arpa.", dns.TypeA, dns.RcodeSuccess, true, 0, ""},
		{"external", "example.org.", dns.TypeA, dns.RcodeRefused, false, 0, ""},
		{"suffix confusion", "nothome.arpa.", dns.TypeA, dns.RcodeRefused, false, 0, ""},
		{"external PTR", "100.2.168.192.in-addr.arpa.", dns.TypePTR, dns.RcodeRefused, false, 0, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			query := new(dns.Msg).SetQuestion(test.query, test.kind)
			response := queryServer(t, server, query)
			if response.Rcode != test.code || response.Authoritative != test.authority {
				t.Fatalf("unexpected response: %s", response)
			}
			if response.RecursionAvailable || response.AuthenticatedData || response.Id != query.Id || !response.RecursionDesired {
				t.Fatalf("incorrect response flags: %s", response)
			}
			if test.answerKind == 0 {
				if len(response.Answer) != 0 {
					t.Fatalf("unexpected answers: %v", response.Answer)
				}
				if test.authority {
					if len(response.Ns) != 1 || response.Ns[0].Header().Rrtype != dns.TypeSOA || response.Ns[0].Header().Ttl != 0 {
						t.Fatalf("missing zero-TTL negative SOA: %s", response)
					}
				}
				return
			}
			if len(response.Answer) != 1 || response.Answer[0].Header().Rrtype != test.answerKind {
				t.Fatalf("unexpected answers: %v", response.Answer)
			}
			switch answer := response.Answer[0].(type) {
			case *dns.A:
				if answer.A.String() != test.value {
					t.Fatalf("A = %v; want %s", answer.A, test.value)
				}
			case *dns.PTR:
				if answer.Ptr != test.value {
					t.Fatalf("PTR = %s; want %s", answer.Ptr, test.value)
				}
			case *dns.NS:
				if answer.Ns != test.value || len(response.Extra) != 1 {
					t.Fatalf("NS lacks expected target/glue: %s", response)
				}
			}
			if (strings.EqualFold(test.query, entry.Hostname) || test.query == "100.1.168.192.in-addr.arpa.") && response.Answer[0].Header().Ttl > 20 {
				t.Fatalf("TTL exceeds lease lifetime: %v", response.Answer)
			}
		})
	}
}

func TestServeDNSARecords(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.ARecords = map[string]netip.Addr{
		"NAS":                netip.MustParseAddr("192.168.1.10"),
		"printer.home.arpa.": netip.MustParseAddr("192.168.1.20"),
		"app.lab.HOME.ARPA":  netip.MustParseAddr("10.0.0.30"),
		"expired":            netip.MustParseAddr("192.168.1.40"),
		"@":                  netip.MustParseAddr("192.168.1.50"),
		"alias":              netip.MustParseAddr("192.168.1.10"),
	}
	server := newTestServer(t, config,
		lease.Lease{Hostname: "nas.home.arpa.", IP: netip.MustParseAddr("192.168.1.100"), ExpiresAt: time.Now().Add(10 * time.Second)},
		lease.Lease{Hostname: "expired.home.arpa.", IP: netip.MustParseAddr("192.168.1.101"), ExpiresAt: time.Now().Add(-time.Second)},
		lease.Lease{Hostname: "laptop.home.arpa.", IP: netip.MustParseAddr("192.168.1.102"), ExpiresAt: time.Now().Add(time.Hour)},
	)
	for _, test := range []struct {
		name  string
		query string
		kind  uint16
		code  int
		value string
	}{
		{"static overrides active lease", "NaS.HoMe.ArPa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.10"},
		{"qualified name", "printer.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.20"},
		{"nested hostname outside subnet", "app.lab.home.arpa.", dns.TypeA, dns.RcodeSuccess, "10.0.0.30"},
		{"static outlives expired lease", "expired.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.40"},
		{"apex address", "home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.50"},
		{"shared address", "alias.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.10"},
		{"ANY answer", "nas.home.arpa.", dns.TypeANY, dns.RcodeSuccess, "192.168.1.10"},
		{"static AAAA NODATA", "nas.home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, ""},
		{"static TXT NODATA", "nas.home.arpa.", dns.TypeTXT, dns.RcodeSuccess, ""},
		{"apex AAAA NODATA", "home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, ""},
		{"static has no PTR", "10.1.168.192.in-addr.arpa.", dns.TypePTR, dns.RcodeNameError, ""},
		{"dynamic address retained", "laptop.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.102"},
		{"gateway retained", "gateway.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.1"},
		{"nameserver retained", "ns.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := queryServer(t, server, new(dns.Msg).SetQuestion(test.query, test.kind))
			if response.Rcode != test.code || !response.Authoritative {
				t.Fatalf("unexpected static response: %s", response)
			}
			if test.value == "" {
				if len(response.Answer) != 0 || len(response.Ns) != 1 || response.Ns[0].Header().Rrtype != dns.TypeSOA {
					t.Fatalf("negative response lacks SOA: %s", response)
				}
				return
			}
			if len(response.Answer) != 1 {
				t.Fatalf("expected one A answer: %s", response)
			}
			answer, ok := response.Answer[0].(*dns.A)
			if !ok || answer.A.String() != test.value || answer.Hdr.Ttl != 60 {
				t.Fatalf("expected A %s with configured TTL: %s", test.value, response)
			}
		})
	}
	for _, kind := range []uint16{dns.TypeSOA, dns.TypeNS} {
		response := queryServer(t, server, new(dns.Msg).SetQuestion("home.arpa.", kind))
		if response.Rcode != dns.RcodeSuccess || !response.Authoritative || len(response.Answer) != 1 || response.Answer[0].Header().Rrtype != kind {
			t.Fatalf("static apex changed zone records: %s", response)
		}
	}
}

func TestServeDNSARecordApexSpelling(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"@", "home.arpa", "HOME.ARPA."} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			config := testConfig()
			config.TTL = 0
			config.ARecords = map[string]netip.Addr{name: netip.MustParseAddr("192.168.1.10")}
			server := newTestServer(t, config)
			response := queryServer(t, server, new(dns.Msg).SetQuestion("home.arpa.", dns.TypeA))
			if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
				t.Fatalf("apex did not resolve: %s", response)
			}
			answer, ok := response.Answer[0].(*dns.A)
			if !ok || answer.A.String() != "192.168.1.10" || answer.Hdr.Ttl != 0 {
				t.Fatalf("unexpected apex address or TTL: %s", response)
			}
		})
	}
}

func TestServeDNSWildcardARecords(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.ARecords = map[string]netip.Addr{
		"*":                     netip.MustParseAddr("192.168.1.10"),
		"*.apps.home.arpa":      netip.MustParseAddr("192.168.1.20"),
		"fixed":                 netip.MustParseAddr("192.168.1.30"),
		"leaf.static.home.arpa": netip.MustParseAddr("192.168.1.40"),
		"*.deep.apps.home.arpa": netip.MustParseAddr("192.168.1.50"),
	}
	server := newTestServer(t, config,
		lease.Lease{Hostname: "laptop.home.arpa.", IP: netip.MustParseAddr("192.168.1.100"), ExpiresAt: time.Now().Add(time.Hour)},
		lease.Lease{Hostname: "host.dhcp.home.arpa.", IP: netip.MustParseAddr("192.168.1.101"), ExpiresAt: time.Now().Add(time.Hour)},
		lease.Lease{Hostname: "old.expired.home.arpa.", IP: netip.MustParseAddr("192.168.1.102"), ExpiresAt: time.Now().Add(-time.Second)},
	)
	for _, test := range []struct {
		name  string
		query string
		kind  uint16
		code  int
		value string
	}{
		{"root wildcard", "missing.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.10"},
		{"case insensitive", "MiSsInG.HoMe.ArPa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.10"},
		{"multiple absent levels", "one.two.three.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.10"},
		{"ANY synthesis", "missing.home.arpa.", dns.TypeANY, dns.RcodeSuccess, "192.168.1.10"},
		{"AAAA synthesis NODATA", "missing.home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, ""},
		{"TXT synthesis NODATA", "missing.home.arpa.", dns.TypeTXT, dns.RcodeSuccess, ""},
		{"exact static wins", "fixed.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.30"},
		{"exact static without AAAA", "fixed.home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, ""},
		{"static subtree blocks broader wildcard", "child.fixed.home.arpa.", dns.TypeA, dns.RcodeNameError, ""},
		{"static empty non-terminal exists", "static.home.arpa.", dns.TypeA, dns.RcodeSuccess, ""},
		{"static empty non-terminal blocks broader wildcard", "other.static.home.arpa.", dns.TypeA, dns.RcodeNameError, ""},
		{"exact DHCP wins", "laptop.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.100"},
		{"exact DHCP without AAAA", "laptop.home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, ""},
		{"DHCP subtree blocks broader wildcard", "child.laptop.home.arpa.", dns.TypeA, dns.RcodeNameError, ""},
		{"DHCP empty non-terminal exists", "dhcp.home.arpa.", dns.TypeA, dns.RcodeSuccess, ""},
		{"DHCP empty non-terminal blocks broader wildcard", "other.dhcp.home.arpa.", dns.TypeA, dns.RcodeNameError, ""},
		{"expired DHCP does not override wildcard", "old.expired.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.10"},
		{"expired DHCP ancestor does not exist", "expired.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.10"},
		{"expired DHCP subtree does not block wildcard", "other.expired.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.10"},
		{"nameserver wins", "ns.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.1"},
		{"nameserver subtree blocks wildcard", "child.ns.home.arpa.", dns.TypeA, dns.RcodeNameError, ""},
		{"gateway wins", "gateway.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.1"},
		{"gateway subtree blocks wildcard", "child.gateway.home.arpa.", dns.TypeA, dns.RcodeNameError, ""},
		{"zone apex not synthesized", "home.arpa.", dns.TypeA, dns.RcodeSuccess, ""},
		{"nested wildcard", "web.apps.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.20"},
		{"nested multiple absent levels", "one.two.apps.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.20"},
		{"wildcard parent exists", "apps.home.arpa.", dns.TypeA, dns.RcodeSuccess, ""},
		{"closest wildcard", "web.deep.apps.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.50"},
		{"nested wildcard parent exists", "deep.apps.home.arpa.", dns.TypeA, dns.RcodeSuccess, ""},
		{"literal wildcard query", "*.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.10"},
		{"wildcard does not match own subtree", "child.*.home.arpa.", dns.TypeA, dns.RcodeNameError, ""},
		{"PTR unaffected", "10.1.168.192.in-addr.arpa.", dns.TypePTR, dns.RcodeNameError, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			response := queryServer(t, server, new(dns.Msg).SetQuestion(test.query, test.kind))
			if response.Rcode != test.code || !response.Authoritative {
				t.Fatalf("unexpected wildcard response: %s", response)
			}
			if test.value == "" {
				if len(response.Answer) != 0 || len(response.Ns) != 1 || response.Ns[0].Header().Rrtype != dns.TypeSOA {
					t.Fatalf("negative answer lacks SOA: %s", response)
				}
				return
			}
			if len(response.Answer) != 1 {
				t.Fatalf("expected one A answer: %s", response)
			}
			answer, ok := response.Answer[0].(*dns.A)
			if !ok || answer.A.String() != test.value || answer.Hdr.Name != strings.ToLower(test.query) || answer.Hdr.Ttl != 60 {
				t.Fatalf("incorrect wildcard owner, address, or TTL: %s", response)
			}
		})
	}
}

func TestServeDNSWildcardLeaseLifecycle(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		config := testConfig()
		config.ARecords = map[string]netip.Addr{"*": netip.MustParseAddr("192.168.1.10")}
		clientIP := netip.MustParseAddr("192.168.1.100")
		manager, err := lease.New(lease.Config{
			Domain: config.Domain, PoolStart: clientIP, PoolEnd: clientIP.Next(), LeaseDuration: time.Minute,
		})
		if err != nil {
			t.Fatal(err)
		}
		server, err := New(config, manager, nil)
		if err != nil {
			t.Fatal(err)
		}
		check := func(name string, code int, address string) {
			t.Helper()
			response := queryServer(t, server, new(dns.Msg).SetQuestion(name, dns.TypeA))
			if response.Rcode != code || !response.Authoritative {
				t.Fatalf("unexpected response for %s: %s", name, response)
			}
			if address == "" {
				if len(response.Answer) != 0 {
					t.Fatalf("unexpected answer for %s: %s", name, response)
				}
				return
			}
			if len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != address {
				t.Fatalf("expected %s for %s: %s", address, name, response)
			}
		}
		check("host.dhcp.home.arpa.", dns.RcodeSuccess, "192.168.1.10")
		if _, err := manager.Commit("client", clientIP, "host.dhcp.home.arpa"); err != nil {
			t.Fatal(err)
		}
		check("host.dhcp.home.arpa.", dns.RcodeSuccess, clientIP.String())
		check("dhcp.home.arpa.", dns.RcodeSuccess, "")
		check("other.dhcp.home.arpa.", dns.RcodeNameError, "")
		if _, err := manager.Commit("client", clientIP, "host.renamed.home.arpa"); err != nil {
			t.Fatal(err)
		}
		check("host.dhcp.home.arpa.", dns.RcodeSuccess, "192.168.1.10")
		check("dhcp.home.arpa.", dns.RcodeSuccess, "192.168.1.10")
		check("host.renamed.home.arpa.", dns.RcodeSuccess, clientIP.String())
		check("other.renamed.home.arpa.", dns.RcodeNameError, "")
		if err := manager.Release("client", clientIP); err != nil {
			t.Fatal(err)
		}
		check("host.renamed.home.arpa.", dns.RcodeSuccess, "192.168.1.10")
		check("other.renamed.home.arpa.", dns.RcodeSuccess, "192.168.1.10")
		if _, err := manager.Commit("client", clientIP, "host.expiring.home.arpa"); err != nil {
			t.Fatal(err)
		}
		check("expiring.home.arpa.", dns.RcodeSuccess, "")
		check("other.expiring.home.arpa.", dns.RcodeNameError, "")
		time.Sleep(time.Minute)
		check("host.expiring.home.arpa.", dns.RcodeSuccess, "192.168.1.10")
		check("expiring.home.arpa.", dns.RcodeSuccess, "192.168.1.10")
		check("other.expiring.home.arpa.", dns.RcodeSuccess, "192.168.1.10")
	})
}

func TestServeDNSWildcardSingleLabelApex(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Domain = "lan"
	config.ARecords = map[string]netip.Addr{"*": netip.MustParseAddr("192.168.1.10")}
	clientIP := netip.MustParseAddr("192.168.1.100")
	manager, err := lease.New(lease.Config{
		Domain: config.Domain, PoolStart: clientIP, PoolEnd: clientIP.Next(), LeaseDuration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Commit("client", clientIP, "lan"); err != nil {
		t.Fatal(err)
	}
	server, err := New(config, manager, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := queryServer(t, server, new(dns.Msg).SetQuestion("lan.", dns.TypeA))
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 0 || len(response.Ns) != 1 {
		t.Fatalf("relative DHCP name or wildcard overrode zone apex: %s", response)
	}
	response = queryServer(t, server, new(dns.Msg).SetQuestion("lan.lan.", dns.TypeA))
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != clientIP.String() {
		t.Fatalf("DHCP name did not resolve below single-label zone: %s", response)
	}
}

func TestServeDNSBounds(t *testing.T) {
	t.Parallel()
	server := newTestServer(t, testConfig())
	for _, test := range []struct {
		name string
		edit func(*dns.Msg)
		code int
	}{
		{"missing question", func(q *dns.Msg) { q.Question = nil }, dns.RcodeFormatError},
		{"multiple questions", func(q *dns.Msg) { q.Question = append(q.Question, q.Question[0]) }, dns.RcodeFormatError},
		{"DNS update", func(q *dns.Msg) { q.Opcode = dns.OpcodeUpdate }, dns.RcodeNotImplemented},
		{"unsupported class", func(q *dns.Msg) { q.Question[0].Qclass = dns.ClassCHAOS }, dns.RcodeRefused},
		{"zone transfer", func(q *dns.Msg) { q.Question[0].Qtype = dns.TypeAXFR }, dns.RcodeRefused},
		{"incremental transfer", func(q *dns.Msg) { q.Question[0].Qtype = dns.TypeIXFR }, dns.RcodeRefused},
		{"unknown EDNS version", func(q *dns.Msg) { q.SetEdns0(4096, false); q.IsEdns0().SetVersion(1) }, dns.RcodeBadVers},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := new(dns.Msg).SetQuestion("home.arpa.", dns.TypeA)
			test.edit(request)
			if response := queryServer(t, server, request); response.Rcode != test.code {
				t.Fatalf("rcode = %d; want %d", response.Rcode, test.code)
			}
		})
	}
}

func TestServeDNSGatewayOverridesLease(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Domain = " HOME.ARPA. "
	server := newTestServer(t, config, lease.Lease{
		IP: netip.MustParseAddr("192.168.1.100"), Hostname: "gateway.home.arpa.", ExpiresAt: time.Now().Add(time.Hour),
	})
	response := queryServer(t, server, new(dns.Msg).SetQuestion("gateway.home.arpa.", dns.TypeA))
	if response.Rcode != dns.RcodeSuccess || !response.Authoritative || len(response.Answer) != 1 {
		t.Fatalf("unexpected gateway response: %s", response)
	}
	answer, ok := response.Answer[0].(*dns.A)
	if !ok || answer.A.String() != config.ServerIP.String() {
		t.Fatalf("lease overrode gateway address: %s", response)
	}
}

func TestServeDNSGatewayMigratesSavedLease(t *testing.T) {
	t.Parallel()
	config := testConfig()
	savedLease := lease.Lease{
		ClientID: "legacy-client", IP: netip.MustParseAddr("192.168.1.100"),
		Hostname: "gateway.home.arpa.", ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
	leaseFile := filepath.Join(t.TempDir(), "leases.json")
	data, err := json.Marshal(struct {
		Version int           `json:"version"`
		Leases  []lease.Lease `json:"leases"`
	}{Version: 1, Leases: []lease.Lease{savedLease}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leaseFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	manager, err := lease.New(lease.Config{
		PoolStart: savedLease.IP, PoolEnd: savedLease.IP.Next(), Domain: config.Domain,
		LeaseDuration: time.Hour, File: leaseFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(config, manager, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := queryServer(t, server, new(dns.Msg).SetQuestion("gateway.home.arpa.", dns.TypeA))
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("legacy lease prevented gateway resolution: %s", response)
	}
	answer, ok := response.Answer[0].(*dns.A)
	if !ok || answer.A.String() != config.ServerIP.String() {
		t.Fatalf("legacy lease overrode gateway address: %s", response)
	}
	reverse, err := dns.ReverseAddr(savedLease.IP.String())
	if err != nil {
		t.Fatal(err)
	}
	response = queryServer(t, server, new(dns.Msg).SetQuestion(reverse, dns.TypePTR))
	if response.Rcode != dns.RcodeNameError || len(response.Answer) != 0 {
		t.Fatalf("legacy lease retained gateway reverse registration: %s", response)
	}
	if current, ok := manager.LookupIP(savedLease.IP); !ok || current.ClientID != savedLease.ClientID {
		t.Fatalf("legacy lease lost address ownership: %+v, %v", current, ok)
	}
}

func TestServeDNSClasslessSubnet(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.Subnet = netip.MustParsePrefix("192.168.1.0/25")
	server := newTestServer(t, config, lease.Lease{IP: netip.MustParseAddr("192.168.1.100"), Hostname: "laptop.home.arpa.", ExpiresAt: time.Now().Add(time.Hour)})
	for _, test := range []struct {
		name  string
		query string
		code  int
	}{
		{"own lease", "100.1.168.192.in-addr.arpa.", dns.RcodeSuccess},
		{"neighbour subnet", "200.1.168.192.in-addr.arpa.", dns.RcodeRefused},
		{"parent zone", "1.168.192.in-addr.arpa.", dns.RcodeRefused},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if response := queryServer(t, server, new(dns.Msg).SetQuestion(test.query, dns.TypePTR)); response.Rcode != test.code {
				t.Fatalf("unexpected response: %s", response)
			}
		})
	}
}

type responseRecorder struct{ response *dns.Msg }

func (w *responseRecorder) LocalAddr() net.Addr            { return &net.UDPAddr{} }
func (w *responseRecorder) RemoteAddr() net.Addr           { return &net.UDPAddr{} }
func (w *responseRecorder) WriteMsg(msg *dns.Msg) error    { w.response = msg.Copy(); return nil }
func (w *responseRecorder) Write(data []byte) (int, error) { return len(data), nil }
func (w *responseRecorder) Close() error                   { return nil }
func (w *responseRecorder) TsigStatus() error              { return nil }
func (w *responseRecorder) TsigTimersOnly(bool)            {}
func (w *responseRecorder) Hijack()                        {}

func queryServer(t *testing.T, server *Server, query *dns.Msg) *dns.Msg {
	t.Helper()
	writer := new(responseRecorder)
	server.ServeDNS(writer, query)
	if writer.response == nil {
		t.Fatal("no DNS response")
	}
	return writer.response
}
