//go:build integration

package dnsserver

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/dhcpserver"
	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/miekg/dns"
)

func TestRunUDPAndTCPIntegration(t *testing.T) {
	t.Parallel()
	address := startDNSServer(t, testConfig(), lease.Lease{
		IP: netip.MustParseAddr("192.168.1.100"), Hostname: "laptop.home.arpa.", ExpiresAt: time.Now().Add(time.Hour),
	})
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			t.Parallel()
			client := dns.Client{Net: network, Timeout: time.Second}
			response, _, err := client.Exchange(new(dns.Msg).SetQuestion("laptop.home.arpa.", dns.TypeA), address)
			if err != nil {
				t.Fatal(err)
			}
			if len(response.Answer) != 1 || response.Answer[0].(*dns.A).A.String() != "192.168.1.100" {
				t.Fatalf("unexpected response: %s", response)
			}
		})
	}
}

func TestStaticARecordsUDPAndTCPIntegration(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.ARecords = map[string]netip.Addr{
		"NAS": netip.MustParseAddr("192.168.1.10"),
		"@":   netip.MustParseAddr("10.0.0.20"),
	}
	address := startDNSServer(t, config, lease.Lease{
		IP: netip.MustParseAddr("192.168.1.100"), Hostname: "nas.home.arpa.", ExpiresAt: time.Now().Add(time.Hour),
	})
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			t.Parallel()
			client := dns.Client{Net: network, Timeout: time.Second}
			for _, test := range []struct {
				name string
				ip   string
			}{
				{"nas.home.arpa.", "192.168.1.10"},
				{"home.arpa.", "10.0.0.20"},
			} {
				t.Run(test.name, func(t *testing.T) {
					response, _, err := client.Exchange(new(dns.Msg).SetQuestion(test.name, dns.TypeA), address)
					if err != nil {
						t.Fatal(err)
					}
					if response.Rcode != dns.RcodeSuccess || !response.Authoritative || len(response.Answer) != 1 {
						t.Fatalf("unexpected static response over %s: %s", network, response)
					}
					answer, ok := response.Answer[0].(*dns.A)
					if !ok || answer.A.String() != test.ip || answer.Hdr.Ttl != 60 {
						t.Fatalf("unexpected static answer over %s: %s", network, response)
					}
				})
			}
		})
	}
}

func TestWildcardARecordsUDPAndTCPIntegration(t *testing.T) {
	t.Parallel()
	config := testConfig()
	config.ARecords = map[string]netip.Addr{
		"*":                    netip.MustParseAddr("192.168.1.10"),
		"leaf.fixed.home.arpa": netip.MustParseAddr("192.168.1.20"),
		"*.apps.home.arpa":     netip.MustParseAddr("192.168.1.30"),
	}
	address := startDNSServer(t, config, lease.Lease{
		IP: netip.MustParseAddr("192.168.1.100"), Hostname: "laptop.home.arpa.", ExpiresAt: time.Now().Add(time.Hour),
	})
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			t.Parallel()
			client := dns.Client{Net: network, Timeout: time.Second}
			for _, test := range []struct {
				name  string
				query string
				kind  uint16
				code  int
				ip    string
			}{
				{"wildcard", "web.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.10"},
				{"multiple absent levels", "one.two.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.10"},
				{"nested wildcard", "web.apps.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.30"},
				{"static exact", "leaf.fixed.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.20"},
				{"DHCP exact", "laptop.home.arpa.", dns.TypeA, dns.RcodeSuccess, "192.168.1.100"},
				{"empty non-terminal", "fixed.home.arpa.", dns.TypeA, dns.RcodeSuccess, ""},
				{"static shadowing", "other.fixed.home.arpa.", dns.TypeA, dns.RcodeNameError, ""},
				{"DHCP shadowing", "child.laptop.home.arpa.", dns.TypeA, dns.RcodeNameError, ""},
				{"AAAA NODATA", "web.home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, ""},
				{"apex NODATA", "home.arpa.", dns.TypeA, dns.RcodeSuccess, ""},
			} {
				t.Run(test.name, func(t *testing.T) {
					response, _, err := client.Exchange(new(dns.Msg).SetQuestion(test.query, test.kind), address)
					if err != nil {
						t.Fatal(err)
					}
					if response.Rcode != test.code || !response.Authoritative {
						t.Fatalf("unexpected wildcard response over %s: %s", network, response)
					}
					if test.ip == "" {
						if len(response.Answer) != 0 || len(response.Ns) != 1 || response.Ns[0].Header().Rrtype != dns.TypeSOA {
							t.Fatalf("negative response lacks SOA over %s: %s", network, response)
						}
						return
					}
					if len(response.Answer) != 1 {
						t.Fatalf("expected one wildcard answer over %s: %s", network, response)
					}
					answer, ok := response.Answer[0].(*dns.A)
					if !ok || answer.A.String() != test.ip || answer.Hdr.Name != test.query || answer.Hdr.Ttl != 60 {
						t.Fatalf("unexpected wildcard answer over %s: %s", network, response)
					}
				})
			}
		})
	}
}

func TestRunStartupFailureClosesSiblingIntegration(t *testing.T) {
	t.Parallel()
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = udp.Close() }()
	config := testConfig()
	config.Address = udp.LocalAddr().String()
	server := newTestServer(t, config)
	if err := server.Run(t.Context()); err == nil {
		t.Fatal("Run succeeded with an occupied UDP port")
	}
	tcp, err := net.Listen("tcp4", config.Address)
	if err != nil {
		t.Fatalf("TCP listener leaked after UDP startup failure: %v", err)
	}
	_ = tcp.Close()
}

func TestForwardingIntegration(t *testing.T) {
	t.Parallel()
	var udpQueries, tcpQueries atomic.Int32
	upstream := startUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		_, tcp := w.RemoteAddr().(*net.TCPAddr)
		if tcp {
			tcpQueries.Add(1)
		} else {
			udpQueries.Add(1)
		}
		response := new(dns.Msg).SetReply(request)
		name := request.Question[0].Name
		switch name {
		case "missing.example.":
			response.Rcode = dns.RcodeNameError
		case "wrong.example.":
			response.Question[0].Name = "unrelated.example."
		case "large.example.":
			if !tcp {
				response.Truncated = true
			} else {
				for range 12 {
					response.Answer = append(response.Answer, &dns.TXT{
						Hdr: header(name, dns.TypeTXT, 60), Txt: []string{strings.Repeat("a", 100)},
					})
				}
			}
		default:
			if name == "fallback.example." && !tcp {
				response.Truncated = true
			} else {
				response.Answer = []dns.RR{&dns.A{Hdr: header(name, dns.TypeA, 60), A: net.IPv4(203, 0, 113, 1)}}
			}
		}
		if err := w.WriteMsg(response); err != nil {
			t.Errorf("write upstream answer: %v", err)
		}
	}))
	config := testConfig()
	config.Upstream = upstream
	address := startDNSServer(t, config)
	client := dns.Client{Net: "udp", Timeout: time.Second}
	for _, test := range []struct {
		name    string
		query   string
		code    int
		answers int
	}{
		{"normal response", "www.example.", dns.RcodeSuccess, 1},
		{"TCP fallback", "fallback.example.", dns.RcodeSuccess, 1},
		{"upstream NXDOMAIN", "missing.example.", dns.RcodeNameError, 0},
		{"mismatched question", "wrong.example.", dns.RcodeServerFailure, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			query := new(dns.Msg).SetQuestion(test.query, dns.TypeA)
			response, _, err := client.Exchange(query, address)
			if err != nil {
				t.Fatal(err)
			}
			if response.Rcode != test.code || len(response.Answer) != test.answers || !response.RecursionAvailable || response.Authoritative || response.Id != query.Id {
				t.Fatalf("unexpected forwarded response: %s", response)
			}
		})
	}
	if udpQueries.Load() != 4 || tcpQueries.Load() != 1 {
		t.Fatalf("upstream counts: UDP=%d TCP=%d; want 4 and 1", udpQueries.Load(), tcpQueries.Load())
	}
	for _, name := range []string{
		"missing.home.arpa.", "100.1.168.192.in-addr.arpa.", "ns.home.arpa.", "gateway.home.arpa.",
	} {
		if _, _, err := client.Exchange(new(dns.Msg).SetQuestion(name, dns.TypeA), address); err != nil {
			t.Fatal(err)
		}
	}
	gatewayQuery := new(dns.Msg).SetQuestion("gateway.home.arpa.", dns.TypeAAAA)
	gatewayResponse, _, err := client.Exchange(gatewayQuery, address)
	if err != nil {
		t.Fatal(err)
	}
	if gatewayResponse.Rcode != dns.RcodeSuccess || !gatewayResponse.Authoritative || len(gatewayResponse.Answer) != 0 {
		t.Fatalf("gateway AAAA did not return authoritative NODATA: %s", gatewayResponse)
	}
	query := new(dns.Msg).SetQuestion("www.example.", dns.TypeA)
	query.RecursionDesired = false
	response, _, err := client.Exchange(query, address)
	if err != nil || response.Rcode != dns.RcodeRefused {
		t.Fatalf("nonrecursive external query: response=%v error=%v", response, err)
	}
	if udpQueries.Load() != 4 || tcpQueries.Load() != 1 {
		t.Fatal("local or nonrecursive query reached upstream")
	}
	query = new(dns.Msg).SetQuestion("large.example.", dns.TypeTXT)
	response, _, err = client.Exchange(query, address)
	if err != nil {
		t.Fatal(err)
	}
	response.Compress = true
	if !response.Truncated || response.Len() > dns.MinMsgSize {
		t.Fatalf("UDP response exceeds requested bounds: response=%v error=%v", response, err)
	}
	client.Net = "tcp"
	response, _, err = client.Exchange(query, address)
	if err != nil || response.Truncated || len(response.Answer) != 12 {
		t.Fatalf("TCP response was truncated: response=%v error=%v", response, err)
	}
}

func TestExternalOverridesAndForwardingIntegration(t *testing.T) {
	t.Parallel()
	var upstreamQueries atomic.Int32
	upstream := startUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		upstreamQueries.Add(1)
		response := new(dns.Msg).SetReply(request)
		response.Answer = []dns.RR{&dns.A{
			Hdr: header(request.Question[0].Name, dns.TypeA, 300), A: net.IPv4(203, 0, 113, 1),
		}}
		if err := w.WriteMsg(response); err != nil {
			t.Errorf("write upstream answer: %v", err)
		}
	}))
	config := testConfig()
	config.Upstream = upstream
	config.ARecords = map[string]netip.Addr{
		"*.Google.COM.":         netip.MustParseAddr("192.168.1.10"),
		"fixed.google.com":      netip.MustParseAddr("192.168.1.20"),
		"leaf.empty.google.com": netip.MustParseAddr("192.168.1.30"),
		"*.apps.google.com":     netip.MustParseAddr("192.168.1.40"),
		"example.org":           netip.MustParseAddr("192.168.1.50"),
	}
	address := startDNSServer(t, config, lease.Lease{
		Hostname: "laptop.home.arpa.", IP: netip.MustParseAddr("192.168.1.100"), ExpiresAt: time.Now().Add(time.Hour),
	})
	var expectedUpstreamQueries int32
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			client := dns.Client{Net: network, Timeout: time.Second}
			for _, test := range []struct {
				name      string
				query     string
				kind      uint16
				recursive bool
				forwarded bool
				code      int
				ip        string
				soa       string
			}{
				{"wildcard", "www.google.com.", dns.TypeA, true, false, dns.RcodeSuccess, "192.168.1.10", ""},
				{"nonrecursive wildcard", "WWW.GOOGLE.COM.", dns.TypeA, false, false, dns.RcodeSuccess, "192.168.1.10", ""},
				{"wildcard multiple absent levels", "a.b.google.com.", dns.TypeA, true, false, dns.RcodeSuccess, "192.168.1.10", ""},
				{"wildcard AAAA stays local", "www.google.com.", dns.TypeAAAA, true, false, dns.RcodeSuccess, "", "google.com."},
				{"exact override", "example.org.", dns.TypeA, true, false, dns.RcodeSuccess, "192.168.1.50", ""},
				{"nonrecursive exact", "example.org.", dns.TypeA, false, false, dns.RcodeSuccess, "192.168.1.50", ""},
				{"exact AAAA stays local", "example.org.", dns.TypeAAAA, true, false, dns.RcodeSuccess, "", "example.org."},
				{"exact TXT stays local", "example.org.", dns.TypeTXT, true, false, dns.RcodeSuccess, "", "example.org."},
				{"exact beats wildcard", "fixed.google.com.", dns.TypeA, true, false, dns.RcodeSuccess, "192.168.1.20", ""},
				{"nested wildcard", "www.apps.google.com.", dns.TypeA, true, false, dns.RcodeSuccess, "192.168.1.40", ""},
				{"wildcard parent forwarded", "google.com.", dns.TypeA, true, true, dns.RcodeSuccess, "203.0.113.1", ""},
				{"nested parent forwarded", "apps.google.com.", dns.TypeA, true, true, dns.RcodeSuccess, "203.0.113.1", ""},
				{"exact descendant forwarded", "www.example.org.", dns.TypeA, true, true, dns.RcodeSuccess, "203.0.113.1", ""},
				{"exact blocks broader wildcard", "child.fixed.google.com.", dns.TypeA, true, true, dns.RcodeSuccess, "203.0.113.1", ""},
				{"empty non-terminal forwarded", "empty.google.com.", dns.TypeA, true, true, dns.RcodeSuccess, "203.0.113.1", ""},
				{"empty non-terminal blocks wildcard", "other.empty.google.com.", dns.TypeA, true, true, dns.RcodeSuccess, "203.0.113.1", ""},
				{"unrelated forwarded", "unrelated.net.", dns.TypeA, true, true, dns.RcodeSuccess, "203.0.113.1", ""},
				{"suffix boundary forwarded", "notgoogle.com.", dns.TypeA, true, true, dns.RcodeSuccess, "203.0.113.1", ""},
				{"nonrecursive unmatched refused", "google.com.", dns.TypeA, false, false, dns.RcodeRefused, "", ""},
				{"DHCP stays local", "laptop.home.arpa.", dns.TypeA, true, false, dns.RcodeSuccess, "192.168.1.100", ""},
				{"missing local stays local", "missing.home.arpa.", dns.TypeA, true, false, dns.RcodeNameError, "", "home.arpa."},
				{"missing PTR stays local", "10.1.168.192.in-addr.arpa.", dns.TypePTR, true, false, dns.RcodeNameError, "", "1.168.192.in-addr.arpa."},
			} {
				t.Run(test.name, func(t *testing.T) {
					query := new(dns.Msg).SetQuestion(test.query, test.kind)
					query.RecursionDesired = test.recursive
					response, _, err := client.Exchange(query, address)
					if err != nil {
						t.Fatal(err)
					}
					if test.forwarded {
						expectedUpstreamQueries++
					}
					if got := upstreamQueries.Load(); got != expectedUpstreamQueries {
						t.Fatalf("upstream received %d queries, want %d", got, expectedUpstreamQueries)
					}
					authoritative := !test.forwarded && test.code != dns.RcodeRefused
					if response.Rcode != test.code || response.Authoritative != authoritative || !response.RecursionAvailable {
						t.Fatalf("incorrect override/forwarding flags: %s", response)
					}
					if test.ip != "" {
						if len(response.Answer) != 1 {
							t.Fatalf("expected one A answer: %s", response)
						}
						answer, ok := response.Answer[0].(*dns.A)
						if !ok || answer.A.String() != test.ip || (!test.forwarded && answer.Hdr.Ttl != 60) {
							t.Fatalf("incorrect override/forwarding A answer: %s", response)
						}
						return
					}
					if len(response.Answer) != 0 {
						t.Fatalf("unexpected answer: %s", response)
					}
					if test.soa == "" {
						if len(response.Ns) != 0 {
							t.Fatalf("unexpected authority records: %s", response)
						}
						return
					}
					if len(response.Ns) != 1 {
						t.Fatalf("negative answer lacks SOA: %s", response)
					}
					soa, ok := response.Ns[0].(*dns.SOA)
					if !ok || soa.Hdr.Name != test.soa || soa.Hdr.Ttl != 0 || soa.Minttl != 0 {
						t.Fatalf("negative answer has incorrect SOA owner or TTL: %s", response)
					}
				})
			}
		})
	}
}

func TestCancelInterruptsForwardingIntegration(t *testing.T) {
	t.Parallel()
	received := make(chan struct{}, 1)
	release := make(chan struct{})
	defer close(release)
	upstream := startUpstream(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		select {
		case received <- struct{}{}:
		default:
		}
		<-release
	}))
	config := testConfig()
	config.Upstream = upstream
	server := newTestServer(t, config)
	tcp, udp := listenPair(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, tcp, udp) }()
	queryDone := make(chan struct{})
	go func() {
		defer close(queryDone)
		client := dns.Client{Net: "udp", Timeout: time.Second}
		// Cancellation may interrupt this query; only shutdown completion matters.
		_, _, _ = client.Exchange(new(dns.Msg).SetQuestion("pending.example.", dns.TypeA), tcp.Addr().String())
	}()
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not receive query")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS cancellation waited for the upstream timeout")
	}
	<-queryDone
}

func startDNSServer(t *testing.T, config Config, entries ...lease.Lease) string {
	t.Helper()
	return startServer(t, newTestServer(t, config, entries...))
}

func startServer(t *testing.T, server *Server) string {
	t.Helper()
	tcp, udp := listenPair(t)
	address := tcp.Addr().String()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, tcp, udp) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("DNS shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("DNS shutdown did not complete")
		}
	})
	client := dns.Client{Net: "udp", Timeout: 50 * time.Millisecond}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, _, err := client.Exchange(new(dns.Msg).SetQuestion("home.arpa.", dns.TypeSOA), address); err == nil {
			return address
		}
		if time.Now().After(deadline) {
			t.Fatal("DNS did not become ready")
		}
	}
}

func TestDHCPDNSLifecycleIntegration(t *testing.T) {
	t.Parallel()
	config := testConfig()
	manager, err := lease.New(lease.Config{
		PoolStart: netip.MustParseAddr("192.168.1.100"), PoolEnd: netip.MustParseAddr("192.168.1.110"),
		Domain: config.Domain, LeaseDuration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dnsServer, err := New(config, manager, logger)
	if err != nil {
		t.Fatal(err)
	}
	address := startServer(t, dnsServer)
	dhcpServer, err := dhcpserver.New(dhcpserver.Config{
		ServerIP: config.ServerIP, Subnet: config.Subnet, Domain: config.Domain, LeaseDuration: time.Hour,
	}, manager, logger)
	if err != nil {
		t.Fatal(err)
	}
	dhcpRequest := func(kind dhcpv4.MessageType, options ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
		t.Helper()
		base := []dhcpv4.Modifier{dhcpv4.WithMessageType(kind), dhcpv4.WithHwAddr(net.HardwareAddr{2, 0, 0, 0, 0, 1})}
		packet, err := dhcpv4.New(append(base, options...)...)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := dhcpServer.Handle(packet)
		if err != nil {
			t.Fatal(err)
		}
		return reply
	}
	checkDNS := func(name string, kind uint16, code int, value string) {
		t.Helper()
		client := dns.Client{Net: "udp", Timeout: time.Second}
		response, _, err := client.Exchange(new(dns.Msg).SetQuestion(name, kind), address)
		if err != nil {
			t.Fatal(err)
		}
		if response.Rcode != code {
			t.Fatalf("query %s: expected rcode %d, got %s", name, code, response)
		}
		if value == "" {
			if len(response.Answer) != 0 {
				t.Fatalf("query %s: unexpected answer %v", name, response.Answer)
			}
			return
		}
		if len(response.Answer) != 1 {
			t.Fatalf("query %s: expected one answer, got %s", name, response)
		}
		switch answer := response.Answer[0].(type) {
		case *dns.A:
			if answer.A.String() != value {
				t.Fatalf("A = %v; want %s", answer.A, value)
			}
		case *dns.PTR:
			if answer.Ptr != value {
				t.Fatalf("PTR = %s; want %s", answer.Ptr, value)
			}
		default:
			t.Fatalf("unexpected answer: %v", answer)
		}
	}
	checkDNS("gateway.home.arpa.", dns.TypeA, dns.RcodeSuccess, config.ServerIP.String())
	checkDNS("gateway.home.arpa.", dns.TypeAAAA, dns.RcodeSuccess, "")
	offer := dhcpRequest(dhcpv4.MessageTypeDiscover, dhcpv4.WithOption(dhcpv4.OptHostName("Laptop")))
	if offer == nil || offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("expected DHCP OFFER, got %v", offer)
	}
	checkDNS("laptop.home.arpa.", dns.TypeA, dns.RcodeNameError, "")
	ack := dhcpRequest(dhcpv4.MessageTypeRequest,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier())),
	)
	if ack == nil || ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("expected DHCP ACK, got %v", ack)
	}
	reverse, err := dns.ReverseAddr(ack.YourIPAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	checkDNS("laptop.home.arpa.", dns.TypeA, dns.RcodeSuccess, ack.YourIPAddr.String())
	checkDNS(reverse, dns.TypePTR, dns.RcodeSuccess, "laptop.home.arpa.")
	renewal := dhcpRequest(dhcpv4.MessageTypeRequest,
		dhcpv4.WithClientIP(ack.YourIPAddr), dhcpv4.WithOption(dhcpv4.OptHostName("desktop")),
	)
	if renewal == nil || renewal.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("expected renewed DHCP ACK, got %v", renewal)
	}
	checkDNS("laptop.home.arpa.", dns.TypeA, dns.RcodeNameError, "")
	checkDNS("desktop.home.arpa.", dns.TypeA, dns.RcodeSuccess, ack.YourIPAddr.String())
	checkDNS(reverse, dns.TypePTR, dns.RcodeSuccess, "desktop.home.arpa.")
	reserved := dhcpRequest(dhcpv4.MessageTypeRequest,
		dhcpv4.WithClientIP(ack.YourIPAddr), dhcpv4.WithOption(dhcpv4.OptHostName("GATEWAY.HOME.ARPA.")),
	)
	if reserved == nil || reserved.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("reserved hostname prevented DHCP renewal: %v", reserved)
	}
	checkDNS("gateway.home.arpa.", dns.TypeA, dns.RcodeSuccess, config.ServerIP.String())
	checkDNS("desktop.home.arpa.", dns.TypeA, dns.RcodeNameError, "")
	checkDNS(reverse, dns.TypePTR, dns.RcodeNameError, "")
	if reply := dhcpRequest(dhcpv4.MessageTypeRelease, dhcpv4.WithClientIP(ack.YourIPAddr),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(ack.ServerIdentifier()))); reply != nil {
		t.Fatalf("unexpected RELEASE response: %v", reply)
	}
	checkDNS("desktop.home.arpa.", dns.TypeA, dns.RcodeNameError, "")
	checkDNS(reverse, dns.TypePTR, dns.RcodeNameError, "")
	checkDNS("gateway.home.arpa.", dns.TypeA, dns.RcodeSuccess, config.ServerIP.String())

	const generatedHostname = "host-hw-1-020000000001.home.arpa"
	offer = dhcpRequest(dhcpv4.MessageTypeDiscover)
	if offer == nil || offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("expected unnamed client DHCP OFFER, got %v", offer)
	}
	if offer.HostName() != generatedHostname {
		t.Fatalf("OFFER hostname = %q; want %q", offer.HostName(), generatedHostname)
	}
	reverse, err = dns.ReverseAddr(offer.YourIPAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	checkDNS(generatedHostname+".", dns.TypeA, dns.RcodeNameError, "")
	checkDNS(reverse, dns.TypePTR, dns.RcodeNameError, "")
	ack = dhcpRequest(dhcpv4.MessageTypeRequest,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier())),
	)
	if ack == nil || ack.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("expected unnamed client DHCP ACK, got %v", ack)
	}
	if ack.HostName() != generatedHostname || !ack.YourIPAddr.Equal(offer.YourIPAddr) {
		t.Fatalf("ACK did not retain offered hostname and IP: %v", ack)
	}
	current, found := manager.LookupName(generatedHostname)
	if !found || current.Hostname != generatedHostname+"." {
		t.Fatalf("generated lease hostname = %q, found = %v", current.Hostname, found)
	}
	checkDNS(generatedHostname+".", dns.TypeA, dns.RcodeSuccess, ack.YourIPAddr.String())
	checkDNS(reverse, dns.TypePTR, dns.RcodeSuccess, generatedHostname+".")

	// A new identity on the same hardware must get its own forward and reverse DNS.
	clientID := dhcpv4.WithOption(dhcpv4.OptClientIdentifier([]byte{1, 2, 0, 0, 0, 0, 1}))
	const identifiedHostname = "host-id-01020000000001.home.arpa."
	identifiedOffer := dhcpRequest(dhcpv4.MessageTypeDiscover, clientID)
	if identifiedOffer == nil || identifiedOffer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatalf("expected identified client DHCP OFFER, got %v", identifiedOffer)
	}
	checkDNS(identifiedHostname, dns.TypeA, dns.RcodeNameError, "")
	identifiedAck := dhcpRequest(dhcpv4.MessageTypeRequest, clientID,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(identifiedOffer.YourIPAddr)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(identifiedOffer.ServerIdentifier())),
	)
	if identifiedAck == nil || identifiedAck.MessageType() != dhcpv4.MessageTypeAck {
		t.Fatalf("expected identified client DHCP ACK, got %v", identifiedAck)
	}
	if identifiedAck.YourIPAddr.Equal(ack.YourIPAddr) {
		t.Fatal("different client identities received the same address")
	}
	identifiedReverse, err := dns.ReverseAddr(identifiedAck.YourIPAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	checkDNS(identifiedHostname, dns.TypeA, dns.RcodeSuccess, identifiedAck.YourIPAddr.String())
	checkDNS(identifiedReverse, dns.TypePTR, dns.RcodeSuccess, identifiedHostname)
	checkDNS(generatedHostname+".", dns.TypeA, dns.RcodeSuccess, ack.YourIPAddr.String())
	checkDNS(reverse, dns.TypePTR, dns.RcodeSuccess, generatedHostname+".")

	if reply := dhcpRequest(dhcpv4.MessageTypeRelease, dhcpv4.WithClientIP(ack.YourIPAddr),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(ack.ServerIdentifier()))); reply != nil {
		t.Fatalf("unexpected unnamed client RELEASE response: %v", reply)
	}
	checkDNS(generatedHostname+".", dns.TypeA, dns.RcodeNameError, "")
	checkDNS(reverse, dns.TypePTR, dns.RcodeNameError, "")
	checkDNS(identifiedHostname, dns.TypeA, dns.RcodeSuccess, identifiedAck.YourIPAddr.String())
	checkDNS(identifiedReverse, dns.TypePTR, dns.RcodeSuccess, identifiedHostname)
	if reply := dhcpRequest(dhcpv4.MessageTypeRelease, clientID, dhcpv4.WithClientIP(identifiedAck.YourIPAddr),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(identifiedAck.ServerIdentifier()))); reply != nil {
		t.Fatalf("unexpected identified client RELEASE response: %v", reply)
	}
	checkDNS(identifiedHostname, dns.TypeA, dns.RcodeNameError, "")
	checkDNS(identifiedReverse, dns.TypePTR, dns.RcodeNameError, "")
}

func listenPair(t *testing.T) (net.Listener, net.PacketConn) {
	t.Helper()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tcp.Close() })
	udp, err := net.ListenPacket("udp4", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	return tcp, udp
}

func startUpstream(t *testing.T, handler dns.Handler) string {
	t.Helper()
	tcp, udp := listenPair(t)
	for _, server := range []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler, UDPSize: maxUDPPayload}} {
		ready := make(chan struct{})
		server.NotifyStartedFunc = func() { close(ready) }
		done := make(chan error, 1)
		go func() { done <- server.ActivateAndServe() }()
		select {
		case <-ready:
		case err := <-done:
			t.Fatalf("start upstream: %v", err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if err := server.ShutdownContext(ctx); err != nil {
				t.Errorf("upstream shutdown: %v", err)
			}
			if err := <-done; err != nil {
				t.Errorf("upstream listener: %v", err)
			}
		})
	}
	return tcp.Addr().String()
}
