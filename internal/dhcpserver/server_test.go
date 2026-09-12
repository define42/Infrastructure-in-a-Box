package dhcpserver

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
	"github.com/insomniacslk/dhcp/dhcpv4"
)

func testServer(t *testing.T, file string) (*Server, *lease.Manager) {
	t.Helper()
	manager, err := lease.New(lease.Config{
		PoolStart: netip.MustParseAddr("192.168.50.100"), PoolEnd: netip.MustParseAddr("192.168.50.101"),
		Domain: "home.arpa", LeaseDuration: time.Hour, File: file,
	})
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		ServerIP: netip.MustParseAddr("192.168.50.1"), Subnet: netip.MustParsePrefix("192.168.50.0/24"),
		Router: netip.MustParseAddr("192.168.50.254"), Domain: "home.arpa", LeaseDuration: time.Hour,
	}, manager, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return server, manager
}

func packet(t *testing.T, kind dhcpv4.MessageType, client byte, mods ...dhcpv4.Modifier) *dhcpv4.DHCPv4 {
	t.Helper()
	base := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(kind), dhcpv4.WithHwAddr(net.HardwareAddr{2, 0, 0, 0, 0, client}),
	}
	p, err := dhcpv4.New(append(base, mods...)...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func handle(t *testing.T, s *Server, p *dhcpv4.DHCPv4, kind dhcpv4.MessageType) *dhcpv4.DHCPv4 {
	t.Helper()
	reply, err := s.Handle(p)
	if err != nil {
		t.Fatal(err)
	}
	if reply == nil || reply.MessageType() != kind {
		t.Fatalf("reply = %v, want %s", reply, kind)
	}
	// Every response must survive a real DHCP packet round trip.
	decoded, err := dhcpv4.FromBytes(reply.ToBytes())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.TransactionID != p.TransactionID || decoded.OpCode != dhcpv4.OpcodeBootReply {
		t.Fatal("reply lost transaction ID or opcode")
	}
	return decoded
}

func TestHandleLeaseLifecycle(t *testing.T) {
	t.Parallel()
	s, manager := testServer(t, "")
	discover := packet(t, dhcpv4.MessageTypeDiscover, 1, dhcpv4.WithOption(dhcpv4.OptHostName("Laptop")))
	offer := handle(t, s, discover, dhcpv4.MessageTypeOffer)
	if _, ok := manager.LookupName("laptop.home.arpa."); ok {
		t.Fatal("offer registered DNS before acknowledgement")
	}
	request := packet(t, dhcpv4.MessageTypeRequest, 1,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier())),
	)
	ack := handle(t, s, request, dhcpv4.MessageTypeAck)
	if !ack.YourIPAddr.Equal(offer.YourIPAddr) || ack.IPAddressLeaseTime(0) != time.Hour {
		t.Fatal("ack does not match offered IP and lease duration")
	}
	if got := ack.DNS(); len(got) != 1 || !got[0].Equal(net.ParseIP("192.168.50.1")) {
		t.Fatalf("DNS option = %v", got)
	}
	if ack.DomainName() != "home.arpa" || len(ack.Router()) != 1 || ack.SubnetMask().String() != "ffffff00" {
		t.Fatal("missing subnet, domain or router options")
	}
	active, ok := manager.LookupName("laptop.home.arpa.")
	if !ok || active.IP != ipv4(ack.YourIPAddr) {
		t.Fatal("ack did not register DISCOVER hostname")
	}
	renewal := packet(t, dhcpv4.MessageTypeRequest, 1,
		dhcpv4.WithClientIP(ack.YourIPAddr), dhcpv4.WithOption(dhcpv4.OptHostName("desktop")),
	)
	handle(t, s, renewal, dhcpv4.MessageTypeAck)
	if _, ok := manager.LookupName("laptop.home.arpa."); ok {
		t.Fatal("rename retained old DNS record")
	}
	if _, ok := manager.LookupName("desktop.home.arpa."); !ok {
		t.Fatal("rename did not register new DNS record")
	}
	release := packet(t, dhcpv4.MessageTypeRelease, 1,
		dhcpv4.WithClientIP(ack.YourIPAddr), dhcpv4.WithOption(dhcpv4.OptServerIdentifier(ack.ServerIdentifier())),
	)
	if reply, err := s.Handle(release); reply != nil || err != nil {
		t.Fatalf("release = %v, %v", reply, err)
	}
	if _, ok := manager.LookupIP(active.IP); ok {
		t.Fatal("release retained lease and DNS")
	}
}

func TestRootCAAdvertisement(t *testing.T) {
	t.Parallel()
	for _, serverIP := range []string{"192.168.50.1", "192.168.50.2"} {
		t.Run(serverIP, func(t *testing.T) {
			t.Parallel()
			s, manager := testServer(t, "")
			cfg := s.config
			cfg.ServerIP = netip.MustParseAddr(serverIP)
			s, err := New(cfg, manager, s.logger)
			if err != nil {
				t.Fatal(err)
			}
			check := func(reply *dhcpv4.DHCPv4) {
				t.Helper()
				want := "http://" + serverIP + "/ca.pem"
				if got := string(reply.Options.Get(dhcpv4.OptionVendorSpecificInformation)); got != want {
					t.Fatalf("%s option 43 = %q, want %q", reply.MessageType(), got, want)
				}
			}
			// Advertise even when option 43 is absent from the parameter request list.
			offer := handle(t, s, packet(t, dhcpv4.MessageTypeDiscover, 1), dhcpv4.MessageTypeOffer)
			check(offer)
			request := packet(t, dhcpv4.MessageTypeRequest, 1,
				dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
				dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier())),
			)
			check(handle(t, s, request, dhcpv4.MessageTypeAck))
			renewal := packet(t, dhcpv4.MessageTypeRequest, 1, dhcpv4.WithClientIP(offer.YourIPAddr))
			check(handle(t, s, renewal, dhcpv4.MessageTypeAck))
			inform := packet(t, dhcpv4.MessageTypeInform, 2,
				dhcpv4.WithClientIP(net.IPv4(192, 168, 50, 200)),
				dhcpv4.WithRequestedOptions(dhcpv4.OptionVendorSpecificInformation),
			)
			check(handle(t, s, inform, dhcpv4.MessageTypeAck))
			conflict := packet(t, dhcpv4.MessageTypeRequest, 2,
				dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
			)
			nak := handle(t, s, conflict, dhcpv4.MessageTypeNak)
			if nak.Options.Has(dhcpv4.OptionVendorSpecificInformation) {
				t.Fatal("NAK must not advertise the root CA URL")
			}
		})
	}
}

func TestHandleMissingHostname(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		mods []dhcpv4.Modifier
		want string
	}{
		{
			name: "missing options",
			want: "host-hw-1-020000000001.home.arpa",
		},
		{
			name: "empty option 12",
			mods: []dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptHostName(""))},
			want: "host-hw-1-020000000001.home.arpa",
		},
		{
			name: "empty FQDN",
			mods: []dhcpv4.Modifier{dhcpv4.WithGeneric(dhcpv4.OptionFQDN, []byte{4, 0, 0, 0})},
			want: "host-hw-1-020000000001.home.arpa",
		},
		{
			name: "client identifier before MAC",
			mods: []dhcpv4.Modifier{
				dhcpv4.WithGeneric(dhcpv4.OptionClientIdentifier, []byte{0, 'i', 'd'}),
				dhcpv4.WithHwAddr(net.HardwareAddr{0x02, 0xab, 0xcd, 0xef, 0x00, 0x42}),
			},
			want: "host-id-006964.home.arpa",
		},
		{
			name: "no hardware address",
			mods: []dhcpv4.Modifier{
				dhcpv4.WithGeneric(dhcpv4.OptionClientIdentifier, []byte{0, 'i', 'd'}),
				dhcpv4.WithHwAddr(net.HardwareAddr{}),
			},
			want: "host-id-006964.home.arpa",
		},
		{
			name: "explicit invalid hostname",
			mods: []dhcpv4.Modifier{dhcpv4.WithOption(dhcpv4.OptHostName("bad_name"))},
		},
		{
			name: "DNS registration disabled",
			mods: []dhcpv4.Modifier{dhcpv4.WithGeneric(dhcpv4.OptionFQDN, []byte{8, 0, 0})},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, manager := testServer(t, "")
			request := packet(t, dhcpv4.MessageTypeRequest, 1, tc.mods...)
			request.UpdateOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.168.50.100")))
			ack := handle(t, s, request, dhcpv4.MessageTypeAck)
			if got := ack.HostName(); got != tc.want {
				t.Fatalf("ACK option 12 = %q, want %q", got, tc.want)
			}
			current, ok := manager.LookupIP(ipv4(ack.YourIPAddr))
			if !ok {
				t.Fatal("ACK did not commit the lease")
			}
			want := tc.want
			if want != "" {
				want += "."
			}
			if current.Hostname != want {
				t.Fatalf("lease hostname = %q, want %q", current.Hostname, want)
			}
		})
	}
}

func TestHandleFallbackHostnameLifecycle(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "leases.json")
	s, manager := testServer(t, file)
	const fallback = "host-hw-1-020000000001.home.arpa"
	offer := handle(t, s, packet(t, dhcpv4.MessageTypeDiscover, 1), dhcpv4.MessageTypeOffer)
	if got := offer.HostName(); got != fallback {
		t.Fatalf("OFFER option 12 = %q, want %q", got, fallback)
	}
	if _, ok := manager.LookupName(fallback); ok {
		t.Fatal("offer registered the fallback before acknowledgement")
	}
	ack := handle(t, s, packet(t, dhcpv4.MessageTypeRequest, 1,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier())),
	), dhcpv4.MessageTypeAck)
	if got := ack.HostName(); got != fallback {
		t.Fatalf("ACK option 12 = %q, want %q", got, fallback)
	}
	// Restoring and renewing the lease must retain its generated registration.
	s, manager = testServer(t, file)
	current, ok := manager.LookupName(fallback)
	if !ok || current.IP != ipv4(ack.YourIPAddr) {
		t.Fatal("fallback registration was not restored")
	}
	renewal := packet(t, dhcpv4.MessageTypeRequest, 1, dhcpv4.WithClientIP(ack.YourIPAddr))
	if got := handle(t, s, renewal, dhcpv4.MessageTypeAck).HostName(); got != fallback {
		t.Fatalf("renewal option 12 = %q, want %q", got, fallback)
	}
	// A client-supplied name replaces the fallback and survives unnamed renewals.
	renewal.UpdateOption(dhcpv4.OptHostName("Laptop"))
	handle(t, s, renewal, dhcpv4.MessageTypeAck)
	if _, ok := manager.LookupName(fallback); ok {
		t.Fatal("rename retained the generated DNS name")
	}
	renewal.Options.Del(dhcpv4.OptionHostName)
	if got := handle(t, s, renewal, dhcpv4.MessageTypeAck).HostName(); got != "laptop.home.arpa" {
		t.Fatalf("unnamed renewal replaced the stored hostname: %q", got)
	}
}

func TestHandleFallbackHostnameDistinctClientIdentities(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "leases.json")
	s, manager := testServer(t, file)
	mac := net.HardwareAddr{0xa4, 0xbb, 0x6d, 0x73, 0xdb, 0x00}
	clientID := []byte{1, 0xa4, 0xbb, 0x6d, 0x73, 0xdb, 0x00}
	identities := []struct {
		id       []byte
		clientID string
		hostname string
		ip       netip.Addr
	}{
		{
			clientID: "hw:1:a4bb6d73db00",
			hostname: "host-hw-1-a4bb6d73db00.home.arpa",
			ip:       netip.MustParseAddr("192.168.50.100"),
		},
		{
			id:       clientID,
			clientID: "id:01a4bb6d73db00",
			hostname: "host-id-01a4bb6d73db00.home.arpa",
			ip:       netip.MustParseAddr("192.168.50.101"),
		},
	}
	checkRegistration := func(name, clientID string, ip netip.Addr) {
		t.Helper()
		forward, ok := manager.LookupName(name)
		if !ok || forward.IP != ip || forward.ClientID != clientID {
			t.Fatalf("name lookup for %q = %+v, %v", name, forward, ok)
		}
		reverse, ok := manager.LookupIP(ip)
		if !ok || reverse.Hostname != name+"." || reverse.ClientID != clientID {
			t.Fatalf("IP lookup for %s = %+v, %v", ip, reverse, ok)
		}
	}
	for _, identity := range identities {
		mods := []dhcpv4.Modifier{dhcpv4.WithHwAddr(mac)}
		if identity.id != nil {
			mods = append(mods, dhcpv4.WithGeneric(dhcpv4.OptionClientIdentifier, identity.id))
		}
		offer := handle(t, s, packet(t, dhcpv4.MessageTypeDiscover, 1, mods...), dhcpv4.MessageTypeOffer)
		if offer.HostName() != identity.hostname || ipv4(offer.YourIPAddr) != identity.ip {
			t.Fatalf("offer for %s = %s, %q", identity.clientID, offer.YourIPAddr, offer.HostName())
		}
		if _, ok := manager.LookupName(identity.hostname); ok {
			t.Fatal("offer registered DNS before acknowledgement")
		}
		mods = append(mods,
			dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
			dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier())),
		)
		ack := handle(t, s, packet(t, dhcpv4.MessageTypeRequest, 1, mods...), dhcpv4.MessageTypeAck)
		if ack.HostName() != identity.hostname || ipv4(ack.YourIPAddr) != identity.ip {
			t.Fatalf("ack for %s = %s, %q", identity.clientID, ack.YourIPAddr, ack.HostName())
		}
		checkRegistration(identity.hostname, identity.clientID, identity.ip)
	}
	s, manager = testServer(t, file)
	for _, identity := range identities {
		checkRegistration(identity.hostname, identity.clientID, identity.ip)
		mods := []dhcpv4.Modifier{dhcpv4.WithHwAddr(mac), dhcpv4.WithClientIP(net.IP(identity.ip.AsSlice()))}
		if identity.id != nil {
			mods = append(mods, dhcpv4.WithGeneric(dhcpv4.OptionClientIdentifier, identity.id))
		}
		ack := handle(t, s, packet(t, dhcpv4.MessageTypeRequest, 1, mods...), dhcpv4.MessageTypeAck)
		if ack.HostName() != identity.hostname || ipv4(ack.YourIPAddr) != identity.ip {
			t.Fatalf("renewal for %s = %s, %q", identity.clientID, ack.YourIPAddr, ack.HostName())
		}
		checkRegistration(identity.hostname, identity.clientID, identity.ip)
	}
}

func TestHandleFallbackHostnameLongClientIdentifiers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		length int
		hashed bool
	}{
		{name: "last readable identifier", length: 27},
		{name: "first hashed identifier", length: 28, hashed: true},
		{name: "maximum identifier", length: 255, hashed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := filepath.Join(t.TempDir(), "leases.json")
			s, manager := testServer(t, file)
			id := bytes.Repeat([]byte{1}, tc.length)
			acquire := func() *dhcpv4.DHCPv4 {
				t.Helper()
				modifier := dhcpv4.WithGeneric(dhcpv4.OptionClientIdentifier, id)
				offer := handle(t, s, packet(t, dhcpv4.MessageTypeDiscover, 1, modifier), dhcpv4.MessageTypeOffer)
				ack := handle(t, s, packet(t, dhcpv4.MessageTypeRequest, 1, modifier,
					dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
					dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier())),
				), dhcpv4.MessageTypeAck)
				if ack.HostName() != offer.HostName() {
					t.Fatalf("ACK hostname %q differs from offer %q", ack.HostName(), offer.HostName())
				}
				return ack
			}
			first := acquire()
			label := strings.TrimSuffix(first.HostName(), ".home.arpa")
			if tc.hashed {
				if !strings.HasPrefix(label, "host-sha256-") || len(label) != 60 {
					t.Fatalf("long identifier hostname label = %q", label)
				}
			} else if want := "host-id-" + strings.Repeat("01", tc.length); label != want {
				t.Fatalf("readable hostname label = %q, want %q", label, want)
			}
			if lease.NormalizeHostname(first.HostName(), "home.arpa") != first.HostName()+"." {
				t.Fatalf("invalid generated DNS name %q", first.HostName())
			}
			// Identifiers differing beyond the readable prefix must not collide.
			id[len(id)-1] = 2
			second := acquire()
			if second.HostName() == first.HostName() || second.HostName() == "" || second.YourIPAddr.Equal(first.YourIPAddr) {
				t.Fatalf("distinct identifiers share an address or hostname: %v, %v", first, second)
			}
			s, manager = testServer(t, file)
			for i, ack := range []*dhcpv4.DHCPv4{first, second} {
				id[len(id)-1] = byte(i + 1)
				stored, ok := manager.LookupName(ack.HostName())
				if !ok || stored.IP != ipv4(ack.YourIPAddr) {
					t.Fatalf("generated name %q was not restored", ack.HostName())
				}
				renewal := packet(t, dhcpv4.MessageTypeRequest, 1,
					dhcpv4.WithGeneric(dhcpv4.OptionClientIdentifier, id),
					dhcpv4.WithClientIP(ack.YourIPAddr),
				)
				if got := handle(t, s, renewal, dhcpv4.MessageTypeAck).HostName(); got != ack.HostName() {
					t.Fatalf("renewed hostname = %q, want %q", got, ack.HostName())
				}
			}
		})
	}
}

func TestHandleFallbackHostnameExistingLeases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		stored   string
		clientID string
		id       []byte
		want     string
	}{
		{
			name: "preserves legacy MAC name", stored: "host-02-00-00-00-00-01",
			clientID: "hw:1:020000000001", want: "host-02-00-00-00-00-01.home.arpa",
		},
		{
			name: "names existing unnamed identity", clientID: "id:006964", id: []byte{0, 'i', 'd'},
			want: "host-id-006964.home.arpa",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			file := filepath.Join(t.TempDir(), "leases.json")
			_, manager := testServer(t, file)
			ip := netip.MustParseAddr("192.168.50.100")
			if _, err := manager.Commit(tc.clientID, ip, tc.stored); err != nil {
				t.Fatal(err)
			}
			s, manager := testServer(t, file)
			renewal := packet(t, dhcpv4.MessageTypeRequest, 1, dhcpv4.WithClientIP(net.IP(ip.AsSlice())))
			if tc.id != nil {
				renewal.UpdateOption(dhcpv4.OptClientIdentifier(tc.id))
			}
			ack := handle(t, s, renewal, dhcpv4.MessageTypeAck)
			if ack.HostName() != tc.want || ipv4(ack.YourIPAddr) != ip {
				t.Fatalf("renewed lease = %s, %q", ack.YourIPAddr, ack.HostName())
			}
			current, ok := manager.LookupName(tc.want)
			if !ok || current.IP != ip || current.ClientID != tc.clientID {
				t.Fatalf("renewed registration = %+v, %v", current, ok)
			}
		})
	}
}

func TestHandleConflictsAndDecline(t *testing.T) {
	t.Parallel()
	s, manager := testServer(t, "")
	wanted := dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.168.50.100")))
	handle(t, s, packet(t, dhcpv4.MessageTypeRequest, 1, wanted,
		dhcpv4.WithOption(dhcpv4.OptHostName("first"))), dhcpv4.MessageTypeAck)
	nak := handle(t, s, packet(t, dhcpv4.MessageTypeRequest, 2, wanted), dhcpv4.MessageTypeNak)
	if ipv4(nak.YourIPAddr).IsValid() || nak.IPAddressLeaseTime(0) != 0 {
		t.Fatal("NAK assigned an address or lease time")
	}
	decline := packet(t, dhcpv4.MessageTypeDecline, 1, wanted,
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.168.50.1"))),
	)
	if _, err := s.Handle(decline); err != nil {
		t.Fatal(err)
	}
	if _, ok := manager.LookupName("first.home.arpa."); ok {
		t.Fatal("decline retained DNS")
	}
	offer := handle(t, s, packet(t, dhcpv4.MessageTypeDiscover, 2), dhcpv4.MessageTypeOffer)
	if !offer.YourIPAddr.Equal(net.ParseIP("192.168.50.101")) {
		t.Fatal("declined address was reused")
	}
	if response, err := s.Handle(packet(t, dhcpv4.MessageTypeDiscover, 3)); response != nil || err != nil {
		t.Fatalf("exhausted pool response = %v, %v", response, err)
	}
}

func TestHandleIgnoresInvalidAndOtherServers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		modify func(*dhcpv4.DHCPv4)
	}{
		{"other server", func(p *dhcpv4.DHCPv4) { p.UpdateOption(dhcpv4.OptServerIdentifier(net.ParseIP("192.168.50.2"))) }},
		{"invalid requested option", func(p *dhcpv4.DHCPv4) { p.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionRequestedIPAddress, []byte{1})) }},
		{"invalid message type", func(p *dhcpv4.DHCPv4) { p.UpdateOption(dhcpv4.OptGeneric(dhcpv4.OptionDHCPMessageType, []byte{3, 3})) }},
		{"no client identity", func(p *dhcpv4.DHCPv4) { p.ClientHWAddr = nil }},
		{"server packet", func(p *dhcpv4.DHCPv4) { p.OpCode = dhcpv4.OpcodeBootReply }},
		{"foreign relay", func(p *dhcpv4.DHCPv4) { p.GatewayIPAddr = net.ParseIP("10.0.0.1") }},
		{"invalid renewal", func(p *dhcpv4.DHCPv4) { p.ClientIPAddr = net.ParseIP("192.168.50.100") }},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			s, manager := testServer(t, "")
			request := packet(t, dhcpv4.MessageTypeRequest, 1,
				dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.168.50.100"))))
			tt.modify(request)
			if reply, err := s.Handle(request); reply != nil || err != nil {
				t.Fatalf("reply = %v, %v; want ignored packet", reply, err)
			}
			if _, ok := manager.LookupIP(netip.MustParseAddr("192.168.50.100")); ok {
				t.Fatal("ignored request mutated leases")
			}
		})
	}
}

func TestHandleInformAndClientID(t *testing.T) {
	t.Parallel()
	s, manager := testServer(t, "")
	id := dhcpv4.WithOption(dhcpv4.OptClientIdentifier([]byte{0, 42}))
	first := handle(t, s, packet(t, dhcpv4.MessageTypeDiscover, 1, id), dhcpv4.MessageTypeOffer)
	second := handle(t, s, packet(t, dhcpv4.MessageTypeDiscover, 2, id), dhcpv4.MessageTypeOffer)
	if !first.YourIPAddr.Equal(second.YourIPAddr) {
		t.Fatal("client identifier was not preferred over hardware address")
	}
	inform := packet(t, dhcpv4.MessageTypeInform, 3, dhcpv4.WithClientIP(net.ParseIP("192.168.50.200")))
	ack := handle(t, s, inform, dhcpv4.MessageTypeAck)
	if ipv4(ack.YourIPAddr).IsValid() || ack.IPAddressLeaseTime(0) != 0 || len(ack.DNS()) != 1 {
		t.Fatal("INFORM should provide configuration without a lease")
	}
	if _, ok := manager.LookupIP(ipv4(inform.ClientIPAddr)); ok {
		t.Fatal("INFORM created a lease")
	}
}

func TestHandlePersistenceFailureDoesNotACK(t *testing.T) {
	t.Parallel()
	file := filepath.Join(t.TempDir(), "leases.json")
	s, manager := testServer(t, file)
	if err := os.Mkdir(file, 0o700); err != nil {
		t.Fatal(err)
	}
	request := packet(t, dhcpv4.MessageTypeRequest, 1,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.168.50.100"))),
		dhcpv4.WithOption(dhcpv4.OptHostName("unwritten")))
	if reply, err := s.Handle(request); reply != nil || err == nil {
		t.Fatalf("persistence failure reply = %v, %v", reply, err)
	}
	if _, ok := manager.LookupName("unwritten.home.arpa."); ok {
		t.Fatal("failed persistence published DNS")
	}
}

func TestReplyAddress(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		current, relay string
		kind           dhcpv4.MessageType
		want           string
	}{
		{"initial broadcast", "", "", dhcpv4.MessageTypeOffer, "255.255.255.255:68"},
		{"renewal", "192.168.50.100", "", dhcpv4.MessageTypeAck, "192.168.50.100:68"},
		{"nak broadcast", "192.168.50.100", "", dhcpv4.MessageTypeNak, "255.255.255.255:68"},
		{"relay", "", "192.168.50.254", dhcpv4.MessageTypeOffer, "192.168.50.254:67"},
		{"relay nak", "", "192.168.50.254", dhcpv4.MessageTypeNak, "192.168.50.254:67"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			request := packet(t, dhcpv4.MessageTypeRequest, 1,
				dhcpv4.WithClientIP(net.ParseIP(tt.current)), dhcpv4.WithGatewayIP(net.ParseIP(tt.relay)))
			reply := packet(t, tt.kind, 1)
			if got := replyAddress(request, reply).String(); got != tt.want {
				t.Fatalf("address = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestHandleMaximumLeaseDuration(t *testing.T) {
	t.Parallel()
	s, _ := testServer(t, "")
	s.config.LeaseDuration = dhcpv4.MaxLeaseTime
	offer := handle(t, s, packet(t, dhcpv4.MessageTypeDiscover, 1), dhcpv4.MessageTypeOffer)
	var rebinding dhcpv4.Duration
	if err := rebinding.FromBytes(offer.Options.Get(dhcpv4.OptionRebindingTimeValue)); err != nil {
		t.Fatal(err)
	}
	want := time.Duration(uint64(1<<32-1)*7/8) * time.Second
	if time.Duration(rebinding) != want {
		t.Fatalf("rebinding = %s, want %s", time.Duration(rebinding), want)
	}
}
