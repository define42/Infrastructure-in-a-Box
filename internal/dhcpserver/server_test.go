package dhcpserver

import (
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
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
