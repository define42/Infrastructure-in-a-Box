package dhcpserver

import (
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func TestNTPAdvertisement(t *testing.T) {
	t.Parallel()
	s, _ := testServer(t, "")
	check := func(reply *dhcpv4.DHCPv4) {
		t.Helper()
		servers := reply.NTPServers()
		if len(servers) != 1 || ipv4(servers[0]) != s.config.ServerIP {
			t.Fatalf("NTP option = %v, want %s", servers, s.config.ServerIP)
		}
	}
	// Advertise even when option 42 is absent from the parameter request list.
	offer := handle(t, s, packet(t, dhcpv4.MessageTypeDiscover, 1), dhcpv4.MessageTypeOffer)
	check(offer)
	check(handle(t, s, packet(t, dhcpv4.MessageTypeRequest, 1,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier()))), dhcpv4.MessageTypeAck))
	check(handle(t, s, packet(t, dhcpv4.MessageTypeRequest, 1,
		dhcpv4.WithClientIP(offer.YourIPAddr)), dhcpv4.MessageTypeAck))
	check(handle(t, s, packet(t, dhcpv4.MessageTypeInform, 2,
		dhcpv4.WithClientIP(net.IPv4(192, 168, 50, 200)),
		dhcpv4.WithRequestedOptions(dhcpv4.OptionNTPServers)), dhcpv4.MessageTypeAck))
	nak := handle(t, s, packet(t, dhcpv4.MessageTypeRequest, 2,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr))), dhcpv4.MessageTypeNak)
	if nak.Options.Has(dhcpv4.OptionNTPServers) {
		t.Fatal("NAK must not advertise NTP configuration")
	}
}
