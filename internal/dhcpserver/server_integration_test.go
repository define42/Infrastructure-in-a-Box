//go:build integration

package dhcpserver

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// routeReply keeps DHCP's standard broadcast/port-68 replies on the ephemeral
// loopback test client. Production destination selection is tested separately.
type routeReply struct {
	net.PacketConn
	client net.Addr
}

func (c routeReply) WriteTo(b []byte, _ net.Addr) (int, error) {
	return c.PacketConn.WriteTo(b, c.client)
}

func TestServeDHCPWireLifecycle(t *testing.T) {
	t.Parallel()
	s, manager := testServer(t, "")
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	client, err := net.Dial("udp4", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, routeReply{listener, client.LocalAddr()}) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("DHCP server did not stop")
		}
	})
	exchange := func(request *dhcpv4.DHCPv4) *dhcpv4.DHCPv4 {
		t.Helper()
		if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := client.Write(request.ToBytes()); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, err := client.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		reply, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		if reply.TransactionID != request.TransactionID {
			t.Fatal("transaction ID did not match")
		}
		return reply
	}
	if _, err := client.Write([]byte("malformed DHCP")); err != nil {
		t.Fatal(err)
	}
	offer := exchange(packet(t, dhcpv4.MessageTypeDiscover, 1, dhcpv4.WithOption(dhcpv4.OptHostName("wire-client"))))
	if offer.MessageType() != dhcpv4.MessageTypeOffer {
		t.Fatal("DISCOVER did not produce OFFER")
	}
	ack := exchange(packet(t, dhcpv4.MessageTypeRequest, 1,
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier()))))
	if ack.MessageType() != dhcpv4.MessageTypeAck || !ack.YourIPAddr.Equal(offer.YourIPAddr) {
		t.Fatal("REQUEST did not acknowledge offered address")
	}
	if _, ok := manager.LookupName("wire-client.home.arpa."); !ok {
		t.Fatal("wire exchange did not register hostname")
	}
	release := packet(t, dhcpv4.MessageTypeRelease, 1,
		dhcpv4.WithClientIP(ack.YourIPAddr), dhcpv4.WithOption(dhcpv4.OptServerIdentifier(ack.ServerIdentifier())))
	if _, err := client.Write(release.ToBytes()); err != nil {
		t.Fatal(err)
	}
	// A following INFORM response confirms the preceding RELEASE was processed.
	exchange(packet(t, dhcpv4.MessageTypeInform, 1, dhcpv4.WithClientIP(ack.YourIPAddr)))
	if _, ok := manager.LookupName("wire-client.home.arpa."); ok {
		t.Fatal("RELEASE retained the hostname")
	}
}

func TestServeAlreadyCancelled(t *testing.T) {
	t.Parallel()
	s, _ := testServer(t, "")
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.Serve(ctx, listener); err != nil {
		t.Fatal(err)
	}
}
