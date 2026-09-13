//go:build integration && linux

package dhcpserver

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"golang.org/x/sys/unix"
)

func TestListenerBroadcastLeaseLifecycle(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{
		"interface": "lo", "server_ip": "192.168.50.1",
		"subnet": "192.168.50.0/24",
		"pool_start": "192.168.50.100", "pool_end": "192.168.50.101"
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	host, _, err := net.SplitHostPort(cfg.DHCPAddress)
	if err != nil {
		t.Fatal(err)
	}

	// Bind every socket to lo before use, including the wildcard DHCP listener.
	// The client also permits broadcasts, which stay inside 127.0.0.0/8.
	clientConfig := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
		var socketErr error
		err := raw.Control(func(fd uintptr) {
			socketErr = unix.BindToDevice(int(fd), "lo")
			if socketErr == nil {
				socketErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BROADCAST, 1)
			}
		})
		return errors.Join(err, socketErr)
	}}
	client, err := clientConfig.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
		t.Skipf("binding test sockets to lo requires additional permissions on this kernel: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	s, manager := testServer(t, "")
	s.config.Interface = cfg.Interface
	// Preserve the configured bind host; only replace port 67 with a free port.
	s.config.Address = net.JoinHostPort(host, "0")
	listener, err := s.listen()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var device string
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		device, socketErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
	}); err != nil {
		t.Fatal(err)
	}
	if socketErr != nil || device != "lo" {
		t.Fatalf("listener must be confined to lo before serving: device=%q, error=%v", device, socketErr)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	// Keep replies on the ephemeral client instead of standard DHCP port 68.
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
	bound, ok := listener.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("unexpected listener address: %T", listener.LocalAddr())
	}
	exchange := func(destination net.IP, request *dhcpv4.DHCPv4, want dhcpv4.MessageType) *dhcpv4.DHCPv4 {
		t.Helper()
		if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := client.WriteTo(request.ToBytes(), &net.UDPAddr{IP: destination, Port: bound.Port}); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4096)
		n, _, err := client.ReadFrom(buf)
		if err != nil {
			t.Fatalf("%s sent to %s did not receive %s: %v", request.MessageType(), destination, want, err)
		}
		reply, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
		if reply.TransactionID != request.TransactionID || reply.MessageType() != want {
			t.Fatalf("unexpected DHCP reply: %s", reply.Summary())
		}
		if ipv4(reply.ServerIdentifier()) != cfg.ServerIP {
			t.Fatalf("server identifier = %s, want configured server_ip %s", reply.ServerIdentifier(), cfg.ServerIP)
		}
		return reply
	}
	broadcast := net.IPv4(127, 255, 255, 255)
	offer := exchange(broadcast, packet(t, dhcpv4.MessageTypeDiscover, 1,
		dhcpv4.WithBroadcast(true), dhcpv4.WithOption(dhcpv4.OptHostName("broadcast-client"))), dhcpv4.MessageTypeOffer)
	ack := exchange(broadcast, packet(t, dhcpv4.MessageTypeRequest, 1,
		dhcpv4.WithBroadcast(true),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier()))), dhcpv4.MessageTypeAck)
	if !ack.YourIPAddr.Equal(offer.YourIPAddr) {
		t.Fatal("broadcast REQUEST did not acknowledge the offered address")
	}
	if _, ok := manager.LookupName("broadcast-client.home.arpa."); !ok {
		t.Fatal("broadcast lease exchange did not register hostname")
	}
	renewal := exchange(net.IPv4(127, 0, 0, 1), packet(t, dhcpv4.MessageTypeRequest, 1,
		dhcpv4.WithClientIP(ack.YourIPAddr)), dhcpv4.MessageTypeAck)
	if !renewal.YourIPAddr.Equal(ack.YourIPAddr) {
		t.Fatal("unicast renewal did not preserve the leased address")
	}
}
