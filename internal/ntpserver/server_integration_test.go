//go:build integration

package ntpserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"
)

func listenLoopback(t *testing.T) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func startServer(t *testing.T, listener *net.UDPConn) {
	t.Helper()
	s, err := New(Config{Address: listener.LocalAddr().String()}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("NTP server did not stop")
		}
		if _, err := listener.WriteToUDP([]byte{0}, listener.LocalAddr().(*net.UDPAddr)); !errors.Is(err, net.ErrClosed) {
			t.Errorf("listener not closed after shutdown: %v", err)
		}
	})
}

func TestServeNTPWireExchange(t *testing.T) {
	t.Parallel()
	listener := listenLoopback(t)
	startServer(t, listener)
	client, err := net.Dial("udp4", listener.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	// None of these may elicit a reply, including truncated oversized datagrams.
	for _, size := range []int{1, 47, 49, 68, 4096} {
		bad := make([]byte, size)
		bad[0] = 0x23
		if _, err := client.Write(bad); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []byte{1, 4, 5, 6, 7} {
		bad := make([]byte, 48)
		bad[0] = 4<<3 | mode
		if _, err := client.Write(bad); err != nil {
			t.Fatal(err)
		}
	}
	for _, version := range []byte{3, 4} {
		request := make([]byte, 48)
		request[0] = version<<3 | 3
		request[2] = 6
		// An opaque nonzero transmit value tests exact origin correlation.
		copy(request[40:], []byte{version, 2, 3, 4, 5, 6, 7, 8})
		before := time.Now()
		if _, err := client.Write(request); err != nil {
			t.Fatal(err)
		}
		var reply [512]byte
		n, err := client.Read(reply[:])
		after := time.Now()
		if err != nil {
			t.Fatal(err)
		}
		if n != 48 || reply[0] != version<<3|4 || reply[1] != 10 || !bytes.Equal(reply[24:32], request[40:48]) {
			t.Fatalf("unexpected NTP response: %x", reply[:n])
		}
		// Decode using the protocol definition, not the production encoder.
		for _, offset := range []int{16, 32, 40} {
			seconds := int64(binary.BigEndian.Uint32(reply[offset:])) - 2_208_988_800
			fraction := uint64(binary.BigEndian.Uint32(reply[offset+4:]))
			stamp := time.Unix(seconds, int64(fraction*1_000_000_000>>32))
			if stamp.Before(before.Add(-time.Microsecond)) || stamp.After(after) {
				t.Errorf("timestamp at offset %d = %s, outside exchange %s to %s", offset, stamp, before, after)
			}
		}
		if binary.BigEndian.Uint64(reply[40:48]) < binary.BigEndian.Uint64(reply[32:40]) {
			t.Fatal("transmit timestamp precedes receive timestamp")
		}
	}
}

func TestServeIdleCancellation(t *testing.T) {
	t.Parallel()
	startServer(t, listenLoopback(t))
}

func TestServeAlreadyCancelled(t *testing.T) {
	t.Parallel()
	listener := listenLoopback(t)
	s, err := New(Config{Address: listener.LocalAddr().String()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := s.Serve(ctx, listener); err != nil {
		t.Fatal(err)
	}
}

func TestListenerFailures(t *testing.T) {
	t.Parallel()
	listener := listenLoopback(t)
	s, err := New(Config{Address: listener.LocalAddr().String()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "listen for NTP") {
		t.Fatalf("occupied port did not fail: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Serve(t.Context(), listener); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("listener failure was swallowed: %v", err)
	}
}
