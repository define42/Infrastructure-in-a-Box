//go:build integration

package tftpserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func startServer(t *testing.T, root string) (*Server, netip.AddrPort, context.CancelFunc, <-chan error) {
	t.Helper()
	s, err := New(Config{Address: "127.0.0.1:0", Root: root}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, conn); close(done) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("TFTP serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("TFTP did not shut down")
		}
	})
	return s, address, cancel, done
}

func udpClient(t *testing.T, ip string) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func send(t *testing.T, conn *net.UDPConn, peer netip.AddrPort, packet []byte) {
	t.Helper()
	if err := conn.SetWriteDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.WriteToUDPAddrPort(packet, peer); err != nil {
		t.Fatal(err)
	}
}

func receive(t *testing.T, conn *net.UDPConn) ([]byte, netip.AddrPort) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, maxBlockSize+4)
	n, peer, err := conn.ReadFromUDPAddrPort(buffer)
	if err != nil {
		t.Fatal(err)
	}
	return buffer[:n], peer
}

func ack(block uint16) []byte {
	packet := []byte{0, opAck, 0, 0}
	binary.BigEndian.PutUint16(packet[2:], block)
	return packet
}

func writeBootFile(t *testing.T, root, name string, data []byte) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func download(t *testing.T, listener netip.AddrPort, name string, options ...string) ([]byte, map[string]string, int) {
	t.Helper()
	conn := udpClient(t, "127.0.0.1")
	send(t, conn, listener, rrq(append([]string{name, "octet"}, options...)...))
	blockSize := defaultBlockSize
	negotiated := make(map[string]string)
	var data []byte
	var peer netip.AddrPort
	expected := uint16(1)
	blocks := 0
	for {
		packet, sender := receive(t, conn)
		if !peer.IsValid() {
			peer = sender
		}
		if sender != peer || peer.Port() == listener.Port() {
			t.Fatal("transfer did not use a stable separate TID")
		}
		if len(packet) < 4 {
			t.Fatalf("short response: %v", packet)
		}
		switch binary.BigEndian.Uint16(packet) {
		case opOptionAck:
			fields := strings.Split(string(packet[2:len(packet)-1]), "\x00")
			if len(fields)%2 != 0 {
				t.Fatalf("malformed OACK: %q", packet)
			}
			for i := 0; i < len(fields); i += 2 {
				negotiated[fields[i]] = fields[i+1]
			}
			if value := negotiated["blksize"]; value != "" {
				var err error
				blockSize, err = strconv.Atoi(value)
				if err != nil {
					t.Fatal(err)
				}
			}
			send(t, conn, peer, ack(0))
		case opData:
			block := binary.BigEndian.Uint16(packet[2:])
			if block != expected {
				t.Fatalf("block = %d, want %d", block, expected)
			}
			blocks++
			expected++
			data = append(data, packet[4:]...)
			send(t, conn, peer, ack(block))
			if len(packet)-4 < blockSize {
				return data, negotiated, blocks
			}
		default:
			t.Fatalf("unexpected packet: %q", packet)
		}
	}
}

func TestReadFilesAndNegotiateOptions(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 1, 511, 512, 513, 1024, 4097} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			root := t.TempDir()
			want := bytes.Repeat([]byte{0xa5}, size)
			writeBootFile(t, root, "pxelinux.cfg/default", want)
			_, address, _, _ := startServer(t, root)
			data, _, blocks := download(t, address, "pxelinux.cfg/default")
			if !bytes.Equal(data, want) || blocks != size/defaultBlockSize+1 {
				t.Fatalf("incorrect default transfer: bytes %d, blocks %d", len(data), blocks)
			}
			data, options, blocks := download(t, address, "pxelinux.cfg/default", "blksize", "1024", "tsize", "0", "timeout", "1", "windowsize", "64")
			if !bytes.Equal(data, want) || options["tsize"] != strconv.Itoa(size) || options["blksize"] != "1024" || options["timeout"] != "1" || options["windowsize"] != "" || blocks != size/1024+1 {
				t.Fatalf("incorrect negotiated transfer: bytes %d, options %v, blocks %d", len(data), options, blocks)
			}
		})
	}
}

func TestReadOnlyAndRootConfinement(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	root := filepath.Join(dir, "public")
	writeBootFile(t, root, "bootx64.efi", []byte("boot"))
	writeBootFile(t, dir, "secret", []byte("secret"))
	if err := os.Symlink(filepath.Join(dir, "secret"), filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("bootx64.efi", filepath.Join(root, "inside")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "directory"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, "fifo"), 0600); err != nil {
		t.Fatal(err)
	}
	_, address, _, _ := startServer(t, root)
	for _, tc := range []struct {
		name string
		code uint16
	}{
		{"missing", 1}, {"../secret", 2}, {filepath.Join(dir, "secret"), 2}, {"escape", 2}, {"directory", 2}, {"fifo", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := udpClient(t, "127.0.0.1")
			send(t, conn, address, rrq(tc.name, "octet"))
			packet, _ := receive(t, conn)
			if len(packet) < 5 || binary.BigEndian.Uint16(packet) != opError || binary.BigEndian.Uint16(packet[2:]) != tc.code {
				t.Fatalf("expected error %d, got %q", tc.code, packet)
			}
		})
	}
	conn := udpClient(t, "127.0.0.1")
	request := rrq("uploaded", "octet")
	request[1] = opWrite
	send(t, conn, address, request)
	packet, _ := receive(t, conn)
	if binary.BigEndian.Uint16(packet) != opError || binary.BigEndian.Uint16(packet[2:]) != 2 {
		t.Fatalf("write not rejected: %q", packet)
	}
	if _, err := os.Stat(filepath.Join(root, "uploaded")); !os.IsNotExist(err) {
		t.Fatal("WRQ created a file")
	}
	if data, _, _ := download(t, address, "inside"); string(data) != "boot" {
		t.Fatal("confined symlink could not be downloaded")
	}
}

func TestRetransmissionDuplicateRRQAndWrongTID(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeBootFile(t, root, "boot", []byte("payload"))
	_, address, _, _ := startServer(t, root)
	conn := udpClient(t, "127.0.0.1")
	request := rrq("boot", "octet", "timeout", "1")
	send(t, conn, address, request)
	initial, peer := receive(t, conn)
	send(t, conn, address, request)
	retry, retryPeer := receive(t, conn) // Drop ACK 0: OACK must be retransmitted from the same TID.
	if !bytes.Equal(initial, retry) || peer != retryPeer {
		t.Fatal("duplicate RRQ spawned a second transfer")
	}
	send(t, conn, peer, ack(0))
	data, sender := receive(t, conn)
	if sender != peer || binary.BigEndian.Uint16(data) != opData {
		t.Fatalf("expected DATA: %q", data)
	}
	stranger := udpClient(t, "127.0.0.1")
	send(t, stranger, peer, ack(1))
	wrongTID, _ := receive(t, stranger)
	if binary.BigEndian.Uint16(wrongTID) != opError || binary.BigEndian.Uint16(wrongTID[2:]) != 5 {
		t.Fatalf("wrong TID accepted: %q", wrongTID)
	}
	retry, sender = receive(t, conn) // Neither the stranger's ACK nor the old ACK completed DATA 1.
	if !bytes.Equal(data, retry) || sender != peer {
		t.Fatal("unacknowledged DATA was not retransmitted")
	}
	send(t, conn, peer, ack(1))
}

func TestExchangeIgnoresStaleACKAndTimesOut(t *testing.T) {
	t.Parallel()
	conn := udpClient(t, "127.0.0.1")
	client := udpClient(t, "127.0.0.1")
	peer := client.LocalAddr().(*net.UDPAddr).AddrPort()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	packet := []byte{0, opData, 0, 2, 'x'}
	go func() { done <- exchange(ctx, conn, peer, packet, 2, 50*time.Millisecond) }()
	for range maxAttempts {
		got, server := receive(t, client)
		if !bytes.Equal(got, packet) {
			t.Fatalf("unexpected retry: %q", got)
		}
		send(t, client, server, ack(1))
	}
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("missing ACK did not time out: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("stale ACKs prevented timeout")
	}
}

func TestTransferLimitsAndShutdown(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeBootFile(t, root, "boot", []byte("payload"))
	_, address, cancel, done := startServer(t, root)
	for i := range maxTransfers {
		ip := "127.0.0." + strconv.Itoa(2+i/maxClientTransfers)
		conn := udpClient(t, ip)
		send(t, conn, address, rrq("boot", "octet"))
		packet, _ := receive(t, conn)
		if binary.BigEndian.Uint16(packet) != opData {
			t.Fatalf("transfer %d rejected: %q", i, packet)
		}
		if i == maxClientTransfers-1 {
			extra := udpClient(t, ip)
			send(t, extra, address, rrq("boot", "octet"))
			packet, _ = receive(t, extra)
			if binary.BigEndian.Uint16(packet) != opError {
				t.Fatal("per-client limit exceeded")
			}
		}
	}
	extra := udpClient(t, "127.0.0.100")
	send(t, extra, address, rrq("boot", "octet"))
	packet, _ := receive(t, extra)
	if binary.BigEndian.Uint16(packet) != opError {
		t.Fatal("global transfer limit exceeded")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("active transfers prevented shutdown")
	}
}

func TestServeCreatesRootAndHandlesCancellation(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "new", "root")
	_, address, cancel, done := startServer(t, root)
	conn := udpClient(t, "127.0.0.1")
	send(t, conn, address, rrq("missing", "octet"))
	receive(t, conn)
	if info, err := os.Stat(root); err != nil || !info.IsDir() {
		t.Fatalf("root not created: %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Address: "127.0.0.1:0", Root: root}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, stop := context.WithCancel(t.Context())
	stop()
	if err := s.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCurlInteroperability(t *testing.T) {
	t.Parallel()
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Skip("curl is not installed")
	}
	version, err := exec.CommandContext(t.Context(), curl, "--version").Output()
	if err != nil || !bytes.Contains(version, []byte("tftp")) {
		t.Skip("curl has no TFTP support")
	}
	root := t.TempDir()
	want := bytes.Repeat([]byte("PXE payload\x00"), 1000)
	writeBootFile(t, root, "bootx64.efi", want)
	_, address, _, _ := startServer(t, root)
	for _, options := range [][]string{{"--tftp-no-options"}, {"--tftp-blksize", "8192"}} {
		args := append([]string{"--silent", "--show-error", "--fail", "--max-time", "5", "--noproxy", "*"}, options...)
		args = append(args, "tftp://"+address.String()+"/bootx64.efi")
		got, err := exec.CommandContext(t.Context(), curl, args...).Output()
		if err != nil {
			t.Fatalf("curl %v: %v", options, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("curl received incorrect file contents")
		}
	}
}

func TestBlockNumberRollover(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	// Small negotiated blocks reach the 16-bit rollover without a huge fixture.
	want := make([]byte, 65536*8+3)
	for i := range want {
		want[i] = byte(i % 251)
	}
	writeBootFile(t, root, "image", want)
	_, address, _, _ := startServer(t, root)
	got, _, blocks := download(t, address, "image", "blksize", "8")
	if blocks != 65537 || !bytes.Equal(got, want) {
		t.Fatalf("rollover corrupted transfer: blocks %d, bytes %d", blocks, len(got))
	}
}

func TestRunReportsStartupFailures(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(root, []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Address: "127.0.0.1:0", Root: root}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "TFTP root") {
		t.Fatalf("unusable root accepted: %v", err)
	}
	occupied := udpClient(t, "127.0.0.1")
	s, err = New(Config{Address: occupied.LocalAddr().String(), Root: t.TempDir()}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "listen for TFTP") {
		t.Fatalf("bind failure ignored: %v", err)
	}
}
