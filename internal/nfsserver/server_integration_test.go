//go:build integration

package nfsserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

// Wire fixtures encode RFC 7530 requests independently of libnfs-go's codec.
func words(values ...uint32) []byte {
	result := make([]byte, 4*len(values))
	for i, v := range values {
		binary.BigEndian.PutUint32(result[i*4:], v)
	}
	return result
}
func opaque(value []byte) []byte {
	b := append(words(uint32(len(value))), value...)
	return append(b, make([]byte, (4-len(value)%4)%4)...)
}
func join(values ...[]byte) []byte { return bytes.Join(values, nil) }
func lookup(name string) []byte    { return join(words(15), opaque([]byte(name))) }
func compound(ops ...[]byte) []byte {
	return join(words(42, 0, 2, 100003, 4, 1, 0, 0, 0, 0), opaque(nil), words(0, uint32(len(ops))), join(ops...))
}
func openOp(name string, access uint32, create bool) []byte {
	how := words(0)
	if create {
		how = words(1, 0, 2, 0, 2, 4, 0644)
	} // UNCHECKED, mode attribute 33
	return join(words(18, 1, access, 0, 0, 1), opaque([]byte("test-owner")), how, words(0), opaque([]byte(name)))
}

func loopbackServer(t *testing.T) (net.Listener, context.CancelFunc, <-chan error, string, string) {
	t.Helper()
	data, software := t.TempDir(), t.TempDir()
	for _, dir := range []string{data, software} {
		if err := os.WriteFile(filepath.Join(dir, "hello"), []byte("hello world"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := New(Config{Address: "127.0.0.1:0", Shares: []config.NFSShare{{Name: "data", Path: data}, {Name: "software", Path: software, ReadOnly: true}}}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
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
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("NFS did not shut down")
		}
	})
	return listener, cancel, done, data, software
}
func connect(t *testing.T, listener net.Listener) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return conn
}
func exchange(t *testing.T, conn net.Conn, request []byte) []byte {
	t.Helper()
	if _, err := conn.Write(join(words(uint32(len(request))|0x80000000), request)); err != nil {
		t.Fatal(err)
	}
	var marker [4]byte
	if _, err := io.ReadFull(conn, marker[:]); err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(marker[:])
	if size&0x80000000 == 0 || size&0x7fffffff > maxRecord {
		t.Fatalf("invalid RPC record %x", size)
	}
	response := make([]byte, size&0x7fffffff)
	if _, err := io.ReadFull(conn, response); err != nil {
		t.Fatal(err)
	}
	if len(response) < 24 || !bytes.Equal(response[:24], words(42, 1, 0, 0, 0, 0)) {
		t.Fatalf("RPC response: %x", response)
	}
	return response[24:]
}
func checkStatus(t *testing.T, reply []byte, status, count uint32) []byte {
	t.Helper()
	if len(reply) < 12 || !bytes.Equal(reply[:12], words(status, 0, count)) {
		t.Fatalf("compound response: %x, want status %d count %d", reply, status, count)
	}
	return reply[12:]
}
func openWire(t *testing.T, conn net.Conn, share, name string, access uint32, create bool) ([]byte, []byte) {
	t.Helper()
	result := checkStatus(t, exchange(t, conn, compound(words(24), lookup(share), openOp(name, access, create), words(10))), 0, 4)
	if len(result) < 80 {
		t.Fatalf("short OPEN response %x", result)
	}
	state := bytes.Clone(result[24:40])
	// OPEN result is 8 + state(16) + change_info(20) + flags(4) + attrs bitmap + delegation(4).
	// Decode the variable bitmap before the following GETFH operation.
	bitmapCount := int(binary.BigEndian.Uint32(result[64:68]))
	getfh := 72 + bitmapCount*4
	if len(result) < getfh+12 {
		t.Fatalf("missing GETFH: %x", result)
	}
	fhLen := int(binary.BigEndian.Uint32(result[getfh+8 : getfh+12]))
	fh := bytes.Clone(result[getfh+12 : getfh+12+fhLen])
	return state, fh
}

func TestNFSWireReadWriteAndReadonly(t *testing.T) {
	t.Parallel()
	listener, _, _, data, software := loopbackServer(t)
	conn := connect(t, listener)
	state, handle := openWire(t, conn, "data", "new", 3, true)
	putfh := join(words(22), opaque(handle))
	write := join(words(38), state, words(0, 0, 2), opaque([]byte("persisted")))
	checkStatus(t, exchange(t, conn, compound(putfh, write)), 0, 2)
	read := join(words(25), state, words(0, 0, 100))
	reply := checkStatus(t, exchange(t, conn, compound(putfh, read)), 0, 2)
	if !bytes.Contains(reply, []byte("persisted")) {
		t.Fatalf("READ: %x", reply)
	}
	checkStatus(t, exchange(t, conn, compound(putfh, join(words(4, 1), state))), 0, 2)
	content, err := os.ReadFile(filepath.Join(data, "new"))
	if err != nil || string(content) != "persisted" {
		t.Fatalf("disk content %q %v", content, err)
	}
	roState, roHandle := openWire(t, conn, "software", "hello", 1, false)
	roPut := join(words(22), opaque(roHandle))
	checkStatus(t, exchange(t, conn, compound(roPut, join(words(25), roState, words(0, 0, 100)))), 0, 2)
	checkStatus(t, exchange(t, conn, compound(roPut, join(words(38), roState, words(0, 0, 2), opaque([]byte("bad"))))), 30, 2)
	checkStatus(t, exchange(t, conn, compound(words(24), lookup("software"), openOp("hello", 2, false))), 30, 3)
	checkStatus(t, exchange(t, conn, compound(words(24), lookup("software"), openOp("created", 3, true))), 30, 3)
	content, err = os.ReadFile(filepath.Join(software, "hello"))
	if err != nil || string(content) != "hello world" {
		t.Fatalf("readonly file changed %q %v", content, err)
	}
}

func TestNFSCompoundStopsOnFailure(t *testing.T) {
	t.Parallel()
	listener, _, _, data, _ := loopbackServer(t)
	conn := connect(t, listener)
	checkStatus(t, exchange(t, conn, compound(words(24), lookup("missing"), lookup("data"), openOp("must-not-exist", 3, true))), 2, 2)
	if _, err := os.Stat(filepath.Join(data, "must-not-exist")); !os.IsNotExist(err) {
		t.Fatalf("later compound operation executed: %v", err)
	}
	// NFSv4.1 negotiation must explicitly fail, so clients can select 4.0.
	request := compound()
	binary.BigEndian.PutUint32(request[44:48], 1)
	checkStatus(t, exchange(t, conn, request), 10021, 0)
}

func TestNFSShutdownClosesIdleClients(t *testing.T) {
	t.Parallel()
	listener, cancel, _, _, _ := loopbackServer(t)
	conn := connect(t, listener)
	exchange(t, conn, join(words(42, 0, 2, 100003, 4, 0, 0, 0, 0, 0)))
	cancel()
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("connection remains open")
	}
}

func TestNFSDirectoryAndExistingCreate(t *testing.T) {
	t.Parallel()
	listener, _, _, data, _ := loopbackServer(t)
	conn := connect(t, listener)
	// READDIR requests type + fileid attributes for the virtual root.
	result := checkStatus(t, exchange(t, conn, compound(words(24), words(26, 0, 0, 0, 0, 4096, 8192, 1, 2|(1<<20)))), 0, 2)
	if !bytes.Contains(result, []byte("data")) || !bytes.Contains(result, []byte("software")) {
		t.Fatalf("READDIR: %x", result)
	}
	state, handle := openWire(t, conn, "data", "hello", 3, true)
	content, err := os.ReadFile(filepath.Join(data, "hello"))
	if err != nil || string(content) != "hello world" {
		t.Fatalf("OPEN(create) truncated existing file: %q %v", content, err)
	}
	checkStatus(t, exchange(t, conn, compound(join(words(22), opaque(handle)), join(words(4, 1), state))), 0, 2)
}
