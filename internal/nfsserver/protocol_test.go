package nfsserver

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

func TestRecordBoundsAndFragments(t *testing.T) {
	t.Parallel()
	var record bytes.Buffer
	for _, item := range []struct {
		marker uint32
		data   string
	}{{2, "ab"}, {0x80000002, "cd"}} {
		if err := binary.Write(&record, binary.BigEndian, item.marker); err != nil {
			t.Fatal(err)
		}
		record.WriteString(item.data)
	}
	got, err := readRecord(&record)
	if err != nil || string(got) != "abcd" {
		t.Fatalf("fragments: %q %v", got, err)
	}
	record.Reset()
	if err := binary.Write(&record, binary.BigEndian, uint32(0x80000000|maxRecord+1)); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecord(&record); err == nil {
		t.Fatal("accepted oversized record")
	}
	if _, err := readRecord(bytes.NewReader([]byte{0x80, 0, 0, 4, 1})); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated record: %v", err)
	}
}

func TestNFSDisabledWaitsForCancellation(t *testing.T) {
	t.Parallel()
	server, err := New(Config{Address: "127.0.0.1:0"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() { result <- server.Run(ctx) }()
	select {
	case err := <-result:
		t.Fatalf("disabled runner exited prematurely: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("disabled runner did not exit")
	}
}

func FuzzNFSOperationLengths(f *testing.F) {
	for _, seed := range [][]byte{{0, 0, 0, 22, 255, 255, 255, 255}, {0, 0, 0, 9, 255, 255, 255, 255}, {0, 0, 0, 34}, {0, 0, 0, 18}, nil} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxRecord {
			return
		}
		c := cursor{data: data}
		_ = c.operation()
		if c.offset > len(data) {
			t.Fatal("parser read beyond request")
		}
	})
}
