package ntpserver

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

func TestResponse(t *testing.T) {
	t.Parallel()
	for _, version := range []byte{3, 4} {
		request := bytes.Repeat([]byte{0xff}, 48)
		request[0] = 0xc0 | version<<3 | 3 // An unsynchronized client is valid.
		request[2] = 6
		original := bytes.Clone(request)
		reply, ok := response(request, time.Unix(0, 500_000_000), time.Unix(1, 250_000_000))
		if !ok || reply[0] != version<<3|4 || reply[1] != 10 || reply[2] != 6 || int8(reply[3]) != -10 {
			t.Fatalf("invalid server header: %x", reply[:4])
		}
		if !bytes.Equal(reply[4:8], make([]byte, 4)) || binary.BigEndian.Uint32(reply[8:12]) != 66 {
			t.Fatalf("invalid root delay/dispersion: %x", reply[4:12])
		}
		if !bytes.Equal(reply[12:16], []byte{127, 127, 1, 0}) {
			t.Fatalf("invalid local reference ID: %x", reply[12:16])
		}
		if !bytes.Equal(reply[24:32], request[40:48]) {
			t.Fatal("origin must copy all eight client transmit bytes")
		}
		// Known NTP wire values, independent of the encoder under test.
		if binary.BigEndian.Uint64(reply[16:24]) != 0x83aa7e8080000000 ||
			binary.BigEndian.Uint64(reply[32:40]) != 0x83aa7e8080000000 ||
			binary.BigEndian.Uint64(reply[40:48]) != 0x83aa7e8140000000 {
			t.Fatalf("incorrect reference, receive or transmit timestamp: %x", reply[16:])
		}
		if !bytes.Equal(request, original) {
			t.Fatal("response modified the request")
		}
	}
}

func TestResponseRejectsUnsupportedPackets(t *testing.T) {
	t.Parallel()
	for _, size := range []int{0, 1, 47, 49, 68, 1024} {
		request := make([]byte, size)
		if size > 0 {
			request[0] = 0x23
		}
		if _, ok := response(request, time.Now(), time.Now()); ok {
			t.Errorf("accepted packet length %d", size)
		}
	}
	for header := range 256 {
		request := make([]byte, 48)
		request[0] = byte(header)
		_, ok := response(request, time.Now(), time.Now())
		version, mode := header>>3&7, header&7
		want := (version == 3 || version == 4) && mode == 3
		if ok != want {
			t.Errorf("header %#x accepted = %v, want %v", header, ok, want)
		}
	}
}

func TestTimestampEraRollover(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		seconds int64
		nanos   int64
		want    uint64
	}{
		{name: "before Unix epoch", seconds: -1, nanos: 0, want: 0x83aa7e7f00000000},
		{name: "end of era zero", seconds: 2_085_978_495, nanos: 999_999_999, want: 0xfffffffffffffffb},
		{name: "start of era one", seconds: 2_085_978_496, nanos: 0, want: 0},
		{name: "fraction in era one", seconds: 2_085_978_497, nanos: 500_000_000, want: 0x0000000180000000},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var wire [8]byte
			putTimestamp(wire[:], time.Unix(tc.seconds, tc.nanos))
			if got := binary.BigEndian.Uint64(wire[:]); got != tc.want {
				t.Errorf("timestamp(%d, %d) = %#x, want %#x", tc.seconds, tc.nanos, got, tc.want)
			}
		})
	}
}

func FuzzResponse(f *testing.F) {
	f.Add([]byte{})
	request := make([]byte, 48)
	request[0] = 0x23
	f.Add(request)
	f.Fuzz(func(t *testing.T, request []byte) {
		reply, ok := response(request, time.Unix(0, 0), time.Unix(1, 0))
		if ok && (len(request) != len(reply) || !bytes.Equal(reply[24:32], request[40:48])) {
			t.Fatal("response must not amplify requests and must preserve origin")
		}
	})
}
