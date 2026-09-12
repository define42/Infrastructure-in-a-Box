package tftpserver

import (
	"bytes"
	"testing"
	"time"
)

func rrq(fields ...string) []byte {
	packet := []byte{0, opRead}
	for _, field := range fields {
		packet = append(packet, field...)
		packet = append(packet, 0)
	}
	return packet
}

func TestParseRequest(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		packet []byte
		code   uint16
	}{
		{"short", []byte{0, opRead}, 4},
		{"missing terminator", []byte{0, opRead, 'x'}, 4},
		{"missing mode", rrq("bootx64.efi"), 4},
		{"oversized", rrq(string(bytes.Repeat([]byte("x"), 510)), "octet"), 4},
		{"absolute", rrq("/etc/passwd", "octet"), 2},
		{"parent", rrq("../secret", "octet"), 2},
		{"nested parent", rrq("boot/../../secret", "octet"), 2},
		{"backslash", rrq(`boot\..\secret`, "octet"), 2},
		{"empty filename", rrq("", "octet"), 2},
		{"root", rrq(".", "octet"), 2},
		{"mail", rrq("boot", "mail"), 4},
		{"netascii", rrq("boot", "netascii"), 4},
		{"incomplete option", rrq("boot", "octet", "blksize"), 4},
		{"duplicate option", rrq("boot", "octet", "blksize", "512", "BLKSIZE", "1024"), 8},
		{"empty option", rrq("boot", "octet", "", "512"), 8},
		{"small block", rrq("boot", "octet", "blksize", "7"), 8},
		{"large block", rrq("boot", "octet", "blksize", "65465"), 8},
		{"negative block", rrq("boot", "octet", "blksize", "-1"), 8},
		{"timeout zero", rrq("boot", "octet", "timeout", "0"), 8},
		{"timeout overflow", rrq("boot", "octet", "timeout", "256"), 8},
		{"nonzero tsize", rrq("boot", "octet", "tsize", "1"), 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRequest(tc.packet)
			if err == nil || err.code != tc.code {
				t.Fatalf("parse error = %v, want code %d", err, tc.code)
			}
		})
	}
	request, err := parseRequest(rrq("pxelinux.cfg/default", "OCTET", "BlKsIzE", "65464", "timeout", "2", "tsize", "0", "windowsize", "32"))
	if err != nil {
		t.Fatal(err)
	}
	if request.blockSize != maxBlockSize || request.timeout != 2*time.Second {
		t.Fatalf("wrong negotiated settings: %+v", request)
	}
	want := []byte("\x00\x06blksize\x001468\x00timeout\x002\x00tsize\x001234\x00")
	if !bytes.Equal(request.optionAck(1234), want) {
		t.Fatalf("OACK = %q, want %q", request.optionAck(1234), want)
	}
	request, err = parseRequest(rrq("boot", "octet", "unknown", "yes"))
	if err != nil || request.optionAck(1) != nil || request.blockSize != defaultBlockSize {
		t.Fatal("unknown option did not fall back to standard TFTP")
	}
}

func FuzzParseRequest(f *testing.F) {
	f.Add(rrq("bootx64.efi", "octet"))
	f.Add(rrq("pxelinux.0", "octet", "blksize", "1468", "tsize", "0"))
	f.Fuzz(func(t *testing.T, packet []byte) {
		request, err := parseRequest(packet)
		if err == nil && (request.blockSize < 8 || request.blockSize > maxBlockSize || request.timeout < time.Second || request.timeout > 255*time.Second) {
			t.Fatalf("invalid negotiated settings: %+v", request)
		}
	})
}
