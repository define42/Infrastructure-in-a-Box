package ldapserver

import (
	"bytes"
	"testing"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

func TestReadMessage(t *testing.T) {
	t.Parallel()
	packet := ber.NewSequence("")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, ""))
	bind := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindRequest, nil, "")
	bind.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 3, ""))
	bind.AppendChild(textPacket("uid=johndoe,ou=users,dc=home,dc=arpa"))
	bind.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, "password", ""))
	packet.AppendChild(bind)
	decoded, err := readMessage(bytes.NewReader(packet.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	id, op, ok := requestEnvelope(decoded)
	if !ok || id != 1 || op.Tag != ldap.ApplicationBindRequest || op.Children[2].Data.String() != "password" {
		t.Fatal("valid bind did not survive BER framing")
	}
}

func TestReadMessageRejectsMalformedFrames(t *testing.T) {
	t.Parallel()
	deep := textPacket("x")
	for range maxBERDepth + 1 {
		parent := ber.NewSequence("")
		parent.AppendChild(deep)
		deep = parent
	}
	wide := ber.NewSequence("")
	for range maxBERNodes + 1 {
		wide.AppendChild(textPacket(""))
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{name: "indefinite", data: []byte{0x30, 0x80, 0, 0}},
		{name: "oversized", data: []byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff}},
		{name: "truncated", data: []byte{0x30, 3, 4, 1}},
		{name: "inner length overflow", data: []byte{0x30, 6, 4, 0x84, 0xff, 0xff, 0xff, 0xff}},
		{name: "constructed length overflow", data: []byte{0x30, 9, 2, 1, 1, 0x60, 0x84, 0xff, 0xff, 0xff, 0xfc}},
		{name: "integer overflow", data: []byte{0x30, 7, 2, 5, 0, 0, 0, 0, 1}},
		{name: "invalid boolean", data: []byte{0x30, 2, 1, 0}},
		{name: "high tag", data: []byte{0x30, 3, 0x1f, 1, 0}},
		{name: "nesting", data: deep.Bytes()},
		{name: "node limit", data: wide.Bytes()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := readMessage(bytes.NewReader(tc.data)); err == nil {
				t.Fatal("malformed frame accepted")
			}
		})
	}
}

func FuzzReadMessage(f *testing.F) {
	f.Add([]byte{0x30, 5, 2, 1, 1, 0x42, 0})
	f.Add([]byte{0x30, 6, 4, 0x84, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = readMessage(bytes.NewReader(data))
	})
}
