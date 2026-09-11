package ldapserver

import (
	"errors"
	"io"
	"net"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

const (
	maxMessageSize = 64 * 1024
	maxBERDepth    = 32
	maxBERNodes    = 4096
)

var errMalformedMessage = errors.New("malformed or oversized LDAP message")

// readMessage bounds allocation, nesting, and node count before BER decoding.
// LDAP requires definite lengths, so indefinite lengths and high tags are rejected.
func readMessage(reader io.Reader) (*ber.Packet, error) {
	header := make([]byte, 2, 6)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, err
	}
	if header[0] != 0x30 {
		return nil, errMalformedMessage
	}
	length := int(header[1])
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 || n > 4 {
			return nil, errMalformedMessage
		}
		header = header[:2+n]
		if _, err := io.ReadFull(reader, header[2:]); err != nil {
			return nil, err
		}
		length = 0
		for _, b := range header[2:] {
			length = length<<8 | int(b)
		}
	}
	if length <= 0 || length > maxMessageSize-len(header) {
		return nil, errMalformedMessage
	}
	data := make([]byte, len(header)+length)
	copy(data, header)
	if _, err := io.ReadFull(reader, data[len(header):]); err != nil {
		return nil, err
	}
	nodes := 0
	if err := validateBER(data, 0, &nodes); err != nil {
		return nil, err
	}
	return ber.DecodePacketErr(data)
}

func validateBER(data []byte, depth int, nodes *int) error {
	if depth >= maxBERDepth {
		return errMalformedMessage
	}
	for len(data) != 0 {
		*nodes++
		if *nodes > maxBERNodes || len(data) < 2 || data[0]&0x1f == 0x1f {
			return errMalformedMessage
		}
		tag, length, header := data[0], int(data[1]), 2
		if length&0x80 != 0 {
			n := length & 0x7f
			if n == 0 || n > 4 || len(data) < 2+n {
				return errMalformedMessage
			}
			header += n
			length = 0
			for _, b := range data[2:header] {
				length = length<<8 | int(b)
			}
		}
		if length < 0 || length > len(data)-header {
			return errMalformedMessage
		}
		if tag&0x20 != 0 {
			if err := validateBER(data[header:header+length], depth+1, nodes); err != nil {
				return err
			}
		} else if tag&0xc0 == 0 {
			// Reject irrelevant ASN.1 types before passing them to the general decoder.
			switch ber.Tag(tag & 0x1f) {
			case ber.TagBoolean:
				if length != 1 {
					return errMalformedMessage
				}
			case ber.TagInteger, ber.TagEnumerated:
				if length < 1 || length > 4 {
					return errMalformedMessage
				}
			case ber.TagOctetString, ber.TagNULL:
			default:
				return errMalformedMessage
			}
		}
		data = data[header+length:]
	}
	return nil
}

func requestEnvelope(packet *ber.Packet) (int64, *ber.Packet, bool) {
	if !isPacket(packet, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) || len(packet.Children) < 2 || len(packet.Children) > 3 {
		return 0, nil, false
	}
	id, ok := integer(packet.Children[0], ber.TagInteger)
	op := packet.Children[1]
	if !ok || id <= 0 || id > 2147483647 || op.ClassType != ber.ClassApplication {
		return 0, nil, false
	}
	return id, op, true
}

func validateControls(packet *ber.Packet) uint16 {
	if len(packet.Children) == 2 {
		return ldap.LDAPResultSuccess
	}
	controls := packet.Children[2]
	if !isPacket(controls, ber.ClassContext, ber.TypeConstructed, 0) || len(controls.Children) == 0 {
		return ldap.LDAPResultProtocolError
	}
	for _, control := range controls.Children {
		if !isPacket(control, ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) || len(control.Children) < 1 || len(control.Children) > 3 || !octetString(control.Children[0]) {
			return ldap.LDAPResultProtocolError
		}
		critical := false
		i := 1
		if len(control.Children) > i && isPacket(control.Children[i], ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean) {
			critical, _ = control.Children[i].Value.(bool)
			i++
		}
		if len(control.Children) > i {
			if !octetString(control.Children[i]) {
				return ldap.LDAPResultProtocolError
			}
			i++
		}
		if i != len(control.Children) {
			return ldap.LDAPResultProtocolError
		}
		if critical {
			return ldap.LDAPResultUnavailableCriticalExtension
		}
		if control.Children[0].Data.String() == ldap.ControlTypePaging {
			return ldap.LDAPResultUnwillingToPerform
		}
	}
	return ldap.LDAPResultSuccess
}

func responseType(tag ber.Tag) (ber.Tag, bool) {
	switch tag {
	case ldap.ApplicationBindRequest, ldap.ApplicationModifyRequest, ldap.ApplicationAddRequest, ldap.ApplicationDelRequest, ldap.ApplicationModifyDNRequest, ldap.ApplicationCompareRequest, ldap.ApplicationExtendedRequest:
		return tag + 1, true
	case ldap.ApplicationSearchRequest:
		return ldap.ApplicationSearchResultDone, true
	default:
		return 0, false
	}
}

func isPacket(p *ber.Packet, class ber.Class, kind ber.Type, tag ber.Tag) bool {
	return p != nil && p.ClassType == class && p.TagType == kind && p.Tag == tag
}

func octetString(p *ber.Packet) bool {
	return isPacket(p, ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString)
}

func integer(p *ber.Packet, tag ber.Tag) (int64, bool) {
	if !isPacket(p, ber.ClassUniversal, ber.TypePrimitive, tag) {
		return 0, false
	}
	v, ok := p.Value.(int64)
	return v, ok
}

func textPacket(value string) *ber.Packet {
	return ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, value, "")
}

func writeResult(conn net.Conn, id int64, tag ber.Tag, code uint16, message string) error {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "")
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), ""))
	op.AppendChild(textPacket(""))
	op.AppendChild(textPacket(message))
	return writeMessage(conn, id, op)
}

func writeMessage(conn net.Conn, id int64, op *ber.Packet) error {
	return writeMessageUntil(conn, id, op, time.Now().Add(ioTimeout))
}

func writeMessageUntil(conn net.Conn, id int64, op *ber.Packet, deadline time.Time) error {
	packet := ber.NewSequence("")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, ""))
	packet.AppendChild(op)
	if ioDeadline := time.Now().Add(ioTimeout); ioDeadline.Before(deadline) {
		deadline = ioDeadline
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	data := packet.Bytes()
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
