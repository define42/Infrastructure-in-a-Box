package dhcpserver

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

// Invalid names deliberately remain nonempty so a renewal can clear an old
// registration. An absent name, in contrast, preserves the previous name.
func clientHostname(request *dhcpv4.DHCPv4) string {
	raw := request.Options.Get(dhcpv4.OptionFQDN)
	if raw == nil {
		return request.HostName()
	}
	if len(raw) < 3 || raw[0]&0xf0 != 0 || raw[0]&8 != 0 {
		return "\x00"
	}
	if raw[0]&4 == 0 {
		return string(raw[3:])
	}
	// RFC 4702 wire names cannot contain compression pointers.
	var labels []string
	for remaining := raw[3:]; len(remaining) > 0; {
		n := int(remaining[0])
		remaining = remaining[1:]
		if n == 0 {
			if len(remaining) != 0 {
				return "\x00"
			}
			return strings.Join(labels, ".")
		}
		if n > 63 || n > len(remaining) {
			return "\x00"
		}
		labels = append(labels, string(remaining[:n]))
		remaining = remaining[n:]
		if len(remaining) == 0 { // A partial name need not have a root label.
			return strings.Join(labels, ".")
		}
	}
	return ""
}

func fallbackHostname(clientID string) string {
	if clientID == "" {
		return ""
	}
	name := "host-" + strings.ReplaceAll(clientID, ":", "-")
	if len(name) <= 63 {
		return name
	}
	// Hash long identities instead of truncating away distinguishing bytes.
	digest := sha256.Sum256([]byte(clientID))
	return "host-sha256-" + hex.EncodeToString(digest[:24])
}

func fqdnReply(request *dhcpv4.DHCPv4, hostname string) []byte {
	raw := request.Options.Get(dhcpv4.OptionFQDN)
	if len(raw) < 3 {
		return nil
	}
	flags := raw[0] & 4 // Echo the client's E (wire encoding) bit.
	if hostname == "" {
		flags |= 8 // No DNS registration was made.
	} else {
		flags |= 1 // The server owns the forward registration.
	}
	if flags&1 != raw[0]&1 {
		flags |= 2 // Override the client's requested S bit.
	}
	result := []byte{flags, 0, 0}
	if flags&4 == 0 {
		return append(result, strings.TrimSuffix(hostname, ".")...)
	}
	if hostname != "" {
		for _, label := range strings.Split(strings.TrimSuffix(hostname, "."), ".") {
			result = append(result, byte(len(label)))
			result = append(result, label...)
		}
	}
	return append(result, 0)
}
