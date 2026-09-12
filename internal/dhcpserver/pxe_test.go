package dhcpserver

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func architectureOption(values ...uint16) dhcpv4.Modifier {
	raw := make([]byte, 2*len(values))
	for i, value := range values {
		binary.BigEndian.PutUint16(raw[2*i:], value)
	}
	return dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, raw))
}

func TestPXEBootArchitecture(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		arch     []byte
		want     string
		selected []byte
	}{
		{"BIOS", []byte{0, 0}, "pxelinux.0", []byte{0, 0}},
		{"EFI BC", []byte{0, 7}, "bootx64.efi", []byte{0, 7}},
		{"EFI x64", []byte{0, 9}, "bootx64.efi", []byte{0, 9}},
		{"EFI IA32", []byte{0, 6}, "", nil},
		{"EFI ARM64", []byte{0, 11}, "", nil},
		{"unknown", []byte{255, 255}, "", nil},
		{"missing", nil, "", nil},
		{"empty", []byte{}, "", nil},
		{"truncated", []byte{0}, "", nil},
		{"odd length", []byte{0, 0, 9}, "", nil},
		{"network byte order", []byte{9, 0}, "", nil},
		{"supported fallback", []byte{0, 6, 0, 9}, "bootx64.efi", []byte{0, 9}},
		{"client order", []byte{0, 0, 0, 9}, "pxelinux.0", []byte{0, 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := testServer(t, "")
			var mods []dhcpv4.Modifier
			if tc.arch != nil {
				mods = append(mods, dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, tc.arch)))
			}
			// No parameter request list: firmware still needs boot fields in OFFER/ACK.
			offer := handle(t, s, packet(t, dhcpv4.MessageTypeDiscover, 1, mods...), dhcpv4.MessageTypeOffer)
			mods = append(mods, dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(offer.YourIPAddr)),
				dhcpv4.WithOption(dhcpv4.OptServerIdentifier(offer.ServerIdentifier())))
			ack := handle(t, s, packet(t, dhcpv4.MessageTypeRequest, 1, mods...), dhcpv4.MessageTypeAck)
			for _, reply := range []*dhcpv4.DHCPv4{offer, ack} {
				if reply.BootFileName != tc.want || reply.BootFileNameOption() != tc.want {
					t.Fatalf("wrong boot file: %q / %q", reply.BootFileName, reply.BootFileNameOption())
				}
				if tc.want == "" {
					if ipv4(reply.ServerIPAddr).IsValid() || reply.TFTPServerName() != "" {
						t.Fatal("unsupported client received PXE server")
					}
				} else if ipv4(reply.ServerIPAddr) != s.config.ServerIP || reply.TFTPServerName() != s.config.ServerIP.String() {
					t.Fatal("boot server does not point to this server")
				}
				if !bytes.Equal(reply.Options.Get(dhcpv4.OptionClientSystemArchitectureType), tc.selected) {
					t.Fatal("wrong selected architecture")
				}
			}
		})
	}
}

func TestPXEExcludedFromNAKAndInform(t *testing.T) {
	t.Parallel()
	s, _ := testServer(t, "")
	nak := handle(t, s, packet(t, dhcpv4.MessageTypeRequest, 1, architectureOption(9),
		dhcpv4.WithOption(dhcpv4.OptRequestedIPAddress(net.ParseIP("192.168.50.99")))), dhcpv4.MessageTypeNak)
	inform := handle(t, s, packet(t, dhcpv4.MessageTypeInform, 1, architectureOption(0),
		dhcpv4.WithClientIP(net.ParseIP("192.168.50.100"))), dhcpv4.MessageTypeAck)
	for _, reply := range []*dhcpv4.DHCPv4{nak, inform} {
		if reply.BootFileName != "" || reply.BootFileNameOption() != "" || reply.TFTPServerName() != "" {
			t.Fatal("boot instructions without address allocation")
		}
	}
}
