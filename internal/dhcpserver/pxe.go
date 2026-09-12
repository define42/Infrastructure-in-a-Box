package dhcpserver

import (
	"encoding/binary"
	"net"

	"github.com/insomniacslk/dhcp/dhcpv4"
)

func (s *Server) bootOptions(request *dhcpv4.DHCPv4) []dhcpv4.Modifier {
	// RFC 4578 option 93 contains a nonempty list of 16-bit network-order
	// architectures. Choose the first supported architecture in the client's list.
	architectures := request.Options.Get(dhcpv4.OptionClientSystemArchitectureType)
	if len(architectures) == 0 || len(architectures)%2 != 0 {
		return nil
	}
	for i := 0; i < len(architectures); i += 2 {
		filename := ""
		switch binary.BigEndian.Uint16(architectures[i : i+2]) {
		case 0:
			filename = "pxelinux.0"
		case 7, 9:
			filename = "bootx64.efi"
		}
		if filename == "" {
			continue
		}
		return []dhcpv4.Modifier{
			dhcpv4.WithServerIP(net.IP(s.config.ServerIP.AsSlice())),
			dhcpv4.WithOption(dhcpv4.OptTFTPServerName(s.config.ServerIP.String())),
			dhcpv4.WithOption(dhcpv4.OptBootFileName(filename)),
			dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionClientSystemArchitectureType, architectures[i:i+2])),
			func(reply *dhcpv4.DHCPv4) { reply.BootFileName = filename },
		}
	}
	return nil
}
