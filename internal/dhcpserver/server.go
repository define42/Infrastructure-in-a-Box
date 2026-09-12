// Package dhcpserver serves a single IPv4 subnet and registers acknowledged
// client names through its shared lease manager.
package dhcpserver

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
)

// Config describes the subnet and options advertised to clients.
type Config struct {
	Interface     string
	Address       string
	ServerIP      netip.Addr
	Subnet        netip.Prefix
	Router        netip.Addr
	Domain        string
	LeaseDuration time.Duration
}

// Server owns the DHCP transport; lease state is shared with DNS.
type Server struct {
	config Config
	leases *lease.Manager
	logger *slog.Logger
}

func New(config Config, leases *lease.Manager, logger *slog.Logger) (*Server, error) {
	if leases == nil || logger == nil {
		return nil, errors.New("lease manager and logger are required")
	}
	if !config.ServerIP.Is4() || !config.Subnet.IsValid() || !config.Subnet.Contains(config.ServerIP) {
		return nil, errors.New("server IPv4 address must belong to the subnet")
	}
	if config.LeaseDuration < time.Minute || config.LeaseDuration > dhcpv4.MaxLeaseTime {
		return nil, errors.New("lease duration must be between one minute and the DHCP maximum")
	}
	config.Domain = strings.ToLower(strings.TrimSuffix(config.Domain, "."))
	return &Server{config: config, leases: leases, logger: logger}, nil
}

// Run binds an interface-specific, broadcast-capable socket until cancellation.
func (s *Server) Run(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp4", s.config.Address)
	if err != nil {
		return fmt.Errorf("resolve DHCP listener: %w", err)
	}
	conn, err := server4.NewIPv4UDPConn(s.config.Interface, addr)
	if err != nil {
		return fmt.Errorf("listen for DHCP: %w", err)
	}
	return s.Serve(ctx, conn)
}

// Serve takes ownership of conn. Requests are processed serially to bound work
// and ensure all lease writes have completed when shutdown returns.
func (s *Server) Serve(ctx context.Context, conn net.PacketConn) error {
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		s.closeConn(conn)
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
		s.closeConn(conn)
	}()
	s.logger.Info("DHCP listening", "address", conn.LocalAddr(), "interface", s.config.Interface)
	buf := make([]byte, 65535)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read DHCP packet: %w", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		request, err := dhcpv4.FromBytes(buf[:n])
		if err != nil {
			s.logger.Debug("invalid DHCP packet", "error", err)
			continue
		}
		reply, err := s.Handle(request)
		if err != nil {
			s.logger.Error("handle DHCP packet", "error", err)
			continue
		}
		if reply == nil {
			continue
		}
		if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return fmt.Errorf("set DHCP write deadline: %w", err)
		}
		if _, err := conn.WriteTo(reply.ToBytes(), replyAddress(request, reply)); err != nil && ctx.Err() == nil {
			s.logger.Error("send DHCP reply", "error", err)
		}
	}
}

func (s *Server) closeConn(conn net.PacketConn) {
	if err := conn.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logger.Error("close DHCP listener", "error", err)
	}
}

// Handle processes a decoded request. A nil reply means no response is needed.
// Storage failures return errors instead of acknowledging an unrecorded lease.
func (s *Server) Handle(request *dhcpv4.DHCPv4) (*dhcpv4.DHCPv4, error) {
	if request == nil || request.OpCode != dhcpv4.OpcodeBootRequest || request.HopCount > 16 {
		return nil, nil
	}
	for _, code := range []dhcpv4.OptionCode{dhcpv4.OptionRequestedIPAddress, dhcpv4.OptionServerIdentifier} {
		if raw := request.Options.Get(code); raw != nil && len(raw) != 4 {
			return nil, nil
		}
	}
	if len(request.Options.Get(dhcpv4.OptionDHCPMessageType)) != 1 {
		return nil, nil
	}
	clientID := clientIdentifier(request)
	if clientID == "" {
		return nil, nil
	}
	if relay := ipv4(request.GatewayIPAddr); relay.IsValid() && !s.config.Subnet.Contains(relay) {
		return nil, nil
	}
	serverID := ipv4(request.ServerIdentifier())
	if serverID.IsValid() && serverID != s.config.ServerIP {
		return nil, nil
	}
	requested := ipv4(request.RequestedIPAddress())
	current := ipv4(request.ClientIPAddr)
	switch request.MessageType() {
	case dhcpv4.MessageTypeDiscover:
		if current.IsValid() || serverID.IsValid() {
			return nil, nil
		}
		allocation, err := s.leases.OfferWithFallback(
			clientID,
			requested,
			clientHostname(request),
			fallbackHostname(clientID),
		)
		if errors.Is(err, lease.ErrPoolExhausted) {
			s.logger.Warn("DHCP pool exhausted")
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("offer lease: %w", err)
		}
		return s.reply(request, dhcpv4.MessageTypeOffer, &allocation)
	case dhcpv4.MessageTypeRequest:
		// SELECTING and INIT-REBOOT use option 50, renewal uses ciaddr.
		if current.IsValid() {
			if requested.IsValid() || serverID.IsValid() {
				return nil, nil
			}
			requested = current
		} else if !requested.IsValid() {
			return nil, nil
		}
		allocation, err := s.leases.CommitWithFallback(
			clientID,
			requested,
			clientHostname(request),
			fallbackHostname(clientID),
		)
		if errors.Is(err, lease.ErrUnavailable) || errors.Is(err, lease.ErrPoolExhausted) {
			return s.reply(request, dhcpv4.MessageTypeNak, nil)
		}
		if err != nil {
			return nil, fmt.Errorf("commit lease: %w", err)
		}
		s.logger.Info("DHCP lease acknowledged", "ip", allocation.IP, "hostname", allocation.Hostname, "expires", allocation.ExpiresAt)
		return s.reply(request, dhcpv4.MessageTypeAck, &allocation)
	case dhcpv4.MessageTypeRelease:
		if serverID != s.config.ServerIP || !current.IsValid() {
			return nil, nil
		}
		if err := s.leases.Release(clientID, current); err != nil && !errors.Is(err, lease.ErrUnavailable) {
			return nil, fmt.Errorf("release lease: %w", err)
		}
	case dhcpv4.MessageTypeDecline:
		if serverID != s.config.ServerIP || !requested.IsValid() || current.IsValid() {
			return nil, nil
		}
		if err := s.leases.Decline(clientID, requested); err != nil && !errors.Is(err, lease.ErrUnavailable) {
			return nil, fmt.Errorf("decline lease: %w", err)
		}
	case dhcpv4.MessageTypeInform:
		if !current.IsValid() || !s.config.Subnet.Contains(current) {
			return nil, nil
		}
		return s.reply(request, dhcpv4.MessageTypeAck, nil)
	}
	return nil, nil
}

func (s *Server) reply(request *dhcpv4.DHCPv4, kind dhcpv4.MessageType, allocation *lease.Lease) (*dhcpv4.DHCPv4, error) {
	modifiers := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(kind),
		dhcpv4.WithOption(dhcpv4.OptServerIdentifier(net.IP(s.config.ServerIP.AsSlice()))),
	}
	if kind == dhcpv4.MessageTypeNak {
		modifiers = append(modifiers, dhcpv4.WithBroadcast(true))
	} else {
		modifiers = append(modifiers,
			dhcpv4.WithClientIP(request.ClientIPAddr),
			dhcpv4.WithNetmask(net.CIDRMask(s.config.Subnet.Bits(), 32)),
			dhcpv4.WithDNS(net.IP(s.config.ServerIP.AsSlice())),
			dhcpv4.WithOption(dhcpv4.OptNTPServers(net.IP(s.config.ServerIP.AsSlice()))),
			// Option 43 carries the raw root CA URL; HTTP on the server IP works before DNS or CA trust is set up.
			dhcpv4.WithOption(dhcpv4.OptGeneric(
				dhcpv4.OptionVendorSpecificInformation, []byte("http://"+s.config.ServerIP.String()+"/ca.pem"),
			)),
			dhcpv4.WithOption(dhcpv4.OptDomainName(s.config.Domain)),
			dhcpv4.WithDomainSearchList(s.config.Domain),
		)
		if s.config.Router.IsValid() {
			modifiers = append(modifiers, dhcpv4.WithRouter(net.IP(s.config.Router.AsSlice())))
		}
		if allocation != nil {
			modifiers = append(modifiers, s.bootOptions(request)...)
			modifiers = append(modifiers,
				dhcpv4.WithYourIP(net.IP(allocation.IP.AsSlice())),
				dhcpv4.WithOption(dhcpv4.OptIPAddressLeaseTime(s.config.LeaseDuration)),
				dhcpv4.WithOption(dhcpv4.OptRenewTimeValue(s.config.LeaseDuration/2)),
				dhcpv4.WithOption(dhcpv4.OptRebindingTimeValue(s.config.LeaseDuration/8*7)),
			)
			if allocation.Hostname != "" {
				modifiers = append(modifiers, dhcpv4.WithOption(dhcpv4.OptHostName(strings.TrimSuffix(allocation.Hostname, "."))))
			}
			if option := fqdnReply(request, allocation.Hostname); option != nil {
				modifiers = append(modifiers, dhcpv4.WithOption(dhcpv4.OptGeneric(dhcpv4.OptionFQDN, option)))
			}
		}
		// UDP cannot unicast to the hardware address of an unconfigured client.
		if !ipv4(request.ClientIPAddr).IsValid() && !ipv4(request.GatewayIPAddr).IsValid() {
			modifiers = append(modifiers, dhcpv4.WithBroadcast(true))
		}
	}
	reply, err := dhcpv4.NewReplyFromRequest(request, modifiers...)
	if err != nil {
		return nil, fmt.Errorf("build DHCP reply: %w", err)
	}
	return reply, nil
}

func replyAddress(request, reply *dhcpv4.DHCPv4) *net.UDPAddr {
	if relay := ipv4(request.GatewayIPAddr); relay.IsValid() {
		return &net.UDPAddr{IP: net.IP(relay.AsSlice()), Port: dhcpv4.ServerPort}
	}
	if reply.MessageType() != dhcpv4.MessageTypeNak {
		if current := ipv4(request.ClientIPAddr); current.IsValid() {
			return &net.UDPAddr{IP: net.IP(current.AsSlice()), Port: dhcpv4.ClientPort}
		}
	}
	return &net.UDPAddr{IP: net.IPv4bcast, Port: dhcpv4.ClientPort}
}

func ipv4(ip net.IP) netip.Addr {
	addr, ok := netip.AddrFromSlice(ip.To4())
	if !ok || addr.IsUnspecified() {
		return netip.Addr{}
	}
	return addr.Unmap()
}

func clientIdentifier(request *dhcpv4.DHCPv4) string {
	if id := request.Options.Get(dhcpv4.OptionClientIdentifier); id != nil {
		if len(id) < 2 || len(id) > 255 {
			return ""
		}
		return "id:" + hex.EncodeToString(id)
	}
	if len(request.ClientHWAddr) == 0 || len(request.ClientHWAddr) > 16 {
		return ""
	}
	return fmt.Sprintf("hw:%d:%s", request.HWType, hex.EncodeToString(request.ClientHWAddr))
}
