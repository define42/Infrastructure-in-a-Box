// Package ntpserver serves the host clock as a local NTP reference for isolated labs.
// It does not synchronize or adjust the host clock, or contact upstream servers.
package ntpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"
)

// Config supplies a specific IPv4 listener. Production uses server_ip:123;
// port zero is available for isolated loopback tests.
type Config struct {
	Address string
}

// Server handles bounded, stateless NTP requests serially.
type Server struct {
	cfg    Config
	logger *slog.Logger
}

// New validates the listener without opening a socket.
func New(cfg Config, logger *slog.Logger) (*Server, error) {
	address, err := netip.ParseAddrPort(cfg.Address)
	unicast := address.Addr().IsGlobalUnicast() || address.Addr().IsLoopback()
	if err != nil || !address.Addr().Is4() || !unicast {
		return nil, errors.New("NTP requires a specific unicast IPv4 listener")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, logger: logger}, nil
}

// Run binds the NTP listener and serves until cancellation.
func (s *Server) Run(ctx context.Context) error {
	address, err := net.ResolveUDPAddr("udp4", s.cfg.Address)
	if err != nil {
		return fmt.Errorf("resolve NTP listener: %w", err)
	}
	conn, err := net.ListenUDP("udp4", address)
	if err != nil {
		return fmt.Errorf("listen for NTP: %w", err)
	}
	return s.Serve(ctx, conn)
}

// Serve owns conn and closes it on return or cancellation. Each valid request
// produces exactly one 48-byte response; no per-client state or workers accrue.
func (s *Server) Serve(ctx context.Context, conn *net.UDPConn) error {
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		_ = conn.Close()
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
		_ = conn.Close()
	}()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To4() == nil || local.IP.IsUnspecified() {
		return errors.New("NTP listener must bind a specific IPv4 address")
	}
	s.logger.Info("NTP listening", "address", conn.LocalAddr(), "reference", "host clock", "stratum", 10)
	// The extra byte detects oversized datagrams, including truncated ones.
	var request [packetSize + 1]byte
	for {
		n, peer, err := conn.ReadFromUDPAddrPort(request[:])
		received := time.Now()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read NTP request: %w", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("set NTP write deadline: %w", err)
		}
		reply, valid := response(request[:n], received, time.Now())
		if !valid || peer.Port() == 0 {
			continue
		}
		if _, err := conn.WriteToUDPAddrPort(reply[:], peer); err != nil && ctx.Err() == nil {
			s.logger.Debug("send NTP reply", "error", err)
		}
	}
}
