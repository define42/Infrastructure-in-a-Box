// Package tftpserver serves built-in iPXE bootloaders over TFTP.
package tftpserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/ipxe"
)

// Config supplies a local IPv4 listener for the built-in bootloaders.
// Production uses server_ip:69. Port zero allows isolated loopback tests.
type Config struct {
	Address string
}

type Server struct {
	cfg    Config
	logger *slog.Logger
	files  fs.FS
}

// New validates settings and selects the embedded iPXE bootloaders.
func New(cfg Config, logger *slog.Logger) (*Server, error) {
	address, err := netip.ParseAddrPort(cfg.Address)
	if err != nil || !address.Addr().Is4() || (!address.Addr().IsGlobalUnicast() && !address.Addr().IsLoopback()) {
		return nil, errors.New("TFTP requires a specific unicast IPv4 listener")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, logger: logger, files: ipxe.Files()}, nil
}

// Run binds the TFTP request listener and serves until cancellation.
func (s *Server) Run(ctx context.Context) error {
	address, err := net.ResolveUDPAddr("udp4", s.cfg.Address)
	if err != nil {
		return fmt.Errorf("resolve TFTP listener: %w", err)
	}
	conn, err := net.ListenUDP("udp4", address)
	if err != nil {
		return fmt.Errorf("listen for TFTP: %w", err)
	}
	return s.Serve(ctx, conn)
}

// Serve owns conn and waits for all transfers before returning. Each transfer
// uses its own UDP port, with global and per-client limits on concurrent work.
func (s *Server) Serve(ctx context.Context, conn *net.UDPConn) error {
	defer func() { _ = conn.Close() }()
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	stopped := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = conn.Close(); close(stopped) })
	defer func() {
		cancel()
		if !stop() {
			<-stopped
		}
		workers.Wait()
	}()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local.IP.To4() == nil || local.IP.IsUnspecified() {
		return errors.New("TFTP listener must bind a specific IPv4 address")
	}
	transferAddress := &net.UDPAddr{IP: local.IP, Port: 0}
	var mu sync.Mutex
	active := make(map[netip.AddrPort]bool)
	clients := make(map[netip.Addr]int)
	s.logger.Info("TFTP listening", "address", conn.LocalAddr(), "files", "built-in iPXE bootloaders")
	packet := make([]byte, maxRequestSize+1)
	for {
		n, peer, err := conn.ReadFromUDPAddrPort(packet)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read TFTP request: %w", err)
		}
		if ctx.Err() != nil {
			return nil
		}
		if n < 2 {
			continue
		}
		switch binary.BigEndian.Uint16(packet[:n]) {
		case opError:
			continue // Never answer ERROR with ERROR.
		case opWrite:
			s.sendError(conn, peer, 2, "TFTP is read-only")
			continue
		case opRead:
		default:
			s.sendError(conn, peer, 4, "expected read request")
			continue
		}
		request, p := parseRequest(packet[:n])
		if p != nil {
			s.sendError(conn, peer, p.code, p.message)
			continue
		}
		mu.Lock()
		if active[peer] {
			// Retransmitted RRQs must not start competing transfers. The existing
			// transfer retransmits its first DATA/OACK until the client acknowledges.
			mu.Unlock()
			continue
		}
		if len(active) >= maxTransfers || clients[peer.Addr()] >= maxClientTransfers {
			mu.Unlock()
			s.sendError(conn, peer, 0, "too many active transfers; retry later")
			continue
		}
		active[peer] = true
		clients[peer.Addr()]++
		mu.Unlock()
		workers.Go(func() {
			defer func() {
				mu.Lock()
				delete(active, peer)
				clients[peer.Addr()]--
				if clients[peer.Addr()] == 0 {
					delete(clients, peer.Addr())
				}
				mu.Unlock()
			}()
			if err := s.transfer(ctx, transferAddress, peer, request); err != nil && ctx.Err() == nil {
				s.logger.Debug("TFTP transfer ended", "client", peer, "filename", request.filename, "error", err)
			}
		})
	}
}

func (s *Server) sendError(conn *net.UDPConn, peer netip.AddrPort, code uint16, message string) {
	if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return
	}
	if _, err := conn.WriteToUDPAddrPort(errorPacket(code, message), peer); err != nil && !errors.Is(err, net.ErrClosed) {
		s.logger.Debug("send TFTP error", "error", err)
	}
}
