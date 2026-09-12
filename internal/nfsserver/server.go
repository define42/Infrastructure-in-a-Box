// Package nfsserver serves configured directories over NFSv4.0 on TCP.
package nfsserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

const maxConnections = 64

type Config struct {
	Address string
	Shares  []config.NFSShare
}

type Server struct {
	cfg    Config
	logger *slog.Logger
}

// New validates settings without opening sockets or directories.
func New(cfg Config, logger *slog.Logger) (*Server, error) {
	address, err := netip.ParseAddrPort(cfg.Address)
	if err != nil || !address.Addr().Is4() || (!address.Addr().IsGlobalUnicast() && !address.Addr().IsLoopback()) || (address.Port() == 0 && !address.Addr().IsLoopback()) {
		return nil, errors.New("NFS requires a specific unicast IPv4 listener (port zero is only allowed on loopback)")
	}
	if err := config.ValidateNFSShares(cfg.Shares); err != nil {
		return nil, err
	}
	cfg.Shares = slices.Clone(cfg.Shares)
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{cfg: cfg, logger: logger}, nil
}

// Run binds only when at least one share is configured.
func (s *Server) Run(ctx context.Context) error {
	if len(s.cfg.Shares) == 0 {
		<-ctx.Done()
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	listener, err := net.Listen("tcp4", s.cfg.Address)
	if err != nil {
		return fmt.Errorf("listen for NFS: %w", err)
	}
	return s.Serve(ctx, listener)
}

// Serve owns listener and all connections, waiting for their cleanup on return.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	defer func() { _ = listener.Close() }()
	filesystem, err := openFilesystem(s.cfg.Shares)
	if err != nil {
		return fmt.Errorf("open NFS shares: %w", err)
	}
	defer func() { _ = filesystem.Close() }()
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer func() { cancel(); stop(); workers.Wait() }()
	slots := make(chan struct{}, maxConnections)
	s.logger.Info("NFSv4.0 listening", "address", listener.Addr(), "shares", len(s.cfg.Shares))
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept NFS connection: %w", err)
		}
		select {
		case slots <- struct{}{}:
		default:
			_ = conn.Close()
			continue
		}
		workers.Go(func() {
			defer func() { <-slots; _ = conn.Close() }()
			stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stop()
			if err := serveConnection(conn, filesystem); err != nil && ctx.Err() == nil {
				s.logger.Debug("NFS connection ended", "client", conn.RemoteAddr(), "error", err)
			}
		})
	}
}

func serveConnection(conn net.Conn, filesystem *filesystem) (err error) {
	// Isolate malformed requests from bugs in the experimental protocol library.
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("NFS protocol panic: %v", recovered)
		}
	}()
	session := newSession(filesystem)
	defer session.close()
	for {
		if err := conn.SetDeadline(time.Now().Add(5 * time.Minute)); err != nil {
			return err
		}
		request, err := readRecord(conn)
		if err != nil {
			return err
		}
		response, err := session.reply(request)
		if err != nil {
			return err
		}
		if err := writeRecord(conn, response); err != nil {
			return err
		}
	}
}
