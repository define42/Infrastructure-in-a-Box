// Package ldapserver serves a read-only, configuration-backed LDAPv3 directory.
package ldapserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxConnections  = 64
	maxBindAttempts = 20
	idleTimeout     = 2 * time.Minute
	ioTimeout       = 10 * time.Second
)

// Server holds an immutable directory and limits concurrent password checks.
type Server struct {
	config    config.LDAPConfig
	tlsConfig *tls.Config
	logger    *slog.Logger
	entries   []entry
	users     []account
	bindSlots chan struct{}
}

type account struct {
	dn        *ldap.DN
	sha256    []byte
	bcrypt    []byte
	disabled  bool
	canSearch bool
}

// New validates configuration without opening sockets. getCertificate is
// required for LDAPS and may supply renewed certificates on each handshake.
func New(cfg config.LDAPConfig, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), logger *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("LDAP config: %w", err)
	}
	if getCertificate == nil {
		return nil, errors.New("LDAP TLS requires a certificate provider")
	}
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{config: cfg, logger: logger, bindSlots: make(chan struct{}, 4)}
	s.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: getCertificate}
	s.buildDirectory(cfg)
	// Retain only immutable directory data and the credentials needed for binds.
	s.config.Users = nil
	s.config.Groups = nil
	return s, nil
}

// Run serves LDAP and LDAPS until cancellation or either listener fails.
func (s *Server) Run(ctx context.Context) error {
	plain, secure, err := s.listen(ctx)
	if err != nil {
		return err
	}
	s.logger.Info("LDAP server listening", "address", plain.Addr().String(), "tls", false)
	s.logger.Info("LDAP server listening", "address", secure.Addr().String(), "tls", true)
	return s.serve(ctx, plain, secure)
}

// listen opens both endpoints before any clients are accepted.
func (s *Server) listen(ctx context.Context) (net.Listener, net.Listener, error) {
	var lc net.ListenConfig
	plain, err := lc.Listen(ctx, "tcp", s.config.Listen)
	if err != nil {
		return nil, nil, fmt.Errorf("listen for LDAP: %w", err)
	}
	secure, err := lc.Listen(ctx, "tcp", s.config.TLSListen)
	if err != nil {
		_ = plain.Close()
		return nil, nil, fmt.Errorf("listen for LDAPS: %w", err)
	}
	return plain, secure, nil
}

// serve owns both listeners and all connections, including incomplete TLS
// handshakes. Both endpoints share the connection and password-check limits.
func (s *Server) serve(ctx context.Context, plain, secure net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var workers sync.WaitGroup
	connections := make(map[net.Conn]struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		_ = plain.Close()
		_ = secure.Close()
		mu.Lock()
		defer mu.Unlock()
		for conn := range connections {
			_ = conn.Close()
		}
	}()
	defer func() {
		cancel()
		<-stopped
		workers.Wait()
	}()
	failures := make(chan error, 2)
	for _, endpoint := range []struct {
		listener net.Listener
		name     string
		tls      bool
	}{{plain, "LDAP", false}, {secure, "LDAPS", true}} {
		workers.Go(func() {
			for {
				conn, err := endpoint.listener.Accept()
				if err != nil {
					if ctx.Err() == nil {
						failures <- fmt.Errorf("accept %s connection: %w", endpoint.name, err)
					}
					return
				}
				mu.Lock()
				if ctx.Err() != nil || len(connections) >= maxConnections {
					mu.Unlock()
					_ = conn.Close()
					continue
				}
				connections[conn] = struct{}{}
				mu.Unlock()
				workers.Go(func() {
					defer func() {
						_ = conn.Close()
						mu.Lock()
						delete(connections, conn)
						mu.Unlock()
					}()
					s.handleConnection(ctx, conn, endpoint.tls)
				})
			}
		})
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-failures:
		return err
	}
}

func (s *Server) handleConnection(ctx context.Context, conn net.Conn, secure bool) {
	if secure {
		tlsConn := tls.Server(conn, s.tlsConfig)
		if err := tlsConn.SetDeadline(time.Now().Add(ioTimeout)); err != nil {
			return
		}
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return
		}
		conn = tlsConn
	}
	canSearch := false
	attempts := 0
	for ctx.Err() == nil {
		if err := conn.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return
		}
		packet, err := readMessage(conn)
		if err != nil {
			return
		}
		id, op, ok := requestEnvelope(packet)
		if !ok {
			return
		}
		if op.Tag == ldap.ApplicationUnbindRequest {
			return
		}
		if op.Tag == ldap.ApplicationAbandonRequest {
			// Requests run serially; any preceding operation is already complete.
			continue
		}
		responseTag, known := responseType(op.Tag)
		if !known {
			return
		}
		if op.Tag == ldap.ApplicationBindRequest {
			// Every bind, including malformed/unsupported binds, resets authorization.
			canSearch = false
		}
		if code := validateControls(packet); code != ldap.LDAPResultSuccess {
			if writeResult(conn, id, responseTag, code, "unsupported or malformed controls") != nil {
				return
			}
			continue
		}
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			attempts++
			if attempts > maxBindAttempts {
				_ = writeResult(conn, id, responseTag, ldap.LDAPResultAdminLimitExceeded, "bind attempt limit exceeded")
				return
			}
			code, allowed := s.bind(ctx, op)
			canSearch = allowed
			if writeResult(conn, id, responseTag, code, "") != nil {
				return
			}
		case ldap.ApplicationSearchRequest:
			if s.search(ctx, conn, id, op, canSearch) != nil {
				return
			}
		default:
			if writeResult(conn, id, responseTag, ldap.LDAPResultUnwillingToPerform, "directory is read-only; operation is unsupported") != nil {
				return
			}
		}
	}
}

func (s *Server) bind(ctx context.Context, op *ber.Packet) (uint16, bool) {
	if op.TagType != ber.TypeConstructed || len(op.Children) != 3 {
		return ldap.LDAPResultProtocolError, false
	}
	version, ok := integer(op.Children[0], ber.TagInteger)
	if !ok || version != 3 || !octetString(op.Children[1]) {
		return ldap.LDAPResultProtocolError, false
	}
	auth := op.Children[2]
	if auth.ClassType != ber.ClassContext || auth.TagType != ber.TypePrimitive || auth.Tag != 0 {
		return ldap.LDAPResultAuthMethodNotSupported, false
	}
	name, password := op.Children[1].Data.String(), auth.Data.Bytes()
	if name == "" && len(password) == 0 {
		return ldap.LDAPResultSuccess, false
	}
	if name == "" || len(password) == 0 || len(password) > 1024 {
		return ldap.LDAPResultInvalidCredentials, false
	}
	dn, err := ldap.ParseDN(name)
	if err != nil {
		return ldap.LDAPResultInvalidCredentials, false
	}
	// Limit both concurrent expensive hashes and repeated binds on one connection.
	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ldap.LDAPResultUnavailable, false
	case <-timer.C:
	}
	select {
	case s.bindSlots <- struct{}{}:
		defer func() { <-s.bindSlots }()
	case <-ctx.Done():
		return ldap.LDAPResultUnavailable, false
	default:
		return ldap.LDAPResultBusy, false
	}
	for _, user := range s.users {
		if !user.dn.EqualFold(dn) || user.disabled {
			continue
		}
		valid := false
		if len(user.bcrypt) != 0 {
			valid = len(password) <= 72 && bcrypt.CompareHashAndPassword(user.bcrypt, password) == nil
		} else {
			hash := sha256.Sum256(password)
			valid = subtle.ConstantTimeCompare(hash[:], user.sha256) == 1
		}
		if valid {
			return ldap.LDAPResultSuccess, user.canSearch
		}
		break
	}
	return ldap.LDAPResultInvalidCredentials, false
}

func credentials(user config.LDAPUser, dn *ldap.DN) account {
	hash, _ := hex.DecodeString(user.PassSHA256) // Configuration validation checked the encoding.
	return account{dn: dn, sha256: hash, bcrypt: []byte(user.PassBcrypt), disabled: user.Disabled, canSearch: user.CanSearch}
}
