// Package gateway serves the local HTTPS gateway and its public root certificate.
package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const shutdownTimeout = 5 * time.Second

//go:embed page.html
var pageHTML string

// Config configures the gateway listener and the domain containing its hostname.
type Config struct {
	Address string
	Domain  string
}

// Server serves immutable public certificate downloads and a gateway landing page.
type Server struct {
	config         Config
	hostname       string
	rootPEM        []byte
	rootDER        []byte
	page           []byte
	fingerprint    string
	getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	logger         *slog.Logger
}

// New validates configuration and copies the public root certificate without
// opening a network socket. getCertificate must support concurrent TLS handshakes.
func New(config Config, rootPEM []byte, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), logger *slog.Logger) (*Server, error) {
	host, port, err := net.SplitHostPort(config.Address)
	if err != nil {
		return nil, fmt.Errorf("HTTPS listen address: %w", err)
	}
	if host != "" {
		if ip, err := netip.ParseAddr(host); err != nil || ip.IsMulticast() {
			return nil, errors.New("HTTPS listen host must be a literal unicast IP address")
		}
	}
	if number, err := strconv.Atoi(port); err != nil || number < 0 || number > 65535 {
		return nil, errors.New("HTTPS listen port must be between 0 and 65535")
	}
	config.Domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(config.Domain), "."))
	hostname := "gateway." + config.Domain
	if !validHostname(hostname) {
		return nil, errors.New("HTTPS domain must form a valid gateway hostname")
	}
	if getCertificate == nil {
		return nil, errors.New("HTTPS certificate provider is required")
	}
	rootPEM = bytes.TrimSpace(rootPEM)
	block, rest := pem.Decode(rootPEM)
	if !bytes.HasPrefix(rootPEM, []byte("-----BEGIN CERTIFICATE-----")) || bytes.Count(rootPEM, []byte("-----BEGIN ")) != 1 || block == nil ||
		block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("HTTPS public root must contain exactly one PEM certificate")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse HTTPS public root: %w", err)
	}
	if !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 ||
		!bytes.Equal(root.RawIssuer, root.RawSubject) {
		return nil, errors.New("HTTPS public root must be a self-signed CA certificate")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return nil, fmt.Errorf("verify HTTPS public root signature: %w", err)
	}
	if logger == nil {
		logger = slog.Default()
	}
	pageTemplate, err := template.New("gateway").Parse(pageHTML)
	if err != nil {
		return nil, fmt.Errorf("parse gateway page: %w", err)
	}
	var page bytes.Buffer
	fingerprint := strings.ReplaceAll(fmt.Sprintf("% X", sha256.Sum256(root.Raw)), " ", ":")
	if err := pageTemplate.Execute(&page, struct {
		Hostname    string
		Fingerprint string
	}{hostname, fingerprint}); err != nil {
		return nil, fmt.Errorf("render gateway page: %w", err)
	}
	return &Server{
		config: config, hostname: hostname, logger: logger, getCertificate: getCertificate,
		rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}),
		rootDER: bytes.Clone(root.Raw), page: page.Bytes(), fingerprint: fingerprint,
	}, nil
}

func validHostname(hostname string) bool {
	if len(hostname) > 253 {
		return false
	}
	for label := range strings.SplitSeq(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// Run serves HTTPS until cancellation or a serving failure. Cancellation stops
// requests, closes the listener, and allows at most five seconds for shutdown.
func (s *Server) Run(ctx context.Context) error {
	if ctx.Err() != nil {
		return nil
	}
	listenConfig := net.ListenConfig{}
	listener, err := listenConfig.Listen(ctx, "tcp", s.config.Address)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("listen for HTTPS gateway: %w", err)
	}
	defer listener.Close()
	return s.serve(ctx, listener)
}

func (s *Server) serve(ctx context.Context, listener net.Listener) error {
	defer listener.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	server := &http.Server{
		Handler: s,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, GetCertificate: s.getCertificate,
		},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
		ErrorLog:          slog.NewLogLogger(s.logger.Handler(), slog.LevelDebug),
	}
	// A Shutdown before ServeTLS starts is remembered by http.Server, avoiding
	// a lost cancellation even if the listener has not yet been registered.
	done := make(chan error, 1)
	go func() { done <- server.ServeTLS(listener, "", "") }()
	s.logger.Info("HTTPS gateway listening", "address", listener.Addr(), "hostname", s.hostname,
		"root_sha256", s.fingerprint)
	var serveErr error
	select {
	case <-ctx.Done():
	case serveErr = <-done:
	}
	cancel()
	shutdownCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer stop()
	if err := server.Shutdown(shutdownCtx); err != nil {
		s.logger.Debug("HTTPS graceful shutdown", "error", err)
		if err := server.Close(); err != nil {
			s.logger.Debug("HTTPS close", "error", err)
		}
	}
	if serveErr == nil {
		serveErr = <-done
	}
	if !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTPS gateway: %w", serveErr)
	}
	return nil
}

// ServeHTTP serves only public, in-memory content; it never opens a file.
func (s *Server) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("Cache-Control", "no-store")
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		s.write(w, request, http.StatusMethodNotAllowed, "text/plain; charset=utf-8", []byte("method not allowed\n"))
		return
	}
	switch request.URL.Path {
	case "/":
		s.write(w, request, http.StatusOK, "text/html; charset=utf-8", s.page)
	case "/ca.pem":
		w.Header().Set("Content-Disposition", `attachment; filename="root-ca.pem"`)
		s.write(w, request, http.StatusOK, "application/x-pem-file", s.rootPEM)
	case "/ca.crt":
		w.Header().Set("Content-Disposition", `attachment; filename="root-ca.crt"`)
		s.write(w, request, http.StatusOK, "application/pkix-cert", s.rootDER)
	default:
		s.write(w, request, http.StatusNotFound, "text/plain; charset=utf-8", []byte("not found\n"))
	}
}

func (s *Server) write(w http.ResponseWriter, request *http.Request, status int, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if request.Method == http.MethodHead {
		return
	}
	if _, err := w.Write(body); err != nil {
		s.logger.Debug("write HTTPS response", "error", err)
	}
}
