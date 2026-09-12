// Package gateway serves the local HTTP and HTTPS gateway and its public root certificate.
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

// Config configures the gateway listeners and the domain containing its hostname.
type Config struct {
	// Address is the HTTPS listen address; HTTPAddress serves public routes over HTTP.
	Address     string
	HTTPAddress string
	Domain      string
	// BootDirectory optionally exposes public boot assets at /boot/ over HTTP and HTTPS.
	BootDirectory string
	// ACMEHandler optionally serves /acme/ requests, including signed POSTs.
	// The handler must support concurrent requests.
	ACMEHandler http.Handler
}

// Server serves public pages and downloads over HTTP and HTTPS, and ACME over HTTPS.
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

// New validates configuration, prepares the boot directory, and copies the public
// root certificate without opening a network socket. getCertificate must support
// concurrent TLS handshakes.
func New(config Config, rootPEM []byte, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), logger *slog.Logger) (*Server, error) {
	if err := validateAddress(config.Address, "HTTPS"); err != nil {
		return nil, err
	}
	if err := validateAddress(config.HTTPAddress, "HTTP"); err != nil {
		return nil, err
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
	if err := prepareBootDirectory(config.BootDirectory); err != nil {
		return nil, err
	}
	return &Server{
		config: config, hostname: hostname, logger: logger, getCertificate: getCertificate,
		rootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}),
		rootDER: bytes.Clone(root.Raw), page: page.Bytes(), fingerprint: fingerprint,
	}, nil
}

func validateAddress(address, protocol string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%s listen address: %w", protocol, err)
	}
	if host != "" {
		if ip, err := netip.ParseAddr(host); err != nil || ip.IsMulticast() {
			return fmt.Errorf("%s listen host must be a literal unicast IP address", protocol)
		}
	}
	if number, err := strconv.Atoi(port); err != nil || number < 0 || number > 65535 {
		return fmt.Errorf("%s listen port must be between 0 and 65535", protocol)
	}
	return nil
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

// Run serves HTTP and HTTPS until cancellation or a serving failure. Cancellation
// stops requests, closes both listeners, and allows five seconds for shutdown.
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
	defer func() { _ = listener.Close() }()
	httpListener, err := listenConfig.Listen(ctx, "tcp", s.config.HTTPAddress)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return fmt.Errorf("listen for HTTP gateway: %w", err)
	}
	defer func() { _ = httpListener.Close() }()
	return s.serveListeners(ctx, listener, httpListener)
}

func (s *Server) serveListeners(ctx context.Context, httpsListener, httpListener net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- s.serve(ctx, httpsListener, true) }()
	go func() { done <- s.serve(ctx, httpListener, false) }()
	err := <-done
	cancel()
	return errors.Join(err, <-done)
}

func (s *Server) serve(ctx context.Context, listener net.Listener, secure bool) error {
	defer func() { _ = listener.Close() }()
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
	// A Shutdown before Serve starts is remembered by http.Server, avoiding
	// a lost cancellation even if the listener has not yet been registered.
	done := make(chan error, 1)
	protocol := "HTTP"
	if secure {
		protocol = "HTTPS"
		go func() { done <- server.ServeTLS(listener, "", "") }()
	} else {
		go func() { done <- server.Serve(listener) }()
	}
	s.logger.Info(protocol+" gateway listening", "address", listener.Addr(), "hostname", s.hostname,
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
		s.logger.Debug(protocol+" graceful shutdown", "error", err)
		if err := server.Close(); err != nil {
			s.logger.Debug(protocol+" close", "error", err)
		}
	}
	if serveErr == nil {
		serveErr = <-done
	}
	if !errors.Is(serveErr, http.ErrServerClosed) {
		return fmt.Errorf("serve %s gateway: %w", protocol, serveErr)
	}
	return nil
}

// ServeHTTP routes ACME requests to the configured handler and serves public
// certificate and boot downloads and the gateway page for GET and HEAD.
func (s *Server) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if request.TLS != nil {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	w.Header().Set("Cache-Control", "no-store")
	if s.config.ACMEHandler != nil && strings.HasPrefix(request.URL.Path, "/acme/") {
		if request.TLS == nil {
			s.write(w, request, http.StatusForbidden, "text/plain; charset=utf-8", []byte("ACME requires HTTPS\n"))
			return
		}
		s.config.ACMEHandler.ServeHTTP(w, request)
		return
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		s.write(w, request, http.StatusMethodNotAllowed, "text/plain; charset=utf-8", []byte("method not allowed\n"))
		return
	}
	if s.config.BootDirectory != "" && (request.URL.Path == "/boot" || strings.HasPrefix(request.URL.Path, "/boot/")) {
		s.serveBoot(w, request)
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
		s.logger.Debug("write gateway response", "error", err)
	}
}
