//go:build integration

package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func startGateway(t *testing.T, server *Server) (string, context.CancelFunc, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- server.serve(ctx, listener, true)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("gateway shutdown: %v", err)
			}
		case <-time.After(7 * time.Second):
			t.Error("gateway did not stop after cancellation")
		}
	})
	return listener.Addr().String(), cancel, done
}

func TestTrustedHTTPSAndDownloadsIntegration(t *testing.T) {
	t.Parallel()
	manager := testPKI(t)
	server := testServer(t, manager)
	server.config.BootDirectory = bootTestDirectory(t)
	var handshakes atomic.Int32
	server.getCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		handshakes.Add(1)
		return manager.GetCertificate(hello)
	}
	address, cancel, done := startGateway(t, server)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(manager.RootPEM()) {
		t.Fatal("cannot load public root")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, address)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	root, _ := pem.Decode(manager.RootPEM())
	for _, download := range []struct {
		path string
		body []byte
	}{
		{"/ca.pem", manager.RootPEM()},
		{"/ca.crt", root.Bytes},
		{"/boot/bootx64.efi", []byte("0123456789abcdef")},
	} {
		response, err := client.Get("https://gateway.home.arpa" + download.path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != http.StatusOK || !bytes.Equal(body, download.body) {
			t.Errorf("%s download status/content mismatch: %d", download.path, response.StatusCode)
		}
		if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
			t.Fatal("TLS chain was not verified against the generated root")
		}
		if err := response.TLS.PeerCertificates[0].VerifyHostname("gateway.home.arpa"); err != nil {
			t.Errorf("gateway DNS SAN: %v", err)
		}
		if err := response.TLS.PeerCertificates[0].CheckSignatureFrom(response.TLS.VerifiedChains[0][1]); err != nil {
			t.Errorf("gateway certificate was not signed by the root: %v", err)
		}
		// Force another handshake to exercise the live certificate provider.
		transport.CloseIdleConnections()
	}
	if handshakes.Load() < 2 {
		t.Error("certificate callback was not used for new TLS connections")
	}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, &tls.Config{
		RootCAs: roots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("gateway IP SAN: %v", err)
	}
	_ = conn.Close()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("gateway did not stop after cancellation")
	}
	if connection, err := net.DialTimeout("tcp", address, 200*time.Millisecond); err == nil {
		_ = connection.Close()
		t.Error("gateway listener stayed open after shutdown")
	}
}

func TestHTTPSRejectsInvalidTrustAndOldTLSIntegration(t *testing.T) {
	t.Parallel()
	manager := testPKI(t)
	address, _, _ := startGateway(t, testServer(t, manager))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(manager.RootPEM())
	for _, test := range []struct {
		name string
		tls  *tls.Config
	}{
		{"unknown root", &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "gateway.home.arpa", MinVersion: tls.VersionTLS12}},
		{"wrong hostname", &tls.Config{RootCAs: roots, ServerName: "other.home.arpa", MinVersion: tls.VersionTLS12}},
		{"TLS 1.1", &tls.Config{RootCAs: roots, ServerName: "gateway.home.arpa", MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", address, test.tls)
			if err == nil {
				_ = conn.Close()
				t.Fatal("TLS accepted invalid trust or protocol")
			}
			if test.name == "unknown root" {
				var target x509.UnknownAuthorityError
				if !errors.As(err, &target) {
					t.Errorf("wrong TLS failure: %v", err)
				}
			}
			if test.name == "wrong hostname" {
				var target x509.HostnameError
				if !errors.As(err, &target) {
					t.Errorf("wrong TLS failure: %v", err)
				}
			}
		})
	}
}

func TestRunListenerFailureIntegration(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	server := testServer(t, testPKI(t))
	server.config.Address = listener.Addr().String()
	if err := server.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "listen for HTTPS") {
		t.Fatalf("Run error = %v", err)
	}
}

func TestServeListenerFailureIntegration(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	server := testServer(t, testPKI(t))
	if err := server.serve(t.Context(), listener, true); err == nil || !strings.Contains(err.Error(), "serve HTTPS") {
		t.Fatalf("serve error = %v", err)
	}
}

func TestCancelBeforeServingIntegration(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	server := testServer(t, testPKI(t))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, listener, true) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("cancellation before ServeTLS did not stop the server")
	}
	if conn, err := net.DialTimeout("tcp", listener.Addr().String(), 200*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Error("listener stayed open after cancellation before ServeTLS")
	}
}

func startDualGateway(t *testing.T, server *Server) (net.Listener, net.Listener, context.CancelFunc, <-chan error) {
	t.Helper()
	listeners := make([]net.Listener, 0, 2)
	for range 2 {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		listeners = append(listeners, listener)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		done <- server.serveListeners(ctx, listeners[0], listeners[1])
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("gateway shutdown: %v", err)
			}
		case <-time.After(7 * time.Second):
			t.Error("gateway listeners did not stop after cancellation")
		}
	})
	return listeners[0], listeners[1], cancel, done
}

func dualGatewayClient(t *testing.T, rootPEM []byte) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		t.Fatal("cannot load public root")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{
		Transport: transport,
		Timeout:   3 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func checkListenerClosed(t *testing.T, listener net.Listener) {
	t.Helper()
	if conn, err := net.DialTimeout("tcp", listener.Addr().String(), 200*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Errorf("gateway listener %s stayed open", listener.Addr())
	}
}

func TestHTTPAndHTTPSDownloadsIntegration(t *testing.T) {
	t.Parallel()
	manager := testPKI(t)
	server := testServer(t, manager)
	server.config.BootDirectory = bootTestDirectory(t)
	httpsListener, httpListener, cancel, done := startDualGateway(t, server)
	client := dualGatewayClient(t, manager.RootPEM())
	for _, endpoint := range []struct {
		name     string
		baseURL  string
		secure   bool
		wantHSTS string
	}{
		{name: "HTTP", baseURL: "http://" + httpListener.Addr().String()},
		{
			name: "HTTPS", baseURL: "https://" + httpsListener.Addr().String(),
			secure: true, wantHSTS: "max-age=31536000",
		},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, request := range []struct {
				name         string
				method       string
				path         string
				byteRange    string
				status       int
				body         string
				length       int64
				contentRange string
			}{
				{
					name: "gateway page", method: http.MethodGet, path: "/", status: http.StatusOK,
					body: string(server.page), length: int64(len(server.page)),
				},
				{
					name: "CA download", method: http.MethodGet, path: "/ca.pem", status: http.StatusOK,
					body: string(server.rootPEM), length: int64(len(server.rootPEM)),
				},
				{
					name: "boot GET", method: http.MethodGet, path: "/boot/bootx64.efi", status: http.StatusOK,
					body: "0123456789abcdef", length: 16,
				},
				{
					name: "boot HEAD", method: http.MethodHead, path: "/boot/bootx64.efi", status: http.StatusOK,
					length: 16,
				},
				{
					name: "boot Range", method: http.MethodGet, path: "/boot/bootx64.efi", byteRange: "bytes=4-7",
					status: http.StatusPartialContent, body: "4567", length: 4, contentRange: "bytes 4-7/16",
				},
			} {
				t.Run(request.name, func(t *testing.T) {
					req, err := http.NewRequestWithContext(t.Context(), request.method, endpoint.baseURL+request.path, nil)
					if err != nil {
						t.Fatal(err)
					}
					if request.byteRange != "" {
						req.Header.Set("Range", request.byteRange)
					}
					response, err := client.Do(req)
					if err != nil {
						t.Fatal(err)
					}
					body, err := io.ReadAll(response.Body)
					_ = response.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
					if response.StatusCode != request.status || string(body) != request.body {
						t.Errorf("response = %d %q, want %d %q", response.StatusCode, body, request.status, request.body)
					}
					if response.ContentLength != request.length {
						t.Errorf("Content-Length = %d, want %d", response.ContentLength, request.length)
					}
					if got := response.Header.Get("Content-Range"); got != request.contentRange {
						t.Errorf("Content-Range = %q, want %q", got, request.contentRange)
					}
					if got := response.Header.Get("Location"); got != "" {
						t.Errorf("public download redirected to %q", got)
					}
					if got := response.Header.Get("Strict-Transport-Security"); got != endpoint.wantHSTS {
						t.Errorf("Strict-Transport-Security = %q, want %q", got, endpoint.wantHSTS)
					}
					if endpoint.secure {
						if response.TLS == nil || len(response.TLS.VerifiedChains) == 0 {
							t.Error("HTTPS certificate was not verified against the private root")
						}
					} else if response.TLS != nil {
						t.Error("HTTP request used TLS")
					}
				})
			}
		})
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("gateway listeners did not stop after cancellation")
	}
	checkListenerClosed(t, httpsListener)
	checkListenerClosed(t, httpListener)
}

func TestDualGatewayListenerFailureStopsPeerIntegration(t *testing.T) {
	t.Parallel()
	for _, protocol := range []string{"HTTPS", "HTTP"} {
		t.Run(protocol, func(t *testing.T) {
			t.Parallel()
			manager := testPKI(t)
			server := testServer(t, manager)
			httpsListener, httpListener, _, done := startDualGateway(t, server)
			client := dualGatewayClient(t, manager.RootPEM())
			for _, baseURL := range []string{
				"https://" + httpsListener.Addr().String(), "http://" + httpListener.Addr().String(),
			} {
				response, err := client.Get(baseURL + "/ca.pem")
				if err != nil {
					t.Fatal(err)
				}
				_ = response.Body.Close()
				if response.StatusCode != http.StatusOK {
					t.Fatalf("listener was not serving before failure: %d", response.StatusCode)
				}
			}
			failed := httpsListener
			if protocol == "HTTP" {
				failed = httpListener
			}
			if err := failed.Close(); err != nil {
				t.Fatal(err)
			}
			select {
			case err := <-done:
				if err == nil || !strings.Contains(err.Error(), "serve "+protocol+" gateway") {
					t.Fatalf("listener failure = %v, want serve %s error", err, protocol)
				}
			case <-time.After(7 * time.Second):
				t.Fatal("listener failure did not stop both gateway listeners")
			}
			checkListenerClosed(t, httpsListener)
			checkListenerClosed(t, httpListener)
		})
	}
}

func TestRunHTTPListenerFailureIntegration(t *testing.T) {
	t.Parallel()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	server := testServer(t, testPKI(t))
	server.config.HTTPAddress = listener.Addr().String()
	if err := server.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "listen for HTTP gateway") {
		t.Fatalf("Run error = %v, want HTTP bind failure", err)
	}
}
