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
		done <- server.serve(ctx, listener)
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
	if err := server.serve(t.Context(), listener); err == nil || !strings.Contains(err.Error(), "serve HTTPS") {
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
	go func() { done <- server.serve(ctx, listener) }()
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
