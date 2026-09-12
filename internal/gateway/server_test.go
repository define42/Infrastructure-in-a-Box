package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/pki"
)

func testPKI(t *testing.T) *pki.Manager {
	t.Helper()
	manager, err := pki.Open(pki.Config{
		Directory: t.TempDir(), Domain: "home.arpa", ServerIP: netip.MustParseAddr("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func testServer(t *testing.T, manager *pki.Manager) *Server {
	t.Helper()
	server, err := New(Config{Address: "127.0.0.1:0", HTTPAddress: "127.0.0.1:0", Domain: "home.arpa"}, manager.RootPEM(),
		manager.GetCertificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return server
}

func TestPublicCertificateRoutes(t *testing.T) {
	t.Parallel()
	manager := testPKI(t)
	server := testServer(t, manager)
	root, _ := pem.Decode(manager.RootPEM())
	fingerprint := strings.ReplaceAll(fmt.Sprintf("% X", sha256.Sum256(root.Bytes)), " ", ":")
	for _, route := range []struct {
		path        string
		contentType string
		disposition string
		body        []byte
	}{
		{"/", "text/html; charset=utf-8", "", nil},
		{"/ca.pem", "application/x-pem-file", `attachment; filename="root-ca.pem"`, manager.RootPEM()},
		{"/ca.crt", "application/pkix-cert", `attachment; filename="root-ca.crt"`, root.Bytes},
	} {
		t.Run(route.path, func(t *testing.T) {
			t.Parallel()
			get := httptest.NewRecorder()
			server.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "https://gateway.home.arpa"+route.path, nil))
			if get.Code != http.StatusOK {
				t.Fatalf("status = %d", get.Code)
			}
			for name, want := range map[string]string{
				"Content-Type": route.contentType, "Content-Disposition": route.disposition,
				"Content-Length": strconv.Itoa(get.Body.Len()), "X-Content-Type-Options": "nosniff",
				"X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
				"Strict-Transport-Security": "max-age=31536000",
			} {
				if got := get.Header().Get(name); got != want {
					t.Errorf("%s = %q, want %q", name, got, want)
				}
			}
			if !strings.Contains(get.Header().Get("Content-Security-Policy"), "default-src 'none'") {
				t.Error("missing restrictive content security policy")
			}
			if route.body != nil && !bytes.Equal(get.Body.Bytes(), route.body) {
				t.Error("download differs from the public root certificate")
			}
			if bytes.Contains(get.Body.Bytes(), []byte("PRIVATE KEY")) {
				t.Error("response contains a private key")
			}
			if route.path == "/" {
				for _, want := range []string{"gateway.home.arpa", `href="/ca.pem"`, `href="/ca.crt"`, fingerprint, "trusted source"} {
					if !strings.Contains(get.Body.String(), want) {
						t.Errorf("page missing %q", want)
					}
				}
			}
			head := httptest.NewRecorder()
			server.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "https://gateway.home.arpa"+route.path, nil))
			if head.Code != get.Code || head.Body.Len() != 0 {
				t.Errorf("HEAD status/body = %d/%q", head.Code, head.Body.String())
			}
			for name := range get.Header() {
				if head.Header().Get(name) != get.Header().Get(name) {
					t.Errorf("HEAD %s differs from GET", name)
				}
			}
		})
	}
}

func TestOnlyPublicRoutesAndReadMethods(t *testing.T) {
	t.Parallel()
	server := testServer(t, testPKI(t))
	for _, path := range []string{"/root-ca.key", "/root-ca.pem", "/gateway.pem", "/private/ca.pem", "/../root-ca.key", "/%2e%2e/root-ca.key", "/ca.pem/", "/.git/config"} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			response := httptest.NewRecorder()
			server.ServeHTTP(response, httptest.NewRequest(method, path, nil))
			if response.Code != http.StatusNotFound {
				t.Errorf("%s %s status = %d", method, path, response.Code)
			}
			if method == http.MethodHead && response.Body.Len() != 0 {
				t.Errorf("HEAD %s returned a body", path)
			}
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions, http.MethodTrace, http.MethodConnect} {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(method, "/ca.pem", strings.NewReader("untrusted data")))
		if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s status/Allow = %d/%q", method, response.Code, response.Header().Get("Allow"))
		}
	}
}

func TestACMERoutesPreserveRequests(t *testing.T) {
	t.Parallel()
	manager := testPKI(t)
	var receivedBody, receivedPath, receivedMethod string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		receivedBody, receivedPath, receivedMethod = string(body), r.URL.Path, r.Method
		w.Header().Set("Replay-Nonce", "test-nonce")
		w.WriteHeader(http.StatusCreated)
	})
	server, err := New(Config{Address: "127.0.0.1:0", HTTPAddress: "127.0.0.1:0", Domain: "home.arpa", ACMEHandler: handler},
		manager.RootPEM(), manager.GetCertificate, nil)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://gateway.home.arpa/acme/new-order", strings.NewReader("signed JWS")))
	if response.Code != http.StatusCreated || response.Header().Get("Replay-Nonce") != "test-nonce" ||
		receivedBody != "signed JWS" || receivedPath != "/acme/new-order" || receivedMethod != http.MethodPost {
		t.Fatalf("ACME request not forwarded intact: response=%d method=%q path=%q body=%q", response.Code, receivedMethod, receivedPath, receivedBody)
	}
	for _, path := range []string{"/ca.pem", "/acme-other/new-order", "/acme"} {
		response := httptest.NewRecorder()
		server.ServeHTTP(response, httptest.NewRequest(http.MethodPost, path, nil))
		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s escaped gateway method policy: %d", path, response.Code)
		}
	}
}

func TestACMERequiresHTTPS(t *testing.T) {
	t.Parallel()
	server := testServer(t, testPKI(t))
	server.config.ACMEHandler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("unencrypted ACME request reached the handler")
	})
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			response := httptest.NewRecorder()
			request := httptest.NewRequest(method, "http://gateway.home.arpa/acme/directory", nil)
			// Forwarded headers cannot turn a plaintext request into HTTPS.
			request.Header.Set("X-Forwarded-Proto", "https")
			server.ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("HTTP ACME status = %d, want 403", response.Code)
			}
			if method == http.MethodHead && response.Body.Len() != 0 {
				t.Error("HEAD returned a body")
			}
		})
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()
	manager := testPKI(t)
	rootPEM := manager.RootPEM()
	root, _ := pem.Decode(rootPEM)
	damaged := bytes.Clone(root.Bytes)
	damaged[len(damaged)-1] ^= 1
	leaf, err := manager.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name     string
		address  string
		domain   string
		rootPEM  []byte
		provider func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	}{
		{"missing port", "127.0.0.1", "home.arpa", rootPEM, manager.GetCertificate},
		{"invalid port", "127.0.0.1:65536", "home.arpa", rootPEM, manager.GetCertificate},
		{"named port", "127.0.0.1:https", "home.arpa", rootPEM, manager.GetCertificate},
		{"hostname address", "gateway.home.arpa:443", "home.arpa", rootPEM, manager.GetCertificate},
		{"multicast address", "224.0.0.1:443", "home.arpa", rootPEM, manager.GetCertificate},
		{"missing domain", ":443", "", rootPEM, manager.GetCertificate},
		{"invalid label", ":443", "bad-.arpa", rootPEM, manager.GetCertificate},
		{"html domain", ":443", "<script>.arpa", rootPEM, manager.GetCertificate},
		{"no provider", ":443", "home.arpa", rootPEM, nil},
		{"no root", ":443", "home.arpa", nil, manager.GetCertificate},
		{"invalid DER", ":443", "home.arpa", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")}), manager.GetCertificate},
		{"leaf as root", ":443", "home.arpa", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}), manager.GetCertificate},
		{"damaged signature", ":443", "home.arpa", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: damaged}), manager.GetCertificate},
		{"multiple roots", ":443", "home.arpa", append(bytes.Clone(rootPEM), rootPEM...), manager.GetCertificate},
		{"key after root", ":443", "home.arpa", append(bytes.Clone(rootPEM), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")})...), manager.GetCertificate},
		{"key before root", ":443", "home.arpa", append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")}), rootPEM...), manager.GetCertificate},
		{"skipped malformed block", ":443", "home.arpa", append([]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"), rootPEM...), manager.GetCertificate},
		{"trailing text", ":443", "home.arpa", append(bytes.Clone(rootPEM), []byte("secret")...), manager.GetCertificate},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := New(Config{Address: test.address, HTTPAddress: "127.0.0.1:0", Domain: test.domain}, test.rootPEM, test.provider, nil)
			if err == nil {
				t.Fatal("New accepted invalid configuration")
			}
		})
	}
}

func TestNewRejectsInvalidHTTPAddress(t *testing.T) {
	t.Parallel()
	manager := testPKI(t)
	for _, tc := range []struct{ name, address string }{
		{name: "missing", address: ""},
		{name: "missing port", address: "127.0.0.1"},
		{name: "hostname", address: "gateway.home.arpa:80"},
		{name: "multicast", address: "224.0.0.1:80"},
		{name: "negative port", address: "127.0.0.1:-1"},
		{name: "port too large", address: "127.0.0.1:65536"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(Config{Address: "127.0.0.1:0", HTTPAddress: tc.address, Domain: "home.arpa"},
				manager.RootPEM(), manager.GetCertificate, nil)
			if err == nil || !strings.HasPrefix(err.Error(), "HTTP listen") {
				t.Fatalf("New error = %v, want HTTP address validation failure", err)
			}
		})
	}
}

func TestNewCopiesPublicCertificateAndNormalizesDomain(t *testing.T) {
	t.Parallel()
	manager := testPKI(t)
	rootPEM := manager.RootPEM()
	server, err := New(Config{Address: ":443", HTTPAddress: ":80", Domain: " HOME.ARPA. "}, rootPEM, manager.GetCertificate, nil)
	if err != nil {
		t.Fatal(err)
	}
	clear(rootPEM)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ca.pem", nil))
	if !bytes.Equal(response.Body.Bytes(), manager.RootPEM()) {
		t.Error("caller mutation changed served root")
	}
	if server.hostname != "gateway.home.arpa" {
		t.Errorf("hostname = %q", server.hostname)
	}
}

func TestRunAlreadyCancelled(t *testing.T) {
	t.Parallel()
	server := testServer(t, testPKI(t))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := server.Run(ctx); err != nil {
		t.Fatal(err)
	}
}
