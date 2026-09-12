//go:build integration

package acmeserver_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmeserver"
	"github.com/define42/Infrastructure-in-a-Box/internal/acmevalidate"
	"github.com/define42/Infrastructure-in-a-Box/internal/gateway"
	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
	"github.com/define42/Infrastructure-in-a-Box/internal/pki"
	"golang.org/x/crypto/acme"
)

const integrationHostname = "laptop.home.arpa"

// The production validator's pinned port-80 transport is tested in its own
// package. This fixture uses the same lease policy and an unprivileged loopback
// challenge listener so the standard ACME client can complete real HTTP proofs.
type loopbackHTTPValidator struct {
	policy       *acmevalidate.Validator
	challengeURL string
	httpClient   *http.Client
}

func (v *loopbackHTTPValidator) Lookup(name string) (acmevalidate.Target, error) {
	return v.policy.Lookup(name)
}

func (v *loopbackHTTPValidator) Validate(ctx context.Context, name, token, authorization string) (acmevalidate.Target, error) {
	target, err := v.Lookup(name)
	if err != nil {
		return acmevalidate.Target{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, v.challengeURL+"/.well-known/acme-challenge/"+token, nil)
	if err != nil {
		return acmevalidate.Target{}, err
	}
	request.Host = name
	response, err := v.httpClient.Do(request)
	if err != nil {
		return acmevalidate.Target{}, err
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	if err != nil {
		return acmevalidate.Target{}, err
	}
	if response.StatusCode != http.StatusOK || string(body) != authorization {
		return acmevalidate.Target{}, errors.New("loopback HTTP-01 proof did not match client account key")
	}
	return target, nil
}

func TestStandardACMEClientCertificateLifecycle(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	registry, err := lease.New(lease.Config{
		Domain: "home.arpa", PoolStart: netip.MustParseAddr("127.0.0.1"),
		PoolEnd: netip.MustParseAddr("127.0.0.20"), LeaseDuration: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Commit("laptop-client", netip.MustParseAddr("127.0.0.10"), integrationHostname); err != nil {
		t.Fatal(err)
	}
	if _, err := registry.Commit("acme-client", netip.MustParseAddr("127.0.0.1"), ""); err != nil {
		t.Fatal(err)
	}
	policy, err := acmevalidate.New(acmevalidate.Config{
		Domain: "home.arpa", Subnet: netip.MustParsePrefix("127.0.0.0/24"),
	}, registry)
	if err != nil {
		t.Fatal(err)
	}
	var responsesMu sync.Mutex
	responses := make(map[string]string)
	var challengeRequests atomic.Int32
	challengeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != integrationHostname || r.Method != http.MethodGet {
			t.Errorf("challenge request used unexpected method/host: %s %s", r.Method, r.Host)
		}
		responsesMu.Lock()
		body, ok := responses[r.URL.Path]
		responsesMu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		challengeRequests.Add(1)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(challengeServer.Close)
	validator := &loopbackHTTPValidator{policy: policy, challengeURL: challengeServer.URL, httpClient: challengeServer.Client()}

	var active atomic.Pointer[acmeserver.Server]
	httpsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		active.Load().ServeHTTP(w, r)
	}))
	t.Cleanup(httpsServer.Close)
	_, port, err := net.SplitHostPort(httpsServer.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "https://gateway.home.arpa:" + port + "/acme"
	caDir := filepath.Join(t.TempDir(), "pki")
	caConfig := pki.Config{
		Directory: caDir, Domain: "home.arpa", ServerIP: netip.MustParseAddr("127.0.0.1"), CRLURL: baseURL + "/crl",
	}
	ca, err := pki.Open(caConfig)
	if err != nil {
		t.Fatal(err)
	}
	serverConfig := acmeserver.Config{BaseURL: baseURL, Domain: "home.arpa", StateFile: filepath.Join(caDir, "acme.json"), Leases: registry}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := acmeserver.New(serverConfig, ca, validator, logger)
	if err != nil {
		t.Fatal(err)
	}
	active.Store(server)
	publicGateway, err := gateway.New(gateway.Config{
		Address: httpsServer.Listener.Addr().String(), Domain: "home.arpa", ACMEHandler: httpsServer.Config.Handler,
	}, ca.RootPEM(), ca.GetCertificate, logger)
	if err != nil {
		t.Fatal(err)
	}
	httpsServer.Config.Handler = publicGateway
	certificate, err := ca.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	httpsServer.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*certificate}}
	httpsServer.StartTLS()
	rootPool := x509.NewCertPool()
	if !rootPool.AppendCertsFromPEM(ca.RootPEM()) {
		t.Fatal("could not trust generated root")
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: rootPool},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "gateway.home.arpa:"+port {
				return nil, fmt.Errorf("unexpected ACME destination %q", address)
			}
			var dialer net.Dialer
			return dialer.DialContext(ctx, "tcp4", httpsServer.Listener.Addr().String())
		},
	}
	t.Cleanup(transport.CloseIdleConnections)
	httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	accountKey := integrationKey(t)
	client := &acme.Client{Key: accountKey, DirectoryURL: baseURL + "/directory", HTTPClient: httpClient}
	account, err := client.Register(ctx, &acme.Account{Contact: []string{"mailto:admin@example.net"}}, acme.AcceptTOS)
	if err != nil {
		t.Fatalf("register account: %v", err)
	}
	if account.Status != acme.StatusValid || account.URI == "" || account.OrdersURL == "" {
		t.Fatalf("invalid account response: %+v", account)
	}
	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: integrationHostname}})
	if err != nil {
		t.Fatalf("new order: %v", err)
	}
	if order.Status != acme.StatusPending || len(order.AuthzURLs) != 1 {
		t.Fatalf("invalid order response: %+v", order)
	}
	for _, authorizationURL := range order.AuthzURLs {
		authorization, err := client.GetAuthorization(ctx, authorizationURL)
		if err != nil {
			t.Fatalf("get authorization: %v", err)
		}
		if len(authorization.Challenges) != 1 || authorization.Challenges[0].Type != "http-01" {
			t.Fatalf("unexpected challenges: %+v", authorization.Challenges)
		}
		challenge := authorization.Challenges[0]
		response, err := client.HTTP01ChallengeResponse(challenge.Token)
		if err != nil {
			t.Fatal(err)
		}
		responsesMu.Lock()
		responses[client.HTTP01ChallengePath(challenge.Token)] = response
		responsesMu.Unlock()
		if _, err := client.Accept(ctx, challenge); err != nil {
			t.Fatalf("accept HTTP-01 challenge: %v", err)
		}
		if _, err := client.WaitAuthorization(ctx, authorizationURL); err != nil {
			t.Fatalf("wait authorization: %v", err)
		}
	}
	readyOrder, err := client.WaitOrder(ctx, order.URI)
	if err != nil || readyOrder.Status != acme.StatusReady {
		t.Fatalf("wait order: %+v, %v", readyOrder, err)
	}
	leafKey := integrationKey(t)
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: integrationHostname}, DNSNames: []string{integrationHostname},
	}, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	chain, certificateURL, err := client.CreateOrderCert(ctx, readyOrder.FinalizeURL, csr, true)
	if err != nil {
		t.Fatalf("issue certificate: %v", err)
	}
	if len(chain) != 2 || certificateURL == "" {
		t.Fatalf("certificate response has %d entries and URL %q", len(chain), certificateURL)
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: rootPool, DNSName: integrationHostname}); err != nil {
		t.Fatalf("issued certificate did not validate: %v", err)
	}
	if !leaf.PublicKey.(*ecdsa.PublicKey).Equal(&leafKey.PublicKey) {
		t.Fatal("issued certificate does not use client's retained private key")
	}
	if len(leaf.CRLDistributionPoints) != 1 || leaf.CRLDistributionPoints[0] != baseURL+"/crl" {
		t.Fatalf("missing revocation URL: %v", leaf.CRLDistributionPoints)
	}
	if challengeRequests.Load() != 1 {
		t.Fatalf("validated %d challenge requests, want one", challengeRequests.Load())
	}
	if fetched, err := client.FetchCert(ctx, certificateURL, true); err != nil || len(fetched) != 2 || !bytes.Equal(fetched[0], chain[0]) {
		t.Fatalf("download certificate: %d entries, %v", len(fetched), err)
	}

	restart := func() {
		t.Helper()
		reopenedCA, err := pki.Open(caConfig)
		if err != nil {
			t.Fatalf("reopen CA: %v", err)
		}
		reopened, err := acmeserver.New(serverConfig, reopenedCA, validator, logger)
		if err != nil {
			t.Fatalf("restore ACME state: %v", err)
		}
		active.Store(reopened)
	}
	restart()
	// New client instances have no cached nonces or account IDs after restart.
	client = &acme.Client{Key: accountKey, DirectoryURL: baseURL + "/directory", HTTPClient: httpClient}
	if restored, err := client.GetReg(ctx, ""); err != nil || restored.URI != account.URI {
		t.Fatalf("restore account: %+v, %v", restored, err)
	}
	if restored, err := client.GetOrder(ctx, order.URI); err != nil || restored.Status != acme.StatusValid || restored.CertURL != certificateURL {
		t.Fatalf("restore order: %+v, %v", restored, err)
	}
	if fetched, err := client.FetchCert(ctx, certificateURL, true); err != nil || len(fetched) != 2 || !bytes.Equal(fetched[0], chain[0]) {
		t.Fatalf("download restored certificate: %d entries, %v", len(fetched), err)
	}
	newAccountKey := integrationKey(t)
	if err := client.AccountKeyRollover(ctx, newAccountKey); err != nil {
		t.Fatalf("roll over account key: %v", err)
	}
	if updated, err := client.GetReg(ctx, ""); err != nil || updated.URI != account.URI {
		t.Fatalf("account after key rollover: %+v, %v", updated, err)
	}
	if err := client.RevokeCert(ctx, nil, chain[0], acme.CRLReasonKeyCompromise); err != nil {
		t.Fatalf("revoke certificate using new account key: %v", err)
	}
	root, err := x509.ParseCertificate(chain[1])
	if err != nil {
		t.Fatal(err)
	}
	crl := fetchIntegrationCRL(t, ctx, httpClient, baseURL+"/crl", root)
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 ||
		crl.RevokedCertificateEntries[0].ReasonCode != int(acme.CRLReasonKeyCompromise) {
		t.Fatalf("CRL does not report revoked certificate: %+v", crl.RevokedCertificateEntries)
	}
	restart()
	client = &acme.Client{Key: newAccountKey, DirectoryURL: baseURL + "/directory", HTTPClient: httpClient}
	if updated, err := client.GetReg(ctx, ""); err != nil || updated.URI != account.URI {
		t.Fatalf("restore rolled-over account: %+v, %v", updated, err)
	}
	restoredCRL := fetchIntegrationCRL(t, ctx, httpClient, baseURL+"/crl", root)
	if !bytes.Equal(restoredCRL.Raw, crl.Raw) {
		t.Fatal("revocation list changed or disappeared across restart")
	}
}

func integrationKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func fetchIntegrationCRL(t *testing.T, ctx context.Context, client *http.Client, url string, root *x509.Certificate) *x509.RevocationList {
	t.Helper()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "application/pkix-crl") {
		t.Fatalf("CRL response = %d %s: %s", response.StatusCode, response.Header.Get("Content-Type"), body)
	}
	crl, err := x509.ParseRevocationList(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(root); err != nil {
		t.Fatalf("CRL signature failed: %v", err)
	}
	return crl
}
