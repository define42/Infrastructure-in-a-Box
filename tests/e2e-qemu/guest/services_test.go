//go:build e2e_guest

// These tests run only inside the disposable QEMU guest, against the complete
// production server. The normal Go suites never serve non-loopback networks.
package guest_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/miekg/dns"
	"golang.org/x/crypto/acme"
)

const hostname = "client1.home.arpa"

func leaseAddress(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("/run/lease-address")
	if err != nil {
		t.Fatal(err)
	}
	address := strings.TrimSpace(string(data))
	if ip, err := netip.ParseAddr(address); err != nil || !ip.Is4() {
		t.Fatalf("invalid DHCP lease address %q: %v", address, err)
	}
	return address
}

func TestDHCPAddress(t *testing.T) {
	want := leaseAddress(t) + "/24"
	iface, err := net.InterfaceByName("eth0")
	if err != nil {
		t.Fatal(err)
	}
	addresses, err := iface.Addrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		if address.String() == want {
			return
		}
	}
	t.Fatalf("DHCP-assigned address %s is missing from eth0: %v", want, addresses)
}

func TestDNS(t *testing.T) {
	address := leaseAddress(t)
	reverse, err := dns.ReverseAddr(address)
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			for _, query := range []struct {
				name string
				kind uint16
				want string
			}{
				{name: hostname + ".", kind: dns.TypeA, want: address},
				{name: reverse, kind: dns.TypePTR, want: hostname + "."},
			} {
				client := dns.Client{Net: network, Timeout: 3 * time.Second}
				reply, _, err := client.ExchangeContext(t.Context(), new(dns.Msg).SetQuestion(query.name, query.kind), "192.168.77.1:53")
				if err != nil {
					t.Fatal(err)
				}
				if reply.Rcode != dns.RcodeSuccess || len(reply.Answer) != 1 {
					t.Fatalf("unexpected DNS response: %s", reply)
				}
				var got string
				switch answer := reply.Answer[0].(type) {
				case *dns.A:
					got = answer.A.String()
				case *dns.PTR:
					got = answer.Ptr
				}
				if got != query.want {
					t.Fatalf("%s: got %q, want %q", query.name, got, query.want)
				}
			}
		})
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupHost(ctx, "client1")
	if err != nil || len(addresses) != 1 || addresses[0] != address {
		t.Fatalf("DHCP-configured system resolver/search domain: %v, %v", addresses, err)
	}
}

func trust(t *testing.T) (*tls.Config, []byte) {
	t.Helper()
	root, err := os.ReadFile("/root-ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(root) {
		t.Fatal("invalid test CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}, root
}

func TestHTTPSAndACME(t *testing.T) {
	tlsConfig, root := trust(t)
	transport := &http.Transport{TLSClientConfig: tlsConfig}
	t.Cleanup(transport.CloseIdleConnections)
	httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://gateway.home.arpa/ca.pem", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(body, root) {
		t.Fatalf("CA download: status=%d, error=%v", response.StatusCode, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &acme.Client{Key: key, DirectoryURL: "https://gateway.home.arpa/acme/directory", HTTPClient: httpClient}
	if _, err := client.Register(ctx, &acme.Account{}, acme.AcceptTOS); err != nil {
		t.Fatal(err)
	}
	order, err := client.AuthorizeOrder(ctx, []acme.AuthzID{{Type: "dns", Value: hostname}})
	if err != nil {
		t.Fatal(err)
	}
	if len(order.AuthzURLs) != 1 {
		t.Fatalf("expected one authorization: %+v", order)
	}
	authorization, err := client.GetAuthorization(ctx, order.AuthzURLs[0])
	if err != nil {
		t.Fatal(err)
	}
	if len(authorization.Challenges) != 1 || authorization.Challenges[0].Type != "http-01" {
		t.Fatalf("expected HTTP-01 challenge: %+v", authorization)
	}
	challenge := authorization.Challenges[0]
	proof, err := client.HTTP01ChallengeResponse(challenge.Token)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := &http.Server{
		ReadHeaderTimeout: 3 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != hostname || r.URL.Path != client.HTTP01ChallengePath(challenge.Token) {
				http.NotFound(w, r)
				return
			}
			requests.Add(1)
			_, _ = io.WriteString(w, proof)
		}),
	}
	listener, err := net.Listen("tcp4", ":80")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	go func() { _ = server.Serve(listener) }()
	if _, err := client.Accept(ctx, challenge); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WaitAuthorization(ctx, authorization.URI); err != nil {
		t.Fatal(err)
	}
	ready, err := client.WaitOrder(ctx, order.URI)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{hostname}}, key)
	if err != nil {
		t.Fatal(err)
	}
	chain, _, err := client.CreateOrderCert(ctx, ready.FinalizeURL, csr, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(chain) == 0 || requests.Load() == 0 {
		t.Fatal("certificate issuance did not complete an HTTP-01 callback to the guest")
	}
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: tlsConfig.RootCAs, DNSName: hostname}); err != nil {
		t.Fatal(err)
	}
	publicKey, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || !publicKey.Equal(&key.PublicKey) {
		t.Fatal("issued certificate does not match the client's key")
	}
}

func TestLDAP(t *testing.T) {
	for _, scheme := range []string{"ldap", "ldaps"} {
		t.Run(scheme, func(t *testing.T) {
			tlsConfig, _ := trust(t)
			conn, err := ldap.DialURL(scheme+"://ldap.home.arpa",
				ldap.DialWithTLSConfig(tlsConfig), ldap.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			conn.SetTimeout(3 * time.Second)
			if err := conn.Bind("uid=reader,ou=users,dc=home,dc=arpa", "qemu-test-password"); err != nil {
				t.Fatal(err)
			}
			result, err := conn.Search(ldap.NewSearchRequest(
				"dc=home,dc=arpa", ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
				10, 3, false, "(uid=reader)", []string{"uid"}, nil,
			))
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Entries) != 1 || result.Entries[0].GetAttributeValue("uid") != "reader" {
				t.Fatalf("unexpected LDAP search result: %+v", result)
			}
			if err := conn.Bind("uid=reader,ou=users,dc=home,dc=arpa", "wrong-password"); !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
				t.Fatalf("wrong password: %v", err)
			}
		})
	}
}
