//go:build integration

package ldapserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/bcrypt"
)

const testBaseDN = "dc=home,dc=arpa"
const testServiceDN = "uid=service,ou=users," + testBaseDN
const testUserDN = "uid=johndoe,ou=users," + testBaseDN

type ldapFixture struct {
	address      string
	plainAddress string
	clientTLS    *tls.Config
	cancel       context.CancelFunc
	done         <-chan error
	stop         func()
}

func newLDAPFixture(t *testing.T) *ldapFixture {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "LDAP test CA"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{"ldap.home.arpa"},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	hash, err := bcrypt.GenerateFromPassword([]byte("service-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.LDAPConfig{
		Listen: "127.0.0.1:0", TLSListen: "127.0.0.1:0", BaseDN: testBaseDN,
		Groups: []config.LDAPGroup{{Name: "team1", GID: 5505}, {Name: "team10", GID: 5510}, {Name: "empty", GID: 5511}},
		Users: []config.LDAPUser{
			{Name: "johndoe", Mail: "johndoe@home.arpa", PassSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte("user-password"))), UIDNumber: 1001, PrimaryGroup: 5510, OtherGroups: []int{5510, 5505, 5505}},
			{Name: "service", PassBcrypt: string(hash), PrimaryGroup: 5510, CanSearch: true},
			{Name: "disabled", PrimaryGroup: 5505, Disabled: true},
		},
	}
	server, err := New(cfg, func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return certificate, nil }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	plain, secure, err := server.listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, plain, secure) }()
	f := &ldapFixture{address: secure.Addr().String(), plainAddress: plain.Addr().String(), clientTLS: &tls.Config{RootCAs: pool, ServerName: "ldap.home.arpa", MinVersion: tls.VersionTLS12}, cancel: cancel, done: done}
	var once sync.Once
	f.stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("serve: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Error("LDAP shutdown did not terminate active connections")
			}
		})
	}
	t.Cleanup(f.stop)
	return f
}

func (f *ldapFixture) connect(t *testing.T) *ldap.Conn {
	t.Helper()
	return f.connectURL(t, "ldaps://"+f.address)
}

func (f *ldapFixture) connectURL(t *testing.T, address string) *ldap.Conn {
	t.Helper()
	conn, err := ldap.DialURL(address, ldap.DialWithTLSConfig(f.clientTLS), ldap.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}))
	if err != nil {
		t.Fatal(err)
	}
	conn.SetTimeout(3 * time.Second)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func searchRequest(base, filter string, scope int, attrs ...string) *ldap.SearchRequest {
	return ldap.NewSearchRequest(base, scope, ldap.NeverDerefAliases, 0, 0, false, filter, attrs, nil)
}

func requireLDAPError(t *testing.T, err error, code uint16) {
	t.Helper()
	if !ldap.IsErrorWithCode(err, code) {
		t.Fatalf("got error %v, want LDAP result %d", err, code)
	}
}

func TestLDAPBindAndSearch(t *testing.T) {
	t.Parallel()
	f := newLDAPFixture(t)
	for _, endpoint := range []struct {
		name, address string
		secure        bool
	}{
		{"LDAP", "ldap://" + f.plainAddress, false},
		{"LDAPS", "ldaps://" + f.address, true},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			conn := f.connectURL(t, endpoint.address)
			state, ok := conn.TLSConnectionState()
			if ok != endpoint.secure {
				t.Fatalf("TLS active = %v, want %v", ok, endpoint.secure)
			}
			if endpoint.secure && (state.Version < tls.VersionTLS12 || len(state.VerifiedChains) == 0) {
				t.Fatal("client did not verify LDAPS with the test CA")
			}
			testLDAPBindAndSearch(t, conn)
		})
	}
}

func testLDAPBindAndSearch(t *testing.T, conn *ldap.Conn) {
	t.Helper()
	if err := conn.UnauthenticatedBind(""); err != nil {
		t.Fatalf("anonymous bind: %v", err)
	}
	root, err := conn.Search(searchRequest("", "(objectClass=*)", ldap.ScopeBaseObject, "namingContexts", "supportedLDAPVersion"))
	if err != nil || len(root.Entries) != 1 || root.Entries[0].GetAttributeValue("namingContexts") != testBaseDN {
		t.Fatalf("root DSE: result %v error %v", root, err)
	}
	_, err = conn.Search(searchRequest(testBaseDN, "(objectClass=*)", ldap.ScopeWholeSubtree))
	requireLDAPError(t, err, ldap.LDAPResultInsufficientAccessRights)
	if err := conn.Bind(testUserDN, "user-password"); err != nil {
		t.Fatalf("SHA256 bind: %v", err)
	}
	_, err = conn.Search(searchRequest(testBaseDN, "(objectClass=*)", ldap.ScopeWholeSubtree))
	requireLDAPError(t, err, ldap.LDAPResultInsufficientAccessRights)
	if err := conn.Bind(strings.ToUpper(testServiceDN), "service-password"); err != nil {
		t.Fatalf("bcrypt service bind: %v", err)
	}
	result, err := conn.Search(searchRequest("ou=users,"+testBaseDN, "(&(objectClass=inetOrgPerson)(|(uid=john*)(mail=johndoe@home.arpa)))", ldap.ScopeWholeSubtree, "*", "+", "userPassword", "pass_sha256", "pass_bcrypt"))
	if err != nil || len(result.Entries) != 1 {
		t.Fatalf("user search: result %v error %v", result, err)
	}
	user := result.Entries[0]
	if user.DN != testUserDN || user.GetAttributeValue("uidNumber") != "1001" || user.GetAttributeValue("gidNumber") != "5510" || user.GetAttributeValue("homeDirectory") != "/home/johndoe" {
		t.Fatalf("unexpected user attributes: %+v", user)
	}
	membership := user.GetAttributeValues("memberOf")
	if len(membership) != 2 || !slices.Contains(membership, "cn=team10,ou=groups,"+testBaseDN) || !slices.Contains(membership, "cn=team1,ou=groups,"+testBaseDN) {
		t.Fatalf("primary and secondary memberships were not deduplicated: %v", membership)
	}
	for _, attr := range user.Attributes {
		if strings.Contains(strings.ToLower(attr.Name), "pass") {
			t.Fatalf("password material leaked through attribute %s", attr.Name)
		}
	}
	groups, err := conn.Search(searchRequest("ou=groups,"+testBaseDN, "(&(objectClass=posixGroup)(member="+ldap.EscapeFilter(testUserDN)+"))", ldap.ScopeSingleLevel))
	if err != nil || len(groups.Entries) != 2 {
		t.Fatalf("group search: result %v error %v", groups, err)
	}
	for _, group := range groups.Entries {
		if !slices.Contains(group.GetAttributeValues("memberUid"), "johndoe") || !slices.Contains(group.GetAttributeValues("uniqueMember"), testUserDN) {
			t.Fatalf("missing membership aliases: %+v", group)
		}
	}
	service, err := conn.Search(searchRequest(testServiceDN, "(uid=service)", ldap.ScopeBaseObject))
	if err != nil || len(service.Entries) != 1 || service.Entries[0].GetAttributeValue("uidNumber") != "" || slices.Contains(service.Entries[0].GetAttributeValues("objectClass"), "posixAccount") {
		t.Fatalf("non-POSIX account attributes: result %v error %v", service, err)
	}
	if err := conn.Unbind(); err != nil {
		t.Fatal(err)
	}
}

func TestLDAPRebindClearsAuthorization(t *testing.T) {
	t.Parallel()
	f := newLDAPFixture(t)
	for _, tc := range []struct {
		name    string
		request ldap.SimpleBindRequest
		code    uint16
	}{
		{name: "wrong password", request: ldap.SimpleBindRequest{Username: testServiceDN, Password: "wrong"}, code: ldap.LDAPResultInvalidCredentials},
		{name: "empty password", request: ldap.SimpleBindRequest{Username: testServiceDN, AllowEmptyPassword: true}, code: ldap.LDAPResultInvalidCredentials},
		{name: "disabled", request: ldap.SimpleBindRequest{Username: "uid=disabled,ou=users," + testBaseDN, Password: "anything"}, code: ldap.LDAPResultInvalidCredentials},
		{name: "bare name", request: ldap.SimpleBindRequest{Username: "service", Password: "service-password"}, code: ldap.LDAPResultInvalidCredentials},
		{name: "anonymous", request: ldap.SimpleBindRequest{AllowEmptyPassword: true}, code: ldap.LDAPResultSuccess},
		{name: "critical control", request: ldap.SimpleBindRequest{Username: testServiceDN, Password: "service-password", Controls: []ldap.Control{ldap.NewControlString("1.2.3.4", true, "")}}, code: ldap.LDAPResultUnavailableCriticalExtension},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := f.connect(t)
			if err := conn.Bind(testServiceDN, "service-password"); err != nil {
				t.Fatal(err)
			}
			_, err := conn.SimpleBind(&tc.request)
			if tc.code == ldap.LDAPResultSuccess {
				if err != nil {
					t.Fatal(err)
				}
			} else {
				requireLDAPError(t, err, tc.code)
			}
			_, err = conn.Search(searchRequest(testBaseDN, "(objectClass=*)", ldap.ScopeWholeSubtree))
			requireLDAPError(t, err, ldap.LDAPResultInsufficientAccessRights)
		})
	}
}

func TestLDAPSearchOptionsAndReadOnlyErrors(t *testing.T) {
	t.Parallel()
	conn := newLDAPFixture(t).connect(t)
	if err := conn.Bind(testServiceDN, "service-password"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, base   string
		scope, count int
	}{
		{name: "base", base: testBaseDN, scope: ldap.ScopeBaseObject, count: 1},
		{name: "one level", base: testBaseDN, scope: ldap.ScopeSingleLevel, count: 2},
		{name: "subtree", base: testBaseDN, scope: ldap.ScopeWholeSubtree, count: 9},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := conn.Search(searchRequest(tc.base, "(objectClass=*)", tc.scope, "1.1"))
			if err != nil || len(result.Entries) != tc.count {
				t.Fatalf("scope results: %v, error %v", result, err)
			}
			for _, entry := range result.Entries {
				if len(entry.Attributes) != 0 {
					t.Fatal("1.1 attribute selection returned attributes")
				}
			}
		})
	}
	typesRequest := searchRequest(testUserDN, "(uid=*)", ldap.ScopeBaseObject, "uid", "mail")
	typesRequest.TypesOnly = true
	types, err := conn.Search(typesRequest)
	if err != nil || len(types.Entries) != 1 || len(types.Entries[0].Attributes) != 2 {
		t.Fatalf("types only: result %v error %v", types, err)
	}
	for _, attr := range types.Entries[0].Attributes {
		if len(attr.Values) != 0 {
			t.Fatal("types-only search leaked values")
		}
	}
	limited := searchRequest(testBaseDN, "(objectClass=*)", ldap.ScopeWholeSubtree)
	limited.SizeLimit = 2
	result, err := conn.Search(limited)
	requireLDAPError(t, err, ldap.LDAPResultSizeLimitExceeded)
	if len(result.Entries) != 2 {
		t.Fatalf("size-limited search returned %d entries", len(result.Entries))
	}
	_, err = conn.Search(searchRequest("ou=missing,"+testBaseDN, "(objectClass=*)", ldap.ScopeBaseObject))
	requireLDAPError(t, err, ldap.LDAPResultNoSuchObject)
	_, err = conn.Search(searchRequest(testBaseDN, "(objectClass=*)", 9))
	requireLDAPError(t, err, ldap.LDAPResultProtocolError)
	_, err = conn.Search(searchRequest(testBaseDN, "(uidNumber>=0)", ldap.ScopeWholeSubtree))
	requireLDAPError(t, err, ldap.LDAPResultInappropriateMatching)
	controlRequest := searchRequest(testBaseDN, "(objectClass=*)", ldap.ScopeWholeSubtree)
	controlRequest.Controls = []ldap.Control{ldap.NewControlString("1.2.3.4", true, "")}
	_, err = conn.Search(controlRequest)
	requireLDAPError(t, err, ldap.LDAPResultUnavailableCriticalExtension)
	controlRequest.Controls = []ldap.Control{ldap.NewControlPaging(2)}
	_, err = conn.Search(controlRequest)
	requireLDAPError(t, err, ldap.LDAPResultUnwillingToPerform)
	requireLDAPError(t, conn.Add(ldap.NewAddRequest("uid=new,ou=users,"+testBaseDN, nil)), ldap.LDAPResultUnwillingToPerform)
	requireLDAPError(t, conn.Modify(ldap.NewModifyRequest(testUserDN, nil)), ldap.LDAPResultUnwillingToPerform)
	requireLDAPError(t, conn.Del(ldap.NewDelRequest(testUserDN, nil)), ldap.LDAPResultUnwillingToPerform)
	_, err = conn.Extended(ldap.NewExtendedRequest("1.3.6.1.4.1.1466.20037", nil))
	requireLDAPError(t, err, ldap.LDAPResultUnwillingToPerform)
}

func TestLDAPTLSAndShutdown(t *testing.T) {
	t.Parallel()
	f := newLDAPFixture(t)
	untrusted := f.clientTLS.Clone()
	untrusted.RootCAs = x509.NewCertPool()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.address, untrusted)
	if err == nil {
		_ = conn.Close()
		t.Fatal("untrusted LDAP certificate accepted")
	}
	active, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Second}, "tcp", f.address, f.clientTLS)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = active.Close() }()
	incomplete, err := net.DialTimeout("tcp", f.address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = incomplete.Close() }()
	// A partial TLS record ensures an in-progress handshake also terminates.
	if _, err := incomplete.Write([]byte{0x16, 0x03}); err != nil {
		t.Fatal(err)
	}
	plain := f.connectURL(t, "ldap://"+f.plainAddress)
	if err := plain.UnauthenticatedBind(""); err != nil {
		t.Fatal(err)
	}
	f.stop()
	if err := plain.UnauthenticatedBind(""); err == nil {
		t.Fatal("plaintext connection still open after server shutdown")
	}
	for _, conn := range []net.Conn{active, incomplete} {
		if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Read(make([]byte, 1)); err == nil {
			t.Fatal("connection still open after server shutdown")
		} else if networkErr, ok := err.(net.Error); ok && networkErr.Timeout() {
			t.Fatal("server left an active connection waiting after shutdown")
		}
	}
}

func TestLDAPBindAttemptLimit(t *testing.T) {
	t.Parallel()
	conn := newLDAPFixture(t).connect(t)
	for range maxBindAttempts {
		if err := conn.UnauthenticatedBind(""); err != nil {
			t.Fatal(err)
		}
	}
	requireLDAPError(t, conn.UnauthenticatedBind(""), ldap.LDAPResultAdminLimitExceeded)
}

func TestLDAPSearchDeadlineBoundsSlowReader(t *testing.T) {
	t.Parallel()
	server := &Server{config: config.LDAPConfig{BaseDN: testBaseDN}}
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchRequest, nil, "")
	op.AppendChild(textPacket(""))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldap.ScopeBaseObject, ""))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, ldap.NeverDerefAliases, ""))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 0, ""))
	op.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, 1, ""))
	op.AppendChild(ber.NewLDAPBoolean(ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean, false, ""))
	filter, err := ldap.CompileFilter("(objectClass=*)")
	if err != nil {
		t.Fatal(err)
	}
	op.AppendChild(filter)
	op.AppendChild(ber.NewSequence(""))
	op, err = ber.DecodePacketErr(op.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	// Pipe blocks writes until the client reads, without kernel socket buffering.
	writer, reader := net.Pipe()
	defer func() { _ = writer.Close() }()
	defer func() { _ = reader.Close() }()
	done := make(chan error, 1)
	go func() { done <- server.search(t.Context(), writer, 1, op, false) }()
	select {
	case err := <-done:
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatalf("slow reader did not receive a write timeout: %v", err)
		}
	case <-time.After(3 * time.Second):
		_ = reader.Close()
		<-done
		t.Fatal("one-second search limit was replaced by the ten-second I/O timeout")
	}
}
