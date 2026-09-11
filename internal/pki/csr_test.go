package pki

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/url"
	"slices"
	"testing"
	"time"
)

func makeCSR(t *testing.T, template *x509.CertificateRequest, key crypto.Signer) []byte {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func csrKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func parseIssuedChain(t *testing.T, chain []byte) []*x509.Certificate {
	t.Helper()
	var certificates []*x509.Certificate
	for len(chain) != 0 {
		block, rest := pem.Decode(chain)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			t.Fatal("chain must contain only PEM certificates")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		certificates = append(certificates, cert)
		chain = rest
	}
	if len(certificates) != 2 {
		t.Fatalf("chain has %d certificates; want leaf and root", len(certificates))
	}
	return certificates
}

func TestSignCSR(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		key  func(*testing.T) crypto.Signer
	}{
		{name: "ECDSA P256", key: func(t *testing.T) crypto.Signer { return csrKey(t) }},
		{name: "ECDSA P384", key: func(t *testing.T) crypto.Signer {
			key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "ECDSA P521", key: func(t *testing.T) crypto.Signer {
			key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "RSA", key: func(t *testing.T) crypto.Signer {
			key, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
		{name: "Ed25519", key: func(t *testing.T) crypto.Signer {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			return key
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(t)
			cfg.CRLURL = "https://gateway.home.arpa/acme/crl"
			now := testClock()
			m := mustOpen(t, cfg, now)
			gateway, gatewayBundle := mustCertificate(t, m), mustRead(t, cfg, leafBundleName)
			rootBundle := mustRead(t, cfg, rootBundleName)
			key := tc.key(t)
			csrDER := makeCSR(t, &x509.CertificateRequest{
				DNSNames: []string{"Zebra.Home.Arpa", "app.home.arpa"},
				Subject: pkix.Name{
					CommonName: "Zebra.Home.Arpa", Organization: []string{"unverified organization"},
				},
			}, key)
			names := []string{"app.home.arpa", "zebra.home.arpa"}
			chainPEM, err := m.SignCSR(csrDER, names)
			if err != nil {
				t.Fatal(err)
			}
			certificates := parseIssuedChain(t, chainPEM)
			leaf, root := certificates[0], certificates[1]
			if !bytes.Equal(root.Raw, m.root.Leaf.Raw) || !slices.Equal(leaf.DNSNames, names) {
				t.Fatal("issued chain has the wrong root or DNS names")
			}
			publicKey, err := x509.MarshalPKIXPublicKey(key.Public())
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, publicKey) {
				t.Fatal("certificate does not contain the client's public key")
			}
			roots := x509.NewCertPool()
			roots.AddCert(root)
			for _, name := range names {
				if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, CurrentTime: now}); err != nil {
					t.Fatal(err)
				}
			}
			wantUsage := x509.KeyUsageDigitalSignature
			if _, ok := key.(*rsa.PrivateKey); ok {
				wantUsage |= x509.KeyUsageKeyEncipherment
			}
			if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != wantUsage ||
				!slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) ||
				len(leaf.IPAddresses)+len(leaf.EmailAddresses)+len(leaf.URIs)+len(leaf.UnknownExtKeyUsage) != 0 ||
				len(leaf.Subject.Names) != 1 || leaf.Subject.CommonName != "app.home.arpa" ||
				!slices.Equal(leaf.CRLDistributionPoints, []string{cfg.CRLURL}) ||
				!leaf.NotAfter.Equal(now.Add(leafLifetime)) || leaf.SerialNumber.Sign() <= 0 {
				t.Fatal("issued leaf has inappropriate TLS constraints, subject, CRL URL, or lifetime")
			}
			if !bytes.Equal(gatewayBundle, mustRead(t, cfg, leafBundleName)) ||
				!bytes.Equal(rootBundle, mustRead(t, cfg, rootBundleName)) || mustCertificate(t, m) != gateway {
				t.Fatal("CSR signing changed gateway or root state")
			}
			secondPEM, err := m.SignCSR(csrDER, names)
			if err != nil {
				t.Fatal(err)
			}
			if parseIssuedChain(t, secondPEM)[0].SerialNumber.Cmp(leaf.SerialNumber) == 0 {
				t.Fatal("independent certificate issuances reused a serial number")
			}
		})
	}
}

func TestSignCSRRejectsInvalidRequests(t *testing.T) {
	t.Parallel()
	key := csrKey(t)
	names := []string{"app.home.arpa"}
	for _, tc := range []struct {
		name       string
		change     func(*x509.CertificateRequest)
		authorized []string
	}{
		{name: "missing SAN", change: func(c *x509.CertificateRequest) { c.DNSNames = nil }},
		{name: "different name", change: func(c *x509.CertificateRequest) { c.DNSNames = []string{"other.home.arpa"} }},
		{name: "extra name", change: func(c *x509.CertificateRequest) { c.DNSNames = append(c.DNSNames, "other.home.arpa") }},
		{name: "duplicate CSR names", change: func(c *x509.CertificateRequest) { c.DNSNames = []string{"app.home.arpa", "app.home.arpa"} }, authorized: []string{"app.home.arpa", "other.home.arpa"}},
		{name: "duplicate authorizations", authorized: []string{"app.home.arpa", "APP.home.arpa"}, change: func(c *x509.CertificateRequest) { c.DNSNames = []string{"app.home.arpa", "other.home.arpa"} }},
		{name: "IP SAN", change: func(c *x509.CertificateRequest) { c.IPAddresses = []net.IP{net.ParseIP("192.168.50.2")} }},
		{name: "email SAN", change: func(c *x509.CertificateRequest) { c.EmailAddresses = []string{"app@home.arpa"} }},
		{name: "URI SAN", change: func(c *x509.CertificateRequest) {
			c.URIs = []*url.URL{{Scheme: "spiffe", Host: "home.arpa", Path: "/app"}}
		}},
		{name: "wrong common name", change: func(c *x509.CertificateRequest) { c.Subject.CommonName = "other.home.arpa" }},
		{name: "short common name", change: func(c *x509.CertificateRequest) { c.Subject.CommonName = "app" }},
		{name: "multiple common names", change: func(c *x509.CertificateRequest) {
			c.Subject.ExtraNames = []pkix.AttributeTypeAndValue{
				{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "other.home.arpa"},
				{Type: asn1.ObjectIdentifier{2, 5, 4, 3}, Value: "app.home.arpa"},
			}
		}},
		{name: "Unicode authorization", authorized: []string{"\u212a.home.arpa"}, change: func(c *x509.CertificateRequest) {
			c.DNSNames = []string{"k.home.arpa"}
		}},
		{name: "unsupported critical extension", change: func(c *x509.CertificateRequest) {
			c.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{5, 0}}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := mustOpen(t, testConfig(t), testClock())
			csr := &x509.CertificateRequest{DNSNames: []string{"app.home.arpa"}}
			if tc.change != nil {
				tc.change(csr)
			}
			authorized := names
			if tc.authorized != nil {
				authorized = tc.authorized
			}
			if _, err := m.SignCSR(makeCSR(t, csr, key), authorized); !errors.Is(err, ErrInvalidCSR) {
				t.Fatalf("invalid CSR returned %v; want ErrInvalidCSR", err)
			}
		})
	}
	for _, name := range []string{"gateway.home.arpa", "ns.home.arpa", "app", "home.arpa", "*.home.arpa", "app.example.com", "app.home.arpa.example.com", "app.badhome.arpa", "bad_name.home.arpa", "192.168.50.2"} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := mustOpen(t, testConfig(t), testClock())
			csr := makeCSR(t, &x509.CertificateRequest{DNSNames: []string{name}}, key)
			if _, err := m.SignCSR(csr, []string{name}); !errors.Is(err, ErrInvalidCSR) {
				t.Fatalf("invalid identity returned %v; want ErrInvalidCSR", err)
			}
		})
	}
}

func TestSignCSRRejectsLDAPService(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"ldap.home.arpa", "LDAP.Home.Arpa."} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			m := mustOpen(t, testConfig(t), testClock())
			csr := makeCSR(t, &x509.CertificateRequest{DNSNames: []string{name}}, csrKey(t))
			if _, err := m.SignCSR(csr, []string{name}); !errors.Is(err, ErrInvalidCSR) {
				t.Fatalf("built-in LDAP identity returned %v, want ErrInvalidCSR", err)
			}
		})
	}
}

func TestSignCSRRejectsBadEncodingAndSignature(t *testing.T) {
	t.Parallel()
	m := mustOpen(t, testConfig(t), testClock())
	csr := makeCSR(t, &x509.CertificateRequest{DNSNames: []string{"app.home.arpa"}}, csrKey(t))
	csr[len(csr)-1] ^= 1
	for _, tc := range []struct {
		name string
		der  []byte
	}{
		{name: "invalid signature", der: csr},
		{name: "empty"},
		{name: "oversize", der: make([]byte, 65537)},
		{name: "invalid ASN1", der: []byte("malformed")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := m.SignCSR(tc.der, []string{"app.home.arpa"}); !errors.Is(err, ErrInvalidCSR) {
				t.Fatalf("invalid CSR returned %v; want ErrInvalidCSR", err)
			}
		})
	}
}

func TestSignCSRRejectsUnknownSANs(t *testing.T) {
	t.Parallel()
	for _, tag := range []int{0, 3, 4, 5, 8} {
		t.Run(big.NewInt(int64(tag)).String(), func(t *testing.T) {
			t.Parallel()
			san, err := asn1.Marshal([]asn1.RawValue{
				{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("app.home.arpa")},
				{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: tag != 8, Bytes: []byte{5, 0}},
			})
			if err != nil {
				t.Fatal(err)
			}
			csr := makeCSR(t, &x509.CertificateRequest{
				ExtraExtensions: []pkix.Extension{{Id: oidSubjectAltName, Value: san}},
			}, csrKey(t))
			m := mustOpen(t, testConfig(t), testClock())
			if _, err := m.SignCSR(csr, []string{"app.home.arpa"}); !errors.Is(err, ErrInvalidCSR) {
				t.Fatalf("unsupported SAN returned %v; want ErrInvalidCSR", err)
			}
		})
	}
}

func TestSignCSRRejectsWeakKeys(t *testing.T) {
	t.Parallel()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	csr := makeCSR(t, &x509.CertificateRequest{DNSNames: []string{"app.home.arpa"}}, key)
	m := mustOpen(t, testConfig(t), testClock())
	if _, err := m.SignCSR(csr, []string{"app.home.arpa"}); !errors.Is(err, ErrInvalidCSR) {
		t.Fatalf("weak key returned %v; want ErrInvalidCSR", err)
	}
}

func TestSignCSRDiscardsUnverifiedExtensions(t *testing.T) {
	t.Parallel()
	constraints, err := asn1.Marshal(struct{ IsCA bool }{IsCA: true})
	if err != nil {
		t.Fatal(err)
	}
	extendedUsage, err := asn1.Marshal([]asn1.ObjectIdentifier{{2, 5, 29, 37, 0}})
	if err != nil {
		t.Fatal(err)
	}
	customOID := asn1.ObjectIdentifier{1, 2, 3, 4}
	csr := makeCSR(t, &x509.CertificateRequest{
		DNSNames: []string{"app.home.arpa"},
		ExtraExtensions: []pkix.Extension{
			{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Value: constraints},
			{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Value: extendedUsage},
			{Id: customOID, Value: []byte{5, 0}},
		},
	}, csrKey(t))
	m := mustOpen(t, testConfig(t), testClock())
	chain, err := m.SignCSR(csr, []string{"app.home.arpa"})
	if err != nil {
		t.Fatal(err)
	}
	cert := parseIssuedChain(t, chain)[0]
	if cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign != 0 ||
		!slices.Equal(cert.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}) {
		t.Fatal("CSR requested extensions overrode the TLS server certificate profile")
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(customOID) {
			t.Fatal("unverified custom extension was copied into certificate")
		}
	}
}

func TestSignCSRAcceptsCriticalDNSNames(t *testing.T) {
	t.Parallel()
	san, err := asn1.Marshal([]asn1.RawValue{
		{Class: asn1.ClassContextSpecific, Tag: 2, Bytes: []byte("app.home.arpa")},
	})
	if err != nil {
		t.Fatal(err)
	}
	csr := makeCSR(t, &x509.CertificateRequest{
		ExtraExtensions: []pkix.Extension{{Id: oidSubjectAltName, Critical: true, Value: san}},
	}, csrKey(t))
	m := mustOpen(t, testConfig(t), testClock())
	chain, err := m.SignCSR(csr, []string{"app.home.arpa"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(parseIssuedChain(t, chain)[0].DNSNames, []string{"app.home.arpa"}) {
		t.Fatal("critical DNS SAN was not preserved")
	}
}

func TestSignCSRRootValidity(t *testing.T) {
	t.Parallel()
	m := mustOpen(t, testConfig(t), testClock())
	now := m.root.Leaf.NotAfter.Add(-time.Hour)
	m.now = func() time.Time { return now }
	csr := makeCSR(t, &x509.CertificateRequest{DNSNames: []string{"app.home.arpa"}}, csrKey(t))
	chain, err := m.SignCSR(csr, []string{"app.home.arpa"})
	if err != nil {
		t.Fatal(err)
	}
	if !parseIssuedChain(t, chain)[0].NotAfter.Equal(m.root.Leaf.NotAfter) {
		t.Fatal("leaf outlived the root")
	}
	for _, invalidTime := range []time.Time{m.root.Leaf.NotAfter, m.root.Leaf.NotBefore.Add(-time.Second)} {
		now = invalidTime
		if _, err := m.SignCSR(csr, []string{"app.home.arpa"}); err == nil || errors.Is(err, ErrInvalidCSR) {
			t.Fatalf("invalid root returned %v; want an operational error", err)
		}
	}
}

func TestCreateCRL(t *testing.T) {
	t.Parallel()
	now := testClock()
	m := mustOpen(t, testConfig(t), now)
	csr := makeCSR(t, &x509.CertificateRequest{DNSNames: []string{"app.home.arpa"}}, csrKey(t))
	chain, err := m.SignCSR(csr, []string{"app.home.arpa"})
	if err != nil {
		t.Fatal(err)
	}
	serial := parseIssuedChain(t, chain)[0].SerialNumber
	der, err := m.CreateCRL([]x509.RevocationListEntry{{
		SerialNumber: serial, RevocationTime: now.Add(-time.Minute), ReasonCode: 1,
		ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}},
	}}, 2)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.CheckSignatureFrom(m.root.Leaf); err != nil {
		t.Fatal(err)
	}
	if crl.Number.Int64() != 2 || !crl.ThisUpdate.Equal(now) || !crl.NextUpdate.Equal(now.Add(24*time.Hour)) ||
		len(crl.RevokedCertificateEntries) != 1 {
		t.Fatal("unexpected CRL validity, number, or entries")
	}
	entry := crl.RevokedCertificateEntries[0]
	if entry.SerialNumber.Cmp(serial) != 0 || entry.ReasonCode != 1 || !entry.RevocationTime.Equal(now.Add(-time.Minute)) || len(entry.Extensions) != 1 {
		t.Fatal("revocation was lost or unverified extensions were included")
	}
	nearExpiry := m.root.Leaf.NotAfter.Add(-time.Hour)
	m.now = func() time.Time { return nearExpiry }
	der, err = m.CreateCRL(nil, 3)
	if err != nil {
		t.Fatal(err)
	}
	crl, err = x509.ParseRevocationList(der)
	if err != nil {
		t.Fatal(err)
	}
	if !crl.NextUpdate.Equal(m.root.Leaf.NotAfter) {
		t.Fatal("CRL outlived the root")
	}
	nearExpiry = m.root.Leaf.NotAfter
	if _, err := m.CreateCRL(nil, 4); err == nil {
		t.Fatal("expired root signed a CRL")
	}
}

func TestCreateCRLRejectsInvalidEntries(t *testing.T) {
	t.Parallel()
	now := testClock()
	m := mustOpen(t, testConfig(t), now)
	for _, tc := range []struct {
		name   string
		change func(*x509.RevocationListEntry)
	}{
		{name: "nil serial", change: func(e *x509.RevocationListEntry) { e.SerialNumber = nil }},
		{name: "zero serial", change: func(e *x509.RevocationListEntry) { e.SerialNumber = big.NewInt(0) }},
		{name: "negative serial", change: func(e *x509.RevocationListEntry) { e.SerialNumber = big.NewInt(-1) }},
		{name: "future time", change: func(e *x509.RevocationListEntry) { e.RevocationTime = now.Add(time.Second) }},
		{name: "zero time", change: func(e *x509.RevocationListEntry) { e.RevocationTime = time.Time{} }},
		{name: "negative reason", change: func(e *x509.RevocationListEntry) { e.ReasonCode = -1 }},
		{name: "unused reason", change: func(e *x509.RevocationListEntry) { e.ReasonCode = 7 }},
		{name: "unknown reason", change: func(e *x509.RevocationListEntry) { e.ReasonCode = 11 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := x509.RevocationListEntry{SerialNumber: big.NewInt(1), RevocationTime: now, ReasonCode: 0}
			tc.change(&entry)
			if _, err := m.CreateCRL([]x509.RevocationListEntry{entry}, 1); err == nil {
				t.Fatal("invalid CRL entry was accepted")
			}
		})
	}
	if _, err := m.CreateCRL(nil, 0); err == nil {
		t.Fatal("zero CRL number was accepted")
	}
	entry := x509.RevocationListEntry{SerialNumber: big.NewInt(1), RevocationTime: now}
	if _, err := m.CreateCRL([]x509.RevocationListEntry{entry, entry}, 1); err == nil {
		t.Fatal("duplicate revocations were accepted")
	}
}
