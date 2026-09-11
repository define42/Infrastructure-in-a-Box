package pki

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testConfig(t *testing.T) Config {
	t.Helper()
	return Config{Directory: t.TempDir(), Domain: "home.arpa", ServerIP: netip.MustParseAddr("192.168.50.1")}
}

func testClock() time.Time {
	return time.Date(2026, time.September, 11, 12, 0, 0, 0, time.UTC)
}

func mustOpen(t *testing.T, cfg Config, now time.Time) *Manager {
	t.Helper()
	m, err := open(cfg, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func mustCertificate(t *testing.T, m *Manager) *tls.Certificate {
	t.Helper()
	cert, err := m.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func mustRead(t *testing.T, cfg Config, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(cfg.Directory, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOpen(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	now := testClock()
	m := mustOpen(t, cfg, now)
	rootPEM := m.RootPEM()
	block, rest := pem.Decode(rootPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("public CA must contain exactly one certificate and no private key")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !root.IsCA || !root.BasicConstraintsValid || !root.MaxPathLenZero || root.MaxPathLen != 0 ||
		root.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign || root.SerialNumber.Sign() <= 0 {
		t.Fatalf("invalid CA signing constraints: %+v", root)
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		t.Fatalf("root is not self-signed: %v", err)
	}
	if !root.NotAfter.Equal(now.AddDate(10, 0, 0)) {
		t.Fatalf("root expiry = %s", root.NotAfter)
	}
	cert := mustCertificate(t, m)
	if len(cert.Certificate) != 1 {
		t.Fatalf("TLS chain includes %d certificates, want only the leaf", len(cert.Certificate))
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	for _, name := range []string{"gateway.home.arpa", cfg.ServerIP.String()} {
		if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, CurrentTime: now}); err != nil {
			t.Errorf("verify gateway certificate for %s: %v", name, err)
		}
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "other.home.arpa", CurrentTime: now}); err == nil {
		t.Error("certificate verified for an unrelated name")
	}
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{
		Roots: roots, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err == nil {
		t.Error("gateway certificate verified for client authentication")
	}
	if cert.Leaf.IsCA || cert.Leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		!cert.Leaf.NotAfter.Equal(now.Add(leafLifetime)) || cert.Leaf.SerialNumber.Sign() <= 0 {
		t.Fatal("invalid gateway certificate constraints or lifetime")
	}
	if bytes.Equal(root.RawSubjectPublicKeyInfo, cert.Leaf.RawSubjectPublicKeyInfo) {
		t.Error("root and gateway reuse the same key")
	}
	if got := mustRead(t, cfg, rootPublicName); !bytes.Equal(got, rootPEM) {
		t.Error("public CA export differs from RootPEM")
	}
	rootPEM[0] = '!'
	if m.RootPEM()[0] == '!' {
		t.Error("RootPEM exposes mutable manager state")
	}
	for _, entry := range []struct {
		name string
		mode os.FileMode
	}{
		{name: ".", mode: 0o700},
		{name: rootBundleName, mode: 0o600},
		{name: leafBundleName, mode: 0o600},
		{name: rootPublicName, mode: 0o644},
	} {
		info, err := os.Stat(filepath.Join(cfg.Directory, entry.name))
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != entry.mode {
			t.Errorf("%s permissions = %o, want %o", entry.name, info.Mode().Perm(), entry.mode)
		}
	}
	rootBundle, leafBundle := mustRead(t, cfg, rootBundleName), mustRead(t, cfg, leafBundleName)
	reopened := mustOpen(t, cfg, now.Add(time.Hour))
	if !bytes.Equal(rootBundle, mustRead(t, cfg, rootBundleName)) ||
		!bytes.Equal(leafBundle, mustRead(t, cfg, leafBundleName)) ||
		!bytes.Equal(cert.Leaf.Raw, mustCertificate(t, reopened).Leaf.Raw) {
		t.Error("restart changed the persistent CA or unexpired gateway certificate")
	}
}

func TestOpenValidatesConfiguration(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		change func(*Config)
	}{
		{name: "empty directory", change: func(c *Config) { c.Directory = "" }},
		{name: "empty domain", change: func(c *Config) { c.Domain = "" }},
		{name: "wildcard domain", change: func(c *Config) { c.Domain = "*.home.arpa" }},
		{name: "invalid IP", change: func(c *Config) { c.ServerIP = netip.Addr{} }},
		{name: "unspecified IP", change: func(c *Config) { c.ServerIP = netip.IPv4Unspecified() }},
		{name: "multicast IP", change: func(c *Config) { c.ServerIP = netip.MustParseAddr("224.0.0.1") }},
		{name: "scoped IP", change: func(c *Config) { c.ServerIP = netip.MustParseAddr("fe80::1%eth0") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(t)
			tt.change(&cfg)
			if _, err := Open(cfg); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}

func TestOpenRenewsLeaf(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name    string
		elapsed time.Duration
		change  func(*Config)
	}{
		{name: "near expiry", elapsed: 61 * 24 * time.Hour},
		{name: "expired", elapsed: 91 * 24 * time.Hour},
		{name: "domain changed", change: func(c *Config) { c.Domain = "office.test" }},
		{name: "IP changed", change: func(c *Config) { c.ServerIP = netip.MustParseAddr("192.168.50.2") }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(t)
			now := testClock()
			before := mustCertificate(t, mustOpen(t, cfg, now))
			root := mustRead(t, cfg, rootBundleName)
			if tt.change != nil {
				tt.change(&cfg)
			}
			after := mustCertificate(t, mustOpen(t, cfg, now.Add(tt.elapsed)))
			if bytes.Equal(before.Leaf.Raw, after.Leaf.Raw) {
				t.Error("gateway certificate was not renewed")
			}
			if !bytes.Equal(root, mustRead(t, cfg, rootBundleName)) {
				t.Error("renewal changed the root CA")
			}
			for _, name := range []string{"gateway." + cfg.Domain, cfg.ServerIP.String()} {
				if err := after.Leaf.VerifyHostname(name); err != nil {
					t.Error(err)
				}
			}
			if bytes.Equal(before.Leaf.RawSubjectPublicKeyInfo, after.Leaf.RawSubjectPublicKeyInfo) {
				t.Error("renewal did not rotate the gateway key")
			}
		})
	}
}

func TestOpenRepairsPublicExportAndMissingLeaf(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	now := testClock()
	before := mustOpen(t, cfg, now)
	root := mustRead(t, cfg, rootBundleName)
	if err := os.WriteFile(filepath.Join(cfg.Directory, rootPublicName), []byte("stale export"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cfg.Directory, leafBundleName)); err != nil {
		t.Fatal(err)
	}
	after := mustOpen(t, cfg, now)
	if !bytes.Equal(root, mustRead(t, cfg, rootBundleName)) || !bytes.Equal(before.RootPEM(), after.RootPEM()) ||
		!bytes.Equal(after.RootPEM(), mustRead(t, cfg, rootPublicName)) {
		t.Error("repair failed to retain the same trust identity")
	}
	if bytes.Equal(mustCertificate(t, before).Leaf.Raw, mustCertificate(t, after).Leaf.Raw) {
		t.Error("missing leaf was not reissued")
	}
}

func TestOpenRejectsInvalidPrivateState(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name   string
		change func(*testing.T, Config)
	}{
		{name: "missing root", change: func(t *testing.T, cfg Config) {
			if err := os.Remove(filepath.Join(cfg.Directory, rootBundleName)); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "corrupt root", change: func(t *testing.T, cfg Config) {
			writeTestFile(t, cfg, rootBundleName, []byte("corrupt root"))
		}},
		{name: "corrupt leaf", change: func(t *testing.T, cfg Config) {
			writeTestFile(t, cfg, leafBundleName, []byte("corrupt leaf"))
		}},
		{name: "partial root", change: func(t *testing.T, cfg Config) {
			block, _ := pem.Decode(mustRead(t, cfg, rootBundleName))
			writeTestFile(t, cfg, rootBundleName, pem.EncodeToMemory(block))
		}},
		{name: "partial leaf", change: func(t *testing.T, cfg Config) {
			_, key := pem.Decode(mustRead(t, cfg, leafBundleName))
			writeTestFile(t, cfg, leafBundleName, key)
		}},
		{name: "mismatched root key", change: func(t *testing.T, cfg Config) {
			root, _ := pem.Decode(mustRead(t, cfg, rootBundleName))
			_, leafKey := pem.Decode(mustRead(t, cfg, leafBundleName))
			writeTestFile(t, cfg, rootBundleName, append(pem.EncodeToMemory(root), leafKey...))
		}},
		{name: "different signing CA", change: func(t *testing.T, cfg Config) {
			other := testConfig(t)
			mustOpen(t, other, testClock())
			writeTestFile(t, cfg, leafBundleName, mustRead(t, other, leafBundleName))
		}},
		{name: "root used as leaf", change: func(t *testing.T, cfg Config) {
			writeTestFile(t, cfg, leafBundleName, mustRead(t, cfg, rootBundleName))
		}},
		{name: "exposed root key", change: func(t *testing.T, cfg Config) {
			if err := os.Chmod(filepath.Join(cfg.Directory, rootBundleName), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "exposed leaf key", change: func(t *testing.T, cfg Config) {
			if err := os.Chmod(filepath.Join(cfg.Directory, leafBundleName), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := testConfig(t)
			mustOpen(t, cfg, testClock())
			tt.change(t, cfg)
			rootBefore, rootErr := os.ReadFile(filepath.Join(cfg.Directory, rootBundleName))
			leafBefore := mustRead(t, cfg, leafBundleName)
			if _, err := open(cfg, testClock); err == nil {
				t.Fatal("invalid private state accepted")
			}
			rootAfter, afterErr := os.ReadFile(filepath.Join(cfg.Directory, rootBundleName))
			if !bytes.Equal(rootBefore, rootAfter) || (rootErr == nil) != (afterErr == nil) ||
				!bytes.Equal(leafBefore, mustRead(t, cfg, leafBundleName)) {
				t.Error("failed startup changed existing private material")
			}
		})
	}
}

func writeTestFile(t *testing.T, cfg Config, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(cfg.Directory, name), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestOpenRejectsOrphanedKey(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	writeTestFile(t, cfg, "root-ca-key.pem", []byte("previous private material"))
	if _, err := open(cfg, testClock); err == nil || !strings.Contains(err.Error(), "nonempty") {
		t.Fatalf("Open() error = %v, want refusal to overwrite a possible existing identity", err)
	}
	if _, err := os.Stat(filepath.Join(cfg.Directory, rootBundleName)); !os.IsNotExist(err) {
		t.Fatalf("new root exists: %v", err)
	}
}

func TestGetCertificateRenewsConcurrently(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	now := testClock()
	m, err := open(cfg, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	before := mustCertificate(t, m)
	now = now.Add(61 * 24 * time.Hour)
	const clients = 32
	results := make(chan *tls.Certificate, clients)
	var wg sync.WaitGroup
	for range clients {
		wg.Go(func() {
			cert, err := m.GetCertificate(&tls.ClientHelloInfo{ServerName: "attacker.example"})
			if err != nil {
				t.Error(err)
				return
			}
			results <- cert
		})
	}
	wg.Wait()
	close(results)
	after := mustCertificate(t, m)
	if bytes.Equal(before.Leaf.Raw, after.Leaf.Raw) {
		t.Error("handshake callback did not renew expiring certificate")
	}
	if len(after.Leaf.DNSNames) != 1 || after.Leaf.DNSNames[0] != "gateway.home.arpa" {
		t.Error("client hello changed the issued hostname")
	}
	for cert := range results {
		if !bytes.Equal(cert.Leaf.Raw, after.Leaf.Raw) {
			t.Error("concurrent handshakes received different renewed certificates")
		}
	}
	if !bytes.Equal(after.Leaf.Raw, mustCertificate(t, mustOpen(t, cfg, now)).Leaf.Raw) {
		t.Error("renewed certificate did not survive restart")
	}
}

func TestGetCertificateCapsValidityAtRootExpiry(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	now := testClock()
	m, err := open(cfg, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	root := mustRead(t, cfg, rootBundleName)
	rootExpiry := now.AddDate(10, 0, 0)
	now = rootExpiry.Add(-5 * 24 * time.Hour)
	cert := mustCertificate(t, m)
	if !cert.Leaf.NotAfter.Equal(rootExpiry) {
		t.Fatalf("leaf expiry = %s, root expiry = %s", cert.Leaf.NotAfter, rootExpiry)
	}
	if !bytes.Equal(cert.Leaf.Raw, mustCertificate(t, m).Leaf.Raw) {
		t.Error("certificate capped at root expiry was renewed repeatedly")
	}
	now = rootExpiry
	if _, err := m.GetCertificate(nil); err == nil {
		t.Error("expired root accepted during handshake")
	}
	if _, err := open(cfg, func() time.Time { return now }); err == nil {
		t.Error("expired root accepted on restart")
	}
	if !bytes.Equal(root, mustRead(t, cfg, rootBundleName)) {
		t.Error("expired root was silently replaced")
	}
}

func TestGetCertificateReportsPersistenceFailure(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	now := testClock()
	m, err := open(cfg, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.Directory, leafBundleName)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	now = now.Add(61 * 24 * time.Hour)
	if _, err := m.GetCertificate(nil); err == nil || !strings.Contains(err.Error(), "persist") {
		t.Fatalf("GetCertificate() error = %v, want persistence failure", err)
	}
}
