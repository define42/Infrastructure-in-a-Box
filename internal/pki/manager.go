// Package pki maintains the private certificate authority and service certificates.
package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
)

const (
	rootBundleName = "root-ca-bundle.pem"
	leafBundleName = "gateway-bundle.pem"
	ldapBundleName = "ldap-bundle.pem"
	rootPublicName = "root-ca.pem"
	leafLifetime   = 90 * 24 * time.Hour
	renewBefore    = 30 * 24 * time.Hour
	clockSkew      = 5 * time.Minute
)

// Config identifies the private state directory and service certificate names.
type Config struct {
	Directory string
	Domain    string
	ServerIP  netip.Addr
	// CRLURL is the optional public revocation list URL for ACME certificates.
	CRLURL string
}

// Manager holds a persistent CA and renews its service certificates. Certificate
// and key bundles are private; RootPEM and root-ca.pem contain only the public CA.
type Manager struct {
	mu       sync.Mutex
	cfg      Config
	hostname string
	now      func() time.Time
	root     *tls.Certificate
	rootPEM  []byte
	leaf     *tls.Certificate
	ldapLeaf *tls.Certificate
}

// Open creates a CA on first use, or loads the existing identity. Invalid or
// incomplete private material is an error and is never silently replaced.
func Open(cfg Config) (*Manager, error) {
	return open(cfg, time.Now)
}

func open(cfg Config, now func() time.Time) (*Manager, error) {
	hostname := strings.TrimSuffix(lease.NormalizeHostname("gateway", cfg.Domain), ".")
	if hostname == "" {
		return nil, errors.New("invalid domain for gateway certificate")
	}
	if !cfg.ServerIP.IsValid() || cfg.ServerIP.IsUnspecified() || cfg.ServerIP.IsMulticast() || cfg.ServerIP.Zone() != "" {
		return nil, errors.New("gateway certificate requires a valid unicast server IP")
	}
	cfg.ServerIP = cfg.ServerIP.Unmap()
	if strings.TrimSpace(cfg.Directory) == "" {
		return nil, errors.New("CA directory is required")
	}
	if err := os.MkdirAll(cfg.Directory, 0o700); err != nil {
		return nil, fmt.Errorf("create CA directory: %w", err)
	}
	info, err := os.Lstat(cfg.Directory)
	if err != nil {
		return nil, fmt.Errorf("inspect CA directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("CA directory must be a directory, not a symlink")
	}
	if err := os.Chmod(cfg.Directory, 0o700); err != nil {
		return nil, fmt.Errorf("secure CA directory: %w", err)
	}
	m := &Manager{cfg: cfg, hostname: hostname, now: now}
	m.root, err = readBundle(filepath.Join(cfg.Directory, rootBundleName))
	if errors.Is(err, os.ErrNotExist) {
		entries, readErr := os.ReadDir(cfg.Directory)
		if readErr != nil {
			return nil, fmt.Errorf("inspect CA state: %w", readErr)
		}
		if len(entries) != 0 {
			return nil, errors.New("root CA bundle is missing from a nonempty CA directory; restore the original bundle")
		}
		m.root, err = m.createRoot()
	}
	if err != nil {
		return nil, fmt.Errorf("load root CA: %w", err)
	}
	if err := m.validateRoot(now()); err != nil {
		return nil, err
	}
	m.rootPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.root.Leaf.Raw})
	// The private bundle is authoritative. Repair a missing or stale public copy
	// without changing the trust identity, including after an interrupted export.
	if err := writeFile(cfg.Directory, rootPublicName, m.rootPEM, 0o644, false); err != nil {
		return nil, fmt.Errorf("export public root CA: %w", err)
	}
	if _, err := m.GetCertificate(nil); err != nil {
		return nil, err
	}
	return m, nil
}

// RootPEM returns a copy of the public CA certificate, without its private key.
func (m *Manager) RootPEM() []byte {
	return bytes.Clone(m.rootPEM)
}

// GetCertificate implements tls.Config.GetCertificate, renewing on demand within
// 30 days of expiry. The returned certificate must not be modified by callers.
// ClientHello names never influence issuance: only the configured gateway is signed.
func (m *Manager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.serviceCertificate("gateway", m.hostname, leafBundleName, &m.leaf)
}

// GetLDAPCertificate implements tls.Config.GetCertificate for ldap.<domain> and
// the configured server IP. It loads or creates its private bundle on first use,
// so callers should invoke it at LDAP startup to report any invalid private state.
// Certificates renew within 30 days of expiry and must not be modified by callers.
// ClientHello names never influence issuance.
func (m *Manager) GetLDAPCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	hostname := "ldap." + strings.TrimPrefix(m.hostname, "gateway.")
	return m.serviceCertificate("LDAP", hostname, ldapBundleName, &m.ldapLeaf)
}

// serviceCertificate runs with m.mu held, including disk writes, so concurrent
// handshakes cannot publish different replacements for the same certificate.
func (m *Manager) serviceCertificate(service, hostname, bundleName string, current **tls.Certificate) (*tls.Certificate, error) {
	now := m.now()
	if err := m.validateRoot(now); err != nil {
		return nil, err
	}
	if *current == nil {
		cert, err := readBundle(filepath.Join(m.cfg.Directory, bundleName))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("load %s certificate: %w", service, err)
		}
		if cert != nil {
			if err := m.validateLeaf(cert); err != nil {
				return nil, fmt.Errorf("validate %s certificate: %w", service, err)
			}
		}
		*current = cert
	}
	if m.needsRenewal(*current, hostname, now) {
		cert, err := m.issueLeaf(hostname, bundleName, now)
		if err != nil {
			return nil, fmt.Errorf("issue %s certificate: %w", service, err)
		}
		*current = cert
	}
	return *current, nil
}

func (m *Manager) validateRoot(now time.Time) error {
	root := m.root.Leaf
	if !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("root certificate is not a signing CA")
	}
	if !bytes.Equal(root.RawSubject, root.RawIssuer) {
		return errors.New("root CA must be self-issued")
	}
	if err := root.CheckSignatureFrom(root); err != nil {
		return fmt.Errorf("verify root CA signature: %w", err)
	}
	if now.Before(root.NotBefore) || !now.Before(root.NotAfter) {
		return fmt.Errorf("root CA is not valid at %s; check the clock or explicitly migrate the CA", now.UTC().Format(time.RFC3339))
	}
	if len(root.UnhandledCriticalExtensions) != 0 {
		return errors.New("root CA contains unsupported critical extensions")
	}
	return nil
}

func (m *Manager) validateLeaf(cert *tls.Certificate) error {
	leaf := cert.Leaf
	if leaf.IsCA || !leaf.BasicConstraintsValid || leaf.KeyUsage != x509.KeyUsageDigitalSignature ||
		len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		return errors.New("certificate must be a TLS server certificate")
	}
	if err := leaf.CheckSignatureFrom(m.root.Leaf); err != nil {
		return fmt.Errorf("certificate does not belong to the root CA: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(m.root.Leaf)
	// Verify structural and chain constraints at issuance time so an expired
	// otherwise valid service certificate can be renewed after a long shutdown.
	_, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: leaf.NotBefore})
	return err
}

func (m *Manager) needsRenewal(cert *tls.Certificate, hostname string, now time.Time) bool {
	if cert == nil {
		return true
	}
	leaf := cert.Leaf
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != hostname || len(leaf.IPAddresses) != 1 ||
		!leaf.IPAddresses[0].Equal(net.IP(m.cfg.ServerIP.AsSlice())) {
		return true
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return true
	}
	// A certificate capped at root expiry cannot be extended. Avoid reissuing
	// it on every handshake during the root's final 30 days.
	return !now.Add(renewBefore).Before(leaf.NotAfter) && leaf.NotAfter.Before(m.root.Leaf.NotAfter)
}

func (m *Manager) createRoot() (*tls.Certificate, error) {
	now := m.now()
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "Infrastructure-in-a-Box Root CA"},
		NotBefore:             now.Add(-clockSkew),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	cert, bundle, err := issue(template, nil)
	if err != nil {
		return nil, err
	}
	if err := writeFile(m.cfg.Directory, rootBundleName, bundle, 0o600, true); err != nil {
		return nil, fmt.Errorf("persist root CA: %w", err)
	}
	return cert, nil
}

func (m *Manager) issueLeaf(hostname, bundleName string, now time.Time) (*tls.Certificate, error) {
	notBefore, notAfter := now.Add(-clockSkew), now.Add(leafLifetime)
	if notBefore.Before(m.root.Leaf.NotBefore) {
		notBefore = m.root.Leaf.NotBefore
	}
	if notAfter.After(m.root.Leaf.NotAfter) {
		notAfter = m.root.Leaf.NotAfter
	}
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: hostname},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
		IPAddresses:           []net.IP{net.IP(m.cfg.ServerIP.AsSlice())},
	}
	cert, bundle, err := issue(template, m.root)
	if err != nil {
		return nil, err
	}
	if err := writeFile(m.cfg.Directory, bundleName, bundle, 0o600, false); err != nil {
		return nil, fmt.Errorf("persist certificate: %w", err)
	}
	return cert, nil
}

func issue(template *x509.Certificate, parent *tls.Certificate) (*tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate key: %w", err)
	}
	// A nonzero random 128-bit serial fits comfortably inside RFC 5280's limit.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	template.SerialNumber = serial.Add(serial, big.NewInt(1))
	signer, issuer := key, template
	if parent != nil {
		signer, issuer = parent.PrivateKey.(*ecdsa.PrivateKey), parent.Leaf
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("encode private key: %w", err)
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})...)
	cert, err := parseBundle(bundle)
	return cert, bundle, err
}
