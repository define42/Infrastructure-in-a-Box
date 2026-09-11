package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func readBundle(path string) (*tls.Certificate, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file, not a symlink", path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s contains a private key; restrict its permissions to 0600", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseBundle(data)
}

func parseBundle(data []byte) (*tls.Certificate, error) {
	rest := bytes.TrimSpace(data)
	for _, blockType := range []string{"CERTIFICATE", "PRIVATE KEY"} {
		if !bytes.HasPrefix(rest, []byte("-----BEGIN "+blockType+"-----")) {
			return nil, fmt.Errorf("certificate bundle is missing its %s block", blockType)
		}
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != blockType || len(block.Headers) != 0 {
			return nil, fmt.Errorf("certificate bundle contains an invalid %s block", blockType)
		}
		rest = bytes.TrimSpace(remaining)
	}
	if len(rest) != 0 {
		return nil, errors.New("certificate bundle contains unexpected trailing data")
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return nil, fmt.Errorf("parse certificate and matching private key: %w", err)
	}
	key, ok := cert.PrivateKey.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("certificate bundle requires an ECDSA P-256 private key")
	}
	// Explicit parsing also supports GODEBUG=x509keypairleaf=0.
	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}
	return &cert, nil
}

// writeFile publishes a fully written bundle atomically. Root creation uses an
// exclusive hard link so competing processes cannot overwrite the trust identity.
func writeFile(dir, name string, data []byte, mode os.FileMode, exclusive bool) error {
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := tmp.Chmod(mode); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	path := filepath.Join(dir, name)
	if exclusive {
		err = os.Link(tmp.Name(), path)
	} else {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		return err
	}
	// Persist the directory entry as well as file contents before reporting
	// success; an unclean restart must not silently lose a newly created CA.
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
