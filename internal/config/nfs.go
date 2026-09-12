package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// NFSShare exports Path at /Share in the NFSv4 namespace.
// Path must be an absolute directory path; directories must exist at startup.
type NFSShare struct {
	Share    string `json:"share"`
	Path     string `json:"path"`
	ReadOnly bool   `json:"read_only"`
}

var nfsSharePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}$`)

// ValidateNFSShares checks names, paths, and overlapping exports without filesystem I/O.
func ValidateNFSShares(shares []NFSShare) error {
	names := make(map[string]bool, len(shares))
	for i, share := range shares {
		if !nfsSharePattern.MatchString(share.Share) {
			return fmt.Errorf("nfs[%d].share must be a single name of 1–255 ASCII letters, digits, underscores, dots, or hyphens, starting with a letter, digit, or underscore", i)
		}
		if names[share.Share] {
			return fmt.Errorf("nfs[%d].share duplicates %q", i, share.Share)
		}
		names[share.Share] = true
		if !filepath.IsAbs(share.Path) || strings.ContainsRune(share.Path, 0) {
			return fmt.Errorf("nfs[%d].path must be an absolute directory path", i)
		}
		for _, previous := range shares[:i] {
			if pathWithin(previous.Path, share.Path) || pathWithin(share.Path, previous.Path) {
				return fmt.Errorf("nfs shares %q and %q must not overlap", previous.Share, share.Share)
			}
		}
	}
	return nil
}

func decodeNFS(decoder *json.Decoder) ([]NFSShare, error) {
	return decodeLDAPArray(decoder, "nfs", func(decoder *json.Decoder, path string) (NFSShare, error) {
		var share NFSShare
		err := decodeLDAPObject(decoder, path, map[string]any{
			"share": &share.Share, "path": &share.Path, "read_only": &share.ReadOnly,
		})
		return share, err
	})
}

// canonicalPath resolves existing ancestors, including when a state file or
// directory has not been created yet. This catches exports through symlink aliases.
func canonicalPath(name string) (string, error) {
	resolved, err := filepath.EvalSymlinks(name)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(name)
	if parent == name {
		return "", err
	}
	resolved, err = canonicalPath(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(resolved, filepath.Base(name)), nil
}

func (c Config) validateNFSPaths(configPath string) error {
	if len(c.NFS) == 0 {
		return nil
	}
	protected := []struct{ name, path string }{
		{"configuration file", configPath}, {"ca_dir", c.CADirectory},
		{"lease_file", c.LeaseFile}, {"acme_state", c.ACMEStateFile},
	}
	for i := range protected {
		if protected[i].path == "" {
			continue
		}
		resolved, err := canonicalPath(protected[i].path)
		if err != nil {
			return fmt.Errorf("resolve NFS protected %s: %w", protected[i].name, err)
		}
		protected[i].path = resolved
	}
	resolvedShares := make([]NFSShare, 0, len(c.NFS))
	for _, share := range c.NFS {
		resolved, err := canonicalPath(share.Path)
		if err != nil {
			return fmt.Errorf("resolve nfs share %q: %w", share.Share, err)
		}
		share.Path = resolved
		resolvedShares = append(resolvedShares, share)
		for _, target := range protected {
			if target.path != "" && pathWithin(share.Path, target.path) {
				return fmt.Errorf("nfs share %q must not contain the %s", share.Share, target.name)
			}
			if target.name == "ca_dir" && pathWithin(target.path, share.Path) {
				return fmt.Errorf("nfs share %q must not be inside ca_dir", share.Share)
			}
		}
	}
	return ValidateNFSShares(resolvedShares)
}
