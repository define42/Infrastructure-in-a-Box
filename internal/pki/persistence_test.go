package pki

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestReadBundleRejectsSymlink(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	mustOpen(t, cfg, testClock())
	for _, name := range []string{rootBundleName, leafBundleName} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(cfg.Directory, name)
			link := filepath.Join(t.TempDir(), name)
			if err := os.Symlink(path, link); err != nil {
				t.Fatal(err)
			}
			if _, err := readBundle(link); err == nil {
				t.Error("symlink accepted for private state")
			}
		})
	}
}

func TestParseBundleRejectsTrailingData(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	mustOpen(t, cfg, testClock())
	bundle := mustRead(t, cfg, rootBundleName)
	for _, tt := range []struct {
		name string
		data []byte
	}{
		{name: "trailing text", data: append(bytes.Clone(bundle), []byte("trailing junk")...)},
		{name: "extra PEM block", data: append(bytes.Clone(bundle), bundle...)},
		{name: "leading text", data: append([]byte("leading junk"), bundle...)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseBundle(tt.data); err == nil {
				t.Error("bundle with extraneous data accepted")
			}
		})
	}
}

func TestWriteFileNeverOverwritesExistingRoot(t *testing.T) {
	t.Parallel()
	cfg := testConfig(t)
	mustOpen(t, cfg, testClock())
	original := mustRead(t, cfg, rootBundleName)
	if err := writeFile(cfg.Directory, rootBundleName, []byte("replacement"), 0o600, true); !os.IsExist(err) {
		t.Fatalf("exclusive root write error = %v, want file exists", err)
	}
	if !bytes.Equal(original, mustRead(t, cfg, rootBundleName)) {
		t.Error("exclusive write replaced the existing trust identity")
	}
	entries, err := os.ReadDir(cfg.Directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("directory contains %d files, want only the two bundles and public export", len(entries))
	}
}
