package config_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func TestBootConfiguration(t *testing.T) {
	t.Parallel()
	for _, root := range []string{"boot", "assets/pxe", "/srv/tftp"} {
		t.Run(root, func(t *testing.T) {
			path := writeConfig(t, "boot_root", root, "server_ip", "192.168.50.3")
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			want := root
			if !filepath.IsAbs(root) {
				want = filepath.Join(filepath.Dir(path), root)
			}
			if cfg.BootDirectory != want {
				t.Fatalf("BootDirectory = %q, want %q", cfg.BootDirectory, want)
			}
		})
	}
}

func TestBootRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		values []string
	}{
		{"empty root", []string{"boot_root", ""}},
		{"blank root", []string{"boot_root", " "}},
		{"configuration exposed", []string{"boot_root", "."}},
		{"CA exposed", []string{"boot_root", "pki"}},
		{"inside CA", []string{"boot_root", "pki/boot"}},
		{"leases exposed", []string{"boot_root", "boot", "lease_file", "boot/leases.json"}},
		{"ACME exposed", []string{"boot_root", "boot", "acme_state", "boot/acme.json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Load(writeConfig(t, tc.values...))
			if err == nil || !strings.Contains(err.Error(), "boot_root") {
				t.Fatalf("unsafe boot settings accepted: %v", err)
			}
		})
	}
}
