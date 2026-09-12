package config_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func TestTFTPConfiguration(t *testing.T) {
	t.Parallel()
	for _, root := range []string{"boot", "assets/pxe", "/srv/tftp"} {
		t.Run(root, func(t *testing.T) {
			path := writeConfig(t, "tftp_root", root, "server_ip", "192.168.50.3")
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatal(err)
			}
			want := root
			if !filepath.IsAbs(root) {
				want = filepath.Join(filepath.Dir(path), root)
			}
			if cfg.TFTPAddress != "192.168.50.3:69" || cfg.TFTPDirectory != want {
				t.Fatalf("unexpected TFTP settings: %+v", cfg)
			}
		})
	}
}

func TestTFTPRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		values []string
	}{
		{"empty root", []string{"tftp_root", ""}},
		{"blank root", []string{"tftp_root", " "}},
		{"configuration exposed", []string{"tftp_root", "."}},
		{"CA exposed", []string{"tftp_root", "pki"}},
		{"inside CA", []string{"tftp_root", "pki/boot"}},
		{"leases exposed", []string{"tftp_root", "boot", "lease_file", "boot/leases.json"}},
		{"ACME exposed", []string{"tftp_root", "boot", "acme_state", "boot/acme.json"}},
		{"DHCP port conflict", []string{"dhcp_listen", ":69"}},
		{"listener cannot be disabled", []string{"tftp_listen", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.Load(writeConfig(t, tc.values...))
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), "tftp") {
				t.Fatalf("unsafe TFTP settings accepted: %v", err)
			}
		})
	}
}
