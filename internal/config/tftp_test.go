package config_test

import (
	"strings"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func TestTFTPRejectsUnsafeConfiguration(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		values []string
	}{
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
