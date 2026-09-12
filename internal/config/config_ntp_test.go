package config_test

import (
	"strings"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func TestNTPAlwaysUsesServerIP(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(writeConfig(t, "server_ip", "192.168.50.3"))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NTPAddress != "192.168.50.3:123" {
		t.Fatalf("NTP address = %q", cfg.NTPAddress)
	}
}

func TestNTPRejectsConflictingDHCPListener(t *testing.T) {
	t.Parallel()
	for _, address := range []string{":123", "0.0.0.0:123", "192.168.50.2:123"} {
		_, err := config.Load(writeConfig(t, "server_ip", "192.168.50.2", "dhcp_listen", address))
		if err == nil || !strings.Contains(err.Error(), "conflicts with NTP") {
			t.Errorf("DHCP listener %q: %v", address, err)
		}
	}
}
