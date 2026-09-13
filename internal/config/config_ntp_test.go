package config_test

import (
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
