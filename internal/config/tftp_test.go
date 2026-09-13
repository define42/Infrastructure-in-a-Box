package config_test

import (
	"strings"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func TestTFTPListenerCannotBeDisabled(t *testing.T) {
	t.Parallel()
	_, err := config.Load(writeConfig(t, "tftp_listen", ""))
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "tftp") {
		t.Fatalf("unsafe TFTP settings accepted: %v", err)
	}
}
