//go:build integration

package ldapserver

import (
	"net"
	"strings"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func TestLDAPListenFailureClosesSibling(t *testing.T) {
	t.Parallel()
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Addr().String()
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}
	// The first listener occupies the selected port, so the second must fail.
	// Run must release the first listener before reporting that startup failed.
	server := &Server{config: config.LDAPConfig{Listen: address, TLSListen: address}}
	if err := server.Run(t.Context()); err == nil || !strings.Contains(err.Error(), "listen for LDAPS:") {
		t.Fatalf("expected LDAPS startup failure, got %v", err)
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("LDAP listener still bound after LDAPS startup failed: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
}
