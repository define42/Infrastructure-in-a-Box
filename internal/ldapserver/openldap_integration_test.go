//go:build integration

package ldapserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
	"github.com/define42/Infrastructure-in-a-Box/internal/pki"
)

// Exercise a separate LDAP implementation when OpenLDAP client tools are present.
func TestOpenLDAPClientIntegration(t *testing.T) {
	t.Parallel()
	client, err := exec.LookPath("ldapsearch")
	if err != nil {
		t.Skip("OpenLDAP ldapsearch is not installed")
	}
	dir := t.TempDir()
	ca, err := pki.Open(pki.Config{
		Directory: filepath.Join(dir, "pki"), Domain: "home.arpa", ServerIP: netip.MustParseAddr("127.0.0.1"),
	})
	if err != nil {
		t.Fatal(err)
	}
	password := "loopback-only-test-password"
	digest := sha256.Sum256([]byte(password))
	cfg := config.LDAPConfig{
		Listen: "127.0.0.1:0", TLSListen: "127.0.0.1:0", BaseDN: "dc=home,dc=arpa",
		Users: []config.LDAPUser{
			{Name: "reader", PrimaryGroup: 5500, PassSHA256: hex.EncodeToString(digest[:]), CanSearch: true},
			{Name: "johndoe", PrimaryGroup: 5510, OtherGroups: []int{5510}, Disabled: true},
		},
		Groups: []config.LDAPGroup{{Name: "readers", GID: 5500}, {Name: "team", GID: 5510}},
	}
	server, err := New(cfg, ca.GetLDAPCertificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	plain, secure, err := server.listen(ctx)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.serve(ctx, plain, secure) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("LDAP shutdown: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("LDAP server did not stop")
		}
	})
	rootFile := filepath.Join(dir, "pki", "root-ca.pem")
	for _, tt := range []struct {
		name string
		url  string
	}{
		{name: "LDAP", url: "ldap://" + plain.Addr().String()},
		{name: "LDAPS", url: "ldaps://" + secure.Addr().String()},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			passwordFile := filepath.Join(t.TempDir(), "password")
			if err := os.WriteFile(passwordFile, []byte(password), 0o600); err != nil {
				t.Fatal(err)
			}
			run := func(args ...string) (string, error) {
				t.Helper()
				ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				base := []string{"-LLL", "-x", "-H", tt.url}
				cmd := exec.CommandContext(ctx, client, append(base, args...)...)
				cmd.Env = append(os.Environ(), "LDAPTLS_CACERT="+rootFile, "LDAPTLS_REQCERT=demand", "LDAPTLS_REQSAN=demand")
				out, err := cmd.CombinedOutput()
				return string(out), err
			}
			out, err := run("-s", "base", "-b", "", "(objectClass=*)", "namingContexts")
			if err != nil || !strings.Contains(out, "namingContexts: dc=home,dc=arpa") {
				t.Fatalf("OpenLDAP root DSE discovery: %v\n%s", err, out)
			}
			out, err = run(
				"-D", "uid=reader,ou=users,dc=home,dc=arpa", "-y", passwordFile,
				"-b", "ou=groups,dc=home,dc=arpa", "(member=uid=johndoe,ou=users,dc=home,dc=arpa)", "cn", "memberUid", "member",
			)
			if err != nil {
				t.Fatalf("OpenLDAP group search: %v\n%s", err, out)
			}
			for _, want := range []string{
				"dn: cn=team,ou=groups,dc=home,dc=arpa", "cn: team", "memberUid: johndoe", "member: uid=johndoe,ou=users,dc=home,dc=arpa",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("OpenLDAP response missing %q:\n%s", want, out)
				}
			}
			if err := os.WriteFile(passwordFile, []byte("wrong-password"), 0o600); err != nil {
				t.Fatal(err)
			}
			out, err = run("-D", "uid=reader,ou=users,dc=home,dc=arpa", "-y", passwordFile, "-b", cfg.BaseDN)
			if err == nil || !strings.Contains(out, "(49)") {
				t.Fatalf("OpenLDAP accepted invalid credentials: %v\n%s", err, out)
			}
		})
	}
}
