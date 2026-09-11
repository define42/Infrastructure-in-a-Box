package ldapserver

import (
	"slices"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func TestDirectoryPreservesMultivaluedBaseRDN(t *testing.T) {
	t.Parallel()
	server := &Server{}
	server.buildDirectory(config.LDAPConfig{BaseDN: "cn=foo+CN=bar,dc=home,dc=arpa"})
	values := server.entries[0].values("cn")
	if len(values) != 2 || !slices.Contains(values, "foo") || !slices.Contains(values, "bar") {
		t.Fatalf("base RDN lost naming values: %v", values)
	}
}
