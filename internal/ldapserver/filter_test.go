package ldapserver

import (
	"testing"

	ldap "github.com/go-ldap/ldap/v3"
)

func TestSearchFilters(t *testing.T) {
	t.Parallel()
	user := newEntry("uid=johndoe,ou=users,dc=home,dc=arpa", map[string][]string{
		"uid": {"johndoe"}, "cn": {"John Doe"}, "uidNumber": {"1234"},
		"objectClass": {"inetOrgPerson"}, "memberOf": {"cn=team,ou=groups,dc=home,dc=arpa"},
	})
	for _, tc := range []struct {
		name   string
		filter string
		want   match
	}{
		{name: "equality", filter: "(uid=JOHNDOE)", want: matchTrue},
		{name: "presence", filter: "(uid=*)", want: matchTrue},
		{name: "missing presence", filter: "(mail=*)", want: matchFalse},
		{name: "compound", filter: "(&(objectClass=inetOrgPerson)(|(uid=johndoe)(uid=other))(!(mail=*)))", want: matchTrue},
		{name: "substring", filter: "(cn=Jo*hn*Doe)", want: matchTrue},
		{name: "substring order", filter: "(cn=*Doe*John*)", want: matchFalse},
		{name: "substring overlap", filter: "(uid=john*johndoe)", want: matchFalse},
		{name: "integer", filter: "(uidNumber=01234)", want: matchTrue},
		{name: "DN equality", filter: "(memberOf=CN=TEAM,OU=GROUPS,DC=HOME,DC=ARPA)", want: matchTrue},
		{name: "password hidden", filter: "(userPassword=secret)", want: matchUndefined},
		{name: "password negation hidden", filter: "(!(pass_sha256=secret))", want: matchUndefined},
		{name: "unknown presence negation", filter: "(!(unknown=*))", want: matchUndefined},
		{name: "invalid integer negation", filter: "(!(uidNumber=invalid))", want: matchUndefined},
		{name: "invalid DN negation", filter: "(!(memberOf=invalid))", want: matchUndefined},
		{name: "integer substring", filter: "(uidNumber=12*)", want: matchUndefined},
		{name: "undefined AND false", filter: "(&(unknown=x)(uid=other))", want: matchFalse},
		{name: "undefined OR true", filter: "(|(unknown=x)(uid=johndoe))", want: matchTrue},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet, err := ldap.CompileFilter(tc.filter)
			if err != nil {
				t.Fatal(err)
			}
			filter, err := compileFilter(packet)
			if err != nil {
				t.Fatal(err)
			}
			if got := filter(user); got != tc.want {
				t.Fatalf("filter %q: got %d, want %d", tc.filter, got, tc.want)
			}
		})
	}
}

func TestUnsupportedFilters(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, filter string }{
		{name: "ordering", filter: "(uidNumber>=1)"},
		{name: "approximate", filter: "(cn~=John)"},
		{name: "extensible", filter: "(cn:caseExactMatch:=John)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet, err := ldap.CompileFilter(tc.filter)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := compileFilter(packet); err == nil {
				t.Fatal("unsupported filter accepted")
			}
		})
	}
}
