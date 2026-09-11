package config_test

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
	"golang.org/x/crypto/bcrypt"
)

const ldapTestSHA256 = "6478579e37aff45f013e14eeb30b3cc56c72ccdc310123bcdf53e0333e3f416a"

func TestLDAPConfigValidate(t *testing.T) {
	t.Parallel()
	hash, err := bcrypt.GenerateFromPassword([]byte("test-only-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		change func(*config.LDAPConfig)
		want   string
	}{
		{name: "valid SHA256"},
		{name: "uppercase SHA256", change: func(c *config.LDAPConfig) {
			c.Users[0].PassSHA256 = strings.ToUpper(ldapTestSHA256)
		}},
		{name: "valid bcrypt", change: func(c *config.LDAPConfig) {
			c.Users[0].PassSHA256 = ""
			c.Users[0].PassBcrypt = string(hash)
		}},
		{name: "disabled without password", change: func(c *config.LDAPConfig) {
			c.Users[0].Disabled = true
			c.Users[0].PassSHA256 = ""
		}},
		{name: "no POSIX UID", change: func(c *config.LDAPConfig) { c.Users[0].UIDNumber = 0 }},
		{name: "repeated primary and supplementary membership", change: func(c *config.LDAPConfig) {
			c.Users[0].OtherGroups = []int{5510, 5506, 5510, 5506}
		}},
		{name: "loopback ephemeral", change: func(c *config.LDAPConfig) { c.Listen = "127.0.0.1:0" }},
		{name: "IPv6 loopback ephemeral", change: func(c *config.LDAPConfig) { c.Listen = "[::1]:0" }},
		{name: "wildcard listener", change: func(c *config.LDAPConfig) { c.Listen = ":389" }},
		{name: "TLS loopback ephemeral", change: func(c *config.LDAPConfig) { c.TLSListen = "127.0.0.1:0" }},
		{name: "TLS IPv6 loopback ephemeral", change: func(c *config.LDAPConfig) { c.TLSListen = "[::1]:0" }},
		{name: "both loopback ephemeral", change: func(c *config.LDAPConfig) {
			c.Listen = "127.0.0.1:0"
			c.TLSListen = "127.0.0.1:0"
		}},
		{name: "escaped base DN", change: func(c *config.LDAPConfig) { c.BaseDN = `o=Example\, Inc.,dc=home,dc=arpa` }},
		{name: "missing listen", change: func(c *config.LDAPConfig) { c.Listen = "" }, want: "ldap.listen"},
		{name: "hostname listen", change: func(c *config.LDAPConfig) { c.Listen = "ldap.home.arpa:636" }, want: "numeric IP"},
		{name: "multicast listen", change: func(c *config.LDAPConfig) { c.Listen = "224.0.0.1:636" }, want: "unicast"},
		{name: "wildcard ephemeral", change: func(c *config.LDAPConfig) { c.Listen = ":0" }, want: "port"},
		{name: "LAN ephemeral", change: func(c *config.LDAPConfig) { c.Listen = "192.168.50.2:0" }, want: "port"},
		{name: "invalid port", change: func(c *config.LDAPConfig) { c.Listen = ":65536" }, want: "port"},
		{name: "missing TLS listen", change: func(c *config.LDAPConfig) { c.TLSListen = "" }, want: "ldap.tls_listen"},
		{name: "hostname TLS listen", change: func(c *config.LDAPConfig) { c.TLSListen = "ldap.home.arpa:636" }, want: "ldap.tls_listen"},
		{name: "TLS multicast listen", change: func(c *config.LDAPConfig) { c.TLSListen = "224.0.0.1:636" }, want: "ldap.tls_listen"},
		{name: "TLS wildcard ephemeral", change: func(c *config.LDAPConfig) { c.TLSListen = ":0" }, want: "ldap.tls_listen"},
		{name: "TLS LAN ephemeral", change: func(c *config.LDAPConfig) { c.TLSListen = "192.168.50.2:0" }, want: "ldap.tls_listen"},
		{name: "invalid TLS port", change: func(c *config.LDAPConfig) { c.TLSListen = ":65536" }, want: "ldap.tls_listen"},
		{name: "empty base DN", change: func(c *config.LDAPConfig) { c.BaseDN = "" }, want: "ldap.base_dn"},
		{name: "malformed base DN", change: func(c *config.LDAPConfig) { c.BaseDN = "home.arpa" }, want: "ldap.base_dn"},
		{name: "empty DN value", change: func(c *config.LDAPConfig) { c.BaseDN = "dc=,dc=arpa" }, want: "ldap.base_dn"},
		{name: "DN injection username", change: func(c *config.LDAPConfig) { c.Users[0].Name = "user,ou=groups" }, want: ".name"},
		{name: "non-ASCII username", change: func(c *config.LDAPConfig) { c.Users[0].Name = "jöhn" }, want: ".name"},
		{name: "long username", change: func(c *config.LDAPConfig) { c.Users[0].Name = strings.Repeat("u", 65) }, want: ".name"},
		{name: "duplicate case-insensitive username", change: func(c *config.LDAPConfig) {
			other := c.Users[0]
			other.Name = strings.ToUpper(other.Name)
			c.Users = append(c.Users, other)
		}, want: "duplicates another user name"},
		{name: "duplicate UID", change: func(c *config.LDAPConfig) {
			other := c.Users[0]
			other.Name = "otheruser"
			c.Users = append(c.Users, other)
		}, want: "duplicates another user ID"},
		{name: "negative UID", change: func(c *config.LDAPConfig) { c.Users[0].UIDNumber = -1 }, want: "uid_number"},
		{name: "malformed mail", change: func(c *config.LDAPConfig) { c.Users[0].Mail = "John <john@example.com>" }, want: ".mail"},
		{name: "group name injection", change: func(c *config.LDAPConfig) { c.Groups[0].Name = "team,dc=other" }, want: ".name"},
		{name: "duplicate case-insensitive group", change: func(c *config.LDAPConfig) {
			c.Groups = append(c.Groups, config.LDAPGroup{Name: "TEAM10_R", GID: 6000})
		}, want: "duplicates another group name"},
		{name: "duplicate GID", change: func(c *config.LDAPConfig) {
			c.Groups = append(c.Groups, config.LDAPGroup{Name: "another", GID: 5510})
		}, want: "duplicates another group ID"},
		{name: "zero GID", change: func(c *config.LDAPConfig) { c.Groups[0].GID = 0 }, want: ".gid"},
		{name: "negative GID", change: func(c *config.LDAPConfig) { c.Groups[0].GID = -1 }, want: ".gid"},
		{name: "missing primary group", change: func(c *config.LDAPConfig) { c.Users[0].PrimaryGroup = 5511 }, want: "primary_group references undefined group 5511"},
		{name: "missing supplementary group from proposal", change: func(c *config.LDAPConfig) {
			c.Users[0].OtherGroups = []int{5506, 5510, 5511}
		}, want: "other_groups references undefined group 5511"},
		{name: "active user missing password", change: func(c *config.LDAPConfig) { c.Users[0].PassSHA256 = "" }, want: "active users require"},
		{name: "both password types", change: func(c *config.LDAPConfig) { c.Users[0].PassBcrypt = string(hash) }, want: "only one"},
		{name: "disabled malformed password", change: func(c *config.LDAPConfig) {
			c.Users[0].Disabled = true
			c.Users[0].PassSHA256 = "sensitive-invalid-sha256"
		}, want: "64 hexadecimal"},
		{name: "nonhex SHA256", change: func(c *config.LDAPConfig) { c.Users[0].PassSHA256 = strings.Repeat("z", 64) }, want: "64 hexadecimal"},
		{name: "truncated bcrypt", change: func(c *config.LDAPConfig) {
			c.Users[0].PassSHA256 = ""
			c.Users[0].PassBcrypt = string(hash[:len(hash)-1])
		}, want: "complete bcrypt"},
		{name: "bcrypt expensive cost", change: func(c *config.LDAPConfig) {
			c.Users[0].PassSHA256 = ""
			c.Users[0].PassBcrypt = "$2a$31$" + string(hash[7:])
		}, want: "cost must be between 4 and 14"},
		{name: "bcrypt low cost", change: func(c *config.LDAPConfig) {
			c.Users[0].PassSHA256 = ""
			c.Users[0].PassBcrypt = "$2a$03$" + string(hash[7:])
		}, want: "cost must be between 4 and 14"},
		{name: "bcrypt invalid body", change: func(c *config.LDAPConfig) {
			c.Users[0].PassSHA256 = ""
			c.Users[0].PassBcrypt = "$2a$04$" + strings.Repeat("!", 53)
		}, want: "complete bcrypt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := validLDAP()
			if tc.change != nil {
				tc.change(&cfg)
			}
			err := cfg.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate() = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want %q", err, tc.want)
			}
			for _, user := range cfg.Users {
				for _, password := range []string{user.PassSHA256, user.PassBcrypt} {
					if password != "" && strings.Contains(err.Error(), password) {
						t.Error("validation error exposed password hash")
					}
				}
			}
		})
	}
}

func TestLoadLDAPDefaults(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name     string
		raw      string
		serverIP string
		baseDN   string
	}{
		{name: "empty object", raw: `{}`, serverIP: "192.168.50.2", baseDN: "dc=lab,dc=example"},
		{name: "empty directory", raw: `{"users":[],"groups":[]}`, serverIP: "192.168.50.2", baseDN: "dc=lab,dc=example"},
		{name: "custom base DN", raw: `{"base_dn":"o=Directory,dc=example"}`, serverIP: "192.168.50.2", baseDN: "o=Directory,dc=example"},
		{name: "different server IP", raw: `{}`, serverIP: "192.168.50.3", baseDN: "dc=lab,dc=example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := strings.TrimSuffix(withLDAP(t, tc.raw), "}") + `,"domain":"LAB.Example."}`
			data = strings.Replace(data, `"server_ip":"192.168.50.2"`, `"server_ip":"`+tc.serverIP+`"`, 1)
			cfg, err := config.Load(writeRawConfig(t, data))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.LDAP.Listen != tc.serverIP+":389" || cfg.LDAP.TLSListen != tc.serverIP+":636" {
				t.Errorf("LDAP listeners = %s, %s; want server_ip ports 389 and 636", cfg.LDAP.Listen, cfg.LDAP.TLSListen)
			}
			if cfg.LDAP.BaseDN != tc.baseDN {
				t.Errorf("base DN = %q, want %q", cfg.LDAP.BaseDN, tc.baseDN)
			}
			address, exists := cfg.ARecords["ldap.lab.example."]
			if !exists || address != cfg.ServerIP {
				t.Errorf("LDAP DNS record = %v, exists=%v, want server_ip", address, exists)
			}
		})
	}
	cfg, err := config.Load(writeConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	want := config.LDAPConfig{
		Listen: "192.168.50.2:389", TLSListen: "192.168.50.2:636", BaseDN: "dc=home,dc=arpa",
	}
	if !reflect.DeepEqual(cfg.LDAP, want) || cfg.ARecords["ldap.home.arpa."] != cfg.ServerIP {
		t.Error("omitting LDAP must retain both LDAP and LDAPS with derived settings and its DNS record")
	}
}

func TestLoadLDAPUsersAndGroups(t *testing.T) {
	t.Parallel()
	want := validLDAP()
	want.Users[0].CanSearch = true
	want.Users = append(want.Users, config.LDAPUser{
		Name: "disabled", PrimaryGroup: 5506, Disabled: true, OtherGroups: []int{},
	})
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(writeRawConfig(t, withLDAP(t, string(raw))))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg.LDAP, want) {
		t.Error("LDAP settings did not round-trip through JSON")
	}
}

func TestLoadRejectsInvalidLDAPJSON(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, raw string }{
		{name: "null directory", raw: `null`},
		{name: "array directory", raw: `[]`},
		{name: "string directory", raw: `"ldap"`},
		{name: "unknown field", raw: `{"enable":true}`},
		{name: "wrong case field", raw: `{"Base_DN":"dc=home,dc=arpa"}`},
		{name: "duplicate field", raw: `{"base_dn":"dc=home","base_dn":"dc=arpa"}`},
		{name: "escaped duplicate field", raw: `{"base_dn":"dc=home","\u0062ase_dn":"dc=arpa"}`},
		{name: "null bool", raw: `{"users":[{"disabled":null}]}`},
		{name: "string bool", raw: `{"users":[{"disabled":"true"}]}`},
		{name: "number bool", raw: `{"users":[{"can_search":1}]}`},
		{name: "null string", raw: `{"base_dn":null}`},
		{name: "number string", raw: `{"base_dn":636}`},
		{name: "users null", raw: `{"users":null}`},
		{name: "users object", raw: `{"users":{}}`},
		{name: "null user", raw: `{"users":[null]}`},
		{name: "array user", raw: `{"users":[[]]}`},
		{name: "unknown user field", raw: `{"users":[{"password":"secret"}]}`},
		{name: "duplicate user field", raw: `{"users":[{"disabled":true,"disabled":false}]}`},
		{name: "null user string", raw: `{"users":[{"pass_sha256":null}]}`},
		{name: "object user string", raw: `{"users":[{"pass_bcrypt":{"secret":"value"}}]}`},
		{name: "null UID", raw: `{"users":[{"uid_number":null}]}`},
		{name: "fractional UID", raw: `{"users":[{"uid_number":1000.5}]}`},
		{name: "noninteger syntax UID", raw: `{"users":[{"uid_number":1000.0}]}`},
		{name: "string UID", raw: `{"users":[{"uid_number":"1000"}]}`},
		{name: "null other groups", raw: `{"users":[{"other_groups":null}]}`},
		{name: "scalar other groups", raw: `{"users":[{"other_groups":5510}]}`},
		{name: "null supplementary GID", raw: `{"users":[{"other_groups":[null]}]}`},
		{name: "string supplementary GID", raw: `{"users":[{"other_groups":["5510"]}]}`},
		{name: "nested supplementary GID", raw: `{"users":[{"other_groups":[[5510]]}]}`},
		{name: "fractional supplementary GID", raw: `{"users":[{"other_groups":[5510.1]}]}`},
		{name: "null search permission", raw: `{"users":[{"can_search":null}]}`},
		{name: "groups null", raw: `{"groups":null}`},
		{name: "null group", raw: `{"groups":[null]}`},
		{name: "unknown group field", raw: `{"groups":[{"gid_number":5510}]}`},
		{name: "duplicate group field", raw: `{"groups":[{"gid":5510,"gid":5511}]}`},
		{name: "null group GID", raw: `{"groups":[{"gid":null}]}`},
		{name: "string group GID", raw: `{"groups":[{"gid":"5510"}]}`},
		{name: "incomplete nested object", raw: `{"users":[{"name":"incomplete"}`},
		{name: "invalid user", raw: `{"users":[{"name":"user"}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := config.Load(writeRawConfig(t, withLDAP(t, tc.raw))); err == nil {
				t.Fatal("invalid LDAP configuration accepted")
			}
		})
	}
	for _, data := range []string{
		strings.TrimSuffix(withLDAP(t, `{}`), "}") + `,"ldap":{}}`,
		strings.Replace(withLDAP(t, `{}`), `"ldap"`, `"LDAP"`, 1),
	} {
		if _, err := config.Load(writeRawConfig(t, data)); err == nil {
			t.Error("invalid top-level LDAP key accepted")
		}
	}
}

func TestLoadRejectsLDAPRuntimeSettings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, raw, key string }{
		{name: "enabled", raw: `{"enabled":true}`, key: "enabled"},
		{name: "disabled", raw: `{"enabled":false}`, key: "enabled"},
		{name: "TLS true", raw: `{"tls":true}`, key: "tls"},
		{name: "TLS false", raw: `{"tls":false}`, key: "tls"},
		{name: "listener", raw: `{"listen":"192.168.50.2:389"}`, key: "listen"},
		{name: "TLS listener", raw: `{"tls_listen":"192.168.50.2:636"}`, key: "tls_listen"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Load(writeRawConfig(t, withLDAP(t, tc.raw)))
			if err == nil || !strings.Contains(err.Error(), `unknown ldap key "`+tc.key+`"`) {
				t.Fatalf("Load() = %v, want unknown LDAP key %q", err, tc.key)
			}
		})
	}
}

func TestLoadLDAPListenerAndDNSReservations(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		setting string
		records string
		want    string
	}{
		{name: "DNS LDAP conflict", setting: `"dns_listen":":389"`, want: "LDAP listener"},
		{name: "DNS LDAPS conflict", setting: `"dns_listen":":636"`, want: "LDAPS listener"},
		{name: "HTTPS LDAP conflict", setting: `"https_listen":"192.168.50.2:389"`, want: "LDAP listener"},
		{name: "HTTPS LDAPS conflict", setting: `"https_listen":"192.168.50.2:636"`, want: "LDAPS listener"},
		{name: "UDP LDAP port allowed", setting: `"dhcp_listen":":389"`},
		{name: "UDP LDAPS port allowed", setting: `"dhcp_listen":":636"`},
		{name: "existing identical record", records: `{"LDAP":"192.168.50.2"}`},
		{name: "conflicting record", records: `{"ldap":"192.168.50.3"}`, want: "ldap hostname must point to server_ip"},
		{name: "wildcard coexistence", records: `{"*":"192.168.50.3"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			data := withLDAP(t, `{}`)
			if tc.setting != "" {
				data = strings.TrimSuffix(data, "}") + `,` + tc.setting + "}"
			}
			if tc.records != "" {
				data = strings.TrimSuffix(data, "}") + `,"a_records":` + tc.records + "}"
			}
			cfg, err := config.Load(writeRawConfig(t, data))
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("Load() = %v, want %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ARecords["ldap.home.arpa."] != netip.MustParseAddr("192.168.50.2") {
				t.Error("LDAP did not reserve its DNS name")
			}
		})
	}
}

func TestLoadRejectsLDAPCertificatePathCollisions(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"lease_file", "acme_state"} {
		t.Run(field, func(t *testing.T) {
			t.Parallel()
			_, err := config.Load(writeConfig(t, field, "pki/ldap-bundle.pem"))
			if err == nil || !strings.Contains(err.Error(), field+" must differ") {
				t.Fatalf("Load() = %v, want LDAP certificate path collision", err)
			}
		})
	}
	path := writeConfig(t, "ca_dir", ".")
	certificatePath := filepath.Join(filepath.Dir(path), "ldap-bundle.pem")
	if err := os.Rename(path, certificatePath); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(certificatePath); err == nil || !strings.Contains(err.Error(), "configuration file must differ") {
		t.Fatalf("Load() = %v, want configuration/certificate collision", err)
	}
}

func validLDAP() config.LDAPConfig {
	return config.LDAPConfig{
		Listen:    "192.168.50.2:389",
		TLSListen: "192.168.50.2:636",
		BaseDN:    "dc=home,dc=arpa",
		Users: []config.LDAPUser{{
			Name: "johndoe", Mail: "johndoe@home.arpa", PassSHA256: ldapTestSHA256,
			UIDNumber: 1001, PrimaryGroup: 5510, OtherGroups: []int{5506},
		}},
		Groups: []config.LDAPGroup{{Name: "team10_r", GID: 5510}, {Name: "team2_rw", GID: 5506}},
	}
}

func withLDAP(t *testing.T, raw string) string {
	t.Helper()
	data, err := json.Marshal(validValues())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(string(data), "}") + `,"ldap":` + raw + "}"
}
