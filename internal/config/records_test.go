package config_test

import (
	"encoding/json"
	"maps"
	"net/netip"
	"strings"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
)

func TestLoadARecords(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		raw  string
		want map[string]netip.Addr
	}{
		{name: "empty", raw: `{}`},
		{
			name: "external names", raw: `{"GOOGLE.COM.":"192.168.50.10","*.Google.Com":"192.168.50.20"}`,
			want: map[string]netip.Addr{
				"google.com.":   netip.MustParseAddr("192.168.50.10"),
				"*.google.com.": netip.MustParseAddr("192.168.50.20"),
			},
		},
		{
			name: "external gateway name", raw: `{"gateway.example.com":"192.168.50.10"}`,
			want: map[string]netip.Addr{"gateway.example.com.": netip.MustParseAddr("192.168.50.10")},
		},
		{
			name: "similar external suffix", raw: `{"nothome.arpa":"192.168.50.10"}`,
			want: map[string]netip.Addr{"nothome.arpa.": netip.MustParseAddr("192.168.50.10")},
		},
		{
			name: "wildcard shorthand", raw: `{"*":"192.168.50.20"}`,
			want: map[string]netip.Addr{"*.home.arpa.": netip.MustParseAddr("192.168.50.20")},
		},
		{
			name: "wildcard fully qualified", raw: `{"*.HOME.ARPA.":"192.168.50.20"}`,
			want: map[string]netip.Addr{"*.home.arpa.": netip.MustParseAddr("192.168.50.20")},
		},
		{
			name: "nested wildcard", raw: `{"*.Apps.Home.Arpa.":"192.168.50.20"}`,
			want: map[string]netip.Addr{"*.apps.home.arpa.": netip.MustParseAddr("192.168.50.20")},
		},
		{
			name: "relative wildcard", raw: `{"*.apps":"192.168.50.20"}`,
			want: map[string]netip.Addr{"*.apps.home.arpa.": netip.MustParseAddr("192.168.50.20")},
		},
		{
			name: "short and fully qualified names",
			raw:  `{"Printer":"192.168.50.10","NaS.HoMe.ArPa.":"192.168.50.20"}`,
			want: map[string]netip.Addr{
				"printer.home.arpa.": netip.MustParseAddr("192.168.50.10"),
				"nas.home.arpa.":     netip.MustParseAddr("192.168.50.20"),
			},
		},
		{
			name: "apex shorthand", raw: `{"@":"192.168.50.2"}`,
			want: map[string]netip.Addr{"home.arpa.": netip.MustParseAddr("192.168.50.2")},
		},
		{
			name: "apex fully qualified", raw: `{"HOME.ARPA.":"192.168.50.2"}`,
			want: map[string]netip.Addr{"home.arpa.": netip.MustParseAddr("192.168.50.2")},
		},
		{
			name: "address outside subnet", raw: `{"remote":"192.0.2.10"}`,
			want: map[string]netip.Addr{"remote.home.arpa.": netip.MustParseAddr("192.0.2.10")},
		},
		{
			name: "DNS record does not reserve an address", raw: `{"alias":"192.168.50.150"}`,
			want: map[string]netip.Addr{"alias.home.arpa.": netip.MustParseAddr("192.168.50.150")},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := config.Load(writeRawConfig(t, withARecords(t, tc.raw)))
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]netip.Addr{"ldap.home.arpa.": netip.MustParseAddr("192.168.50.2")}
			maps.Copy(want, tc.want)
			if !maps.Equal(cfg.ARecords, want) {
				t.Errorf("ARecords = %v, want %v", cfg.ARecords, want)
			}
		})
	}
}

func TestLoadRejectsInvalidARecords(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, raw string }{
		{name: "null", raw: `null`},
		{name: "array", raw: `[]`},
		{name: "string", raw: `"printer"`},
		{name: "number", raw: `1`},
		{name: "null address", raw: `{"printer":null}`},
		{name: "numeric address", raw: `{"printer":1234}`},
		{name: "array address", raw: `{"printer":["192.168.50.10"]}`},
		{name: "object address", raw: `{"printer":{"ip":"192.168.50.10"}}`},
		{name: "duplicate JSON name", raw: `{"printer":"192.168.50.10","printer":"192.168.50.20"}`},
		{name: "duplicate escaped name", raw: `{"printer":"192.168.50.10","\u0070rinter":"192.168.50.20"}`},
		{name: "duplicate normalized name", raw: `{"Printer":"192.168.50.10","printer.home.arpa.":"192.168.50.20"}`},
		{name: "duplicate apex", raw: `{"@":"192.168.50.10","home.arpa":"192.168.50.20"}`},
		{name: "empty name", raw: `{"":"192.168.50.10"}`},
		{name: "duplicate external name", raw: `{"google.com":"192.168.50.10","GOOGLE.COM.":"192.168.50.20"}`},
		{name: "duplicate external wildcard", raw: `{"*.google.com":"192.168.50.10","*.GOOGLE.COM.":"192.168.50.20"}`},
		{name: "duplicate wildcard", raw: `{"*":"192.168.50.10","*.HOME.ARPA.":"192.168.50.20"}`},
		{name: "duplicate relative wildcard", raw: `{"*.apps":"192.168.50.10","*.apps.home.arpa":"192.168.50.20"}`},
		{name: "invalid external label", raw: `{"*.bad_name.example.com":"192.168.50.10"}`},
		{name: "partial wildcard", raw: `{"app*.home.arpa":"192.168.50.10"}`},
		{name: "nonleftmost wildcard", raw: `{"app.*.home.arpa":"192.168.50.10"}`},
		{name: "repeated wildcard", raw: `{"*.*.home.arpa":"192.168.50.10"}`},
		{name: "wildcard empty label", raw: `{"*..home.arpa":"192.168.50.10"}`},
		{name: "wildcard unicode folding", raw: `{"*.K.home.arpa":"192.168.50.10"}`},
		{name: "bad label", raw: `{"bad_name":"192.168.50.10"}`},
		{name: "unicode folding", raw: `{"K":"192.168.50.10"}`},
		{name: "reserved ns", raw: `{"NS":"192.168.50.10"}`},
		{name: "reserved gateway", raw: `{"Gateway.Home.Arpa.":"192.168.50.10"}`},
		{name: "IPv6", raw: `{"printer":"2001:db8::1"}`},
		{name: "mapped IPv4", raw: `{"printer":"::ffff:192.168.50.10"}`},
		{name: "missing address", raw: `{"printer":""}`},
		{name: "hostname address", raw: `{"printer":"nas.home.arpa"}`},
		{name: "unspecified", raw: `{"printer":"0.0.0.0"}`},
		{name: "multicast", raw: `{"printer":"224.0.0.1"}`},
		{name: "broadcast", raw: `{"printer":"255.255.255.255"}`},
		{name: "loopback", raw: `{"printer":"127.0.0.1"}`},
		{name: "incomplete object", raw: `{"printer":"192.168.50.10"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := config.Load(writeRawConfig(t, withARecords(t, tc.raw)))
			if err == nil {
				t.Fatal("invalid A records accepted")
			}
		})
	}
	for _, data := range []string{
		strings.TrimSuffix(withARecords(t, `{}`), "}") + `,"a_records":{}}`,
		strings.Replace(withARecords(t, `{}`), `"a_records"`, `"A_Records"`, 1),
	} {
		if _, err := config.Load(writeRawConfig(t, data)); err == nil {
			t.Errorf("invalid top-level a_records key accepted: %s", data)
		}
	}
}

func withARecords(t *testing.T, raw string) string {
	t.Helper()
	data, err := json.Marshal(validValues())
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(string(data), "}") + `,"a_records":` + raw + "}"
}
