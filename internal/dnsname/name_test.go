package dnsname_test

import (
	"strings"
	"testing"

	"github.com/define42/Infrastructure-in-a-Box/internal/dnsname"
)

func TestNormalizeARecord(t *testing.T) {
	t.Parallel()
	longParent := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 49) + ".home.arpa"
	tooLongParent := strings.Replace(longParent, strings.Repeat("b", 49), strings.Repeat("b", 50), 1)
	for _, tc := range []struct{ name, input, want string }{
		{name: "hostname", input: "Printer", want: "printer.home.arpa."},
		{name: "external hostname", input: "GoOgLe.COM.", want: "google.com."},
		{name: "external subdomain", input: "maps.google.com", want: "maps.google.com."},
		{name: "apex alias", input: "@", want: "home.arpa."},
		{name: "apex", input: "HOME.ARPA.", want: "home.arpa."},
		{name: "wildcard alias", input: "*", want: "*.home.arpa."},
		{name: "wildcard apex", input: "*.HoMe.ArPa.", want: "*.home.arpa."},
		{name: "wildcard subdomain", input: "*.APPS.home.arpa", want: "*.apps.home.arpa."},
		{name: "wildcard relative", input: "*.apps", want: "*.apps.home.arpa."},
		{name: "maximum length", input: "*." + longParent, want: "*." + longParent + "."},
		{name: "too long", input: "*." + tooLongParent},
		{name: "empty", input: ""},
		{name: "external wildcard", input: "*.example.com", want: "*.example.com."},
		{name: "external wildcard case", input: "*.GOOGLE.COM.", want: "*.google.com."},
		{name: "similar external suffix", input: "*.nothome.arpa", want: "*.nothome.arpa."},
		{name: "local prefix on external name", input: "home.arpa.example.com", want: "home.arpa.example.com."},
		{name: "root", input: "."},
		{name: "external underscore", input: "my_host.google.com"},
		{name: "external empty label", input: "google..com"},
		{name: "external trailing hyphen", input: "google-.com"},
		{name: "external repeated root dot", input: "google.com.."},
		{name: "external escaped label", input: `g\111ogle.com`},
		{name: "empty label", input: "*..home.arpa"},
		{name: "partial label", input: "app*.home.arpa"},
		{name: "repeated wildcard", input: "*.*.home.arpa"},
		{name: "nonleftmost wildcard", input: "app.*.home.arpa"},
		{name: "unicode folding", input: "*.K.home.arpa"},
		{name: "leading space", input: " *.home.arpa"},
		{name: "trailing space", input: "*.home.arpa "},
		{name: "oversized label", input: "*." + strings.Repeat("a", 64) + ".home.arpa"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := dnsname.NormalizeARecord(tc.input, "HOME.ARPA."); got != tc.want {
				t.Errorf("NormalizeARecord(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
