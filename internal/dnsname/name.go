// Package dnsname normalizes configured DNS record names.
package dnsname

import (
	"strings"

	"github.com/define42/Infrastructure-in-a-Box/internal/lease"
)

// NormalizeARecord returns a lowercase, fully qualified local A record name.
// It accepts hostnames, @ for the zone apex, and a single leftmost wildcard
// label. Domain must already be a valid DNS domain. Invalid names return "".
func NormalizeARecord(name, domain string) string {
	for _, c := range name {
		if c > 127 {
			return ""
		}
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "@" || name == domain {
		return domain + "."
	}
	if name == "*" {
		name = "*." + domain
	}
	if parent, wildcard := strings.CutPrefix(name, "*."); wildcard {
		if parent == domain {
			parent += "."
		} else {
			parent = lease.NormalizeHostname(parent, domain)
		}
		// The textual name, excluding its root dot, must fit 253 bytes.
		if parent == "" || len(parent)+2 > 254 {
			return ""
		}
		return "*." + parent
	}
	return lease.NormalizeHostname(name, domain)
}
