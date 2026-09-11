// Package dnsname normalizes configured DNS record names.
package dnsname

import "strings"

// NormalizeARecord returns a lowercase, fully qualified A record name.
// Short hostnames, @, *, and wildcard parents with a single label are relative
// to domain. Other names may be inside or outside domain. Only a single leftmost
// wildcard label is allowed. Domain must be valid. Invalid names return "".
func NormalizeARecord(name, domain string) string {
	for _, c := range name {
		if c > 127 {
			return ""
		}
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "@" {
		name = domain
	}
	if name == "*" {
		name = "*." + domain
	}
	name, wildcard := strings.CutPrefix(name, "*.")
	if name != domain && !strings.Contains(name, ".") {
		name += "." + domain
	}
	if !validHostname(name) {
		return ""
	}
	if wildcard {
		name = "*." + name
	}
	if len(name) > 253 {
		return ""
	}
	return name + "."
}

func validHostname(name string) bool {
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}
