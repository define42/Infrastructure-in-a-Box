package lease

import "strings"

// NormalizeHostname returns a lowercase, fully qualified hostname under domain.
// Empty or invalid names, and names outside the domain, return an empty string.
func NormalizeHostname(hostname, domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	hostname = strings.ToLower(strings.TrimSuffix(hostname, "."))
	if !validDNSName(domain) || !validDNSName(hostname) {
		return ""
	}
	if !strings.Contains(hostname, ".") {
		hostname += "." + domain
	} else if !strings.HasSuffix(hostname, "."+domain) {
		return ""
	}
	if !validDNSName(hostname) {
		return ""
	}
	return hostname + "."
}

func validDNSName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
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
