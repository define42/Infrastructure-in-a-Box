package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"

	"github.com/define42/Infrastructure-in-a-Box/internal/dnsname"
)

func decodeARecords(decoder *json.Decoder) (map[string]string, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("read a_records: %w", err)
	}
	if token != json.Delim('{') {
		return nil, errors.New("a_records must be an object mapping DNS names to IPv4 strings")
	}
	records := make(map[string]string)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("read a_records name: %w", err)
		}
		name, ok := token.(string)
		if !ok {
			return nil, errors.New("a_records names must be strings")
		}
		if _, exists := records[name]; exists {
			return nil, fmt.Errorf("duplicate a_records name %q", name)
		}
		token, err = decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("read a_records[%q]: %w", name, err)
		}
		ip, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("a_records[%q] must be an IPv4 string", name)
		}
		records[name] = ip
	}
	if _, err := decoder.Token(); err != nil {
		return nil, fmt.Errorf("close a_records object: %w", err)
	}
	return records, nil
}

func parseARecords(domain string, records map[string]string) (map[string]netip.Addr, error) {
	if len(records) == 0 {
		return nil, nil
	}
	result := make(map[string]netip.Addr, len(records))
	for name, value := range records {
		canonical := dnsname.NormalizeARecord(name, domain)
		if canonical == "" {
			return nil, fmt.Errorf("a_records name %q must be an ASCII hostname or a single leftmost wildcard", name)
		}
		if canonical == "ns."+domain+"." || canonical == "gateway."+domain+"." {
			return nil, fmt.Errorf("a_records name %q is reserved for the infrastructure server", name)
		}
		if _, exists := result[canonical]; exists {
			return nil, fmt.Errorf("duplicate a_records hostname %q", canonical)
		}
		ip, err := parseIPv4(fmt.Sprintf("a_records[%q]", name), value)
		if err != nil {
			return nil, err
		}
		result[canonical] = ip
	}
	return result, nil
}
