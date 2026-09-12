package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const maxConfigBytes = 1 << 20

// Parse selects a JSON file with -config (default config.json) and loads it.
// Service settings come only from the file. Help does not read configuration;
// it is written to output and returns flag.ErrHelp.
func Parse(args []string, output io.Writer) (Config, error) {
	if output == nil {
		output = io.Discard
	}
	flags := flag.NewFlagSet("infra-box", flag.ContinueOnError)
	flags.SetOutput(output)
	path := flags.String("config", "config.json", "JSON configuration file")
	if err := flags.Parse(args); err != nil {
		return Config{}, err
	}
	if flags.NArg() != 0 {
		return Config{}, fmt.Errorf("unexpected positional argument %q", flags.Arg(0))
	}
	return Load(*path)
}

// Load reads one JSON object and validates every setting before services start.
// Relative persistence paths resolve against the configuration file's directory.
// It neither creates state files nor inspects network interfaces.
func Load(path string) (Config, error) {
	if strings.TrimSpace(path) == "" {
		return Config{}, errors.New("config path must name a JSON file")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return Config{}, fmt.Errorf("resolve configuration path: %w", err)
	}
	data, err := readConfig(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration %q: %w", path, err)
	}
	settings := fileSettings{
		cfg: Config{
			DHCPAddress: ":67", Domain: "home.arpa", LeaseFile: "leases.json", CADirectory: "pki", TFTPDirectory: "tftp",
		},
		leaseDuration: "12h", dnsTTL: "1m",
	}
	if err := settings.decode(data); err != nil {
		return Config{}, fmt.Errorf("decode configuration %q: %w", path, err)
	}
	cfg, err := settings.config()
	if err != nil {
		return Config{}, fmt.Errorf("validate configuration %q: %w", path, err)
	}
	dir := filepath.Dir(path)
	cfg.LeaseFile = resolvePath(dir, cfg.LeaseFile)
	cfg.TFTPDirectory = resolvePath(dir, cfg.TFTPDirectory)
	cfg.CADirectory = resolvePath(dir, cfg.CADirectory)
	cfg.ACMEStateFile = resolvePath(dir, cfg.ACMEStateFile)
	if err := cfg.validatePaths(path); err != nil {
		return Config{}, fmt.Errorf("validate configuration %q: %w", path, err)
	}
	return cfg, nil
}

func readConfig(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("configuration must be a regular file")
	}
	if info.Size() > maxConfigBytes {
		return nil, errors.New("configuration exceeds 1 MiB")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxConfigBytes+1))
	if err := errors.Join(readErr, f.Close()); err != nil {
		return nil, err
	}
	if len(data) > maxConfigBytes {
		return nil, errors.New("configuration exceeds 1 MiB")
	}
	if !utf8.Valid(data) {
		return nil, errors.New("configuration must be valid UTF-8 JSON")
	}
	return data, nil
}

// Keep human-readable duration and address strings separate from runtime types.
type fileSettings struct {
	cfg                                          Config
	serverIP, subnet, poolStart, poolEnd, router string
	leaseDuration, dnsTTL                        string
	aRecords                                     map[string]string
}

func (settings *fileSettings) decode(data []byte) error {
	fields := map[string]*string{
		"interface":      &settings.cfg.Interface,
		"server_ip":      &settings.serverIP,
		"subnet":         &settings.subnet,
		"pool_start":     &settings.poolStart,
		"pool_end":       &settings.poolEnd,
		"router":         &settings.router,
		"domain":         &settings.cfg.Domain,
		"lease_duration": &settings.leaseDuration,
		"lease_file":     &settings.cfg.LeaseFile,
		"dhcp_listen":    &settings.cfg.DHCPAddress,
		"upstream":       &settings.cfg.Upstream,
		"dns_ttl":        &settings.dnsTTL,
		"ca_dir":         &settings.cfg.CADirectory,
		"tftp_root":      &settings.cfg.TFTPDirectory,
		"acme_state":     &settings.cfg.ACMEStateFile,
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("expected a JSON object: %w", err)
	}
	if token != json.Delim('{') {
		return errors.New("configuration must be a JSON object")
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("read configuration key: %w", err)
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("configuration keys must be strings")
		}
		if seen[key] {
			return fmt.Errorf("duplicate configuration key %q", key)
		}
		seen[key] = true
		if key == "ldap" {
			settings.cfg.LDAP, err = decodeLDAP(decoder)
			if err != nil {
				return err
			}
			continue
		}
		if key == "a_records" {
			settings.aRecords, err = decodeARecords(decoder)
			if err != nil {
				return err
			}
			continue
		}
		target, ok := fields[key]
		if !ok {
			return fmt.Errorf("unknown configuration key %q", key)
		}
		token, err = decoder.Token()
		if err != nil {
			return fmt.Errorf("read %s: %w", key, err)
		}
		value, ok := token.(string)
		if !ok {
			return fmt.Errorf("%s must be a JSON string", key)
		}
		*target = value
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("close configuration object: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("configuration must contain a single JSON object with no trailing data")
	}
	return nil
}

func resolvePath(dir, path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(dir, path)
}

func (c Config) validatePaths(configPath string) error {
	protected := []struct{ name, path string }{
		{name: "configuration file", path: configPath},
		{name: "ca_dir", path: c.CADirectory},
		{name: "CA certificate/key files", path: filepath.Join(c.CADirectory, "root-ca-bundle.pem")},
		{name: "CA certificate/key files", path: filepath.Join(c.CADirectory, "gateway-bundle.pem")},
		{name: "CA certificate/key files", path: filepath.Join(c.CADirectory, "ldap-bundle.pem")},
		{name: "CA certificate/key files", path: filepath.Join(c.CADirectory, "root-ca.pem")},
	}
	for _, target := range protected {
		if c.ACMEStateFile == target.path {
			return fmt.Errorf("acme_state must differ from the %s", target.name)
		}
		if c.LeaseFile == target.path {
			return fmt.Errorf("lease_file must differ from the %s", target.name)
		}
	}
	if c.ACMEStateFile == c.LeaseFile {
		return errors.New("acme_state must differ from the lease_file")
	}
	for _, target := range protected[1:] {
		if target.path == configPath {
			return fmt.Errorf("configuration file must differ from the %s", target.name)
		}
	}
	// Boot files are public. The root must not contain private state, and it
	// must not be placed inside the CA directory.
	for _, target := range append(protected, struct{ name, path string }{"lease_file", c.LeaseFile},
		struct{ name, path string }{"acme_state", c.ACMEStateFile}) {
		if target.path != "" && pathWithin(c.TFTPDirectory, target.path) {
			return fmt.Errorf("tftp_root must not contain the %s", target.name)
		}
	}
	if pathWithin(c.CADirectory, c.TFTPDirectory) {
		return errors.New("tftp_root must not be inside ca_dir")
	}
	return nil
}

func pathWithin(directory, path string) bool {
	relative, err := filepath.Rel(directory, path)
	return err == nil && (relative == "." || filepath.IsLocal(relative))
}
