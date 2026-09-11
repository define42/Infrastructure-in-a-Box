package config

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/mail"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/crypto/bcrypt"
)

// LDAPConfig describes the always-running directory managed through configuration.
// Load derives Listen and TLSListen from server_ip using ports 389 and 636.
type LDAPConfig struct {
	Listen    string      `json:"-"`
	TLSListen string      `json:"-"`
	BaseDN    string      `json:"base_dn"`
	Users     []LDAPUser  `json:"users"`
	Groups    []LDAPGroup `json:"groups"`
}

// LDAPUser describes an account. UIDNumber zero omits POSIX account attributes.
// Names contain 1–64 ASCII letters, digits, underscores, dots, or hyphens, and
// start with a letter or underscore. Names are unique without regard to case.
// CanSearch grants directory search access; Disabled prevents authentication.
type LDAPUser struct {
	Name         string `json:"name"`
	Mail         string `json:"mail"`
	PassSHA256   string `json:"pass_sha256"`
	PassBcrypt   string `json:"pass_bcrypt"`
	UIDNumber    int    `json:"uid_number"`
	PrimaryGroup int    `json:"primary_group"`
	OtherGroups  []int  `json:"other_groups"`
	Disabled     bool   `json:"disabled"`
	CanSearch    bool   `json:"can_search"`
}

// LDAPGroup describes a POSIX group. Names follow the LDAPUser naming rules.
type LDAPGroup struct {
	Name string `json:"name"`
	GID  int    `json:"gid"`
}

var (
	ldapNamePattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}$`)
	bcryptHashPattern = regexp.MustCompile(`^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$`)
)

// Validate checks directory entries and listener syntax, including disabled
// accounts. It permits an ephemeral port only on loopback for isolated servers
// and tests; Load additionally requires a fixed IPv4 port on the server address.
func (c LDAPConfig) Validate() error {
	if err := validateLDAPListen("ldap.listen", c.Listen); err != nil {
		return err
	}
	if err := validateLDAPListen("ldap.tls_listen", c.TLSListen); err != nil {
		return err
	}
	dn, err := ldap.ParseDN(c.BaseDN)
	if err != nil || len(dn.RDNs) == 0 {
		return errors.New("ldap.base_dn must be a nonempty valid distinguished name")
	}
	for _, rdn := range dn.RDNs {
		for _, attr := range rdn.Attributes {
			if strings.TrimSpace(attr.Type) == "" || strings.TrimSpace(attr.Value) == "" {
				return errors.New("ldap.base_dn attributes must have nonempty types and values")
			}
		}
	}
	groups := make(map[int]bool, len(c.Groups))
	groupNames := make(map[string]bool, len(c.Groups))
	for i, group := range c.Groups {
		path := fmt.Sprintf("ldap.groups[%d]", i)
		if !ldapNamePattern.MatchString(group.Name) {
			return fmt.Errorf("%s.name must start with an ASCII letter or underscore and contain 1–64 letters, digits, underscores, dots, or hyphens", path)
		}
		name := strings.ToLower(group.Name)
		if groupNames[name] {
			return fmt.Errorf("%s.name duplicates another group name", path)
		}
		groupNames[name] = true
		if group.GID <= 0 || group.GID > math.MaxInt32 {
			return fmt.Errorf("%s.gid must be between 1 and %d", path, math.MaxInt32)
		}
		if groups[group.GID] {
			return fmt.Errorf("%s.gid duplicates another group ID", path)
		}
		groups[group.GID] = true
	}
	userNames := make(map[string]bool, len(c.Users))
	uids := make(map[int]bool, len(c.Users))
	for i, user := range c.Users {
		path := fmt.Sprintf("ldap.users[%d]", i)
		if !ldapNamePattern.MatchString(user.Name) {
			return fmt.Errorf("%s.name must start with an ASCII letter or underscore and contain 1–64 letters, digits, underscores, dots, or hyphens", path)
		}
		name := strings.ToLower(user.Name)
		if userNames[name] {
			return fmt.Errorf("%s.name duplicates another user name", path)
		}
		userNames[name] = true
		if user.UIDNumber < 0 || user.UIDNumber > math.MaxInt32 {
			return fmt.Errorf("%s.uid_number must be zero or between 1 and %d", path, math.MaxInt32)
		}
		if user.UIDNumber != 0 {
			if uids[user.UIDNumber] {
				return fmt.Errorf("%s.uid_number duplicates another user ID", path)
			}
			uids[user.UIDNumber] = true
		}
		if !groups[user.PrimaryGroup] {
			return fmt.Errorf("%s.primary_group references undefined group %d", path, user.PrimaryGroup)
		}
		for _, gid := range user.OtherGroups {
			if !groups[gid] {
				return fmt.Errorf("%s.other_groups references undefined group %d", path, gid)
			}
		}
		if user.Mail != "" {
			address, err := mail.ParseAddress(user.Mail)
			if err != nil || address.Name != "" || address.Address != user.Mail {
				return fmt.Errorf("%s.mail must be a plain email address", path)
			}
		}
		if err := validateLDAPPassword(user); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}

func validateLDAPListen(name, value string) error {
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s must be a numeric IP address and port", name)
	}
	if host == "" {
		host = "0.0.0.0"
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return fmt.Errorf("%s must use a numeric IP address without a zone", name)
	}
	unicast := addr.IsGlobalUnicast() || addr.IsLoopback()
	if !unicast && !addr.IsUnspecified() {
		return fmt.Errorf("%s must use a unicast or unspecified address", name)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || (port == 0 && !addr.IsLoopback()) {
		return fmt.Errorf("%s port must be between 1 and 65535 (zero is permitted on loopback only)", name)
	}
	return nil
}

func validateLDAPPassword(user LDAPUser) error {
	hasSHA256 := user.PassSHA256 != ""
	hasBcrypt := user.PassBcrypt != ""
	if hasSHA256 && hasBcrypt {
		return errors.New("provide only one of pass_bcrypt or pass_sha256")
	}
	if !user.Disabled && !hasSHA256 && !hasBcrypt {
		return errors.New("active users require pass_bcrypt or pass_sha256")
	}
	if hasSHA256 {
		decoded, err := hex.DecodeString(user.PassSHA256)
		if err != nil || len(decoded) != 32 {
			return errors.New("pass_sha256 must contain exactly 64 hexadecimal characters")
		}
	}
	if hasBcrypt {
		if !bcryptHashPattern.MatchString(user.PassBcrypt) {
			return errors.New("pass_bcrypt must be a complete bcrypt hash using the 2a, 2b, or 2y format")
		}
		cost, err := bcrypt.Cost([]byte(user.PassBcrypt))
		if err != nil || cost < bcrypt.MinCost || cost > 14 {
			return errors.New("pass_bcrypt cost must be between 4 and 14")
		}
	}
	return nil
}

func decodeLDAP(decoder *json.Decoder) (LDAPConfig, error) {
	var cfg LDAPConfig
	err := decodeLDAPObject(decoder, "ldap", map[string]any{
		"base_dn": &cfg.BaseDN, "users": &cfg.Users, "groups": &cfg.Groups,
	})
	return cfg, err
}

func decodeLDAPUser(decoder *json.Decoder, path string) (LDAPUser, error) {
	var user LDAPUser
	err := decodeLDAPObject(decoder, path, map[string]any{
		"name": &user.Name, "mail": &user.Mail, "pass_sha256": &user.PassSHA256,
		"pass_bcrypt": &user.PassBcrypt, "uid_number": &user.UIDNumber,
		"primary_group": &user.PrimaryGroup, "other_groups": &user.OtherGroups,
		"disabled": &user.Disabled, "can_search": &user.CanSearch,
	})
	return user, err
}

func decodeLDAPGroup(decoder *json.Decoder, path string) (LDAPGroup, error) {
	var group LDAPGroup
	err := decodeLDAPObject(decoder, path, map[string]any{"name": &group.Name, "gid": &group.GID})
	return group, err
}

func decodeLDAPObject(decoder *json.Decoder, path string, fields map[string]any) error {
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return fmt.Errorf("%s must be a JSON object", path)
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("read %s key: %w", path, err)
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("%s keys must be strings", path)
		}
		if seen[key] {
			return fmt.Errorf("duplicate %s key %q", path, key)
		}
		seen[key] = true
		target, ok := fields[key]
		if !ok {
			return fmt.Errorf("unknown %s key %q", path, key)
		}
		fieldPath := path + "." + key
		switch target := target.(type) {
		case *[]LDAPUser:
			*target, err = decodeLDAPArray(decoder, fieldPath, decodeLDAPUser)
		case *[]LDAPGroup:
			*target, err = decodeLDAPArray(decoder, fieldPath, decodeLDAPGroup)
		case *[]int:
			*target, err = decodeLDAPArray(decoder, fieldPath, func(decoder *json.Decoder, path string) (int, error) {
				var value int
				err := decodeLDAPScalar(decoder, path, &value)
				return value, err
			})
		default:
			err = decodeLDAPScalar(decoder, fieldPath, target)
		}
		if err != nil {
			return err
		}
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') {
		return fmt.Errorf("close %s object: invalid JSON", path)
	}
	return nil
}

func decodeLDAPArray[T any](
	decoder *json.Decoder,
	path string,
	decode func(*json.Decoder, string) (T, error),
) ([]T, error) {
	token, err := decoder.Token()
	if err != nil || token != json.Delim('[') {
		return nil, fmt.Errorf("%s must be a JSON array", path)
	}
	values := []T{}
	for decoder.More() {
		value, err := decode(decoder, fmt.Sprintf("%s[%d]", path, len(values)))
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim(']') {
		return nil, fmt.Errorf("close %s array: invalid JSON", path)
	}
	return values, nil
}

func decodeLDAPScalar(decoder *json.Decoder, path string, target any) error {
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return fmt.Errorf("%s must contain a valid JSON value", path)
	}
	// Decode through RawMessage so null cannot silently leave a zero value.
	// Do not include decoder errors: they may contain password material.
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%s must not be null", path)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		return fmt.Errorf("%s has an invalid JSON type or value", path)
	}
	return nil
}
