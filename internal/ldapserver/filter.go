package ldapserver

import (
	"errors"
	"strconv"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

type match uint8

const (
	matchFalse match = iota
	matchTrue
	matchUndefined
)

type entryFilter func(entry) match

var errUnsupportedFilter = errors.New("unsupported or malformed LDAP search filter")

// compileFilter validates the entire tree before evaluating any entries. Unknown
// attributes have undefined equality, including password/hash attributes, so NOT
// cannot turn an unknown comparison into an attribute-value oracle.
func compileFilter(packet *ber.Packet) (entryFilter, error) {
	if packet.ClassType != ber.ClassContext {
		return nil, errUnsupportedFilter
	}
	if packet.Tag == ldap.FilterPresent {
		if packet.TagType != ber.TypePrimitive || packet.Data.Len() == 0 {
			return nil, errUnsupportedFilter
		}
		name := strings.ToLower(packet.Data.String())
		return func(e entry) match {
			if !knownAttribute(name) {
				return matchUndefined
			}
			return truth(len(e.values(name)) != 0)
		}, nil
	}
	if packet.TagType != ber.TypeConstructed {
		return nil, errUnsupportedFilter
	}
	switch packet.Tag {
	case ldap.FilterAnd, ldap.FilterOr, ldap.FilterNot:
		if len(packet.Children) == 0 || (packet.Tag == ldap.FilterNot && len(packet.Children) != 1) {
			return nil, errUnsupportedFilter
		}
		children := make([]entryFilter, 0, len(packet.Children))
		for _, child := range packet.Children {
			filter, err := compileFilter(child)
			if err != nil {
				return nil, err
			}
			children = append(children, filter)
		}
		return func(e entry) match {
			undefined := false
			for _, child := range children {
				value := child(e)
				if packet.Tag == ldap.FilterNot {
					if value == matchUndefined {
						return value
					}
					return truth(value == matchFalse)
				}
				if (packet.Tag == ldap.FilterAnd && value == matchFalse) || (packet.Tag == ldap.FilterOr && value == matchTrue) {
					return value
				}
				undefined = undefined || value == matchUndefined
			}
			if undefined {
				return matchUndefined
			}
			return truth(packet.Tag == ldap.FilterAnd)
		}, nil
	case ldap.FilterEqualityMatch:
		if len(packet.Children) != 2 || !octetString(packet.Children[0]) || !octetString(packet.Children[1]) {
			return nil, errUnsupportedFilter
		}
		name, value := strings.ToLower(packet.Children[0].Data.String()), packet.Children[1].Data.String()
		if name == "" {
			return nil, errUnsupportedFilter
		}
		valid := knownAttribute(name)
		switch name {
		case "member", "uniquemember", "memberof", "namingcontexts":
			_, err := ldap.ParseDN(value)
			valid = err == nil
		case "uidnumber", "gidnumber":
			_, err := strconv.ParseInt(value, 10, 64)
			valid = err == nil
		}
		return func(e entry) match {
			if !valid {
				return matchUndefined
			}
			for _, candidate := range e.values(name) {
				if equalAttribute(name, candidate, value) {
					return matchTrue
				}
			}
			return matchFalse
		}, nil
	case ldap.FilterSubstrings:
		return compileSubstrings(packet)
	default:
		return nil, errUnsupportedFilter
	}
}

func compileSubstrings(packet *ber.Packet) (entryFilter, error) {
	if len(packet.Children) != 2 || !octetString(packet.Children[0]) || !isPacket(packet.Children[1], ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) || len(packet.Children[1].Children) == 0 {
		return nil, errUnsupportedFilter
	}
	name := strings.ToLower(packet.Children[0].Data.String())
	if name == "" {
		return nil, errUnsupportedFilter
	}
	parts := packet.Children[1].Children
	for i, part := range parts {
		if part.ClassType != ber.ClassContext || part.TagType != ber.TypePrimitive || part.Tag > 2 || (part.Tag == 0 && i != 0) || (part.Tag == 2 && i != len(parts)-1) {
			return nil, errUnsupportedFilter
		}
	}
	return func(e entry) match {
		if !knownAttribute(name) {
			return matchUndefined
		}
		switch name {
		case "member", "uniquemember", "memberof", "namingcontexts", "uidnumber", "gidnumber":
			// DN and integer attributes do not define substring matching rules.
			return matchUndefined
		}
		for _, value := range e.values(name) {
			rest := strings.ToLower(value)
			matched := true
			for _, part := range parts {
				fragment := strings.ToLower(part.Data.String())
				switch part.Tag {
				case 0:
					matched = strings.HasPrefix(rest, fragment)
					if matched {
						rest = rest[len(fragment):]
					}
				case 1:
					index := strings.Index(rest, fragment)
					matched = index >= 0
					if matched {
						rest = rest[index+len(fragment):]
					}
				case 2:
					matched = strings.HasSuffix(rest, fragment)
				}
				if !matched {
					break
				}
			}
			if matched {
				return matchTrue
			}
		}
		return matchFalse
	}, nil
}

func truth(value bool) match {
	if value {
		return matchTrue
	}
	return matchFalse
}

func knownAttribute(name string) bool {
	switch name {
	case "objectclass", "uid", "cn", "sn", "ou", "dc", "o", "mail", "uidnumber", "gidnumber", "homedirectory", "loginshell", "member", "uniquemember", "memberuid", "memberof", "namingcontexts", "supportedldapversion", "vendorname":
		return true
	default:
		return false
	}
}

func equalAttribute(name, a, b string) bool {
	switch name {
	case "member", "uniquemember", "memberof", "namingcontexts":
		x, err := ldap.ParseDN(a)
		if err != nil {
			return false
		}
		y, err := ldap.ParseDN(b)
		return err == nil && x.EqualFold(y)
	case "gidnumber", "uidnumber":
		x, err := strconv.ParseInt(a, 10, 64)
		if err != nil {
			return false
		}
		y, err := strconv.ParseInt(b, 10, 64)
		return err == nil && x == y
	default:
		return strings.EqualFold(a, b)
	}
}
