package ldapserver

import (
	"slices"
	"strconv"
	"strings"

	"github.com/define42/Infrastructure-in-a-Box/internal/config"
	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

type entry struct {
	dn       string
	parsedDN *ldap.DN
	attrs    map[string][]string
}

func newEntry(dn string, attrs map[string][]string) entry {
	parsed, _ := ldap.ParseDN(dn) // DNs are composed solely from validated config.
	return entry{dn: dn, parsedDN: parsed, attrs: attrs}
}

func (e entry) values(name string) []string {
	for attr, values := range e.attrs {
		if strings.EqualFold(attr, name) {
			return values
		}
	}
	return nil
}

func (s *Server) buildDirectory(cfg config.LDAPConfig) {
	base := newEntry(cfg.BaseDN, map[string][]string{"objectClass": {"top", "organizationalRole", "extensibleObject"}, "cn": {"Directory"}})
	rdnAttrs := make(map[string][]string)
	for _, attr := range base.parsedDN.RDNs[0].Attributes {
		name := strings.ToLower(attr.Type)
		rdnAttrs[name] = append(rdnAttrs[name], attr.Value)
		if strings.EqualFold(attr.Type, "dc") {
			base.attrs["objectClass"] = []string{"top", "domain", "extensibleObject"}
		}
	}
	for name, values := range rdnAttrs {
		if name == "objectclass" {
			base.attrs["objectClass"] = append(base.attrs["objectClass"], values...)
			continue
		}
		base.attrs[name] = values
	}
	s.entries = []entry{
		base,
		newEntry("ou=users,"+cfg.BaseDN, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"users"}}),
		newEntry("ou=groups,"+cfg.BaseDN, map[string][]string{"objectClass": {"top", "organizationalUnit"}, "ou": {"groups"}}),
	}
	groups := make(map[int]*entry, len(cfg.Groups))
	for _, group := range cfg.Groups {
		// extensibleObject permits DN memberships without combining incompatible
		// structural classes, and also permits groups with no members.
		e := newEntry("cn="+ldap.EscapeDN(group.Name)+",ou=groups,"+cfg.BaseDN, map[string][]string{
			"objectClass": {"top", "posixGroup", "extensibleObject"},
			"cn":          {group.Name}, "gidNumber": {strconv.Itoa(group.GID)},
		})
		groups[group.GID] = &e
	}
	for _, user := range cfg.Users {
		e := newEntry("uid="+ldap.EscapeDN(user.Name)+",ou=users,"+cfg.BaseDN, map[string][]string{
			"objectClass": {"top", "person", "organizationalPerson", "inetOrgPerson", "extensibleObject"},
			"uid":         {user.Name}, "cn": {user.Name}, "sn": {user.Name},
			"gidNumber": {strconv.Itoa(user.PrimaryGroup)},
		})
		if user.Mail != "" {
			e.attrs["mail"] = []string{user.Mail}
		}
		if user.UIDNumber > 0 {
			e.attrs["objectClass"] = append(e.attrs["objectClass"], "posixAccount")
			e.attrs["uidNumber"] = []string{strconv.Itoa(user.UIDNumber)}
			e.attrs["homeDirectory"] = []string{"/home/" + user.Name}
			e.attrs["loginShell"] = []string{"/bin/sh"}
		}
		gids := append([]int{user.PrimaryGroup}, user.OtherGroups...)
		slices.Sort(gids)
		for _, gid := range slices.Compact(gids) {
			group := groups[gid]
			e.attrs["memberOf"] = append(e.attrs["memberOf"], group.dn)
			group.attrs["member"] = append(group.attrs["member"], e.dn)
			group.attrs["uniqueMember"] = append(group.attrs["uniqueMember"], e.dn)
			group.attrs["memberUid"] = append(group.attrs["memberUid"], user.Name)
		}
		s.entries = append(s.entries, e)
		s.users = append(s.users, credentials(user, e.parsedDN))
	}
	for _, group := range cfg.Groups {
		s.entries = append(s.entries, *groups[group.GID])
	}
}

func (s *Server) rootDSE() entry {
	return newEntry("", map[string][]string{
		"objectClass":          {"top"},
		"namingContexts":       {s.config.BaseDN},
		"supportedLDAPVersion": {"3"},
		"vendorName":           {"Infrastructure-in-a-Box"},
	})
}

func (e entry) packet(attributes []string, typesOnly bool) *ber.Packet {
	op := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "")
	op.AppendChild(textPacket(e.dn))
	attrs := ber.NewSequence("")
	names := make([]string, 0, len(e.attrs))
	for name := range e.attrs {
		if selectAttribute(name, attributes) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		attr := ber.NewSequence("")
		attr.AppendChild(textPacket(name))
		values := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "")
		if !typesOnly {
			for _, value := range e.attrs[name] {
				values.AppendChild(textPacket(value))
			}
		}
		attr.AppendChild(values)
		attrs.AppendChild(attr)
	}
	op.AppendChild(attrs)
	return op
}

func selectAttribute(name string, requested []string) bool {
	operational := false
	switch strings.ToLower(name) {
	case "namingcontexts", "supportedldapversion", "vendorname":
		operational = true
	}
	if len(requested) == 0 {
		return !operational
	}
	for _, attr := range requested {
		if strings.EqualFold(name, attr) || (attr == "*" && !operational) || (attr == "+" && operational) {
			return true
		}
	}
	return false
}
