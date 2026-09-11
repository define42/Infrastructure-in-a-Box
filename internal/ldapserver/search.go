package ldapserver

import (
	"context"
	"net"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	ldap "github.com/go-ldap/ldap/v3"
)

const maxSearchResults = 1000

func (s *Server) search(ctx context.Context, conn net.Conn, id int64, op *ber.Packet, canSearch bool) error {
	done := func(code uint16, message string) error {
		return writeResult(conn, id, ldap.ApplicationSearchResultDone, code, message)
	}
	if op.TagType != ber.TypeConstructed || len(op.Children) != 8 || !octetString(op.Children[0]) {
		return done(ldap.LDAPResultProtocolError, "malformed search request")
	}
	args := op.Children
	scope, scopeOK := integer(args[1], ber.TagEnumerated)
	deref, derefOK := integer(args[2], ber.TagEnumerated)
	size, sizeOK := integer(args[3], ber.TagInteger)
	seconds, timeOK := integer(args[4], ber.TagInteger)
	if !scopeOK || scope < 0 || scope > 2 || !derefOK || deref < 0 || deref > 3 || !sizeOK || size < 0 || !timeOK || seconds < 0 || !isPacket(args[5], ber.ClassUniversal, ber.TypePrimitive, ber.TagBoolean) || !isPacket(args[7], ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence) {
		return done(ldap.LDAPResultProtocolError, "malformed search request")
	}
	base, err := ldap.ParseDN(args[0].Data.String())
	if err != nil {
		return done(ldap.LDAPResultInvalidDNSyntax, "invalid search base")
	}
	root := len(base.RDNs) == 0 && scope == ldap.ScopeBaseObject
	if !root && !canSearch {
		return done(ldap.LDAPResultInsufficientAccessRights, "directory search requires an authorized bind")
	}
	filter, err := compileFilter(args[6])
	if err != nil {
		return done(ldap.LDAPResultInappropriateMatching, "unsupported or malformed filter")
	}
	attributes := make([]string, 0, len(args[7].Children))
	for _, attr := range args[7].Children {
		if !octetString(attr) {
			return done(ldap.LDAPResultProtocolError, "malformed attribute selection")
		}
		attributes = append(attributes, attr.Data.String())
	}
	typesOnly, _ := args[5].Value.(bool)
	entries := s.entries
	if root {
		entries = []entry{s.rootDSE()}
	}
	foundBase := false
	for _, e := range entries {
		if e.parsedDN.EqualFold(base) {
			foundBase = true
			break
		}
	}
	if !foundBase {
		return done(ldap.LDAPResultNoSuchObject, "search base does not exist")
	}
	limit := int64(maxSearchResults)
	if size > 0 && size < limit {
		limit = size
	}
	duration := ioTimeout
	if seconds > 0 && seconds < int64(duration/time.Second) {
		duration = time.Duration(seconds) * time.Second
	}
	deadline := time.Now().Add(duration)
	var count int64
	for _, e := range entries {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Now().After(deadline) {
			return done(ldap.LDAPResultTimeLimitExceeded, "search time limit exceeded")
		}
		inScope := e.parsedDN.EqualFold(base)
		if scope != ldap.ScopeBaseObject && base.AncestorOfFold(e.parsedDN) {
			inScope = scope == ldap.ScopeWholeSubtree || len(e.parsedDN.RDNs) == len(base.RDNs)+1
		} else if scope == ldap.ScopeSingleLevel {
			inScope = false
		}
		if !inScope || filter(e) != matchTrue {
			continue
		}
		if count == limit {
			return done(ldap.LDAPResultSizeLimitExceeded, "search size limit exceeded")
		}
		if err := writeMessageUntil(conn, id, e.packet(attributes, typesOnly), deadline); err != nil {
			return err
		}
		count++
	}
	if time.Now().After(deadline) {
		return done(ldap.LDAPResultTimeLimitExceeded, "search time limit exceeded")
	}
	return done(ldap.LDAPResultSuccess, "")
}
