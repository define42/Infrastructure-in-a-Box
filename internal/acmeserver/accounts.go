package acmeserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strings"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmeauth"
	"github.com/go-jose/go-jose/v4"
)

type accountInput struct {
	Contact            json.RawMessage `json:"contact"`
	Status             json.RawMessage `json:"status"`
	OnlyReturnExisting bool            `json:"onlyReturnExisting"`
}

func (s *Server) newAccount(w http.ResponseWriter, signed *acmeauth.Request) {
	if signed.KeyID != "" {
		s.writeProblem(w, failure(400, "malformed", "new-account requires an embedded public JWK"))
		return
	}
	var input accountInput
	if err := decodePayload(signed.Payload, &input); err != nil {
		s.writeProblem(w, failure(400, "malformed", "invalid account request"))
		return
	}
	s.mu.Lock()
	for _, a := range s.state.Accounts {
		if a.Thumbprint == signed.Thumbprint {
			s.mu.Unlock()
			w.Header().Set("Location", s.url("/account/"+a.ID))
			s.writeJSON(w, http.StatusOK, s.accountView(a))
			return
		}
	}
	if input.OnlyReturnExisting {
		s.mu.Unlock()
		s.writeProblem(w, failure(400, "accountDoesNotExist", "no account is registered with this key"))
		return
	}
	contact, p := accountContacts(input.Contact)
	if p != nil {
		s.mu.Unlock()
		s.writeProblem(w, p)
		return
	}
	if len(s.state.Accounts) >= maxAccounts {
		s.mu.Unlock()
		s.writeProblem(w, failure(429, "rateLimited", "the certificate authority has reached its account limit"))
		return
	}
	id, err := randomID()
	if err != nil {
		s.mu.Unlock()
		s.internalError(w, err)
		return
	}
	a := account{ID: id, Key: signed.Key, Thumbprint: signed.Thumbprint, Status: "valid", Contact: contact}
	next := s.state.clone()
	next.Accounts[id] = a
	err = s.commit(next)
	s.mu.Unlock()
	if err != nil {
		s.internalError(w, err)
		return
	}
	w.Header().Set("Location", s.url("/account/"+id))
	s.writeJSON(w, http.StatusCreated, s.accountView(a))
}

func (s *Server) account(w http.ResponseWriter, signed *acmeauth.Request, accountID, id string) {
	if id != accountID {
		s.writeProblem(w, failure(403, "unauthorized", "account belongs to another key"))
		return
	}
	var input accountInput
	if len(signed.Payload) != 0 {
		if err := decodePayload(signed.Payload, &input); err != nil {
			s.writeProblem(w, failure(400, "malformed", "invalid account update"))
			return
		}
	}
	contact, p := accountContacts(input.Contact)
	if p != nil {
		s.writeProblem(w, p)
		return
	}
	status := ""
	if len(input.Status) != 0 {
		if err := json.Unmarshal(input.Status, &status); err != nil || (status != "valid" && status != "deactivated") {
			s.writeProblem(w, failure(400, "malformed", "account status must be valid or deactivated"))
			return
		}
	}
	s.mu.Lock()
	a, p := s.activeAccount(signed, accountID)
	if p != nil {
		s.mu.Unlock()
		s.writeProblem(w, p)
		return
	}
	if len(input.Contact) != 0 || status != "" {
		next := s.state.clone()
		if len(input.Contact) != 0 {
			a.Contact = contact
		}
		if status != "" {
			a.Status = status
		}
		next.Accounts[id] = a
		if a.Status == "deactivated" {
			for orderID, o := range next.Orders {
				if o.AccountID == id && (o.Status == "pending" || o.Status == "ready") {
					o.Status = "invalid"
					o.Error = failure(403, "unauthorized", "account was deactivated")
					next.Orders[orderID] = o
				}
			}
			for authID, auth := range next.Authorizations {
				if auth.AccountID == id && auth.Status == "pending" {
					auth.Status = "deactivated"
					auth.ChallengeStatus = "invalid"
					auth.Error = failure(403, "unauthorized", "account was deactivated")
					next.Authorizations[authID] = auth
				}
			}
		}
		if err := s.commit(next); err != nil {
			s.mu.Unlock()
			s.internalError(w, err)
			return
		}
	}
	s.mu.Unlock()
	s.writeJSON(w, http.StatusOK, s.accountView(a))
}

func (s *Server) accountOrders(w http.ResponseWriter, signed *acmeauth.Request, accountID, id string) {
	if !s.postAsGet(w, signed) {
		return
	}
	if accountID != id {
		s.writeProblem(w, failure(403, "unauthorized", "orders belong to another account"))
		return
	}
	s.mu.Lock()
	if _, p := s.activeAccount(signed, accountID); p != nil {
		s.mu.Unlock()
		s.writeProblem(w, p)
		return
	}
	orders := make([]string, 0)
	for _, o := range s.state.Orders {
		if o.AccountID == id && o.Status != "invalid" && (o.Status == "valid" || s.now().Before(o.Expires)) {
			orders = append(orders, s.url("/order/"+o.ID))
		}
	}
	s.mu.Unlock()
	slices.Sort(orders)
	s.writeJSON(w, http.StatusOK, map[string]any{"orders": orders})
}

func (s *Server) keyChange(w http.ResponseWriter, signed *acmeauth.Request, accountID string) {
	inner, err := acmeauth.VerifyKeyChange(signed.Payload, s.url("/key-change"))
	if err != nil {
		if authErr, ok := errors.AsType[*acmeauth.Error](err); ok {
			s.writeProblem(w, failure(authErr.Status, authErr.Type, authErr.Detail))
		} else {
			s.internalError(w, err)
		}
		return
	}
	var input struct {
		Account string          `json:"account"`
		OldKey  jose.JSONWebKey `json:"oldKey"`
	}
	if err := decodePayload(inner.Payload, &input); err != nil || input.Account != signed.KeyID {
		s.writeProblem(w, failure(400, "malformed", "key-change must identify the current account and old public key"))
		return
	}
	oldThumbprint, err := acmeauth.Thumbprint(input.OldKey)
	if err != nil || oldThumbprint != signed.Thumbprint {
		s.writeProblem(w, failure(400, "malformed", "key-change oldKey does not match the account key"))
		return
	}
	if inner.Thumbprint == oldThumbprint {
		s.writeProblem(w, failure(400, "malformed", "key-change requires a different new key"))
		return
	}
	s.mu.Lock()
	a, p := s.activeAccount(signed, accountID)
	if p != nil {
		s.mu.Unlock()
		s.writeProblem(w, p)
		return
	}
	for _, existing := range s.state.Accounts {
		if existing.Thumbprint == inner.Thumbprint {
			s.mu.Unlock()
			w.Header().Set("Location", s.url("/account/"+existing.ID))
			s.writeProblem(w, failure(409, "malformed", "the new key is already associated with an account"))
			return
		}
	}
	a.Key = inner.Key
	a.Thumbprint = inner.Thumbprint
	next := s.state.clone()
	next.Accounts[accountID] = a
	err = s.commit(next)
	s.mu.Unlock()
	if err != nil {
		s.internalError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.accountView(a))
}

// activeAccount requires s.mu to be held, and rechecks the signing key so a
// concurrent rollover or deactivation cannot authorize a stale request.
func (s *Server) activeAccount(signed *acmeauth.Request, accountID string) (account, *problem) {
	a, ok := s.state.Accounts[accountID]
	if !ok || a.Status != "valid" || a.Thumbprint != signed.Thumbprint || signed.KeyID != s.url("/account/"+accountID) {
		return account{}, failure(403, "unauthorized", "account is not active or its key has changed")
	}
	return a, nil
}

func (s *Server) accountView(a account) any {
	return struct {
		Status  string   `json:"status"`
		Contact []string `json:"contact,omitempty"`
		Orders  string   `json:"orders"`
	}{Status: a.Status, Contact: a.Contact, Orders: s.url("/orders/" + a.ID)}
}

func accountContacts(data json.RawMessage) ([]string, *problem) {
	if len(data) == 0 {
		return nil, nil
	}
	var contact []string
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) || json.Unmarshal(data, &contact) != nil || len(contact) > 16 {
		return nil, failure(400, "invalidContact", "contact must be an array of at most 16 mailto URLs")
	}
	for _, value := range contact {
		u, err := url.Parse(value)
		if err != nil || len(value) > 2048 || strings.TrimSpace(value) != value {
			return nil, failure(400, "invalidContact", "invalid contact URL")
		}
		if !strings.EqualFold(u.Scheme, "mailto") {
			return nil, failure(400, "unsupportedContact", "only mailto contact URLs are supported")
		}
		address, err := url.PathUnescape(u.Opaque)
		if err != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host != "" || u.User != nil ||
			strings.ContainsAny(address, "\r\n<>") || strings.TrimSpace(address) != address {
			return nil, failure(400, "invalidContact", "mailto contact must contain one email address and no headers")
		}
		parsed, err := mail.ParseAddress(address)
		if err != nil || parsed.Name != "" {
			return nil, failure(400, "invalidContact", "mailto contact must contain one valid email address")
		}
	}
	return contact, nil
}
