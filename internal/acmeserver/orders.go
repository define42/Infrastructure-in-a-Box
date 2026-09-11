package acmeserver

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/define42/Infrastructure-in-a-Box/internal/acmeauth"
	"github.com/define42/Infrastructure-in-a-Box/internal/pki"
)

func (s *Server) newOrder(w http.ResponseWriter, signed *acmeauth.Request, accountID string) {
	var body struct {
		Identifiers []identifier `json:"identifiers"`
		NotBefore   string       `json:"notBefore"`
		NotAfter    string       `json:"notAfter"`
	}
	if err := decodePayload(signed.Payload, &body); err != nil || len(body.Identifiers) == 0 || len(body.Identifiers) > maxIdentifiers {
		s.writeProblem(w, failure(400, "malformed", "an order requires between 1 and 16 DNS identifiers"))
		return
	}
	if body.NotBefore != "" || body.NotAfter != "" {
		s.writeProblem(w, failure(400, "rejectedIdentifier", "custom certificate validity periods are not supported"))
		return
	}
	seen := make(map[string]bool)
	for i, name := range body.Identifiers {
		for _, c := range name.Value {
			if c > 127 {
				s.writeProblem(w, failure(400, "rejectedIdentifier", "DNS identifiers must use ASCII names"))
				return
			}
		}
		name.Value = strings.ToLower(strings.TrimSuffix(name.Value, "."))
		if name.Type != "dns" || !s.allowedName(name.Value) || seen[name.Value] {
			s.writeProblem(w, failure(400, "rejectedIdentifier", "identifiers must be unique DHCP hostnames in the configured domain"))
			return
		}
		if _, err := s.validator.Lookup(name.Value); err != nil {
			s.writeProblem(w, failure(400, "rejectedIdentifier", "the requested hostname has no eligible active DHCP lease"))
			return
		}
		seen[name.Value] = true
		body.Identifiers[i] = name
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, p := s.activeAccount(signed, accountID); p != nil {
		s.writeProblem(w, p)
		return
	}
	next := s.state.clone()
	s.prune(&next)
	pending := 0
	for _, o := range next.Orders {
		if o.AccountID == accountID && (o.Status == "pending" || o.Status == "ready") {
			pending++
		}
	}
	if pending >= 32 || len(next.Orders) >= maxRecords || len(next.Authorizations)+len(body.Identifiers) > maxRecords {
		w.Header().Set("Retry-After", "3600")
		s.writeProblem(w, failure(429, "rateLimited", "too many outstanding orders"))
		return
	}
	id, err := randomID()
	if err != nil {
		s.internalError(w, err)
		return
	}
	o := order{ID: id, AccountID: accountID, Status: "pending", Expires: s.now().Add(orderLifetime).UTC(), Identifiers: body.Identifiers}
	for _, name := range body.Identifiers {
		authID, err := randomID()
		if err != nil {
			s.internalError(w, err)
			return
		}
		token, err := randomID()
		if err != nil {
			s.internalError(w, err)
			return
		}
		next.Authorizations[authID] = authorization{
			ID: authID, AccountID: accountID, OrderID: id, Name: name.Value,
			Status: "pending", Expires: o.Expires, Token: token, ChallengeStatus: "pending",
		}
		o.AuthIDs = append(o.AuthIDs, authID)
	}
	next.Orders[id] = o
	if err := s.commit(next); err != nil {
		s.internalError(w, err)
		return
	}
	w.Header().Set("Location", s.url("/order/"+id))
	s.writeJSON(w, http.StatusCreated, s.orderView(o))
}

func (s *Server) orderView(o order) map[string]any {
	status := o.Status
	if (status == "pending" || status == "ready") && !s.now().Before(o.Expires) {
		status = "invalid"
	}
	auths := make([]string, 0, len(o.AuthIDs))
	for _, id := range o.AuthIDs {
		auths = append(auths, s.url("/authz/"+id))
	}
	view := map[string]any{"status": status, "expires": o.Expires, "identifiers": o.Identifiers,
		"authorizations": auths, "finalize": s.url("/finalize/" + o.ID)}
	if o.CertificateID != "" {
		view["certificate"] = s.url("/certificate/" + o.CertificateID)
	}
	if o.Error != nil {
		view["error"] = o.Error
	}
	return view
}

func (s *Server) challengeView(a authorization) map[string]any {
	view := map[string]any{"type": "http-01", "url": s.url("/challenge/" + a.ID), "status": a.ChallengeStatus, "token": a.Token}
	if a.Validated != nil {
		view["validated"] = a.Validated
	}
	if a.Error != nil {
		view["error"] = a.Error
	}
	return view
}

func (s *Server) authorizationView(a authorization) map[string]any {
	status := a.Status
	if (status == "pending" || status == "valid") && !s.now().Before(a.Expires) {
		status = "expired"
	}
	return map[string]any{"status": status, "expires": a.Expires, "identifier": identifier{Type: "dns", Value: a.Name},
		"challenges": []any{s.challengeView(a)}}
}

func (s *Server) getOrder(w http.ResponseWriter, signed *acmeauth.Request, accountID, id string) {
	if !s.postAsGet(w, signed) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, p := s.activeAccount(signed, accountID); p != nil {
		s.writeProblem(w, p)
		return
	}
	o, ok := s.state.Orders[id]
	if !ok || o.AccountID != accountID {
		s.writeProblem(w, failure(404, "malformed", "order not found"))
		return
	}
	s.writeJSON(w, http.StatusOK, s.orderView(o))
}

func (s *Server) getAuthorization(w http.ResponseWriter, signed *acmeauth.Request, accountID, id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, p := s.activeAccount(signed, accountID); p != nil {
		s.writeProblem(w, p)
		return
	}
	a, ok := s.state.Authorizations[id]
	if !ok || a.AccountID != accountID {
		s.writeProblem(w, failure(404, "malformed", "authorization not found"))
		return
	}
	if len(signed.Payload) != 0 {
		var update struct {
			Status string `json:"status"`
		}
		if err := decodePayload(signed.Payload, &update); err != nil || update.Status != "deactivated" {
			s.writeProblem(w, failure(400, "malformed", "only authorization deactivation is supported"))
			return
		}
		next := s.state.clone()
		a.Status = "deactivated"
		if a.ChallengeStatus == "processing" {
			a.ChallengeStatus = "invalid"
		}
		next.Authorizations[id] = a
		o := next.Orders[a.OrderID]
		if o.Status == "pending" || o.Status == "ready" {
			o.Status, o.Error = "invalid", failure(403, "unauthorized", "an authorization was deactivated")
			next.Orders[o.ID] = o
		}
		if err := s.commit(next); err != nil {
			s.internalError(w, err)
			return
		}
	}
	s.writeJSON(w, http.StatusOK, s.authorizationView(a))
}

func (s *Server) challenge(w http.ResponseWriter, r *http.Request, signed *acmeauth.Request, accountID, id string) {
	if len(signed.Payload) != 0 {
		var body map[string]any
		if err := decodePayload(signed.Payload, &body); err != nil || len(body) != 0 {
			s.writeProblem(w, failure(400, "malformed", "challenge acknowledgement must be an empty JSON object"))
			return
		}
	}
	s.mu.Lock()
	if _, p := s.activeAccount(signed, accountID); p != nil {
		s.mu.Unlock()
		s.writeProblem(w, p)
		return
	}
	a, ok := s.state.Authorizations[id]
	if !ok || a.AccountID != accountID {
		s.mu.Unlock()
		s.writeProblem(w, failure(404, "malformed", "challenge not found"))
		return
	}
	w.Header().Set("Link", "<"+s.url("/authz/"+id)+">;rel=\"up\"")
	if len(signed.Payload) == 0 || a.ChallengeStatus == "processing" || a.Status == "valid" {
		view := s.challengeView(a)
		s.mu.Unlock()
		s.writeJSON(w, http.StatusOK, view)
		return
	}
	o := s.state.Orders[a.OrderID]
	if a.Status != "pending" || o.Status != "pending" || !s.now().Before(a.Expires) {
		s.mu.Unlock()
		s.writeProblem(w, failure(400, "unauthorized", "authorization is no longer pending"))
		return
	}
	select {
	case s.validations <- struct{}{}:
	default:
		s.mu.Unlock()
		w.Header().Set("Retry-After", "5")
		s.writeProblem(w, failure(429, "rateLimited", "too many simultaneous challenge validations"))
		return
	}
	defer func() { <-s.validations }()
	next := s.state.clone()
	a.ChallengeStatus = "processing"
	next.Authorizations[id] = a
	if err := s.commit(next); err != nil {
		s.retryInterruptedChallenge(id)
		s.mu.Unlock()
		s.internalError(w, err)
		return
	}
	s.mu.Unlock()

	target, validationErr := s.validator.Validate(r.Context(), a.Name, a.Token, a.Token+"."+signed.Thumbprint)

	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok = s.state.Authorizations[id]
	if !ok {
		s.writeProblem(w, failure(404, "malformed", "authorization expired"))
		return
	}
	if a.Status != "pending" || a.ChallengeStatus != "processing" {
		s.writeJSON(w, http.StatusOK, s.challengeView(a))
		return
	}
	next = s.state.clone()
	o = next.Orders[a.OrderID]
	now := s.now().UTC()
	_, accountErr := s.activeAccount(signed, accountID)
	currentAccount := next.Accounts[accountID]
	if accountErr != nil && currentAccount.Status == "valid" && currentAccount.Thumbprint != signed.Thumbprint &&
		now.Before(a.Expires) && o.Status == "pending" {
		// Rollover changes the key authorization, but RFC 8555 section 7.3.5
		// preserves pending orders. Discard this old-key proof and allow a
		// fresh acknowledgement authenticated with the new account key.
		a.ChallengeStatus = "pending"
		next.Authorizations[id] = a
		if err := s.commit(next); err != nil {
			s.retryInterruptedChallenge(id)
			s.internalError(w, err)
			return
		}
		s.writeJSON(w, http.StatusOK, s.challengeView(a))
		return
	}
	if validationErr != nil || accountErr != nil || !now.Before(a.Expires) || o.Status != "pending" {
		a.Status, a.ChallengeStatus = "invalid", "invalid"
		a.Error = failure(400, "unauthorized", "HTTP-01 validation failed; serve the key authorization at the challenge path on the leased host's port 80")
		o.Status, o.Error = "invalid", a.Error
		if validationErr != nil {
			s.logger.Info("ACME HTTP-01 validation failed", "hostname", a.Name, "error", validationErr)
		}
	} else {
		a.Status, a.ChallengeStatus, a.Validated, a.Target = "valid", "valid", &now, target
	}
	next.Authorizations[id] = a
	if o.Status == "pending" {
		ready := true
		for _, authID := range o.AuthIDs {
			if next.Authorizations[authID].Status != "valid" {
				ready = false
				break
			}
		}
		if ready {
			o.Status = "ready"
		}
	}
	next.Orders[o.ID] = o
	if err := s.commit(next); err != nil {
		s.retryInterruptedChallenge(id)
		s.internalError(w, err)
		return
	}
	s.writeJSON(w, http.StatusOK, s.challengeView(a))
}

// A failed snapshot must not strand an outbound check in processing. Discard
// any uncommitted proof in memory; restart recovery does the same for the disk
// snapshot. If rename succeeded, the committed result is already in s.state.
// The caller holds s.mu.
func (s *Server) retryInterruptedChallenge(id string) {
	a, ok := s.state.Authorizations[id]
	if ok && a.Status == "pending" && a.ChallengeStatus == "processing" {
		a.ChallengeStatus = "pending"
		s.state.Authorizations[id] = a
	}
}

func (s *Server) finalize(w http.ResponseWriter, signed *acmeauth.Request, accountID, id string) {
	var body struct {
		CSR string `json:"csr"`
	}
	if err := decodePayload(signed.Payload, &body); err != nil {
		s.writeProblem(w, failure(400, "badCSR", "a base64url-encoded CSR is required"))
		return
	}
	csr, err := base64.RawURLEncoding.Strict().DecodeString(body.CSR)
	if err != nil || len(csr) == 0 || len(csr) > 48*1024 {
		s.writeProblem(w, failure(400, "badCSR", "CSR is empty, too large, or not valid base64url"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, p := s.activeAccount(signed, accountID); p != nil {
		s.writeProblem(w, p)
		return
	}
	o, ok := s.state.Orders[id]
	if !ok || o.AccountID != accountID {
		s.writeProblem(w, failure(404, "malformed", "order not found"))
		return
	}
	if o.Status == "valid" && sameCSR(o.CSR, csr) {
		w.Header().Set("Location", s.url("/order/"+id))
		s.writeJSON(w, http.StatusOK, s.orderView(o))
		return
	}
	if o.Status != "ready" || !s.now().Before(o.Expires) {
		s.writeProblem(w, failure(403, "orderNotReady", "order is not ready for certificate issuance"))
		return
	}
	if len(s.state.Certificates) >= maxRecords {
		s.writeProblem(w, failure(429, "rateLimited", "certificate storage capacity has been reached"))
		return
	}
	names := make([]string, 0, len(o.AuthIDs))
	for _, authID := range o.AuthIDs {
		a := s.state.Authorizations[authID]
		target, err := s.validator.Lookup(a.Name)
		if err != nil || a.Status != "valid" || !s.now().Before(a.Expires) || target != a.Target {
			next := s.state.clone()
			o.Status, o.Error = "invalid", failure(403, "unauthorized", "DHCP ownership changed or an authorization expired; create a new order")
			next.Orders[id] = o
			if err := s.commit(next); err != nil {
				s.internalError(w, err)
				return
			}
			s.writeProblem(w, o.Error)
			return
		}
		names = append(names, a.Name)
	}
	chain, err := s.ca.SignCSR(csr, names)
	if err != nil {
		if errors.Is(err, pki.ErrInvalidCSR) {
			s.writeProblem(w, failure(400, "badCSR", err.Error()))
		} else {
			s.internalError(w, err)
		}
		return
	}
	leaf, err := parseLeaf(chain)
	if err != nil {
		s.internalError(w, err)
		return
	}
	certID, err := randomID()
	if err != nil {
		s.internalError(w, err)
		return
	}
	next := s.state.clone()
	next.Certificates[certID] = certificate{ID: certID, AccountID: accountID, OrderID: id, PEM: chain, Serial: leaf.SerialNumber.String(), NotAfter: leaf.NotAfter}
	o.Status, o.CertificateID, o.CSR, o.Expires = "valid", certID, csr, leaf.NotAfter
	next.Orders[id] = o
	if err := s.commit(next); err != nil {
		s.internalError(w, err)
		return
	}
	w.Header().Set("Location", s.url("/order/"+id))
	s.writeJSON(w, http.StatusOK, s.orderView(o))
}

func (s *Server) getCertificate(w http.ResponseWriter, signed *acmeauth.Request, accountID, id string) {
	if !s.postAsGet(w, signed) {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, p := s.activeAccount(signed, accountID); p != nil {
		s.writeProblem(w, p)
		return
	}
	c, ok := s.state.Certificates[id]
	if !ok || c.AccountID != accountID {
		s.writeProblem(w, failure(404, "malformed", "certificate not found"))
		return
	}
	w.Header().Set("Content-Type", "application/pem-certificate-chain")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(c.PEM); err != nil {
		s.logger.Debug("write ACME certificate", "error", err)
	}
}
