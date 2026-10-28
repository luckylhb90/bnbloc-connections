package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc-connections/provider"
	"github.com/luckylhb90/bnbloc/component"
)

// handleHosts answers which hosts this component handles for the turn: for
// the person's own agent, the enabled connectors' (connected or not: a
// call to one not connected gets a card) and its own API's; for a borrowed
// or platform agent, the connectors a digital worker serves it at; with
// the connectors' CLI placeholders.
func (s *Service) handleHosts(w http.ResponseWriter, r *http.Request, t component.Turn, _ []byte) {
	// Streams: a streamed request is decided here on its method and path
	// (streamedRefusal).
	out := component.EgressHosts{Hosts: []string{}, Env: map[string]string{}, Streams: true}
	if t.Drive != component.DriveOwn {
		systems, err := s.systemsFor(r.Context(), t)
		if err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "connectors unreadable"})
			return
		}
		list, _ := s.enabled(r.Context(), t.Org)
		for i, v := range systems {
			if v.Connected {
				out.Hosts = append(out.Hosts, list[i].Hosts...)
				for k, val := range list[i].CLIEnv {
					out.Env[k] = val
				}
			}
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	list, err := s.enabled(r.Context(), t.Org)
	if err != nil {
		slog.Warn("connections: connectors unreadable", "org", t.Org, "error", err)
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "connectors unreadable"})
		return
	}
	out.Hosts = append(out.Hosts, s.SelfHost())
	for _, c := range list {
		out.Hosts = append(out.Hosts, c.Hosts...)
		for k, v := range c.CLIEnv {
			out.Env[k] = v
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// refusal is an egress answer of the component's own: JSON the agent
// reports like any API error, and the card the person gets.
func refusal(status int, msg string, card *component.Card, extra map[string]any) component.EgressResponse {
	body := map[string]any{"error": msg, "from": "bnbloc connections"}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	return component.EgressResponse{Status: status, Header: map[string][]string{"Content-Type": {"application/json"}}, Body: raw, Card: card}
}

// handleEgress serves one request a turn's command sent to a claimed host.
func (s *Service) handleEgress(w http.ResponseWriter, r *http.Request, t component.Turn, body []byte) {
	var in component.EgressRequest
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "not an egress request"})
		return
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "an egress request names an https URL"})
		return
	}
	if err := connector.CheckPath(u); err != nil {
		writeJSON(w, http.StatusOK, refusal(http.StatusBadRequest, err.Error(), nil, nil))
		return
	}
	host := strings.ToLower(u.Hostname())
	out, a := s.serve(r.Context(), t, in, u, host)
	if a != nil {
		audit(w, *a)
	}
	writeJSON(w, http.StatusOK, out)
}

// serve decides one request: the drive, the connector, the connection, the
// policy; then the call as the member.
func (s *Service) serve(ctx context.Context, t component.Turn, in component.EgressRequest, u *url.URL, host string) (component.EgressResponse, *component.Audit) {
	if host == s.SelfHost() {
		if t.Drive != component.DriveOwn {
			return refusal(http.StatusForbidden, "the connections API serves the person's own agent", nil, nil), nil
		}
		return s.selfAPI(ctx, t, in, u), nil
	}
	list, err := s.enabled(ctx, t.Org)
	if err != nil {
		return refusal(http.StatusBadGateway, "the connections component cannot read its connectors right now", nil, nil), nil
	}
	var c connector.Connector
	for _, x := range list {
		if x.Handles(host) {
			c = x
		}
	}
	if c.Name == "" {
		return refusal(http.StatusForbidden, host+" is not a system your organization enabled", nil, nil), nil
	}
	target := in.Method + " " + u.Path
	if in.Report == nil && !s.limiter.allow(t.Requester+"\n"+c.Name, s.now()) {
		return refusal(http.StatusTooManyRequests, "too many requests to "+c.DisplayName+" for now; slow down", nil, nil),
			&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "deny", Detail: "rate"}
	}
	act, err := s.actingAs(ctx, t, c)
	if err == nil && !act.ok && t.Drive == component.DriveOwn && s.settleWait(ctx, t.Requester, t.Org, c) {
		// The person consented in their browser and never came back to the
		// page: the request completes the connection.
		act, err = s.actingAs(ctx, t, c)
	}
	if err != nil {
		return refusal(http.StatusBadGateway, "the connections component cannot read your connection right now", nil, nil), nil
	}
	if !act.ok {
		return s.notConnected(t, c, in, u, act)
	}
	p, g := act.p, act.g
	if p.Worker != nil && in.Report == nil && !s.limiter.allow(p.key()+"\n"+c.Name, s.now()) {
		return refusal(http.StatusTooManyRequests, "too many requests to "+c.DisplayName+" as "+p.as()+" for now; slow down", nil, nil),
			&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "deny", Detail: "rate, as worker " + p.asID()}
	}
	if p.Worker != nil && c.FromMember() && t.Drive == component.DriveBorrowed {
		// A worker's credentials never go to a colleague's computer.
		return refusal(http.StatusForbidden, c.DisplayName+" is reached from members' computers, and a borrowed agent does not carry "+p.as()+"'s credentials there", nil, nil),
			&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "deny", Detail: "borrowed drive, worker sent from a member's computer"}
	}
	as := asDetail(p)
	if ans, ok := c.Answering(in.Method, u.Path); ok {
		// A CLI's own sign-in step: the component holds the credential, so
		// it answers the step itself and sends nothing.
		s.record(ctx, t, p, c, in.Method, u.Path, ans.Status, "answered")
		return component.EgressResponse{Status: ans.Status, Header: map[string][]string{"Content-Type": {ans.ContentType}}, Body: []byte(ans.Body)},
			&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "allow", Detail: "answered here" + as}
	}
	if in.Streamed {
		if why := streamedRefusal(c, in.Method, u.Path); why != "" {
			s.record(ctx, t, p, c, in.Method, u.Path, 0, "refused")
			return refusal(http.StatusRequestEntityTooLarge, why, nil, nil),
				&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "deny", Detail: "streamed body"}
		}
	}
	class := c.Classify(in.Method, u.Path, in.Body)
	switch {
	case class == "":
		s.record(ctx, t, p, c, in.Method, u.Path, 0, "refused")
		s.signal(ctx, t.Org, c, in.Method, u.Path, signalRefused)
		return refusal(http.StatusForbidden, in.Method+" "+u.Path+" is not a request the "+c.DisplayName+" connector allows", nil, nil),
			&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "deny", Detail: "policy"}
	case class == connector.Write && g.Reach != connector.Write && in.Report == nil && !s.changeAllowed(ctx, t, p, c, in):
		id, err := s.hold(ctx, t, p, c, in)
		if err != nil {
			return refusal(http.StatusBadGateway, "the change could not be held for "+t.Requester+": "+err.Error(), nil, nil), nil
		}
		s.record(ctx, t, p, c, in.Method, u.Path, http.StatusAccepted, "held")
		return refusal(http.StatusAccepted, "held: this change waits for "+t.Requester+" to allow it in the room; it was not made yet",
				heldCard(c, p, in, u, id), map[string]any{"status": "held", "id": id}),
			&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "queued", Detail: "held" + as}
	}
	// A change that goes without a card because the person allowed this system in this room says so
	// in its audit row (a one-time allowance and the connection's own reach do not).
	underRoom := ""
	if class == connector.Write && g.Reach != connector.Write && in.Report == nil && mayRoomAllow(t, p) && s.roomAllows(ctx, t.Requester, t.Org, t.Room, c.Name) {
		underRoom = ", room allowance"
	}
	if c.FromMember() {
		resp, a := s.fromMember(ctx, t, p, c, &g, in, u, class)
		if a != nil && underRoom != "" && a.Outcome == "allow" {
			a.Detail += underRoom
		}
		return resp, a
	}
	resp, err := s.call(ctx, c, t.Org, p, &g, in, u)
	if err != nil {
		return s.failed(ctx, t, p, c, in, u, err)
	}
	s.record(ctx, t, p, c, in.Method, u.Path, resp.Status, class)
	return resp, &component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "allow", Detail: class + fmt.Sprintf(" %d", resp.Status) + as + underRoom}
}

// streamedRefusal is why a streamed request (its body larger than an
// envelope and not here; docs/prd/2026-10-27-streamed-member-sends.md in
// bnbloc) cannot be served, or "": it can only go out from the member's
// computer, and only where neither the policy nor a signature needs its body.
func streamedRefusal(c connector.Connector, method, path string) string {
	const large = "the request body is larger than 8 MiB"
	switch {
	case !c.FromMember():
		// decision: docs/prd/2026-10-27-streamed-member-sends.md (1), never
		// sent from the member's computer instead of the server.
		return large + ", too large to go through the service: an administrator can switch the " + c.DisplayName + " connector to send from members' computers"
	case c.Connect.APIKey != nil && c.Connect.APIKey.Sign != nil:
		return large + ", and the " + c.DisplayName + " connector signs request bodies"
	case c.Policy.ReadsBody(method, path):
		return large + ", and whether " + method + " " + path + " is a read depends on its body, which is not read at that size"
	}
	return ""
}

// asDetail is an audit row's note of a worker ("" for the member).
func asDetail(p principal) string {
	if p.Worker == nil {
		return ""
	}
	return ", as worker " + p.Worker.ID
}

// notConnected answers a request nobody may make yet: the requester's own
// agent gets a card to connect (naming a worker that would serve once its
// owners connect it); another drive is told only a digital worker serves
// it there.
func (s *Service) notConnected(t component.Turn, c connector.Connector, in component.EgressRequest, u *url.URL, act acting) (component.EgressResponse, *component.Audit) {
	target := in.Method + " " + u.Path
	waiting := act.waiting
	if act.required {
		return refusal(http.StatusForbidden, c.DisplayName+" in this room acts as "+waiting.DisplayName+", which is not connected to it yet: its owners ("+strings.Join(waiting.Owners, ", ")+") connect it", nil, map[string]any{"system": c.Name, "connected": false}),
			&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "deny", Detail: "room requires worker " + waiting.ID + ", not connected"}
	}
	if t.Drive != component.DriveOwn {
		msg := c.DisplayName + " is reached here only as a digital worker of the organization, and none serves " + t.Requester + "'s request on this agent"
		if waiting != nil {
			msg = c.DisplayName + " is reached here as " + waiting.DisplayName + ", which is not connected to it yet: its owners connect it"
		}
		return refusal(http.StatusForbidden, msg, nil, map[string]any{"system": c.Name, "connected": false}),
			&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "deny", Detail: "no worker for drive " + t.Drive}
	}
	return refusal(http.StatusForbidden, c.DisplayName+" is not connected: "+t.Requester+" was asked in the room to connect it",
			connectCard(c, in.Method, u.Path, false, waiting), map[string]any{"system": c.Name, "connected": false}),
		&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "deny", Detail: "not connected"}
}

// failed answers a request whose credentials or call failed: a dead
// connection asks to connect again, an administrator's item says so,
// anything else is the system's own error.
func (s *Service) failed(ctx context.Context, t component.Turn, p principal, c connector.Connector, in component.EgressRequest, u *url.URL, err error) (component.EgressResponse, *component.Audit) {
	target := in.Method + " " + u.Path
	switch {
	case errors.Is(err, errReconnect) && p.Worker != nil:
		s.record(ctx, t, p, c, in.Method, u.Path, 0, "reconnect")
		return refusal(http.StatusForbidden, p.as()+"'s connection to "+c.DisplayName+" no longer works: its owners connect it again (nothing for "+t.Requester+" to do)", nil, map[string]any{"system": c.Name, "connected": false}),
			&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "deny", Detail: "reconnect" + asDetail(p)}
	case errors.Is(err, errReconnect):
		s.record(ctx, t, p, c, in.Method, u.Path, 0, "reconnect")
		// The member's Connections page says the connection no longer works.
		_ = s.P.PutJSON(ctx, platform.Member(p.Member), checkPrefix+t.Org+":"+c.Name,
			tryResult{Hash: reviewHash(c), AtMs: s.now().UnixMilli(), Line: target + ": the system refused the credentials (401, or a sign-in it no longer takes)"})
		return refusal(http.StatusForbidden, "the connection to "+c.DisplayName+" no longer works: "+t.Requester+" was asked in the room to connect it again",
				connectCard(c, in.Method, u.Path, true, nil), map[string]any{"system": c.Name, "connected": false}),
			&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "deny", Detail: "reconnect"}
	}
	var pe *providerError
	if errors.As(err, &pe) && pe.admin {
		return refusal(http.StatusForbidden, c.DisplayName+" is not available yet: "+pe.msg+" (an administrator arranges it; nothing for "+t.Requester+" to do)", nil, nil),
			&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "failed", Detail: "admin: " + pe.msg + asDetail(p)}
	}
	slog.Warn("connections: request failed", "connector", c.Name, "error", err)
	s.record(ctx, t, p, c, in.Method, u.Path, 0, "failed")
	return refusal(http.StatusBadGateway, c.DisplayName+" could not be reached: "+err.Error(), nil, nil),
		&component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "failed"}
}

// fromMember serves a connector whose requests go out from the member's
// computer: the bridge is told to send the request itself with the
// member's credentials for it (Send), and reports what the system answered.
// A refused sign-in (401, expiredWhen) is sent once more with fresh
// credentials; refused again, the member connects again. An accepted
// answer is recorded and audited like a call made here.
func (s *Service) fromMember(ctx context.Context, t component.Turn, p principal, c connector.Connector, g *Grant, in component.EgressRequest, u *url.URL, class string) (component.EgressResponse, *component.Audit) {
	target := in.Method + " " + u.Path
	force := false
	if r := in.Report; r != nil && !signInReport(r) {
		refused := r.Status == http.StatusUnauthorized || c.IsExpired(r.Status, r.Location, r.Body)
		if !refused {
			s.record(ctx, t, p, c, in.Method, u.Path, r.Status, class)
			return component.EgressResponse{Accept: true}, &component.Audit{Action: "request", Target: c.Name + " " + target, Outcome: "allow", Detail: class + fmt.Sprintf(" %d from the member's computer", r.Status) + asDetail(p)}
		}
		if in.Streamed {
			return s.streamedRefused(ctx, t, p, c, g, in, u)
		}
		if r.Attempt >= component.MaxEgressSends {
			return s.failed(ctx, t, p, c, in, u, errReconnect)
		}
		s.dropAuth(grantKey{p.key(), t.Org, c.Name})
		force = true
	}
	send, _, err := s.memberSend(ctx, c, t.Org, p, g, in, u, force)
	if err != nil {
		return s.failed(ctx, t, p, c, in, u, err)
	}
	return component.EgressResponse{Send: send}, nil
}

// streamedRefused answers a refused sign-in for a streamed request, which
// is never sent a second time (decision: docs/prd/2026-10-27-streamed-member-sends.md
// (3), its body is not kept): the cached credentials are dropped; renewed,
// the agent is told to run it again; not renewable or dead, the member
// connects again.
func (s *Service) streamedRefused(ctx context.Context, t component.Turn, p principal, c connector.Connector, g *Grant, in component.EgressRequest, u *url.URL) (component.EgressResponse, *component.Audit) {
	s.dropAuth(grantKey{p.key(), t.Org, c.Name})
	if !renewable(c) {
		return s.failed(ctx, t, p, c, in, u, errReconnect)
	}
	if _, err := s.credentials(ctx, c, t.Org, p, g, true); err != nil {
		return s.failed(ctx, t, p, c, in, u, err)
	}
	s.record(ctx, t, p, c, in.Method, u.Path, http.StatusUnauthorized, "renewed")
	return refusal(http.StatusUnauthorized, "the sign-in to "+c.DisplayName+" had ended and is renewed now; this request was sent once and its body is not kept: run it again", nil, nil),
		&component.Audit{Action: "request", Target: c.Name + " " + in.Method + " " + u.Path, Outcome: "failed", Detail: "sign-in renewed, streamed body not sent again" + asDetail(p)}
}

// renewable reports whether c's credentials can be made fresh without the
// member: a refresh, a provider's authorization, a key's exchange.
func renewable(c connector.Connector) bool {
	switch c.Connect.Kind {
	case connector.KindOAuth2, connector.KindProvider:
		return true
	case connector.KindAPIKey:
		return c.Connect.APIKey.Exchange != nil
	}
	return false
}

// memberSend is the Send that has the bridge send in from the member's
// computer with p's credentials (force: fresh ones), signed here when the
// connector signs, and the credentials it carries.
func (s *Service) memberSend(ctx context.Context, c connector.Connector, org string, p principal, g *Grant, in component.EgressRequest, u *url.URL, force bool) (*component.EgressSend, cachedAuth, error) {
	var signedIn []provider.Step
	if in.Report != nil && signInReport(in.Report) {
		// The sign-in's answers, from the member's computer: the provider
		// makes the request's credentials from them.
		for _, st := range in.Report.Steps {
			signedIn = append(signedIn, provider.Step{Method: http.MethodGet, URL: st.URL, Status: st.Status, Location: st.Location, Body: st.Body})
		}
		force = true
	}
	auth, err := s.credentialsWith(ctx, c, org, p, g, force, signedIn)
	var need *signInNeeded
	if errors.As(err, &need) {
		// A sign-in on the member's computer first (docs/prd/2026-10-28-member-held-sessions.md
		// in bnbloc): its steps with the principal's session, made afresh.
		steps := make([]component.EgressStep, 0, len(need.steps))
		for _, st := range need.steps {
			steps = append(steps, component.EgressStep{Method: firstNonEmpty(st.Method, http.MethodGet), URL: st.URL})
		}
		return &component.EgressSend{Session: sessionName(p), Steps: steps, StepsOnly: true, EndSession: true}, cachedAuth{}, nil
	}
	if err != nil {
		return nil, cachedAuth{}, err
	}
	send := &component.EgressSend{Remove: c.CredentialHeaders(), Header: auth.header, Query: auth.query}
	if auth.session {
		send.Session = sessionName(p)
	}
	if a := c.Connect.APIKey; a != nil && a.Sign != nil {
		// Signed here over the exact query and body the bridge sends.
		var changed bool
		send.Query = nil
		var signHeaders http.Header
		send.RawQuery, send.Body, signHeaders, changed = signRequest(c, auth, in.Method, u, in.Body, headerValue(in.Header, "Content-Type"), s.now())
		if len(signHeaders) > 0 {
			merged := map[string][]string{}
			for k, v := range auth.header {
				merged[k] = v
			}
			for k, v := range signHeaders {
				merged[k] = v
			}
			send.Header = merged
		}
		send.ReplaceBody = changed
		if !changed {
			send.Body = nil
		}
	}
	return send, auth, nil
}

// signInReport reports the answers of a sign-in's steps only (StepsOnly):
// the request itself was not sent yet.
func signInReport(r *component.EgressReport) bool { return r.Status == 0 && len(r.Steps) > 0 }

// sessionName names a principal's session held on the member's computer:
// a person's and each digital worker's apart.
func sessionName(p principal) string { return "connections:" + p.key() }

// call makes the request as the member: every credential the agent sent is
// replaced with the member's; a refusal (401, or the connector's
// expiredWhen) is retried once with fresh credentials; cookies never come
// back.
func (s *Service) call(ctx context.Context, c connector.Connector, org string, p principal, g *Grant, in component.EgressRequest, u *url.URL) (component.EgressResponse, error) {
	for attempt := 0; ; attempt++ {
		auth, err := s.credentials(ctx, c, org, p, g, attempt > 0)
		if err != nil {
			return component.EgressResponse{}, err
		}
		target := *u
		body := in.Body
		var signHeaders http.Header
		if a := c.Connect.APIKey; a != nil && a.Sign != nil {
			target.RawQuery, body, signHeaders, _ = signRequest(c, auth, in.Method, u, in.Body, headerValue(in.Header, "Content-Type"), s.now())
		} else if len(auth.query) > 0 {
			q := target.Query()
			for k, v := range auth.query {
				q[k] = v
			}
			target.RawQuery = q.Encode()
		}
		req, err := http.NewRequestWithContext(ctx, in.Method, target.String(), bytes.NewReader(body))
		if err != nil {
			return component.EgressResponse{}, err
		}
		for k, v := range in.Header {
			req.Header[http.CanonicalHeaderKey(k)] = v
		}
		for _, h := range c.CredentialHeaders() {
			req.Header.Del(h)
		}
		req.Header.Del("Content-Length")
		for k, v := range auth.header {
			req.Header[k] = v
		}
		for k, v := range signHeaders {
			req.Header[k] = v
		}
		resp, err := s.upstream().Do(req)
		if err != nil {
			return component.EgressResponse{}, err
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, component.MaxEgressBody+1))
		_ = resp.Body.Close()
		if err != nil {
			return component.EgressResponse{}, err
		}
		if len(raw) > component.MaxEgressBody {
			return component.EgressResponse{}, errors.New("the answer is larger than 8 MiB")
		}
		refused := resp.StatusCode == http.StatusUnauthorized || c.IsExpired(resp.StatusCode, resp.Header.Get("Location"), raw)
		if refused && attempt == 0 {
			s.dropAuth(grantKey{p.key(), org, c.Name})
			continue
		}
		if refused {
			return component.EgressResponse{}, errReconnect
		}
		header := map[string][]string{}
		for k, v := range resp.Header {
			if k == "Set-Cookie" || k == "Content-Length" || k == "Transfer-Encoding" || k == "Connection" {
				continue
			}
			header[k] = v
		}
		return component.EgressResponse{Status: resp.StatusCode, Header: header, Body: raw}, nil
	}
}

// connectCard asks the person to connect a system an agent tried.
func connectCard(c connector.Connector, method, path string, again bool, waiting *Worker) *component.Card {
	title := "Connect " + c.DisplayName
	text := "Your agent tried " + method + " " + clip(path, 120) + " in " + c.DisplayName + ". Connect it so your own agents can use it as you (reading only, until you allow changes)."
	// A sign-in or a provider's connect starts in place; a key is pasted on
	// the page.
	actions := []component.CardAction{{Kind: component.CardOpen, Label: "Connect", Page: "connections", Query: "system=" + url.QueryEscape(c.Name)}}
	if c.Connect.Kind != connector.KindAPIKey {
		actions[0] = callAction("Connect", "connect", url.Values{"system": {c.Name}})
	}
	if waiting != nil {
		text += " Or ask " + strings.Join(waiting.Owners, ", ") + " to connect " + waiting.DisplayName + ", a digital worker your agents may act as, and choose it for this room."
		actions = append(actions, component.CardAction{Kind: component.CardOpen, Label: "Choose who acts here", Page: "connections", Query: "system=" + url.QueryEscape(c.Name) + "&identity=1"})
	}
	if again {
		title = "Connect " + c.DisplayName + " again"
		text = "Your connection to " + c.DisplayName + " no longer works (" + method + " " + clip(path, 120) + " was refused). Connect it again."
	}
	return &component.Card{Title: clip(title, component.MaxCardTitle), Text: text, Actions: append(actions, component.CardAction{Kind: component.CardAskAgain, Label: "Ask again"})}
}

// heldCard asks the person to allow one change.
func heldCard(c connector.Connector, p principal, in component.EgressRequest, u *url.URL, id string) *component.Card {
	text := "Your agent wants to " + in.Method + " " + clip(u.Path, 160) + " in " + c.DisplayName + "."
	if p.Worker != nil {
		text = "Your agent wants to " + in.Method + " " + clip(u.Path, 160) + " in " + c.DisplayName + " as " + p.Worker.DisplayName + "."
	}
	if s := bodySummary(in.Body); s != "" {
		text += "\n" + s
	}
	return &component.Card{Title: clip("Allow a change in "+c.DisplayName+"?", component.MaxCardTitle), Text: clip(text, component.MaxCardText), Actions: []component.CardAction{
		callAction("Allow", "approve", url.Values{"id": {id}, "decision": {"allow"}}),
		callAction("Allow in this room", "approve", url.Values{"id": {id}, "decision": {"room"}}),
		callAction("Don't allow", "approve", url.Values{"id": {id}, "decision": {"deny"}}),
		{Kind: component.CardOpen, Label: "Review", Page: "approve", Query: "id=" + url.QueryEscape(id)},
	}}
}

// bodySummary is the first characters of a text body, one line.
func bodySummary(b []byte) string {
	if len(b) == 0 || !utf8.Valid(b) {
		return ""
	}
	return clip(strings.Join(strings.Fields(string(b)), " "), 300)
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
