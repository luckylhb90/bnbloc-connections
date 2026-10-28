package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc/component"
)

// Trying a connection (docs/prd/2026-10-25-ai-checks-its-work.md in
// bnbloc): the connector's test request, a read, sent with someone's own
// connection, from where the connector sends: from here, or from the
// person's own computer (docs/prd/2026-10-25-member-sends.md: their action
// grants it, their bnbloc desktop app sends it and the answer comes back
// to handleSendEgress). It tells a member their connection works right
// after they connect; an admin's Try it that fails is reality's word the
// review is given, and the review proposes the fix. What the system
// answered is kept without any credential in it.

// tryResult is one try: for the connector as it was (Hash), whether the
// system answered 2xx, and one line saying what it answered; Pending
// while the person's computer has not answered.
type tryResult struct {
	Hash    string `json:"hash"`
	AtMs    int64  `json:"atMs"`
	OK      bool   `json:"ok"`
	Status  int    `json:"status,omitempty"`
	Line    string `json:"line"`
	Pending bool   `json:"pending,omitempty"`
}

// Waiting reports a try still waiting for the person's computer.
func (t tryResult) Waiting(now time.Time) bool {
	return t.Pending && now.UnixMilli()-t.AtMs < component.MaxSendWait.Milliseconds()
}

// View is the try's line as a page shows it.
func (t tryResult) View(now time.Time) string {
	switch {
	case t.Waiting(now):
		return "sent from your computer, waiting for the answer…"
	case t.Pending:
		return "your bnbloc desktop app did not answer: is it open and up to date?"
	case t.OK:
		return t.Line + ": it works"
	}
	return t.Line
}

// The purposes of a try: an admin's Try it (kept for the organization:
// the review's evidence) and a member's check after connecting (kept for
// them).
const (
	tryAdmin = "try"
	tryCheck = "check"
)

// Store keys of tries.
const (
	tryPrefix   = "try:"   // org scope, try:<connector>: the admin's last try
	checkPrefix = "check:" // member scope, check:<org>:<connector>
	sendPrefix  = "send:"  // org scope, send:<id>: a try a computer sends
)

// pendingSend is a try the person's computer sends: whose (always as
// themselves), for which connector, which purpose.
type pendingSend struct {
	Purpose   string `json:"purpose"`
	Connector string `json:"connector"`
	Member    string `json:"member"`
	Hash      string `json:"hash"`
	AtMs      int64  `json:"atMs"`
}

// errNoTry is a connection that cannot be tried: no test, or one that
// sends from a computer without a grant to.
var errNoTry = errors.New("cannot be tried here")

// testRequest is c's test request on its first host.
func testRequest(c connector.Connector) (string, *url.URL, error) {
	if c.Test == nil {
		return "", nil, errNoTry
	}
	method := c.Test.Method
	if method == "" {
		method = "GET"
	}
	u, err := url.Parse("https://" + c.Hosts[0] + c.Test.Path)
	return method, u, err
}

// tryConnection sends c's test request from here as p. errNoTry when c
// names none or sends from the members' computers (tryFromComputer).
func (s *Service) tryConnection(ctx context.Context, org string, p principal, c connector.Connector) (tryResult, error) {
	if c.FromMember() {
		return tryResult{}, errNoTry
	}
	method, u, err := testRequest(c)
	if err != nil {
		return tryResult{}, err
	}
	g, ok, err := s.grantOf(ctx, p, org, c.Name)
	if err != nil || !ok {
		return tryResult{}, errors.New("not connected")
	}
	out := tryResult{Hash: reviewHash(c), AtMs: s.now().UnixMilli()}
	auth, _ := s.credentials(ctx, c, org, p, &g, false)
	resp, err := s.call(ctx, c, org, p, &g, component.EgressRequest{Method: method, URL: u.String()}, u)
	switch {
	case errors.Is(err, errReconnect):
		out.Line = method + " " + c.Test.Path + ": the system refused the credentials (401, or a sign-in it no longer takes)"
	case err != nil:
		out.Line = method + " " + c.Test.Path + ": " + err.Error()
	default:
		out = answered(out, method, c.Test.Path, resp.Status, resp.Body)
	}
	out.Line = redact(out.Line, auth, g)
	return out, nil
}

// answered is a try the system answered with status and body.
func answered(t tryResult, method, path string, status int, body []byte) tryResult {
	t.Status, t.OK, t.Pending = status, status >= 200 && status < 300, false
	t.Line = fmt.Sprintf("%s %s answered %d", method, path, status)
	if !t.OK {
		if b := bodySummary(body); b != "" {
			t.Line += ": " + clip(b, 300)
		}
	}
	return t
}

// tryFromComputer asks the member's own computer to send c's test as
// them, granted by their action (m.Act); the answer arrives at
// handleSendEgress. component.ErrNoMemberComputer when none of their
// desktop apps is running.
func (s *Service) tryFromComputer(ctx context.Context, m component.Member, c connector.Connector, purpose string) error {
	method, u, err := testRequest(c)
	if err != nil || m.Act == "" {
		return errNoTry
	}
	if _, ok, err := s.grant(ctx, m.Subject, m.Org, c.Name); err != nil || !ok {
		return errors.New("not connected")
	}
	id, err := s.P.SendFromMember(ctx, m.Act, method, u.String())
	if err != nil {
		return err
	}
	ps := pendingSend{Purpose: purpose, Connector: c.Name, Member: m.Subject, Hash: reviewHash(c), AtMs: s.now().UnixMilli()}
	if err := s.P.PutJSON(ctx, platform.Org(m.Org), sendPrefix+id, ps); err != nil {
		return err
	}
	s.keepResult(ctx, m.Org, ps, tryResult{Hash: ps.Hash, AtMs: ps.AtMs, Pending: true})
	return nil
}

// handleSendEgress serves the egress exchange of a try a computer sends:
// the member's credentials for it (Send), then the system's answer (the
// report) is the try, and Accept ends it.
func (s *Service) handleSendEgress(w http.ResponseWriter, r *http.Request, sd component.Send, body []byte) {
	ctx := r.Context()
	var in component.EgressRequest
	u, err := url.Parse("")
	if json.Unmarshal(body, &in) == nil {
		u, err = url.Parse(in.URL)
	}
	var ps pendingSend
	if found, _ := s.P.GetJSON(ctx, platform.Org(sd.Org), sendPrefix+sd.ID, &ps); err != nil || !found || ps.Member != sd.Member {
		writeJSON(w, http.StatusOK, refusal(http.StatusNotFound, "no try waits for this send", nil, nil))
		return
	}
	p := asMember(ps.Member)
	c, ok := s.connectorNamed(ctx, sd.Org, ps.Connector)
	var g Grant
	if ok {
		g, ok, _ = s.grantOf(ctx, p, sd.Org, c.Name)
	}
	if !ok {
		s.finishTry(w, ctx, sd.Org, sd.ID, ps, c, tryResult{Hash: ps.Hash, AtMs: s.now().UnixMilli(), Line: "not connected, or the connector is no longer enabled"})
		writeJSON(w, http.StatusOK, refusal(http.StatusForbidden, "not connected", nil, nil))
		return
	}
	force := false
	if rep := in.Report; rep != nil {
		refused := rep.Status == http.StatusUnauthorized || c.IsExpired(rep.Status, rep.Location, rep.Body)
		if !refused || rep.Attempt >= component.MaxEgressSends {
			auth, _ := s.credentials(ctx, c, sd.Org, p, &g, false)
			t := answered(tryResult{Hash: ps.Hash, AtMs: s.now().UnixMilli()}, in.Method, u.RequestURI(), rep.Status, rep.Body)
			if refused {
				// A refusal the connector names (expiredWhen) may come as a 200.
				t.OK, t.Line = false, in.Method+" "+u.RequestURI()+": the system refused the credentials (401, or a sign-in it no longer takes)"
			}
			t.Line = redact(t.Line, auth, g)
			s.finishTry(w, ctx, sd.Org, sd.ID, ps, c, t)
			writeJSON(w, http.StatusOK, component.EgressResponse{Accept: true})
			return
		}
		s.dropAuth(grantKey{p.key(), sd.Org, c.Name})
		force = true
	}
	send, auth, err := s.memberSend(ctx, c, sd.Org, p, &g, in, u, force)
	if err != nil {
		s.finishTry(w, ctx, sd.Org, sd.ID, ps, c, tryResult{Hash: ps.Hash, AtMs: s.now().UnixMilli(), Line: redact(in.Method+" "+u.RequestURI()+": "+err.Error(), auth, g)})
		writeJSON(w, http.StatusOK, refusal(http.StatusBadGateway, "the credentials could not be had", nil, nil))
		return
	}
	writeJSON(w, http.StatusOK, component.EgressResponse{Send: send})
}

// finishTry keeps a computer's try and audits it; a failed Try it has the
// review run again with it, for a fix.
func (s *Service) finishTry(w http.ResponseWriter, ctx context.Context, org, id string, ps pendingSend, c connector.Connector, t tryResult) {
	_ = s.P.Delete(ctx, platform.Org(org), sendPrefix+id)
	s.keepResult(ctx, org, ps, t)
	action := "connector-try"
	if ps.Purpose == tryCheck {
		action = "connect-check"
	}
	audit(w, component.Audit{Action: action, Target: ps.Connector, Outcome: map[bool]string{true: "ok", false: "failed"}[t.OK], Detail: t.Line + " (from the member's computer)"})
	if ps.Purpose == tryAdmin && !t.OK && c.Name != "" {
		s.ensureReview(ctx, org, ps.Member, c, false, true)
	}
}

// keepResult keeps a try where its purpose reads it.
func (s *Service) keepResult(ctx context.Context, org string, ps pendingSend, t tryResult) {
	if ps.Purpose == tryAdmin {
		s.keepTry(ctx, org, ps.Connector, t)
		return
	}
	_ = s.P.PutJSON(ctx, platform.Member(ps.Member), checkPrefix+org+":"+ps.Connector, t)
}

// lastCheck is the member's last check of connector name.
func (s *Service) lastCheck(ctx context.Context, member, org, name string) (tryResult, bool) {
	var t tryResult
	ok, err := s.P.GetJSON(ctx, platform.Member(member), checkPrefix+org+":"+name, &t)
	return t, ok && err == nil
}

// redact leaves out of a line every credential value a request carried
// (a system may echo a header back).
func redact(line string, auth cachedAuth, g Grant) string {
	var secrets []string
	for _, vs := range auth.header {
		for _, v := range vs {
			secrets = append(secrets, v, strings.TrimPrefix(v, "Bearer "))
		}
	}
	for _, vs := range auth.query {
		secrets = append(secrets, vs...)
	}
	secrets = append(secrets, auth.key, auth.secret, g.APIKey)
	for _, v := range g.Extra {
		secrets = append(secrets, v)
	}
	for _, v := range secrets {
		if len(v) >= 6 {
			line = strings.ReplaceAll(line, v, "[credential]")
			line = strings.ReplaceAll(line, url.QueryEscape(v), "[credential]")
		}
	}
	return line
}

// answers is the sentence a connect ends with: whether the system answers
// the connector's test as p, tried from here, or from the member's
// computer when it sends from there ("" when there is nothing to try).
func (s *Service) answers(ctx context.Context, m component.Member, p principal, c connector.Connector) string {
	if c.FromMember() {
		if p.Worker != nil {
			return ""
		}
		switch err := s.tryFromComputer(ctx, m, c, tryCheck); {
		case err == nil:
			return " Checking it from your computer…"
		case errors.Is(err, component.ErrNoMemberComputer):
			return " Open your bnbloc desktop app to check it: " + c.DisplayName + " is reached from your computer."
		}
		return ""
	}
	t, err := s.tryConnection(ctx, m.Org, p, c)
	switch {
	case err != nil:
		return ""
	case t.OK:
		return " It answers."
	}
	return " But it does not answer yet (" + t.Line + "): check what you entered, or tell an administrator."
}

func (s *Service) keepTry(ctx context.Context, org, name string, t tryResult) {
	_ = s.P.PutJSON(ctx, platform.Org(org), tryPrefix+name, t)
}

// lastTry is the latest try of connector name as it is now (hash).
func (s *Service) lastTry(ctx context.Context, org, name, hash string) (tryResult, bool) {
	var t tryResult
	ok, err := s.P.GetJSON(ctx, platform.Org(org), tryPrefix+name, &t)
	return t, ok && err == nil && t.Hash == hash
}

// docLinks are the https addresses an admin gave beside a description (at
// most 3).
func docLinks(v string) []string {
	var out []string
	for _, f := range splitList(v) {
		if u, err := url.Parse(f); err == nil && u.Scheme == "https" && u.Host != "" && len(out) < 3 {
			out = append(out, u.String())
		}
	}
	return out
}
