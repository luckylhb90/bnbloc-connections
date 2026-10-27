package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc/component"
)

// Deciding a held change: one owner for the review page and the card's
// in-place Allow / Don't allow (cards.go).

// heldChange is a member's held change with its system, address and who
// it acts as.
type heldChange struct {
	h Held
	c connector.Connector
	u *url.URL
	p principal
}

// heldFor is the member's held change id (nil: gone or expired), or why it
// can no longer be decided (it is then dropped).
func (s *Service) heldFor(ctx context.Context, m component.Member, id string) (*heldChange, string) {
	h, ok := s.held(ctx, m.Subject, id)
	if !ok || h.Org != m.Org {
		return nil, ""
	}
	c, found := s.connectorNamed(ctx, m.Org, h.Connector)
	if !found {
		return nil, ""
	}
	u, _ := url.Parse(h.Request.URL)
	hc := &heldChange{h: h, c: c, u: u, p: asMember(m.Subject)}
	if h.As != "" {
		wk, found := s.worker(ctx, m.Org, h.As)
		if !found || !wk.Serves(m.Subject, firstNonEmpty(h.Drive, component.DriveOwn)) {
			_ = s.P.Delete(ctx, platform.Member(m.Subject), heldPrefix+h.ID)
			return nil, "The digital worker this change acts as no longer serves you here."
		}
		hc.p = principal{Member: m.Subject, Worker: &wk}
	}
	return hc, ""
}

// decision is what deciding a held change came to: a heading and a line
// for the person, a sign-in to start (open: the change keeps waiting), the
// system's answer when the change was made here, and the audit row.
type decision struct {
	heading, text string
	open          string
	result        *component.EgressResponse
	audit         *component.Audit
}

// decide allows the change (always: changes in that system go without
// asking from now on) or refuses it.
func (s *Service) decide(ctx context.Context, m component.Member, hc heldChange, allow, always bool) decision {
	h, c, u, p := hc.h, hc.c, hc.u, hc.p
	target := c.Name + " " + h.Request.Method + " " + u.Path
	t := component.Turn{Org: h.Org, Room: h.Room, Job: h.Job, Requester: m.Subject, Drive: firstNonEmpty(h.Drive, component.DriveOwn)}
	drop := func() { _ = s.P.Delete(ctx, platform.Member(m.Subject), heldPrefix+h.ID) }
	if !allow {
		drop()
		s.record(ctx, t, p, c, h.Request.Method, u.Path, 0, "not allowed")
		return decision{heading: "Not made", text: "The change was not made. Your agent sees nothing changed.",
			audit: &component.Audit{Action: "change", Target: target, Outcome: "deny"}}
	}
	g, ok, err := s.grantOf(ctx, p, m.Org, c.Name)
	if err != nil || !ok {
		drop()
		return decision{heading: "Not made", text: c.DisplayName + " is not connected any more: connect it, then ask your agent again."}
	}
	if p.Worker != nil && !g.canChange(c) {
		return decision{heading: "Not made", text: p.as() + " reaches " + c.DisplayName + " for reading only: its owners connect it for changes."}
	}
	if !g.canChange(c) {
		// The sign-in granted reading only: sign in again with the write
		// scopes; the change stays held until it is allowed again.
		reach := g.Reach
		if always {
			reach = connector.Write
		}
		next, err := s.authorizeURL(ctx, c, m, reach, connector.Write, h.ID)
		if err != nil {
			return decision{heading: "Not made", text: "The sign-in for changes cannot start: " + err.Error()}
		}
		return decision{heading: "Sign in for changes", text: c.DisplayName + " asks you to sign in again to allow changes; then allow this one again.", open: next}
	}
	drop()
	s.signal(ctx, m.Org, c, h.Request.Method, u.Path, signalAllowed)
	if always && g.Reach != connector.Write && p.Worker == nil {
		g.Reach = connector.Write
		if err := s.saveGrant(ctx, m.Subject, m.Org, g); err != nil {
			slog.Warn("connections: reach not saved", "error", err)
		}
	}
	if c.FromMember() {
		// The system is reached from the member's computer: the change is
		// made by the agent's next send of it, through the member's bridge.
		if err := s.allow(ctx, m.Subject, h); err != nil {
			return decision{heading: "Not allowed", text: "The change could not be allowed right now: " + err.Error()}
		}
		s.record(ctx, t, p, c, h.Request.Method, u.Path, 0, "allowed")
		return decision{heading: "Allowed", text: "Ask your agent again: its next try of this change goes through, from your computer (within an hour).",
			audit: &component.Audit{Action: "change", Target: target, Outcome: "allow", Detail: "sent from the member's computer" + asDetail(p)}}
	}
	if h.Request.Streamed {
		// Held while the connector sent from members' computers: its body
		// was never here, so the service cannot make it.
		return decision{heading: "Not made", text: c.DisplayName + " now sends from the server, and this change's body (larger than 8 MiB) can only go from your computer: ask your agent again after an administrator switches it back.",
			audit: &component.Audit{Action: "change", Target: target, Outcome: "failed", Detail: "streamed body, server send"}}
	}
	resp, err := s.call(ctx, c, m.Org, p, &g, h.Request, u)
	if err != nil {
		s.record(ctx, t, p, c, h.Request.Method, u.Path, 0, "failed")
		return decision{heading: "Not made", text: c.DisplayName + " did not take the change: " + err.Error(),
			audit: &component.Audit{Action: "change", Target: target, Outcome: "failed", Detail: strings.TrimPrefix(asDetail(p), ", ")}}
	}
	s.record(ctx, t, p, c, h.Request.Method, u.Path, resp.Status, "allowed")
	return decision{heading: "Done", text: fmt.Sprintf("%s answered %d %s.", c.DisplayName, resp.Status, http.StatusText(resp.Status)), result: &resp,
		audit: &component.Audit{Action: "change", Target: target, Outcome: "allow", Detail: http.StatusText(resp.Status) + asDetail(p)}}
}
