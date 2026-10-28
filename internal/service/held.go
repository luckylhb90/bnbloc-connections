package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc/component"
)

// heldTTL is how long a held change waits for its person.
const heldTTL = 24 * time.Hour

// Held is one change an agent asked for that waits for the member's click:
// the request as the agent sent it, where it was asked, and when.
type Held struct {
	ID          string                  `json:"id"`
	Org         string                  `json:"org"`
	Connector   string                  `json:"connector"`
	Room        string                  `json:"room"`
	Job         string                  `json:"job"`
	Request     component.EgressRequest `json:"request"`
	CreatedAtMs int64                   `json:"createdAtMs"`
	// As is the digital worker the change acts as ("": the member); Drive
	// the turn's.
	As    string `json:"as,omitempty"`
	Drive string `json:"drive,omitempty"`
}

// hold keeps a change waiting for its person. It is idempotent: the id is
// the request's (the allowance's key without its prefix), so the same request
// held again (an agent that retries) finds the change already waiting, keeps
// its id and age, and so makes the same card, not another. docs/prd/
// 2026-10-28-held-change-continues.md (2.3) in bnbloc.
func (s *Service) hold(ctx context.Context, t component.Turn, p principal, c connector.Connector, in component.EgressRequest) (string, error) {
	id := strings.TrimPrefix(allowanceKey(t.Org, c.Name, t.Room, in), allowPrefix)
	var prev Held
	if ok, err := s.P.GetJSON(ctx, platform.Member(t.Requester), heldPrefix+id, &prev); err == nil && ok && s.now().UnixMilli()-prev.CreatedAtMs <= heldTTL.Milliseconds() {
		// The job it waits under is the newest turn's, so deciding it continues that one.
		if prev.Job != t.Job {
			prev.Job = t.Job
			_ = s.P.PutJSON(ctx, platform.Member(t.Requester), heldPrefix+id, prev)
		}
		return id, nil
	}
	h := Held{ID: id, Org: t.Org, Connector: c.Name, Room: t.Room, Job: t.Job, Request: in, CreatedAtMs: s.now().UnixMilli(), As: p.asID(), Drive: t.Drive}
	return id, s.P.PutJSON(ctx, platform.Member(t.Requester), heldPrefix+id, h)
}

// allowanceTTL is how long an allowed change waits for the agent to send
// it (a connector whose requests go out from the member's computer).
const allowanceTTL = time.Hour

// allowanceKey names one allowed change: the same request again (method,
// URL, body), in the same organization, system and room. A streamed
// request has no body here, so its key is its method and URL.
// decision: docs/prd/2026-10-27-streamed-member-sends.md (2) in bnbloc.
func allowanceKey(org, connectorName, room string, in component.EgressRequest) string {
	h := sha256.New()
	for _, part := range []string{org, connectorName, room, in.Method, in.URL} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write(in.Body)
	return allowPrefix + hex.EncodeToString(h.Sum(nil))[:32]
}

// allowance is one allowed change waiting for the agent's next send.
type allowance struct {
	AtMs      int64  `json:"atMs"`
	Org       string `json:"org"`
	Connector string `json:"connector"`
}

// allow lets the agent's next send of the same request, in the same room,
// through once.
func (s *Service) allow(ctx context.Context, member string, h Held) error {
	return s.P.PutJSON(ctx, platform.Member(member), allowanceKey(h.Org, h.Connector, h.Room, h.Request), allowance{AtMs: s.now().UnixMilli(), Org: h.Org, Connector: h.Connector})
}

// changeAllowed reports whether a change goes without a card: the person's
// allowance of this system in this room (their own agents, as themselves), or
// a one-time allowance of this very request, which it spends.
func (s *Service) changeAllowed(ctx context.Context, t component.Turn, p principal, c connector.Connector, in component.EgressRequest) bool {
	if mayRoomAllow(t, p) && s.roomAllows(ctx, t.Requester, t.Org, t.Room, c.Name) {
		return true
	}
	return s.takeAllowance(ctx, t, c, in)
}

// takeAllowance spends an allowance of this request, if there is a live one.
func (s *Service) takeAllowance(ctx context.Context, t component.Turn, c connector.Connector, in component.EgressRequest) bool {
	key := allowanceKey(t.Org, c.Name, t.Room, in)
	var a allowance
	if ok, err := s.P.GetJSON(ctx, platform.Member(t.Requester), key, &a); err != nil || !ok {
		return false
	}
	_ = s.P.Delete(ctx, platform.Member(t.Requester), key)
	return s.now().UnixMilli()-a.AtMs <= allowanceTTL.Milliseconds()
}

// roomAllowanceKey names the person's allowance of one system's changes in
// one room (docs/prd/2026-10-28-held-change-continues.md): until they stop it.
func roomAllowanceKey(org, room, name string) string {
	return roomAllowPrefix + org + ":" + room + ":" + name
}

// roomAllowance is the person's standing allowance of a system's changes in a
// room: made without asking, for their own agents, until stopped.
type roomAllowance struct {
	AtMs      int64  `json:"atMs"`
	Org       string `json:"org"`
	Room      string `json:"room"`
	Connector string `json:"connector"`
}

// allowRoom records the allowance.
func (s *Service) allowRoom(ctx context.Context, member, org, room, name string) error {
	return s.P.PutJSON(ctx, platform.Member(member), roomAllowanceKey(org, room, name), roomAllowance{AtMs: s.now().UnixMilli(), Org: org, Room: room, Connector: name})
}

// roomAllows reports whether the person allowed this system's changes in the
// room. It covers their own agents only: a borrowed drive and a digital
// worker's changes always ask (the caller checks, see mayRoomAllow).
func (s *Service) roomAllows(ctx context.Context, member, org, room, name string) bool {
	if room == "" {
		return false
	}
	var a roomAllowance
	ok, err := s.P.GetJSON(ctx, platform.Member(member), roomAllowanceKey(org, room, name), &a)
	return err == nil && ok
}

// stopRoomAllowance ends the allowance (false: there was none).
func (s *Service) stopRoomAllowance(ctx context.Context, member, org, room, name string) bool {
	had := s.roomAllows(ctx, member, org, room, name)
	_ = s.P.Delete(ctx, platform.Member(member), roomAllowanceKey(org, room, name))
	return had
}

// mayRoomAllow reports whether a change may go under a room allowance: the
// turn is the person's own drive and the change acts as them, not as a digital
// worker whose credentials are not theirs.
func mayRoomAllow(t component.Turn, p principal) bool {
	return t.Drive == component.DriveOwn && p.Worker == nil
}

// held is the member's held change (false when gone or expired).
func (s *Service) held(ctx context.Context, member, id string) (Held, bool) {
	var h Held
	ok, err := s.P.GetJSON(ctx, platform.Member(member), heldPrefix+id, &h)
	if err != nil || !ok {
		return Held{}, false
	}
	if s.now().UnixMilli()-h.CreatedAtMs > heldTTL.Milliseconds() {
		_ = s.P.Delete(ctx, platform.Member(member), heldPrefix+id)
		return Held{}, false
	}
	return h, true
}

// dropWaiting removes the member's held changes and allowances for one
// system of one organization (a disconnect).
func (s *Service) dropWaiting(ctx context.Context, member, org, name string) {
	keys, err := s.P.Keys(ctx, platform.Member(member))
	if err != nil {
		return
	}
	for _, k := range keys {
		var v struct {
			Org       string `json:"org"`
			Connector string `json:"connector"`
		}
		if !strings.HasPrefix(k, heldPrefix) && !strings.HasPrefix(k, allowPrefix) && !strings.HasPrefix(k, roomAllowPrefix) {
			continue
		}
		if ok, _ := s.P.GetJSON(ctx, platform.Member(member), k, &v); ok && v.Org == org && v.Connector == name {
			_ = s.P.Delete(ctx, platform.Member(member), k)
		}
	}
}

// waiting is the member's held changes in the organization, newest first.
func (s *Service) waiting(ctx context.Context, member, org string) []Held {
	keys, err := s.P.Keys(ctx, platform.Member(member))
	if err != nil {
		return nil
	}
	var out []Held
	for _, k := range keys {
		id, ok := strings.CutPrefix(k, heldPrefix)
		if !ok {
			continue
		}
		if h, ok := s.held(ctx, member, id); ok && h.Org == org {
			out = append(out, h)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAtMs > out[j].CreatedAtMs })
	return out
}
