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

func (s *Service) hold(ctx context.Context, t component.Turn, p principal, c connector.Connector, in component.EgressRequest) (string, error) {
	id := randomToken(12)
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
		if !strings.HasPrefix(k, heldPrefix) && !strings.HasPrefix(k, allowPrefix) {
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
