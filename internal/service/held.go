package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
}

func (s *Service) hold(ctx context.Context, t component.Turn, c connector.Connector, in component.EgressRequest) (string, error) {
	id := randomToken(12)
	h := Held{ID: id, Org: t.Org, Connector: c.Name, Room: t.Room, Job: t.Job, Request: in, CreatedAtMs: s.now().UnixMilli()}
	return id, s.P.PutJSON(ctx, platform.Member(t.Requester), heldPrefix+id, h)
}

// allowanceTTL is how long an allowed change waits for the agent to send
// it (a connector whose requests go out from the member's computer).
const allowanceTTL = time.Hour

// allowanceKey names one allowed change: the same request again (method,
// URL, body), in the same organization and system.
func allowanceKey(org, connectorName string, in component.EgressRequest) string {
	h := sha256.New()
	for _, part := range []string{org, connectorName, in.Method, in.URL} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	h.Write(in.Body)
	return allowPrefix + hex.EncodeToString(h.Sum(nil))[:32]
}

// allow lets the agent's next send of the same request through once.
func (s *Service) allow(ctx context.Context, member string, h Held) error {
	return s.P.PutJSON(ctx, platform.Member(member), allowanceKey(h.Org, h.Connector, h.Request), map[string]int64{"atMs": s.now().UnixMilli()})
}

// takeAllowance spends an allowance of this request, if there is a live one.
func (s *Service) takeAllowance(ctx context.Context, t component.Turn, c connector.Connector, in component.EgressRequest) bool {
	key := allowanceKey(t.Org, c.Name, in)
	var a struct {
		AtMs int64 `json:"atMs"`
	}
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
