package service

import (
	"context"
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
