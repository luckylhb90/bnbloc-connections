package service

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc/component"
)

// Call is one request an agent made through a connection: when, in which
// room, to which system, the method and path (never the query or the body),
// its answer's status and what happened (read, write, held, refused, …).
type Call struct {
	AtMs      int64  `json:"atMs"`
	Room      string `json:"room"`
	Connector string `json:"connector"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status,omitempty"`
	Outcome   string `json:"outcome"`
}

// maxActivity bounds the calls kept per member and organization.
const maxActivity = 100

var activityMu sync.Mutex

// record keeps one call in the member's activity (best-effort).
func (s *Service) record(ctx context.Context, t component.Turn, c connector.Connector, method, path string, status int, outcome string) {
	activityMu.Lock()
	defer activityMu.Unlock()
	key := activityPrefix + t.Org
	var list []Call
	if _, err := s.P.GetJSON(ctx, platform.Member(t.Requester), key, &list); err != nil {
		slog.Warn("connections: activity unreadable", "error", err)
	}
	list = append(list, Call{AtMs: s.now().UnixMilli(), Room: t.Room, Connector: c.Name, Method: method, Path: clip(path, 200), Status: status, Outcome: outcome})
	if len(list) > maxActivity {
		list = list[len(list)-maxActivity:]
	}
	if err := s.P.PutJSON(ctx, platform.Member(t.Requester), key, list); err != nil {
		slog.Warn("connections: activity not kept", "error", err)
	}
}

// activity is the member's recent calls in the organization, newest last.
func (s *Service) activity(ctx context.Context, member, org string) []Call {
	var list []Call
	_, _ = s.P.GetJSON(ctx, platform.Member(member), activityPrefix+org, &list)
	return list
}

// limiter is a token bucket per member and connector.
type limiter struct {
	mu      sync.Mutex
	buckets map[string]bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

// Rate: a burst of 60, then one a second.
const (
	rateBurst  = 60
	ratePerSec = 1.0
)

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.buckets == nil {
		l.buckets = map[string]bucket{}
	}
	b, ok := l.buckets[key]
	if !ok {
		b = bucket{tokens: rateBurst, at: now}
	}
	b.tokens = min(rateBurst, b.tokens+now.Sub(b.at).Seconds()*ratePerSec)
	b.at = now
	if b.tokens < 1 {
		l.buckets[key] = b
		return false
	}
	b.tokens--
	l.buckets[key] = b
	return true
}
