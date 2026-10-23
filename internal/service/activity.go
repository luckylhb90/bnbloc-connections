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

// activityKey is one member's activity in one organization.
type activityKey struct{ member, org string }

// activityQueue holds calls not yet written: a request only queues its
// call, and one writer per member and organization appends what queued
// (read once, written once), off every request's path. The component runs
// as one replica, so its writes do not race another's.
type activityQueue struct {
	mu      sync.Mutex
	pending map[activityKey][]Call
	writing map[activityKey]bool
}

// record keeps one call in the member's activity (best-effort).
func (s *Service) record(ctx context.Context, t component.Turn, c connector.Connector, method, path string, status int, outcome string) {
	k := activityKey{t.Requester, t.Org}
	call := Call{AtMs: s.now().UnixMilli(), Room: t.Room, Connector: c.Name, Method: method, Path: clip(path, 200), Status: status, Outcome: outcome}
	q := &s.activityQ
	q.mu.Lock()
	if q.pending == nil {
		q.pending, q.writing = map[activityKey][]Call{}, map[activityKey]bool{}
	}
	q.pending[k] = append(q.pending[k], call)
	start := !q.writing[k]
	q.writing[k] = true
	q.mu.Unlock()
	if start {
		s.later(func() { s.writeActivity(k) })
	}
}

// writeActivity appends what queued for k until nothing does.
func (s *Service) writeActivity(k activityKey) {
	q := &s.activityQ
	for {
		q.mu.Lock()
		calls := q.pending[k]
		delete(q.pending, k)
		if len(calls) == 0 {
			delete(q.writing, k)
			q.mu.Unlock()
			return
		}
		q.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		key := activityPrefix + k.org
		var list []Call
		if _, err := s.P.GetJSON(ctx, platform.Member(k.member), key, &list); err != nil {
			slog.Warn("connections: activity unreadable", "error", err)
		}
		list = append(list, calls...)
		if len(list) > maxActivity {
			list = list[len(list)-maxActivity:]
		}
		if err := s.P.PutJSON(ctx, platform.Member(k.member), key, list); err != nil {
			slog.Warn("connections: activity not kept", "error", err)
		}
		cancel()
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
