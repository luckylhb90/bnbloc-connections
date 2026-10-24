package service

import (
	"context"
	"errors"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc/component"
)

// Who agents act as, set by people on pages, never by an agent
// (docs/prd/2026-10-24-connections-room-identity.md in bnbloc):
//   - a room's owner sets, per system, a digital worker for everyone in the
//     room: by default (each member may still act as themselves) or
//     required;
//   - each member chooses, per system, in a room or everywhere: themselves
//     or a worker.
//
// One owner writes every setting (applyIdentity) from an IdentityChange and
// the attested page member, whatever proposed it: a page today. An agent's
// or the AI's proposal later is an IdentityChange kept until the person it
// is for confirms it on the same page, through the same function.

// IdentityChange is one change of who agents act as for a system.
type IdentityChange struct {
	// Scope: ScopeRoom (the room's, for everyone; its owner) or ScopeMine
	// (the member's own: in Room, or everywhere with Room "").
	Scope  string `json:"scope"`
	Room   string `json:"room,omitempty"`
	System string `json:"system"`
	// Worker: a worker's id; ActAsSelf (mine only); "" clears the setting.
	Worker string `json:"worker,omitempty"`
	// Mode of a room's worker: ModeDefault or ModeRequired.
	Mode string `json:"mode,omitempty"`
}

// Identity scopes, choices and modes.
const (
	ScopeRoom    = "room"
	ScopeMine    = "mine"
	ActAsSelf    = "self"
	ModeDefault  = "default"
	ModeRequired = "required"
)

// RoomIdentity is a room's worker for a system.
type RoomIdentity struct {
	Worker string `json:"worker"`
	Mode   string `json:"mode"`
	SetBy  string `json:"setBy"`
	AtMs   int64  `json:"atMs"`
}

// Store keys: a room's (organization scope) and a member's in a room
// (member scope); a member's everywhere is actAsPrefix (workers.go).
func roomIdentityKey(room, system string) string { return "roomid:" + room + ":" + system }
func myRoomKey(org, room, system string) string  { return "actasroom:" + org + ":" + room + ":" + system }

func (s *Service) roomIdentity(ctx context.Context, org, room, system string) (RoomIdentity, bool) {
	var r RoomIdentity
	ok, err := s.P.GetJSON(ctx, platform.Org(org), roomIdentityKey(room, system), &r)
	return r, ok && err == nil && r.Worker != ""
}

// myRoomChoice is the member's choice in a room: a worker, ActAsSelf, or
// "" (the room's).
func (s *Service) myRoomChoice(ctx context.Context, member, org, room, system string) string {
	var v struct {
		Worker string `json:"worker"`
	}
	_, _ = s.P.GetJSON(ctx, platform.Member(member), myRoomKey(org, room, system), &v)
	return v.Worker
}

// identityStep is one candidate of actingAs: a worker (required: the room
// requires it) or the member themselves.
type identityStep struct {
	worker   string
	self     bool
	required bool
}

// identitySteps are the settings that apply to t for a system, in their
// order (actingAs): the room's required worker alone; else the member's
// choice in the room, the room's default, the member's choice everywhere,
// then themselves.
func (s *Service) identitySteps(ctx context.Context, t component.Turn, system string) []identityStep {
	var steps []identityStep
	room, hasRoom := RoomIdentity{}, false
	if t.Room != "" {
		room, hasRoom = s.roomIdentity(ctx, t.Org, t.Room, system)
		if hasRoom && room.Mode == ModeRequired {
			return []identityStep{{worker: room.Worker, required: true}, {self: true}}
		}
		switch mine := s.myRoomChoice(ctx, t.Requester, t.Org, t.Room, system); mine {
		case "":
		case ActAsSelf:
			steps = append(steps, identityStep{self: true})
		default:
			steps = append(steps, identityStep{worker: mine})
		}
	}
	if hasRoom {
		steps = append(steps, identityStep{worker: room.Worker})
	}
	if mine := s.choice(ctx, t.Requester, t.Org, system); mine != "" {
		steps = append(steps, identityStep{worker: mine})
	}
	return append(steps, identityStep{self: true})
}

// Refusals of applyIdentity.
var (
	errNotRoomOwner = errors.New("only the room's owner sets who everyone's agents act as in it")
	errNotThisRoom  = errors.New("open this page from the room to change who agents act as there")
)

// applyIdentity is the one writer of who agents act as: the change, as the
// page's member m may make it (the room's owner for the room; anyone for
// their own), naming a worker that exists (and, for their own, serves them).
func (s *Service) applyIdentity(ctx context.Context, m component.Member, ch IdentityChange) (component.Audit, error) {
	if _, ok := s.connectorNamed(ctx, m.Org, ch.System); !ok {
		return component.Audit{}, errors.New("that system is not enabled")
	}
	var w Worker
	if ch.Worker != "" && ch.Worker != ActAsSelf {
		found := false
		if w, found = s.worker(ctx, m.Org, ch.Worker); !found {
			return component.Audit{}, errors.New("no such digital worker")
		}
	}
	a := component.Audit{Action: "act-as", Target: ch.System, Outcome: "ok", Detail: ch.Scope + " " + firstNonEmpty(ch.Worker, "cleared")}
	switch ch.Scope {
	case ScopeRoom:
		if ch.Room == "" || ch.Room != m.Room {
			return component.Audit{}, errNotThisRoom
		}
		if m.RoomRole != component.RoomOwner {
			return component.Audit{}, errNotRoomOwner
		}
		if ch.Worker == "" {
			return a, s.P.Delete(ctx, platform.Org(m.Org), roomIdentityKey(ch.Room, ch.System))
		}
		if ch.Worker == ActAsSelf || (ch.Mode != ModeDefault && ch.Mode != ModeRequired) {
			return component.Audit{}, errors.New("a room sets a digital worker, by default or required")
		}
		a.Detail += " " + ch.Mode + " in room " + ch.Room
		return a, s.P.PutJSON(ctx, platform.Org(m.Org), roomIdentityKey(ch.Room, ch.System), RoomIdentity{Worker: w.ID, Mode: ch.Mode, SetBy: m.Subject, AtMs: s.now().UnixMilli()})
	case ScopeMine:
		if w.ID != "" && !w.Serves(m.Subject, component.DriveOwn) {
			return component.Audit{}, errors.New(w.DisplayName + " does not serve your agents")
		}
		if ch.Room == "" {
			if ch.Worker == ActAsSelf {
				ch.Worker = ""
			}
			return a, s.setChoice(ctx, m.Subject, m.Org, ch.System, ch.Worker)
		}
		if ch.Room != m.Room {
			return component.Audit{}, errNotThisRoom
		}
		if r, ok := s.roomIdentity(ctx, m.Org, ch.Room, ch.System); ok && r.Mode == ModeRequired {
			return component.Audit{}, errors.New("this room requires its digital worker for that system")
		}
		a.Detail += " in room " + ch.Room
		if ch.Worker == "" {
			return a, s.P.Delete(ctx, platform.Member(m.Subject), myRoomKey(m.Org, ch.Room, ch.System))
		}
		return a, s.P.PutJSON(ctx, platform.Member(m.Subject), myRoomKey(m.Org, ch.Room, ch.System), map[string]string{"worker": ch.Worker})
	}
	return component.Audit{}, errors.New("scope: room or mine")
}

// roomIdentityRow is one system on a room's page: the room's setting, the
// member's choice, the workers that serve them.
type roomIdentityRow struct {
	C        connector.Connector
	Room     RoomIdentity
	HasRoom  bool
	RoomName string // the room's worker's name
	Mine     string // the member's choice in the room
	Workers  []Worker
}
