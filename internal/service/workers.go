package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc-connections/provider"
	"github.com/luckylhb90/bnbloc/component"
)

// Digital workers (docs/prd/2026-10-23-connections-digital-workers.md in
// bnbloc): accounts of the organization that are not a person, which
// agents may act as. An admin adds one, names its owners and its audience
// (which members' agents, and which drives, may act as it); an owner or an
// admin connects it to systems through their providers, which sign in as
// its account. Who a request acts as is decided here from the attested
// turn (actingAs), never by the agent.

// Worker is one digital worker.
type Worker struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Purpose     string `json:"purpose,omitempty"`
	// Account is its name in the providers' directory (what they sign in
	// as).
	Account string   `json:"account"`
	Owners  []string `json:"owners,omitempty"`
	// Members may have an agent act as it ("*": every member of the
	// organization); Drives are the drives that may (component.DriveOwn,
	// DriveBorrowed, DrivePlatform).
	Members     []string `json:"members,omitempty"`
	Drives      []string `json:"drives,omitempty"`
	CreatedAtMs int64    `json:"createdAtMs"`
}

// EveryMember in Worker.Members: the whole organization.
const EveryMember = "*"

var workerIDRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

var drives = []string{component.DriveOwn, component.DriveBorrowed, component.DrivePlatform}

// Validate reports the first thing wrong with w.
func (w Worker) Validate() error {
	switch {
	case !workerIDRE.MatchString(w.ID):
		return errors.New("id: 1-32 of a-z, 0-9 and '-'")
	case strings.TrimSpace(w.DisplayName) == "" || utf8.RuneCountInString(w.DisplayName) > 60:
		return errors.New("name: required, at most 60 characters")
	case strings.TrimSpace(w.Account) == "" || len(w.Account) > 200:
		return errors.New("account: its name in the directory")
	case utf8.RuneCountInString(w.Purpose) > 200:
		return errors.New("purpose: at most 200 characters")
	case len(w.Owners) > 20 || len(w.Members) > 500:
		return errors.New("at most 20 owners and 500 members")
	}
	for _, d := range w.Drives {
		if !slices.Contains(drives, d) {
			return fmt.Errorf("drive %q: own, borrowed or platform", d)
		}
	}
	return nil
}

// Serves reports whether requester's agent on drive may act as w.
func (w Worker) Serves(requester, drive string) bool {
	return slices.Contains(w.Drives, drive) && (slices.Contains(w.Members, EveryMember) || slices.Contains(w.Members, requester))
}

// Owned reports whether subject owns w.
func (w Worker) Owned(subject string) bool { return slices.Contains(w.Owners, subject) }

// Store keys of workers: the organization's scope.
const (
	workerPrefix       = "worker:"    // a Worker
	workerGrantPrefix  = "wgrant:"    // wgrant:<worker>:<connector>, its Grant
	workerActivityPref = "wactivity:" // wactivity:<worker>, its []Call
	actAsPrefix        = "actas:"     // member scope, actas:<org>:<connector>: the worker chosen
)

func workerGrantKey(worker, name string) string { return workerGrantPrefix + worker + ":" + name }

// workers are the organization's workers, by id (kept in memory like the
// connectors, orgTTL).
func (s *Service) workers(ctx context.Context, org string) ([]Worker, error) {
	s.mu.Lock()
	if c, ok := s.workerCache[org]; ok && s.now().Sub(c.at) < orgTTL {
		s.mu.Unlock()
		return c.workers, nil
	}
	s.mu.Unlock()
	keys, err := s.P.Keys(ctx, platform.Org(org))
	if err != nil {
		return nil, err
	}
	var out []Worker
	for _, k := range keys {
		if !strings.HasPrefix(k, workerPrefix) {
			continue
		}
		var w Worker
		if ok, err := s.P.GetJSON(ctx, platform.Org(org), k, &w); err != nil || !ok {
			slog.Warn("connections: worker unreadable", "org", org, "key", k, "error", err)
			continue
		}
		out = append(out, w)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	s.mu.Lock()
	if s.workerCache == nil {
		s.workerCache = map[string]workerCache{}
	}
	s.workerCache[org] = workerCache{at: s.now(), workers: out}
	s.mu.Unlock()
	return out, nil
}

type workerCache struct {
	at      time.Time
	workers []Worker
}

// forgetWorkers drops an organization's workers from memory (a change).
func (s *Service) forgetWorkers(org string) {
	s.mu.Lock()
	delete(s.workerCache, org)
	s.mu.Unlock()
}

func (s *Service) worker(ctx context.Context, org, id string) (Worker, bool) {
	var w Worker
	ok, err := s.P.GetJSON(ctx, platform.Org(org), workerPrefix+id, &w)
	return w, ok && err == nil
}

func (s *Service) saveWorker(ctx context.Context, org string, w Worker) error {
	if err := w.Validate(); err != nil {
		return err
	}
	defer s.forgetWorkers(org)
	return s.P.PutJSON(ctx, platform.Org(org), workerPrefix+w.ID, w)
}

// removeWorker drops a worker, its grants and its record.
func (s *Service) removeWorker(ctx context.Context, org, id string) error {
	defer s.forgetWorkers(org)
	keys, err := s.P.Keys(ctx, platform.Org(org))
	if err != nil {
		return err
	}
	for _, k := range keys {
		if strings.HasPrefix(k, workerGrantPrefix+id+":") {
			_ = s.P.Delete(ctx, platform.Org(org), k)
		}
	}
	_ = s.P.Delete(ctx, platform.Org(org), workerActivityPref+id)
	return s.P.Delete(ctx, platform.Org(org), workerPrefix+id)
}

// principal is who a request acts as: the member, or a digital worker
// (Worker set) for the member who asked.
type principal struct {
	Member string
	Worker *Worker
}

// key names the principal's credentials in memory and its rate.
func (p principal) key() string {
	if p.Worker != nil {
		return "worker:" + p.Worker.ID
	}
	return p.Member
}

// as is how the agent is told it acts: "" as the member, else the
// worker's name.
func (p principal) as() string {
	if p.Worker != nil {
		return p.Worker.DisplayName
	}
	return ""
}

// asID is the worker's id ("" for the member).
func (p principal) asID() string {
	if p.Worker != nil {
		return p.Worker.ID
	}
	return ""
}

// forProvider is the provider contract's principal.
func (p principal) forProvider() *provider.Principal {
	if p.Worker != nil {
		return &provider.Principal{Kind: provider.PrincipalWorker, ID: p.Worker.ID, Account: p.Worker.Account}
	}
	return &provider.Principal{Kind: provider.PrincipalMember, ID: p.Member}
}

func asMember(subject string) principal { return principal{Member: subject} }

// grantOf is the principal's grant for a system of the organization.
func (s *Service) grantOf(ctx context.Context, p principal, org, name string) (Grant, bool, error) {
	if p.Worker == nil {
		return s.grant(ctx, p.Member, org, name)
	}
	var g Grant
	ok, err := s.P.GetJSON(ctx, platform.Org(org), workerGrantKey(p.Worker.ID, name), &g)
	return g, ok, err
}

func (s *Service) saveGrantOf(ctx context.Context, p principal, org string, g Grant) error {
	if p.Worker == nil {
		return s.saveGrant(ctx, p.Member, org, g)
	}
	return s.P.PutJSON(ctx, platform.Org(org), workerGrantKey(p.Worker.ID, g.Connector), g)
}

func (s *Service) deleteGrantOf(ctx context.Context, p principal, org, name string) error {
	if p.Worker == nil {
		return s.deleteGrant(ctx, p.Member, org, name)
	}
	s.dropAuth(grantKey{p.key(), org, name})
	return s.P.Delete(ctx, platform.Org(org), workerGrantKey(p.Worker.ID, name))
}

// choice is the worker the member chose for a system ("": as themselves).
func (s *Service) choice(ctx context.Context, member, org, name string) string {
	var v struct {
		Worker string `json:"worker"`
	}
	_, _ = s.P.GetJSON(ctx, platform.Member(member), actAsPrefix+org+":"+name, &v)
	return v.Worker
}

func (s *Service) setChoice(ctx context.Context, member, org, name, worker string) error {
	if worker == "" {
		return s.P.Delete(ctx, platform.Member(member), actAsPrefix+org+":"+name)
	}
	return s.P.PutJSON(ctx, platform.Member(member), actAsPrefix+org+":"+name, map[string]string{"worker": worker})
}

// acting is the outcome of actingAs: who the request acts as and its
// grant (ok), else the worker that could serve it once connected (none:
// nil).
type acting struct {
	p       principal
	g       Grant
	ok      bool
	waiting *Worker
}

// actingAs decides who a request for system c in turn t acts as:
//  1. the requester's own drive: the worker they chose for c, if it serves
//     them there and is connected; else their own connection;
//  2. else a connected worker that serves the requester on this drive
//     (the first by id);
//  3. else nobody: waiting names a worker that serves them but is not
//     connected to c.
//
// A person's own connection serves only their own drive.
func (s *Service) actingAs(ctx context.Context, t component.Turn, c connector.Connector) (acting, error) {
	ws, err := s.workers(ctx, t.Org)
	if err != nil {
		return acting{}, err
	}
	var serving []Worker
	for _, w := range ws {
		if w.Serves(t.Requester, t.Drive) {
			serving = append(serving, w)
		}
	}
	try := func(w Worker) (acting, bool, error) {
		p := principal{Member: t.Requester, Worker: &w}
		g, ok, err := s.grantOf(ctx, p, t.Org, c.Name)
		return acting{p: p, g: g, ok: ok}, ok, err
	}
	if chosen := s.choice(ctx, t.Requester, t.Org, c.Name); chosen != "" {
		if i := slices.IndexFunc(serving, func(w Worker) bool { return w.ID == chosen }); i >= 0 {
			if a, ok, err := try(serving[i]); err != nil || ok {
				return a, err
			}
		}
	}
	if t.Drive == component.DriveOwn {
		g, ok, err := s.grant(ctx, t.Requester, t.Org, c.Name)
		if err != nil || ok {
			return acting{p: asMember(t.Requester), g: g, ok: ok}, err
		}
	}
	for _, w := range serving {
		if a, ok, err := try(w); err != nil || ok {
			return a, err
		}
	}
	out := acting{p: asMember(t.Requester)}
	if len(serving) > 0 {
		out.waiting = &serving[0]
	}
	return out, nil
}
