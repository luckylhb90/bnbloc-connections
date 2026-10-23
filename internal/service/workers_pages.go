package service

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc-connections/provider"
	"github.com/luckylhb90/bnbloc/component"
)

// The Digital workers page: an admin adds workers and sets their owners
// and audience; an owner or an admin connects one to systems and sets its
// reach, and sees its calls; any member sees the workers their agents may
// act as.

type workerRow struct {
	W        Worker
	Manage   bool // an owner or an admin: connect, reach, calls
	Systems  []workerSystem
	Calls    []activityRow
	Owners   string
	Members  string
	Drive    map[string]bool
	ServesMe bool
	Base     string
}

type workerSystem struct {
	C         connector.Connector
	Connected bool
	Changes   bool
	Supported bool // a worker connects through the system's provider
}

func (s *Service) workersPage(w http.ResponseWriter, r *http.Request, m component.Member, action string, form url.Values) {
	ctx := r.Context()
	org := m.Org
	switch action {
	case "":
	case "save":
		if !m.Admin {
			back(w, m, "Only an administrator adds or changes digital workers.", true)
			return
		}
		wk := Worker{ID: strings.TrimSpace(form.Get("id")), DisplayName: strings.TrimSpace(form.Get("displayName")), Purpose: strings.TrimSpace(form.Get("purpose")),
			Account: strings.TrimSpace(form.Get("account")), Owners: splitList(form.Get("owners")), Members: splitList(form.Get("members")), Drives: form["drive"], CreatedAtMs: s.now().UnixMilli()}
		if old, ok := s.worker(ctx, org, wk.ID); ok {
			wk.CreatedAtMs = old.CreatedAtMs
		}
		if err := s.saveWorker(ctx, org, wk); err != nil {
			back(w, m, "Not saved: "+err.Error(), true)
			return
		}
		audit(w, component.Audit{Action: "worker-save", Target: wk.ID, Outcome: "ok", Detail: "drives " + strings.Join(wk.Drives, ",") + ", members " + strings.Join(wk.Members, ",")})
		back(w, m, wk.DisplayName+" saved.", false)
		return
	case "remove":
		if !m.Admin {
			back(w, m, "Only an administrator removes digital workers.", true)
			return
		}
		id := form.Get("id")
		if err := s.removeWorker(ctx, org, id); err != nil {
			back(w, m, "Not removed: "+err.Error(), true)
			return
		}
		audit(w, component.Audit{Action: "worker-remove", Target: id, Outcome: "ok"})
		back(w, m, "Removed.", false)
		return
	case "connect", "disconnect", "reach":
		wk, ok := s.worker(ctx, org, form.Get("id"))
		if !ok || !(m.Admin || wk.Owned(m.Subject)) {
			back(w, m, "Only its owners or an administrator connect a digital worker.", true)
			return
		}
		c, found := s.connectorNamed(ctx, org, form.Get("system"))
		if !found {
			back(w, m, "That system is not enabled.", true)
			return
		}
		p := principal{Member: m.Subject, Worker: &wk}
		switch action {
		case "connect":
			s.connectWorker(w, ctx, m, p, c)
		case "disconnect":
			if g, ok, _ := s.grantOf(ctx, p, org, c.Name); ok && c.Connect.Kind == connector.KindProvider {
				_, _ = s.callProvider(ctx, c, org, provider.RevokePath, provider.Call{Member: m.Subject, Principal: p.forProvider(), Org: org, Grant: g.ProviderGrant})
			}
			if err := s.deleteGrantOf(ctx, p, org, c.Name); err != nil {
				back(w, m, "Not disconnected: "+err.Error(), true)
				return
			}
			audit(w, component.Audit{Action: "worker-disconnect", Target: wk.ID + " " + c.Name, Outcome: "ok"})
			back(w, m, wk.DisplayName+" no longer reaches "+c.DisplayName+".", false)
		case "reach":
			g, ok, err := s.grantOf(ctx, p, org, c.Name)
			if err != nil || !ok {
				back(w, m, wk.DisplayName+" is not connected to "+c.DisplayName+".", true)
				return
			}
			g.Reach = connector.Read
			if form.Get("reach") == connector.Write {
				g.Reach = connector.Write
			}
			if err := s.saveGrantOf(ctx, p, org, g); err != nil {
				back(w, m, "Not saved: "+err.Error(), true)
				return
			}
			audit(w, component.Audit{Action: "worker-reach", Target: wk.ID + " " + c.Name, Outcome: "ok", Detail: g.Reach})
			if g.Reach == connector.Write {
				back(w, m, wk.DisplayName+": changes in "+c.DisplayName+" are made without asking.", false)
			} else {
				back(w, m, wk.DisplayName+": each change in "+c.DisplayName+" asks the person who asked.", false)
			}
		}
		return
	default:
		s.callbackPage(w, http.StatusNotFound, "Not found", "This page does not exist.")
		return
	}
	ws, err := s.workers(ctx, org)
	if err != nil {
		s.callbackPage(w, http.StatusBadGateway, "Digital workers", "The digital workers cannot be read right now.")
		return
	}
	list, _ := s.enabled(ctx, org)
	var rows []workerRow
	for _, wk := range ws {
		row := workerRow{W: wk, Manage: m.Admin || wk.Owned(m.Subject), Owners: strings.Join(wk.Owners, ", "), Members: strings.Join(wk.Members, ", "),
			Drive: map[string]bool{}, ServesMe: wk.Serves(m.Subject, component.DriveOwn), Base: m.PageURL}
		for _, d := range wk.Drives {
			row.Drive[d] = true
		}
		if !row.Manage && !row.ServesMe {
			continue
		}
		p := principal{Worker: &wk}
		for _, c := range list {
			g, ok, _ := s.grantOf(ctx, p, org, c.Name)
			row.Systems = append(row.Systems, workerSystem{C: c, Connected: ok, Changes: ok && g.Reach == connector.Write, Supported: c.Connect.Kind == connector.KindProvider})
		}
		if row.Manage {
			var calls []Call
			_, _ = s.P.GetJSON(ctx, platform.Org(org), workerActivityPref+wk.ID, &calls)
			for i := len(calls) - 1; i >= 0 && len(row.Calls) < 20; i-- {
				row.Calls = append(row.Calls, activityRow{Call: calls[i], When: time.UnixMilli(calls[i].AtMs).UTC().Format("Jan 2 15:04")})
			}
		}
		rows = append(rows, row)
	}
	q := r.URL.Query()
	blank := workerRow{Base: m.PageURL, Drive: map[string]bool{component.DriveOwn: true}}
	render(w, http.StatusOK, "workers", map[string]any{"Title": "Digital workers", "Workers": rows, "Blank": blank, "Admin": m.Admin, "Base": m.PageURL, "Msg": q.Get("msg"), "Err": q.Get("err") != ""})
}

// connectWorker connects a worker to a system through the system's
// provider, which signs in as the worker's account.
func (s *Service) connectWorker(w http.ResponseWriter, ctx context.Context, m component.Member, p principal, c connector.Connector) {
	if c.Connect.Kind != connector.KindProvider {
		back(w, m, "A digital worker connects through a provider (its directory's sign-in); "+c.DisplayName+" connects with "+c.Connect.Kind+", which a worker cannot use yet.", true)
		return
	}
	a, err := s.callProvider(ctx, c, m.Org, provider.ConnectPath, provider.Call{Member: m.Subject, Principal: p.forProvider(), Org: m.Org, Reach: connector.Read})
	switch {
	case err != nil:
		back(w, m, err.Error(), true)
	case a.Status == provider.Connected:
		g := Grant{Connector: c.Name, Reach: connector.Read, ProviderGrant: a.Grant, ConnectedAtMs: s.now().UnixMilli()}
		if err := s.saveGrantOf(ctx, p, m.Org, g); err != nil {
			back(w, m, "The connection could not be kept: "+err.Error(), true)
			return
		}
		audit(w, component.Audit{Action: "worker-connect", Target: p.Worker.ID + " " + c.Name, Outcome: "allow"})
		back(w, m, p.Worker.DisplayName+" reaches "+c.DisplayName+" now (reading only, until you allow changes).", false)
	case a.Status == provider.Pending:
		back(w, m, firstNonEmpty(a.Message, "Confirm the request that was sent, then connect again."), false)
	default:
		msg := firstNonEmpty(a.Message, p.Worker.DisplayName+" could not be connected to "+c.DisplayName+".")
		if a.Admin {
			msg += " (An administrator arranges this.)"
		}
		back(w, m, msg, true)
	}
}

// splitList reads a comma- or space-separated list.
func splitList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
}
