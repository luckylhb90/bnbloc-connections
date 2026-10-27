package service

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc-connections/provider"
	"github.com/luckylhb90/bnbloc/component"
)

// The component's pages, served by bnbloc to a member at an address
// carrying their ticket (component.Member names them): Connections (each
// member's own), Connectors (the organization's admins) and the review of
// one held change (opened from its card, not listed).

//go:embed pages/*.html
var pageFiles embed.FS

var pageTemplates = func() map[string]*template.Template {
	out := map[string]*template.Template{}
	for _, name := range []string{"connections", "approve", "admin", "callback", "workers"} {
		out[name] = template.Must(template.ParseFS(pageFiles, "pages/layout.html", "pages/"+name+".html"))
	}
	return out
}()

func render(w http.ResponseWriter, status int, page string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pageTemplates[page].ExecuteTemplate(w, "layout", data); err != nil {
		slog.Warn("connections: page render failed", "page", page, "error", err)
	}
}

func (s *Service) callbackPage(w http.ResponseWriter, status int, heading, text string) {
	render(w, status, "callback", map[string]any{"Title": heading, "Heading": heading, "Text": text})
}

// handlePageList lists the pages bnbloc offers in Components.
func (s *Service) handlePageList(w http.ResponseWriter, _ *http.Request, _ component.Member, _ []byte) {
	writeJSON(w, http.StatusOK, component.PageList{Version: s.Version, Pages: []component.Page{
		{Name: "connections", Label: "Connections", Audience: component.AudienceMember, InRoom: true},
		{Name: "admin", Label: "Connectors", Audience: component.AudienceAdmin},
		{Name: "workers", Label: "Digital workers", Audience: component.AudienceMember},
	}})
}

// handlePage routes /pages/<page>/<action>.
func (s *Service) handlePage(w http.ResponseWriter, r *http.Request, m component.Member, body []byte) {
	rest := strings.TrimPrefix(r.URL.Path, component.ServicePagesPath+"/")
	page, action, _ := strings.Cut(rest, "/")
	form, _ := url.ParseQuery(string(body))
	if r.Method != http.MethodPost {
		form = nil
	}
	switch page {
	case "connections":
		s.connectionsPage(w, r, m, action, form)
	case "approve":
		s.approvePage(w, r, m, action, form)
	case "workers":
		s.workersPage(w, r, m, action, form)
	case "admin":
		if !m.Admin {
			s.callbackPage(w, http.StatusForbidden, "Connectors", "Only an administrator of your organization manages connectors.")
			return
		}
		s.adminPage(w, r, m, action, form)
	default:
		s.callbackPage(w, http.StatusNotFound, "Not found", "This page does not exist.")
	}
}

// back sends the browser to the page's start with a message.
func back(w http.ResponseWriter, m component.Member, msg string, isErr bool) {
	q := url.Values{"msg": {msg}}
	if isErr {
		q.Set("err", "1")
	}
	w.Header().Set("Location", m.PageURL+"?"+q.Encode())
	w.WriteHeader(http.StatusSeeOther)
}

type systemRow struct {
	SystemView
	Kind      string
	Help      string
	Highlight bool
	// Signs: the key comes with a secret (connector.Sign); Extra: the
	// other values pasted beside it.
	Signs bool
	Extra []connector.Extra
	// Workers serve the member's own agents here; Chosen is the one they
	// chose to act as ("": themselves).
	Workers []Worker
	Chosen  string
	// Check is the last check of the member's connection ("": none).
	Check string
	// Options are a connected provider connector's member options, as set.
	Options []optionRow
	// Waiting: the connection waits for the member's consent at Open
	// (consent_wait.go), followed until it arrives; OpenInTab: Open is a
	// page (a new tab), not an app link (which leaves this page in place).
	Waiting bool
	Open    string
	// OpenIn: the browsers a provider's consent page works in
	// (connector.Provider.OpenIn); elsewhere Connect asks for the
	// provider's own prompt.
	OpenIn string
}

// optionRow is one member option of a connection, on or off.
type optionRow struct {
	Key, Label string
	On         bool
}

type activityRow struct {
	Call
	When string
}

type waitingRow struct {
	Held
	System, Path, When string
}

func (s *Service) connectionsPage(w http.ResponseWriter, r *http.Request, m component.Member, action string, form url.Values) {
	ctx := r.Context()
	switch action {
	case "":
	case "connect":
		key := form.Get("key")
		if sec := strings.TrimSpace(form.Get("secret")); sec != "" {
			key = strings.TrimSpace(key) + ":" + sec
		}
		extra := map[string]string{}
		for k, v := range form {
			if name, ok := strings.CutPrefix(k, "extra-"); ok && len(v) > 0 && strings.TrimSpace(v[0]) != "" {
				extra[name] = strings.TrimSpace(v[0])
			}
		}
		s.connect(w, ctx, m, form.Get("system"), form.Get("reach"), key, extra, form.Get("notify") == "1")
		return
	case "disconnect":
		s.disconnect(w, ctx, m, form.Get("system"))
		return
	case "reach":
		s.setReach(w, ctx, m, form.Get("system"), form.Get("reach"))
		return
	case "option":
		s.setOption(w, ctx, m, form.Get("system"), form.Get("key"), form.Get("value"))
		return
	case "actas", "roomidentity", "myidentity":
		// Who agents act as: everywhere (actas), for everyone in this room
		// (roomidentity, its owner) or for the member in this room.
		ch := IdentityChange{Scope: ScopeMine, System: form.Get("system"), Worker: form.Get("worker"), Mode: form.Get("mode")}
		switch action {
		case "roomidentity":
			ch.Scope, ch.Room = ScopeRoom, m.Room
		case "myidentity":
			ch.Room = m.Room
		}
		a, err := s.applyIdentity(ctx, m, ch)
		if err != nil {
			back(w, m, "Not saved: "+err.Error(), true)
			return
		}
		audit(w, a)
		back(w, m, "Saved.", false)
		return
	case "change":
		// A waiting change, opened from this page: its review, deciding
		// under this page's address.
		s.approvePage(w, r, m, "", form)
		return
	case "decide":
		s.approvePage(w, r, m, "decide", form)
		return
	default:
		s.callbackPage(w, http.StatusNotFound, "Not found", "This page does not exist.")
		return
	}
	// A consent given in the browser completes its connection here.
	if pending, _ := s.enabled(ctx, m.Org); len(pending) > 0 {
		for _, c := range pending {
			s.settleWait(ctx, m.Subject, m.Org, c)
		}
	}
	systems, err := s.systems(ctx, m.Subject, m.Org)
	if err != nil {
		s.callbackPage(w, http.StatusBadGateway, "Connections", "Your connections cannot be read right now.")
		return
	}
	list, _ := s.enabled(ctx, m.Org)
	ws, _ := s.workers(ctx, m.Org)
	ws = slices.DeleteFunc(ws, func(wk Worker) bool { return !wk.Serves(m.Subject, component.DriveOwn) })
	q := r.URL.Query()
	rows := make([]systemRow, 0, len(systems))
	var live []string // what the page waits for (liveState)
	for i, v := range systems {
		c := list[i]
		row := systemRow{SystemView: v, Kind: c.Connect.Kind, Highlight: q.Get("system") == v.Name, Workers: ws, Chosen: s.choice(ctx, m.Subject, m.Org, c.Name)}
		if t, ok := s.lastCheck(ctx, m.Subject, m.Org, c.Name); ok && v.Connected {
			row.Check = t.View(s.now())
			if t.Waiting(s.now()) {
				live = append(live, c.Name+":check")
			}
		}
		switch {
		case c.Connect.APIKey != nil:
			row.Help, row.Signs, row.Extra = c.Connect.APIKey.Help, c.Connect.APIKey.Sign != nil, c.Connect.APIKey.Extra
		case c.Connect.Provider != nil:
			row.Help, row.OpenIn = c.Connect.Provider.Help, c.Connect.Provider.OpenIn
			if wt, ok := s.consentWaitFor(ctx, m.Subject, m.Org, c.Name); ok && !v.Connected {
				row.Waiting, row.Open = true, wt.Open
				live = append(live, c.Name+":consent")
			}
			if v.Connected {
				g, _, _ := s.grant(ctx, m.Subject, m.Org, c.Name)
				vals := c.Connect.Provider.OptionValues(g.Options)
				for _, o := range c.Connect.Provider.Options {
					row.Options = append(row.Options, optionRow{Key: o.Key, Label: o.Label, On: vals[o.Key] == "true"})
				}
			}
		}
		rows = append(rows, row)
	}
	var acts []activityRow
	calls := s.activity(ctx, m.Subject, m.Org)
	for i := len(calls) - 1; i >= 0 && len(acts) < 20; i-- {
		acts = append(acts, activityRow{Call: calls[i], When: time.UnixMilli(calls[i].AtMs).UTC().Format("Jan 2 15:04")})
	}
	var waiting []waitingRow
	for _, h := range s.waiting(ctx, m.Subject, m.Org) {
		row := waitingRow{Held: h, System: h.Connector, When: time.UnixMilli(h.CreatedAtMs).UTC().Format("Jan 2 15:04")}
		if c, ok := s.connectorNamed(ctx, m.Org, h.Connector); ok {
			row.System = c.DisplayName
		}
		if u, err := url.Parse(h.Request.URL); err == nil {
			row.Path = clip(u.Path, 120)
		}
		waiting = append(waiting, row)
	}
	var inRoom []roomIdentityRow
	if m.Room != "" {
		all, _ := s.workers(ctx, m.Org)
		for _, c := range list {
			row := roomIdentityRow{C: c, Workers: ws, Mine: s.myRoomChoice(ctx, m.Subject, m.Org, m.Room, c.Name)}
			if r, ok := s.roomIdentity(ctx, m.Org, m.Room, c.Name); ok {
				row.Room, row.HasRoom, row.RoomName = r, true, r.Worker
				if i := slices.IndexFunc(all, func(wk Worker) bool { return wk.ID == r.Worker }); i >= 0 {
					row.RoomName = all[i].DisplayName
				}
			}
			if m.RoomRole == component.RoomOwner {
				row.Workers = all
			}
			inRoom = append(inRoom, row)
		}
	}
	if q.Has("live") {
		writeLive(w, strings.Join(live, " "), q.Get("live"))
		return
	}
	render(w, http.StatusOK, "connections", map[string]any{
		"Title": "Connections", "Member": m.Subject, "Admin": m.Admin, "Systems": rows, "Activity": acts, "Waiting": waiting, "Base": m.PageURL,
		"Room": m.Room, "RoomOwner": m.RoomRole == component.RoomOwner, "InRoom": inRoom, "MyWorkers": ws,
		"Msg": q.Get("msg"), "Err": q.Get("err") != "", "Refresh": len(live) > 0, "State": strings.Join(live, " "),
	})
}

func (s *Service) connect(w http.ResponseWriter, ctx context.Context, m component.Member, name, reach, key string, extra map[string]string, notify bool) {
	r := s.connectTo(ctx, m, name, reach, key, extra, notify)
	if r.audit != nil {
		audit(w, *r.audit)
	}
	if r.open != "" {
		w.Header().Set("Location", r.open)
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	back(w, m, r.msg, r.err)
}

// connectResult is what connecting came to: a line for the member (err:
// it failed), a sign-in to start (open), the audit row.
type connectResult struct {
	msg   string
	err   bool
	open  string
	audit *component.Audit
}

// connectTo connects the member to a system: a sign-in to start (OAuth), a
// key (apiKey), or the provider's connect: a consent page to open (the
// connection then waits for it, consent_wait.go), or with notify the
// provider's own prompt (a chat card) instead. One owner for the page and
// the card's in-place Connect.
func (s *Service) connectTo(ctx context.Context, m component.Member, name, reach, key string, extra map[string]string, notify bool) connectResult {
	c, ok := s.connectorNamed(ctx, m.Org, name)
	if !ok {
		return connectResult{msg: "That system is not enabled.", err: true}
	}
	if reach != connector.Write {
		reach = connector.Read
	}
	connected := func(g Grant) connectResult {
		if err := s.saveGrant(ctx, m.Subject, m.Org, g); err != nil {
			return connectResult{msg: "The connection could not be kept: " + err.Error(), err: true}
		}
		return connectResult{msg: c.DisplayName + " is connected." + s.answers(ctx, m, asMember(m.Subject), c) + " Ask your agent again.", audit: &component.Audit{Action: "connect", Target: c.Name, Outcome: "allow", Detail: reach}}
	}
	switch c.Connect.Kind {
	case connector.KindOAuth2:
		u, err := s.authorizeURL(ctx, c, m, reach, reach, "")
		if err != nil {
			return connectResult{msg: "The sign-in cannot start: " + err.Error(), err: true}
		}
		return connectResult{msg: "Sign in to " + c.DisplayName + " in the page that opened, then ask your agent again.", open: u}
	case connector.KindAPIKey:
		key = strings.TrimSpace(key)
		if c.Connect.APIKey.Sign != nil {
			// A signing connector takes the key and its secret apart; a
			// private key must read as one.
			k, sec := splitKeySecret(key)
			if k == "" || sec == "" {
				return connectResult{msg: "Paste both the API key and its secret key to connect " + c.DisplayName + ".", err: true}
			}
			if err := checkSecret(sec); err != nil {
				return connectResult{msg: "That private key cannot sign: " + err.Error() + ".", err: true}
			}
		}
		if key == "" || len(key) > 8192 {
			return connectResult{msg: "Paste the key to connect " + c.DisplayName + ".", err: true}
		}
		g := Grant{Connector: c.Name, Reach: reach, APIKey: key, ConnectedAtMs: s.now().UnixMilli()}
		for _, x := range c.Connect.APIKey.Extra {
			v := strings.TrimSpace(extra[x.Name])
			if v == "" || len(v) > 1024 {
				return connectResult{msg: "Fill in the " + x.Label + " to connect " + c.DisplayName + ".", err: true}
			}
			if g.Extra == nil {
				g.Extra = map[string]string{}
			}
			g.Extra[x.Name] = v
		}
		return connected(g)
	case connector.KindProvider:
		a, err := s.callProvider(ctx, c, m.Org, provider.ConnectPath, provider.Call{Member: m.Subject, Org: m.Org, Reach: reach, Notify: notify})
		switch {
		case err != nil:
			return connectResult{msg: err.Error(), err: true}
		case a.Status == provider.Connected:
			return connected(Grant{Connector: c.Name, Reach: reach, ProviderGrant: a.Grant, ConnectedAtMs: s.now().UnixMilli()})
		case a.Status == provider.Pending:
			// The connection waits for what the member does outside bnbloc,
			// and completes on its own (consent_wait.go).
			s.noteWait(ctx, m.Subject, m.Org, c.Name, a.Open)
			r := connectResult{msg: firstNonEmpty(a.Message, "Confirm the request you were sent; the connection completes on its own.")}
			if a.Open != "" && !notify {
				r.open = a.Open
			}
			return r
		default:
			msg := firstNonEmpty(a.Message, c.DisplayName+" could not be connected.")
			if a.Admin {
				msg += " (An administrator arranges this; nothing for you to do.)"
			}
			return connectResult{msg: msg, err: true}
		}
	}
	return connectResult{msg: "Unknown connect kind.", err: true}
}

func (s *Service) disconnect(w http.ResponseWriter, ctx context.Context, m component.Member, name string) {
	g, ok, err := s.grant(ctx, m.Subject, m.Org, name)
	if err != nil || !ok {
		back(w, m, "That system is not connected.", true)
		return
	}
	if c, found := s.connectorNamed(ctx, m.Org, name); found {
		switch c.Connect.Kind {
		case connector.KindOAuth2:
			s.revoke(ctx, c, m.Org, g)
		case connector.KindProvider:
			_, _ = s.callProvider(ctx, c, m.Org, provider.RevokePath, provider.Call{Member: m.Subject, Org: m.Org, Grant: g.ProviderGrant, Options: g.Options})
		}
	}
	if err := s.deleteGrant(ctx, m.Subject, m.Org, name); err != nil {
		back(w, m, "The connection could not be removed: "+err.Error(), true)
		return
	}
	s.dropWaiting(ctx, m.Subject, m.Org, name)
	audit(w, component.Audit{Action: "disconnect", Target: name, Outcome: "ok"})
	back(w, m, "Disconnected.", false)
}

// setOption sets one of the member's options on their connection to a
// provider connector; the provider gets it with its next call.
func (s *Service) setOption(w http.ResponseWriter, ctx context.Context, m component.Member, name, key, value string) {
	g, ok, err := s.grant(ctx, m.Subject, m.Org, name)
	if err != nil || !ok {
		back(w, m, "That system is not connected.", true)
		return
	}
	c, found := s.connectorNamed(ctx, m.Org, name)
	if !found || c.Connect.Provider == nil || !slices.ContainsFunc(c.Connect.Provider.Options, func(o connector.ProviderOption) bool { return o.Key == key }) {
		back(w, m, "That option does not exist.", true)
		return
	}
	if g.Options == nil {
		g.Options = map[string]string{}
	}
	g.Options[key] = strconv.FormatBool(value == "true")
	if err := s.saveGrant(ctx, m.Subject, m.Org, g); err != nil {
		back(w, m, "Not saved: "+err.Error(), true)
		return
	}
	audit(w, component.Audit{Action: "option", Target: name, Outcome: "ok", Detail: key + "=" + g.Options[key]})
	back(w, m, c.DisplayName+": saved.", false)
}

func (s *Service) setReach(w http.ResponseWriter, ctx context.Context, m component.Member, name, reach string) {
	g, ok, err := s.grant(ctx, m.Subject, m.Org, name)
	if err != nil || !ok {
		back(w, m, "That system is not connected.", true)
		return
	}
	if reach != connector.Write {
		reach = connector.Read
	}
	c, found := s.connectorNamed(ctx, m.Org, name)
	if found && reach == connector.Write && !g.canChange(c) {
		// Changes need the write scopes: sign in again asking for them.
		u, err := s.authorizeURL(ctx, c, m, reach, connector.Write, "")
		if err != nil {
			back(w, m, "The sign-in cannot start: "+err.Error(), true)
			return
		}
		w.Header().Set("Location", u)
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	g.Reach = reach
	if err := s.saveGrant(ctx, m.Subject, m.Org, g); err != nil {
		back(w, m, "Not saved: "+err.Error(), true)
		return
	}
	audit(w, component.Audit{Action: "reach", Target: name, Outcome: "ok", Detail: reach})
	if reach == connector.Write {
		back(w, m, "Changes are made without asking you from now on.", false)
	} else {
		back(w, m, "Each change asks you first from now on.", false)
	}
}

func (s *Service) approvePage(w http.ResponseWriter, r *http.Request, m component.Member, action string, form url.Values) {
	ctx := r.Context()
	id := r.URL.Query().Get("id")
	if action == "decide" {
		id = form.Get("id")
	}
	data := map[string]any{"Title": "A change your agent asked for", "Heading": "A change your agent asked for", "Base": m.PageURL}
	hc, why := s.heldFor(ctx, m, id)
	switch {
	case why != "":
		s.callbackPage(w, http.StatusOK, "Not made", why)
		return
	case hc == nil:
		render(w, http.StatusOK, "approve", data)
		return
	}
	data["System"] = hc.c.DisplayName
	if hc.p.Worker != nil {
		data["As"] = hc.p.Worker.DisplayName
	}
	if action != "decide" {
		data["Held"], data["Path"], data["Body"] = hc.h, hc.u.Path, bodySummary(hc.h.Request.Body)
		data["Asked"] = time.UnixMilli(hc.h.CreatedAtMs).UTC().Format("Jan 2 15:04 UTC")
		render(w, http.StatusOK, "approve", data)
		return
	}
	d := s.decide(ctx, m, *hc, form.Get("decision") == "allow", form.Get("always") == "1")
	if d.audit != nil {
		audit(w, *d.audit)
	}
	switch {
	case d.open != "":
		w.Header().Set("Location", d.open)
		w.WriteHeader(http.StatusSeeOther)
	case d.result != nil:
		data["Heading"] = "Done"
		data["Result"], data["ResultBody"] = d.result, bodySummary(d.result.Body)
		render(w, http.StatusOK, "approve", data)
	default:
		s.callbackPage(w, http.StatusOK, d.heading, d.text)
	}
}

type adminRow struct {
	C                 connector.Connector
	JSON              string
	HasClientSecret   bool
	HasProviderSecret bool
	Review            Review
	ReviewBlock       reviewBlock
	Proposal          Proposal
	Refused, Allowed  int
	// Try is the last Try it, as the page shows it.
	Try string
}

type draftRow struct {
	Draft
	JSON        string
	Review      Review
	ReviewBlock reviewBlock
}

// reviewBlock is what the review template shows: the review, and where
// its fixes apply.
type reviewBlock struct {
	R     Review
	Name  string
	Draft bool
	Base  string
}

func pretty(v any) string {
	raw, _ := json.MarshalIndent(v, "", "  ")
	return string(raw)
}

func (s *Service) adminPage(w http.ResponseWriter, r *http.Request, m component.Member, action string, form url.Values) {
	ctx := r.Context()
	org := platform.Org(m.Org)
	switch action {
	case "":
	case "save":
		var c connector.Connector
		if err := json.Unmarshal([]byte(form.Get("json")), &c); err != nil {
			back(w, m, "Not a connector's JSON: "+err.Error(), true)
			return
		}
		if err := c.Validate(); err != nil {
			back(w, m, "Not saved: "+err.Error(), true)
			return
		}
		var old connector.Connector
		if found, _ := s.P.GetJSON(ctx, org, connectorPrefix+c.Name, &old); found {
			c.Enabled = old.Enabled
		} else {
			c.Enabled = false
		}
		if err := s.saveConnector(ctx, m.Org, c); err != nil {
			back(w, m, "Not saved: "+err.Error(), true)
			return
		}
		audit(w, component.Audit{Action: "connector-save", Target: c.Name, Outcome: "ok"})
		back(w, m, c.DisplayName+" saved.", false)
		return
	case "sendfrom":
		name := form.Get("name")
		var c connector.Connector
		if found, err := s.P.GetJSON(ctx, org, connectorPrefix+name, &c); err != nil || !found {
			back(w, m, "No such connector.", true)
			return
		}
		c.SendFrom = connector.SendServer
		if form.Get("sendFrom") == connector.SendMember {
			c.SendFrom = connector.SendMember
		}
		if err := s.saveConnector(ctx, m.Org, c); err != nil {
			back(w, m, "Not saved: "+err.Error(), true)
			return
		}
		audit(w, component.Audit{Action: "connector-send-from", Target: name, Outcome: "ok", Detail: c.SendFrom})
		where := "this service"
		if c.FromMember() {
			where = "each member's computer"
		}
		back(w, m, c.DisplayName+": requests go out from "+where+".", false)
		return
	case "toggle", "delete":
		name := form.Get("name")
		var c connector.Connector
		if found, err := s.P.GetJSON(ctx, org, connectorPrefix+name, &c); err != nil || !found {
			back(w, m, "No such connector.", true)
			return
		}
		if action == "delete" {
			defer s.forget(m.Org)
			_ = s.P.Delete(ctx, org, secretsPrefix+name)
			s.forgetAI(ctx, m.Org, name)
			if err := s.P.Delete(ctx, org, connectorPrefix+name); err != nil {
				back(w, m, "Not removed: "+err.Error(), true)
				return
			}
			audit(w, component.Audit{Action: "connector-remove", Target: name, Outcome: "ok"})
			back(w, m, c.DisplayName+" removed.", false)
			return
		}
		c.Enabled = form.Get("enabled") == "1"
		if err := s.saveConnector(ctx, m.Org, c); err != nil {
			back(w, m, "Not saved: "+err.Error(), true)
			return
		}
		audit(w, component.Audit{Action: map[bool]string{true: "connector-enable", false: "connector-disable"}[c.Enabled], Target: name, Outcome: "ok"})
		back(w, m, c.DisplayName+map[bool]string{true: " enabled.", false: " disabled."}[c.Enabled], false)
		return
	case "secrets":
		name := form.Get("name")
		sec := s.secrets(ctx, m.Org, name)
		if v := strings.TrimSpace(form.Get("clientSecret")); v != "" {
			sec.ClientSecret = v
		}
		if v := strings.TrimSpace(form.Get("providerSecret")); v != "" {
			sec.ProviderSecret = v
		}
		if err := s.P.PutJSON(ctx, org, secretsPrefix+name, sec); err != nil {
			back(w, m, "Not saved: "+err.Error(), true)
			return
		}
		audit(w, component.Audit{Action: "connector-secrets", Target: name, Outcome: "ok"})
		back(w, m, "Secrets saved.", false)
		return
	case "draft":
		name := form.Get("name")
		var d Draft
		if found, err := s.P.GetJSON(ctx, org, draftPrefix+name, &d); err != nil || !found {
			back(w, m, "No such draft.", true)
			return
		}
		_ = s.P.Delete(ctx, org, draftPrefix+name)
		dr := s.review(ctx, m.Org, name, true)
		_ = s.P.Delete(ctx, org, reviewKey(name, true))
		if form.Get("decision") != "accept" {
			back(w, m, "Draft discarded.", false)
			return
		}
		d.Connector.Enabled = false
		if err := s.saveConnector(ctx, m.Org, d.Connector); err != nil {
			back(w, m, "Not added: "+err.Error(), true)
			return
		}
		if dr.Hash == reviewHash(d.Connector) && !dr.Pending {
			_ = s.P.PutJSON(ctx, org, reviewKey(name, false), dr)
		}
		audit(w, component.Audit{Action: "connector-save", Target: name, Outcome: "ok", Detail: "from a draft by " + d.DraftedBy})
		back(w, m, d.Connector.DisplayName+" added, disabled: set its client values and enable it.", false)
		return
	case "review":
		name := form.Get("name")
		draft := form.Get("draft") == "1"
		var c connector.Connector
		found := false
		if draft {
			var d Draft
			found, _ = s.P.GetJSON(ctx, org, draftPrefix+name, &d)
			c = d.Connector
		} else {
			found, _ = s.P.GetJSON(ctx, org, connectorPrefix+name, &c)
		}
		if !found {
			back(w, m, "No such connector.", true)
			return
		}
		s.ensureReview(ctx, m.Org, m.Subject, c, draft, true)
		back(w, m, "Reviewing "+c.DisplayName+"…", false)
		return
	case "try":
		// The admin's own connection runs the connector's test; a failure
		// is the review's evidence, and the review proposes the fix.
		var c connector.Connector
		if found, err := s.P.GetJSON(ctx, org, connectorPrefix+form.Get("name"), &c); err != nil || !found {
			back(w, m, "No such connector.", true)
			return
		}
		if c.FromMember() {
			// Sent from the admin's own computer: the answer comes back
			// as the send's report (handleSendEgress).
			switch err := s.tryFromComputer(ctx, m, c, tryAdmin); {
			case err == nil:
				back(w, m, c.DisplayName+": sent from your computer; the answer appears here in a few seconds.", false)
			case errors.Is(err, component.ErrNoMemberComputer):
				back(w, m, "Open your bnbloc desktop app, then try again: "+c.DisplayName+" is reached from members' computers.", true)
			case errors.Is(err, errNoTry):
				back(w, m, c.DisplayName+" names no test request: nothing to try.", true)
			default:
				back(w, m, "Connect your own account to "+c.DisplayName+" on Connections, then try it.", true)
			}
			return
		}
		t, err := s.tryConnection(ctx, m.Org, asMember(m.Subject), c)
		switch {
		case errors.Is(err, errNoTry):
			back(w, m, c.DisplayName+" names no test request, or its requests go out from members' computers: nothing to try here.", true)
			return
		case err != nil:
			back(w, m, "Connect your own account to "+c.DisplayName+" on Connections, then try it.", true)
			return
		}
		s.keepTry(ctx, m.Org, c.Name, t)
		audit(w, component.Audit{Action: "connector-try", Target: c.Name, Outcome: map[bool]string{true: "ok", false: "failed"}[t.OK], Detail: t.Line})
		if t.OK {
			back(w, m, c.DisplayName+": "+t.Line+". It works.", false)
			return
		}
		s.ensureReview(ctx, m.Org, m.Subject, c, false, true)
		back(w, m, c.DisplayName+": "+t.Line+". AI is reviewing the connector with this answer, for a fix.", true)
		return
	case "propose":
		name := form.Get("name")
		var c connector.Connector
		if found, err := s.P.GetJSON(ctx, org, connectorPrefix+name, &c); err != nil || !found {
			back(w, m, "No such connector.", true)
			return
		}
		s.startProposal(ctx, m.Org, m.Subject, c)
		back(w, m, "Looking at how "+c.DisplayName+" is used…", false)
		return
	case "addrule":
		c, r, err := s.addProposedRule(ctx, m.Org, form.Get("name"), form.Get("id"))
		if err != nil {
			back(w, m, "Not added: "+err.Error(), true)
			return
		}
		audit(w, component.Audit{Action: "connector-rule-add", Target: c.Name, Outcome: "ok", Detail: r.Class + " " + r.Method + " " + r.Path + " (suggested)"})
		back(w, m, c.DisplayName+": "+r.Method+" "+r.Path+" is now "+map[bool]string{true: "a read", false: "a change"}[r.Class == connector.Read]+".", false)
		return
	case "describe":
		// Drafting takes the model's time: it runs off the request, and the
		// page shows it under way until the draft (or why there is none)
		// is there.
		if err := s.startDrafting(ctx, m, form.Get("description"), docLinks(form.Get("links"))); err != nil {
			back(w, m, "No draft: "+err.Error(), true)
			return
		}
		audit(w, component.Audit{Action: "connector-draft", Target: "", Outcome: "queued", Detail: "from a description, by AI"})
		back(w, m, "AI is drafting the connector: it appears under Drafts in a few seconds.", false)
		return
	case "dismissdrafting":
		_ = s.P.Delete(ctx, org, draftingPrefix+form.Get("id"))
		back(w, m, "Dismissed.", false)
		return
	case "applyfix":
		i, _ := strconv.Atoi(form.Get("finding"))
		c, err := s.applyFix(ctx, m.Org, form.Get("name"), i)
		if err != nil {
			back(w, m, "Not applied: "+err.Error(), true)
			return
		}
		audit(w, component.Audit{Action: "connector-fix", Target: c.Name, Outcome: "ok", Detail: "the review's fix"})
		back(w, m, c.DisplayName+": fix applied; reviewing it again.", false)
		return
	case "dismissrule":
		s.dismissProposedRule(ctx, m.Org, form.Get("name"), form.Get("id"))
		back(w, m, "Suggestion dismissed.", false)
		return
	default:
		s.callbackPage(w, http.StatusNotFound, "Not found", "This page does not exist.")
		return
	}
	list, err := s.connectors(ctx, m.Org)
	if err != nil {
		s.callbackPage(w, http.StatusBadGateway, "Connectors", "The connectors cannot be read right now.")
		return
	}
	rows := make([]adminRow, 0, len(list))
	var live []string // what the page waits for (liveState)
	for _, c := range list {
		sec := s.secrets(ctx, m.Org, c.Name)
		row := adminRow{C: c, JSON: pretty(c), HasClientSecret: sec.ClientSecret != "", HasProviderSecret: sec.ProviderSecret != "",
			Review: s.ensureReview(ctx, m.Org, m.Subject, c, false, false), Proposal: s.proposal(ctx, m.Org, c.Name)}
		for _, sig := range s.signals(ctx, m.Org, c.Name) {
			if sig.Outcome == signalRefused {
				row.Refused += sig.Count
			} else {
				row.Allowed += sig.Count
			}
		}
		row.ReviewBlock = reviewBlock{R: row.Review, Name: c.Name, Base: m.PageURL}
		if t, ok := s.lastTry(ctx, m.Org, c.Name, reviewHash(c)); ok {
			row.Try = t.View(s.now())
			if t.Waiting(s.now()) {
				live = append(live, c.Name+":try")
			}
		}
		if row.Review.Pending {
			live = append(live, c.Name+":review")
		}
		if row.Proposal.Pending {
			live = append(live, c.Name+":proposal")
		}
		rows = append(rows, row)
	}
	var drafts []draftRow
	for _, d := range s.drafts(ctx, m.Org) {
		row := draftRow{Draft: d, JSON: pretty(d.Connector), Review: s.ensureReview(ctx, m.Org, m.Subject, d.Connector, true, false)}
		row.ReviewBlock = reviewBlock{R: row.Review, Name: d.Connector.Name, Draft: true, Base: m.PageURL}
		if row.Review.Pending {
			live = append(live, "draft:"+d.Connector.Name+":review")
		}
		drafts = append(drafts, row)
	}
	q := r.URL.Query()
	drafting := s.draftings(ctx, m.Org)
	for i, d := range drafting {
		if d.Error == "" {
			live = append(live, "drafting:"+strconv.Itoa(i))
		}
	}
	if q.Has("live") {
		writeLive(w, strings.Join(live, " "), q.Get("live"))
		return
	}
	render(w, http.StatusOK, "admin", map[string]any{"Title": "Connectors", "Connectors": rows, "Drafts": drafts, "Drafting": drafting, "Base": m.PageURL, "Msg": q.Get("msg"), "Err": q.Get("err") != "", "Refresh": len(live) > 0, "State": strings.Join(live, " ")})
}
