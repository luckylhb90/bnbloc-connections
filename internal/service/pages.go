package service

import (
	"context"
	"embed"
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
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
	for _, name := range []string{"connections", "approve", "admin", "callback"} {
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
	writeJSON(w, http.StatusOK, component.PageList{Pages: []component.Page{
		{Name: "connections", Label: "Connections", Audience: component.AudienceMember},
		{Name: "admin", Label: "Connectors", Audience: component.AudienceAdmin},
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
}

type activityRow struct {
	Call
	When string
}

func (s *Service) connectionsPage(w http.ResponseWriter, r *http.Request, m component.Member, action string, form url.Values) {
	ctx := r.Context()
	switch action {
	case "":
	case "connect":
		s.connect(w, ctx, m, form.Get("system"), form.Get("reach"), form.Get("key"))
		return
	case "disconnect":
		s.disconnect(w, ctx, m, form.Get("system"))
		return
	case "reach":
		s.setReach(w, ctx, m, form.Get("system"), form.Get("reach"))
		return
	default:
		s.callbackPage(w, http.StatusNotFound, "Not found", "This page does not exist.")
		return
	}
	systems, err := s.systems(ctx, m.Subject, m.Org)
	if err != nil {
		s.callbackPage(w, http.StatusBadGateway, "Connections", "Your connections cannot be read right now.")
		return
	}
	list, _ := s.enabled(ctx, m.Org)
	q := r.URL.Query()
	rows := make([]systemRow, 0, len(systems))
	for i, v := range systems {
		c := list[i]
		row := systemRow{SystemView: v, Kind: c.Connect.Kind, Highlight: q.Get("system") == v.Name}
		switch {
		case c.Connect.APIKey != nil:
			row.Help = c.Connect.APIKey.Help
		case c.Connect.Provider != nil:
			row.Help = c.Connect.Provider.Help
		}
		rows = append(rows, row)
	}
	var acts []activityRow
	calls := s.activity(ctx, m.Subject, m.Org)
	for i := len(calls) - 1; i >= 0 && len(acts) < 20; i-- {
		acts = append(acts, activityRow{Call: calls[i], When: time.UnixMilli(calls[i].AtMs).UTC().Format("Jan 2 15:04")})
	}
	render(w, http.StatusOK, "connections", map[string]any{
		"Title": "Connections", "Member": m.Subject, "Admin": m.Admin, "Systems": rows, "Activity": acts, "Base": m.PageURL,
		"Msg": q.Get("msg"), "Err": q.Get("err") != "",
	})
}

func (s *Service) connect(w http.ResponseWriter, ctx context.Context, m component.Member, name, reach, key string) {
	c, ok := s.connectorNamed(ctx, m.Org, name)
	if !ok {
		back(w, m, "That system is not enabled.", true)
		return
	}
	if reach != connector.Write {
		reach = connector.Read
	}
	connected := func(g Grant) {
		if err := s.saveGrant(ctx, m.Subject, m.Org, g); err != nil {
			back(w, m, "The connection could not be kept: "+err.Error(), true)
			return
		}
		audit(w, component.Audit{Action: "connect", Target: c.Name, Outcome: "allow", Detail: reach})
		back(w, m, c.DisplayName+" is connected. Ask your agent again.", false)
	}
	switch c.Connect.Kind {
	case connector.KindOAuth2:
		u, err := s.authorizeURL(ctx, c, m, reach)
		if err != nil {
			back(w, m, "The sign-in cannot start: "+err.Error(), true)
			return
		}
		w.Header().Set("Location", u)
		w.WriteHeader(http.StatusSeeOther)
	case connector.KindAPIKey:
		key = strings.TrimSpace(key)
		if key == "" || len(key) > 4096 {
			back(w, m, "Paste the key to connect "+c.DisplayName+".", true)
			return
		}
		connected(Grant{Connector: c.Name, Reach: reach, APIKey: key, ConnectedAtMs: s.now().UnixMilli()})
	case connector.KindProvider:
		a, err := s.callProvider(ctx, c, m.Org, provider.ConnectPath, provider.Call{Member: m.Subject, Org: m.Org, Reach: reach})
		switch {
		case err != nil:
			back(w, m, err.Error(), true)
		case a.Status == provider.Connected:
			connected(Grant{Connector: c.Name, Reach: reach, ProviderGrant: a.Grant, ConnectedAtMs: s.now().UnixMilli()})
		case a.Status == provider.Pending:
			back(w, m, firstNonEmpty(a.Message, "Confirm the request you were sent, then connect again."), false)
		default:
			msg := firstNonEmpty(a.Message, c.DisplayName+" could not be connected.")
			if a.Admin {
				msg += " (An administrator arranges this; nothing for you to do.)"
			}
			back(w, m, msg, true)
		}
	}
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
			_, _ = s.callProvider(ctx, c, m.Org, provider.RevokePath, provider.Call{Member: m.Subject, Org: m.Org, Grant: g.ProviderGrant})
		}
	}
	if err := s.deleteGrant(ctx, m.Subject, m.Org, name); err != nil {
		back(w, m, "The connection could not be removed: "+err.Error(), true)
		return
	}
	audit(w, component.Audit{Action: "disconnect", Target: name, Outcome: "ok"})
	back(w, m, "Disconnected.", false)
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
	if found && c.Connect.Kind == connector.KindOAuth2 && reach == connector.Write && len(c.Connect.OAuth2.Scopes.Write) > 0 && g.Reach != connector.Write {
		// Changes need the write scopes: sign in again asking for them.
		u, err := s.authorizeURL(ctx, c, m, reach)
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
	h, ok := s.held(ctx, m.Subject, id)
	data := map[string]any{"Title": "A change your agent asked for", "Heading": "A change your agent asked for", "Base": m.PageURL}
	if !ok || h.Org != m.Org {
		render(w, http.StatusOK, "approve", data)
		return
	}
	c, found := s.connectorNamed(ctx, m.Org, h.Connector)
	if !found {
		render(w, http.StatusOK, "approve", data)
		return
	}
	u, _ := url.Parse(h.Request.URL)
	data["System"] = c.DisplayName
	if action != "decide" {
		data["Held"], data["Path"], data["Body"] = h, u.Path, bodySummary(h.Request.Body)
		data["Asked"] = time.UnixMilli(h.CreatedAtMs).UTC().Format("Jan 2 15:04 UTC")
		render(w, http.StatusOK, "approve", data)
		return
	}
	_ = s.P.Delete(ctx, platform.Member(m.Subject), heldPrefix+h.ID)
	t := component.Turn{Org: h.Org, Room: h.Room, Job: h.Job, Requester: m.Subject, Drive: component.DriveOwn}
	if form.Get("decision") != "allow" {
		s.record(ctx, t, c, h.Request.Method, u.Path, 0, "not allowed")
		audit(w, component.Audit{Action: "change", Target: c.Name + " " + h.Request.Method + " " + u.Path, Outcome: "deny"})
		data["Heading"] = "Not made"
		render(w, http.StatusOK, "callback", map[string]any{"Title": "Not made", "Heading": "Not made", "Text": "The change was not made. Your agent sees nothing changed."})
		return
	}
	g, ok, err := s.grant(ctx, m.Subject, m.Org, c.Name)
	if err != nil || !ok {
		s.callbackPage(w, http.StatusOK, "Not made", c.DisplayName+" is not connected any more: connect it, then ask your agent again.")
		return
	}
	if form.Get("always") == "1" && g.Reach != connector.Write {
		g.Reach = connector.Write
		if err := s.saveGrant(ctx, m.Subject, m.Org, g); err != nil {
			slog.Warn("connections: reach not saved", "error", err)
		}
	}
	resp, err := s.call(ctx, c, m.Org, m.Subject, &g, h.Request, u)
	if err != nil {
		s.record(ctx, t, c, h.Request.Method, u.Path, 0, "failed")
		audit(w, component.Audit{Action: "change", Target: c.Name + " " + h.Request.Method + " " + u.Path, Outcome: "failed"})
		s.callbackPage(w, http.StatusOK, "Not made", c.DisplayName+" did not take the change: "+err.Error())
		return
	}
	s.record(ctx, t, c, h.Request.Method, u.Path, resp.Status, "allowed")
	audit(w, component.Audit{Action: "change", Target: c.Name + " " + h.Request.Method + " " + u.Path, Outcome: "allow", Detail: http.StatusText(resp.Status)})
	data["Heading"] = "Done"
	data["Result"], data["ResultBody"] = resp, bodySummary(resp.Body)
	render(w, http.StatusOK, "approve", data)
}

type adminRow struct {
	C                 connector.Connector
	JSON              string
	HasClientSecret   bool
	HasProviderSecret bool
}

type draftRow struct {
	Draft
	JSON string
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
		if form.Get("decision") != "accept" {
			back(w, m, "Draft discarded.", false)
			return
		}
		d.Connector.Enabled = false
		if err := s.saveConnector(ctx, m.Org, d.Connector); err != nil {
			back(w, m, "Not added: "+err.Error(), true)
			return
		}
		audit(w, component.Audit{Action: "connector-save", Target: name, Outcome: "ok", Detail: "from a draft by " + d.DraftedBy})
		back(w, m, d.Connector.DisplayName+" added, disabled: set its client values and enable it.", false)
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
	for _, c := range list {
		sec := s.secrets(ctx, m.Org, c.Name)
		rows = append(rows, adminRow{C: c, JSON: pretty(c), HasClientSecret: sec.ClientSecret != "", HasProviderSecret: sec.ProviderSecret != ""})
	}
	var drafts []draftRow
	for _, d := range s.drafts(ctx, m.Org) {
		drafts = append(drafts, draftRow{Draft: d, JSON: pretty(d.Connector)})
	}
	q := r.URL.Query()
	render(w, http.StatusOK, "admin", map[string]any{"Title": "Connectors", "Connectors": rows, "Drafts": drafts, "Base": m.PageURL, "Msg": q.Get("msg"), "Err": q.Get("err") != ""})
}
