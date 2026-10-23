package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc/component"
)

func (st *fakeStore) takeRuns() []assistRun {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := st.runs
	st.runs = nil
	return out
}

func (fx *fixture) adminPage() string {
	fx.t.Helper()
	rec := fx.page(true, http.MethodGet, "/pages/admin/", nil)
	if rec.Code != http.StatusOK {
		fx.t.Fatalf("admin page = %d %s", rec.Code, rec.Body)
	}
	return rec.Body.String()
}

// The admin page shows the AI's review of every connector: run once per
// version of the connector (on the organization, for the admin), its
// secrets never in it, a high finding on the Enable button; an edit
// reviews again; without a model the page says why. An agent's draft is
// reviewed when it arrives, and its answer to the agent does not change.
func TestConnectorReviewForTheAdmin(t *testing.T) {
	fx := newFixture(t)
	fx.store.assist = func(task string, req component.ServiceAssistRequest) map[string]any {
		return map[string]any{
			"summary":  "Agents read issues and, after the member allows it, file and delete them.",
			"reads":    []any{"Read issues"},
			"changes":  []any{"File an issue", "Delete an issue"},
			"findings": []any{map[string]any{"severity": "HIGH", "about": "write rule", "why": "DELETE is a change anyone allowed once can repeat"}, map[string]any{"severity": "odd", "why": "dropped"}},
		}
	}
	c := issues()
	c.Enabled = false
	if err := fx.svc.saveConnector(context.Background(), "home", c); err != nil {
		t.Fatal(err)
	}
	_ = fx.svc.P.PutJSON(context.Background(), platform.Org("home"), secretsPrefix+"issues", connector.Secrets{ClientSecret: "client-SECRET"})
	page := fx.adminPage()
	if !strings.Contains(page, "file and delete them") || !strings.Contains(page, "Enable (1 high finding)") || strings.Contains(page, "dropped") {
		t.Fatalf("the page = %s", page)
	}
	runs := fx.store.takeRuns()
	if len(runs) != 1 || runs[0].task != "connections-review-connector" || runs[0].req.Org != "home" || runs[0].req.Member != "maya" ||
		!strings.Contains(runs[0].req.Text, `"name": "issues"`) || strings.Contains(runs[0].req.Text, "client-SECRET") || strings.Contains(runs[0].req.Text, `"enabled"`) {
		t.Fatalf("runs = %+v", runs)
	}
	_ = fx.page(true, http.MethodPost, "/pages/admin/toggle", url.Values{"name": {"issues"}, "enabled": {"1"}})
	fx.adminPage()
	if runs := fx.store.takeRuns(); len(runs) != 0 {
		t.Fatalf("enabling it reviewed it again: %+v", runs)
	}
	c.Purpose = "Bugs, tasks and their comments"
	raw, _ := json.Marshal(c)
	if rec := fx.page(true, http.MethodPost, "/pages/admin/save", url.Values{"json": {string(raw)}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("save = %d", rec.Code)
	}
	fx.adminPage()
	if runs := fx.store.takeRuns(); len(runs) != 1 {
		t.Fatalf("an edit reviewed %d times", len(runs))
	}
	fx.store.assist = nil
	_ = fx.page(true, http.MethodPost, "/pages/admin/review", url.Values{"name": {"issues"}})
	if page := fx.adminPage(); !strings.Contains(page, "AI is not available here: no assist model") {
		t.Fatalf("without a model the page = %s", page)
	}

	draft := issues()
	draft.Name, draft.DisplayName = "wiki", "Wiki"
	body, _ := json.Marshal(draft)
	out, _ := fx.egress(component.DriveOwn, "POST", "https://"+fx.svc.SelfHost()+"/drafts", string(body), nil)
	if out.Status != http.StatusCreated || !strings.Contains(string(out.Body), "An admin of the organization reviews it") || strings.Contains(string(out.Body), "AI") {
		t.Fatalf("the agent's answer = %d %s", out.Status, out.Body)
	}
	if r := fx.svc.review(context.Background(), "home", "wiki", true); r.Hash != reviewHash(draft) || r.Pending || r.Error == "" {
		t.Fatalf("the draft's review = %+v", r)
	}
}

// Requests no rule classifies and changes members allow are signals; a
// new refused shape proposes rules (only valid ones that classify a seen
// request); Add puts the rule in the policy and the request is then
// classified by it; Dismiss drops a proposal. The agent's answer is the
// policy's, with nothing of the AI in it.
func TestRulesProposedFromUse(t *testing.T) {
	fx := newFixture(t)
	fx.addConnector(issues())
	if err := fx.svc.saveGrant(context.Background(), "maya", "home", Grant{Connector: "issues", Reach: connector.Read, APIKey: "k"}); err != nil {
		t.Fatal(err)
	}
	fx.store.assist = func(task string, req component.ServiceAssistRequest) map[string]any {
		if task != "connections-propose-rules" {
			return map[string]any{"summary": "ok"}
		}
		return map[string]any{"notes": "Searches are reads.", "rules": []any{
			map[string]any{"class": "read", "method": "post", "path": "/search/*", "why": "a search changes nothing"},
			map[string]any{"class": "write", "method": "PUT", "path": "/elsewhere/**", "why": "matches nothing seen"},
			map[string]any{"class": "admin", "method": "POST", "path": "/search/*", "why": "not a class"},
			map[string]any{"class": "read", "method": "POST", "path": "no-slash", "why": "not a path"},
		}}
	}
	out, _ := fx.egress(component.DriveOwn, "POST", "https://example.com/search/issues", `{"q":"bug"}`, nil)
	if out.Status != http.StatusForbidden || strings.Contains(string(out.Body), "AI") || strings.Contains(string(out.Body), "search changes nothing") {
		t.Fatalf("the agent's answer = %d %s", out.Status, out.Body)
	}
	runs := fx.store.takeRuns()
	if len(runs) != 1 || runs[0].task != "connections-propose-rules" || runs[0].req.Member != "" ||
		!strings.Contains(runs[0].req.Text, "POST /search/issues: refused") || strings.Contains(runs[0].req.Text, "bug") {
		t.Fatalf("runs = %+v", runs)
	}
	p := fx.svc.proposal(context.Background(), "home", "issues")
	if len(p.Rules) != 1 || p.Rules[0].Method != "POST" || p.Rules[0].Path != "/search/*" || p.Rules[0].Matches != 1 || p.Notes != "Searches are reads." {
		t.Fatalf("proposal = %+v", p)
	}
	// The same shape again is no news: no second run.
	_, _ = fx.egress(component.DriveOwn, "POST", "https://example.com/search/issues", `{}`, nil)
	if runs := fx.store.takeRuns(); len(runs) != 0 {
		t.Fatalf("a repeat proposed again: %+v", runs)
	}
	page := fx.adminPage()
	if !strings.Contains(page, "POST /search/*") || !strings.Contains(page, "Agents then call it without asking.") || !strings.Contains(page, "2 refused requests") {
		t.Fatalf("the page = %s", page)
	}
	rec := fx.page(true, http.MethodPost, "/pages/admin/addrule", url.Values{"name": {"issues"}, "id": {p.Rules[0].ID}})
	if a := auditOf(t, rec); rec.Code != http.StatusSeeOther || a.Action != "connector-rule-add" {
		t.Fatalf("add = %d %+v", rec.Code, a)
	}
	c, _ := fx.svc.connectorNamed(context.Background(), "home", "issues")
	if c.Classify("POST", "/search/issues", nil) != connector.Read || len(fx.svc.signals(context.Background(), "home", "issues")) != 0 ||
		len(fx.svc.proposal(context.Background(), "home", "issues").Rules) != 0 {
		t.Fatalf("after add: class %q, signals %v", c.Classify("POST", "/search/issues", nil), fx.svc.signals(context.Background(), "home", "issues"))
	}
	if out, _ := fx.egress(component.DriveOwn, "POST", "https://example.com/search/issues", `{}`, nil); out.Status != 200 {
		t.Fatalf("a search after the rule = %d %s", out.Status, out.Body)
	}

	_, _ = fx.egress(component.DriveOwn, "PATCH", "https://example.com/search/x", `{}`, nil)
	fx.store.takeRuns()
	fx.store.assist = func(string, component.ServiceAssistRequest) map[string]any {
		return map[string]any{"rules": []any{map[string]any{"class": "write", "method": "PATCH", "path": "/search/*", "why": "an edit"}}}
	}
	_ = fx.page(true, http.MethodPost, "/pages/admin/propose", url.Values{"name": {"issues"}})
	p = fx.svc.proposal(context.Background(), "home", "issues")
	if len(p.Rules) != 1 {
		t.Fatalf("asked again = %+v", p)
	}
	_ = fx.page(true, http.MethodPost, "/pages/admin/dismissrule", url.Values{"name": {"issues"}, "id": {p.Rules[0].ID}})
	if p := fx.svc.proposal(context.Background(), "home", "issues"); len(p.Rules) != 0 {
		t.Fatalf("after dismiss = %+v", p)
	}
}
