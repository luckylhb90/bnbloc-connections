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

// An admin describes a system and the AI drafts its connector (a draft,
// reviewed); a review's fix is applied in one click and the connector is
// reviewed again; a fix that would enable it, or does not make a valid
// connector, is not offered.
func TestConfigureByDescriptionAndFixes(t *testing.T) {
	fx := newFixture(t)
	drafted, _ := json.Marshal(issues())
	fx.store.assist = func(task string, req component.ServiceAssistRequest) map[string]any {
		switch task {
		case "connections-draft-connector":
			if !strings.Contains(req.Text, "issue tracker at example.com") {
				return map[string]any{"connector": "{}"}
			}
			return map[string]any{"connector": "```json\n" + string(drafted) + "\n```", "notes": "The token page was not named."}
		default:
			return map[string]any{"summary": "Reads issues; files and deletes them after asking.", "findings": []any{
				map[string]any{"severity": "medium", "about": "write rule", "why": "DELETE is broader than filing", "fix": `{"policy":{"write":[{"methods":["POST"],"paths":["/api/**"]}]}}`},
				map[string]any{"severity": "low", "about": "enabled", "why": "turn it on", "fix": `{"enabled":true}`},
				map[string]any{"severity": "low", "about": "hosts", "why": "broken", "fix": `{"hosts":[]}`},
			}}
		}
	}
	rec := fx.page(true, http.MethodPost, "/pages/admin/describe", url.Values{"description": {"Our issue tracker at example.com: read issues, filing asks first."}})
	if strings.Contains(rec.Header().Get("Location"), "err=1") || auditOf(t, rec).Action != "connector-draft" {
		t.Fatalf("describe = %s", rec.Header().Get("Location"))
	}
	if rec := fx.page(true, http.MethodPost, "/pages/admin/describe", url.Values{"description": {"something else"}}); !strings.Contains(rec.Header().Get("Location"), "err=1") {
		t.Fatal("an invalid draft was kept")
	}
	var d Draft
	if ok, _ := fx.svc.P.GetJSON(context.Background(), platform.Org("home"), draftPrefix+"issues", &d); !ok || d.Notes == "" || d.Connector.Enabled {
		t.Fatalf("draft = %+v", d)
	}
	_ = fx.page(true, http.MethodPost, "/pages/admin/draft", url.Values{"name": {"issues"}, "decision": {"accept"}})
	page := fx.page(true, http.MethodGet, "/pages/admin/", nil).Body.String()
	if strings.Count(page, "Apply the fix") != 1 {
		t.Fatalf("fixes offered = %d", strings.Count(page, "Apply the fix"))
	}
	rec = fx.page(true, http.MethodPost, "/pages/admin/applyfix", url.Values{"name": {"issues"}, "finding": {"0"}})
	if auditOf(t, rec).Action != "connector-fix" {
		t.Fatalf("apply = %s", rec.Header().Get("Location"))
	}
	var got connector.Connector
	_, _ = fx.svc.P.GetJSON(context.Background(), platform.Org("home"), connectorPrefix+"issues", &got)
	if got.Classify("DELETE", "/api/issue/1", nil) != "" || got.Classify("POST", "/api/issue", nil) != connector.Write || got.Enabled {
		t.Fatalf("after the fix = %+v", got.Policy)
	}
	if rec := fx.page(true, http.MethodPost, "/pages/admin/applyfix", url.Values{"name": {"issues"}, "finding": {"0"}}); !strings.Contains(rec.Header().Get("Location"), "err=1") {
		t.Fatal("a fix applied twice")
	}
}
