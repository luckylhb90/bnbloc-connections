package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc/component"
)

func msgOf(rec interface{ Header() http.Header }) (string, bool) {
	u, _ := url.Parse(rec.Header().Get("Location"))
	return u.Query().Get("msg"), u.Query().Get("err") != ""
}

// A draft that does not make a valid connector goes back to the model with
// why, and the second answer is the draft; the links given with the
// description reach the task (https only, at most 3).
func TestDraftChecksItsWork(t *testing.T) {
	fx := newFixture(t)
	good := issues()
	good.Test = &connector.Test{Path: "/api/me"}
	bad := good
	bad.Hosts = nil
	fx.store.assist = func(task string, req component.ServiceAssistRequest) map[string]any {
		c := bad
		if req.Revise != nil && strings.Contains(strings.Join(req.Revise.Problems, " "), "host") {
			c = good
		}
		raw, _ := json.Marshal(c)
		return map[string]any{"connector": string(raw)}
	}
	rec := fx.page(true, http.MethodPost, "/pages/admin/describe", url.Values{"description": {"Our issue tracker"},
		"links": {"https://docs.example.com/api http://plain.example.com/x\nhttps://docs.example.com/auth"}})
	if _, isErr := msgOf(rec); isErr {
		t.Fatalf("describe = %s", rec.Header().Get("Location"))
	}
	var drafts []assistRun
	for _, r := range fx.store.takeRuns() {
		if r.task == "connections-draft-connector" {
			drafts = append(drafts, r)
		}
	}
	if len(drafts) != 2 || drafts[0].req.Revise != nil || drafts[1].req.Revise == nil ||
		strings.Join(drafts[0].req.URLs, " ") != "https://docs.example.com/api https://docs.example.com/auth" {
		t.Fatalf("draft runs = %+v", drafts)
	}
	if ds := fx.svc.drafts(context.Background(), "home"); len(ds) != 1 || ds[0].Connector.Test == nil {
		t.Fatalf("drafts = %+v", ds)
	}
}

// A connector's test runs when a member connects ("it answers"); the
// admin's Try it that fails is kept without the credential the system
// echoed, and the review is given it.
func TestTryAConnection(t *testing.T) {
	fx := newFixture(t)
	c := issues()
	c.Test = &connector.Test{Path: "/api/me"}
	fx.addConnector(c)
	var reviewed []string
	fx.store.assist = func(task string, req component.ServiceAssistRequest) map[string]any {
		if task == "connections-review-connector" {
			reviewed = append(reviewed, req.Text)
		}
		return map[string]any{"summary": "Reads issues."}
	}
	rec := fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}, "key": {"KEY-123456"}})
	if msg, _ := msgOf(rec); !strings.Contains(msg, "It answers.") || fx.last().path != "/api/me" {
		t.Fatalf("connect = %q (last %s)", msg, fx.last().path)
	}

	fx.answer = func(*http.Request) (int, string) {
		return 400, `{"code":"50113","msg":"Invalid sign","echo":"Bearer KEY-123456"}`
	}
	rec = fx.page(true, http.MethodPost, "/pages/admin/try", url.Values{"name": {"issues"}})
	msg, isErr := msgOf(rec)
	if !isErr || !strings.Contains(msg, "answered 400") || !strings.Contains(msg, "50113") || strings.Contains(msg, "KEY-123456") || auditOf(t, rec).Action != "connector-try" {
		t.Fatalf("try = %q", msg)
	}
	if raw := string(fx.store.get("orgs/home/try:issues")); !strings.Contains(raw, "[credential]") || strings.Contains(raw, "KEY-123456") {
		t.Fatalf("kept try = %s", raw)
	}
	if n := len(reviewed); n == 0 || !strings.Contains(reviewed[n-1], "50113") || strings.Contains(reviewed[n-1], "KEY-123456") {
		t.Fatalf("the review was given = %q", reviewed)
	}
	if page := fx.adminPage(); !strings.Contains(page, "Tried with your connection") || !strings.Contains(page, "Try it") {
		t.Fatal("the admin page shows neither the try nor Try it")
	}

	// A member whose key the system refuses is told so when they connect.
	rec = fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}, "key": {"KEY-654321"}})
	if msg, _ := msgOf(rec); !strings.Contains(msg, "does not answer yet") || strings.Contains(msg, "KEY-654321") {
		t.Fatalf("connect, refused = %q", msg)
	}
}

func TestConnectorTestIsARead(t *testing.T) {
	for _, tc := range []struct {
		test connector.Test
		ok   bool
	}{
		{connector.Test{Path: "/api/me"}, true},
		{connector.Test{Method: "HEAD", Path: "/api/me?x=1"}, true},
		{connector.Test{Method: "POST", Path: "/api/me"}, false},
		{connector.Test{Path: "/other/me"}, false},
		{connector.Test{Path: "api/me"}, false},
	} {
		c := issues()
		c.Test = &tc.test
		if err := c.Validate(); (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc.test, err)
		}
	}
}
