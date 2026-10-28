package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// pageAct is a page action carrying the member's grant (component.Member.Act).
func (fx *fixture) pageAct(admin bool, path string, form url.Values) *httptest.ResponseRecorder {
	fx.t.Helper()
	m := member(admin)
	m.Act = "act-" + path
	return fx.do(http.MethodPost, path, component.MemberHeader, m, []byte(form.Encode()))
}

// sendExchange is the member's bridge's egress call for a send.
func (fx *fixture) sendExchange(id string, in component.EgressRequest) component.EgressResponse {
	fx.t.Helper()
	raw, _ := json.Marshal(in)
	rec := fx.do(http.MethodPost, component.ServiceSendEgressPath, component.SendHeader, component.Send{Org: "home", Member: "maya", ID: id, Origin: "https://bnbloc.example.com"}, raw)
	var out component.EgressResponse
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		fx.t.Fatalf("send exchange = %d %s", rec.Code, rec.Body)
	}
	return out
}

// A connector that sends from members' computers is tried from the
// person's own computer: the admin's Try it asks their desktop app (or says
// to open it), gets the member's credentials for the one request, and the
// system's answer, without the credential it echoed, is the review's
// evidence; a member's connect is checked the same way and their page says
// so.
func TestTryFromTheMembersComputer(t *testing.T) {
	fx := newFixture(t)
	c := issues()
	c.SendFrom = connector.SendMember
	c.Test = &connector.Test{Path: "/api/me"}
	fx.addConnector(c)
	var reviewed []string
	fx.store.assist = func(task string, req component.ServiceAssistRequest) map[string]any {
		if task == "connections-review-connector" {
			reviewed = append(reviewed, req.Text)
		}
		return map[string]any{"summary": "Reads issues."}
	}
	// Connecting without the desktop app running says to open it.
	rec := fx.pageAct(false, "/pages/connections/connect", url.Values{"system": {"issues"}, "key": {"KEY-123456"}})
	if msg, _ := msgOf(rec); !strings.Contains(msg, "Open your bnbloc desktop app") {
		t.Fatalf("connect without the app = %q", msg)
	}
	fx.store.computer = true
	if msg, isErr := msgOf(fx.pageAct(true, "/pages/admin/try", url.Values{"name": {"issues"}})); isErr || !strings.Contains(msg, "sent from your computer") {
		t.Fatalf("try = %q", msg)
	}
	if n := len(fx.store.sends); n != 1 || fx.store.sends[0].URL != "https://example.com/api/me" || fx.store.sends[0].Method != "GET" || fx.store.sends[0].Act == "" {
		t.Fatalf("sends = %+v", fx.store.sends)
	}
	if page := fx.adminPage(); !strings.Contains(page, "waiting for the answer") || !strings.Contains(page, `<meta name="live" content="`) {
		t.Fatal("the admin page does not show the try under way")
	}
	in := component.EgressRequest{Method: "GET", URL: "https://example.com/api/me"}
	out := fx.sendExchange("send-1", in)
	if out.Send == nil || out.Send.Header["Authorization"][0] != "Bearer KEY-123456" {
		t.Fatalf("first answer = %+v", out)
	}
	in.Report = &component.EgressReport{Attempt: 1, Status: 400, Body: []byte(`{"code":"50113","msg":"Invalid sign","echo":"Bearer KEY-123456"}`)}
	if out := fx.sendExchange("send-1", in); !out.Accept {
		t.Fatalf("to the report = %+v", out)
	}
	if raw := string(fx.store.get("orgs/home/try:issues")); !strings.Contains(raw, "50113") || strings.Contains(raw, "KEY-123456") || strings.Contains(raw, `"pending":true`) {
		t.Fatalf("kept try = %s", raw)
	}
	if n := len(reviewed); n == 0 || !strings.Contains(reviewed[n-1], "50113") {
		t.Fatalf("the review was not given the try: %q", reviewed)
	}
	if out := fx.sendExchange("send-1", in); out.Status != http.StatusNotFound {
		t.Fatalf("a finished send again = %+v", out)
	}

	// A member's check after connecting.
	_ = fx.pageAct(false, "/pages/connections/connect", url.Values{"system": {"issues"}, "key": {"KEY-123456"}})
	if page := fx.page(false, http.MethodGet, "/pages/connections/", nil).Body.String(); !strings.Contains(page, "waiting for the answer") {
		t.Fatalf("the member's page while checking = %s", page)
	}
	in.Report = nil
	_ = fx.sendExchange("send-2", in)
	in.Report = &component.EgressReport{Attempt: 1, Status: 200, Body: []byte(`{"user":"maya"}`)}
	_ = fx.sendExchange("send-2", in)
	if page := fx.page(false, http.MethodGet, "/pages/connections/", nil).Body.String(); !strings.Contains(page, "answered 200: it works") {
		t.Fatalf("the member's page after the check = %s", page)
	}
}

// A system that refuses a credential with a 200 (expiredWhen names its
// body) fails the member's check: the page says the connection does not
// work and offers to replace the key, never "it works".
func TestCheckRefusedWithA200(t *testing.T) {
	fx := newFixture(t)
	c := issues()
	c.SendFrom = connector.SendMember
	c.Test = &connector.Test{Path: "/api/me"}
	c.ExpiredWhen = []connector.Expired{{Status: 200, BodyContains: `"code":401`}}
	fx.addConnector(c)
	fx.store.computer = true
	_ = fx.pageAct(false, "/pages/connections/connect", url.Values{"system": {"issues"}, "key": {"KEY-123456"}})
	in := component.EgressRequest{Method: "GET", URL: "https://example.com/api/me"}
	_ = fx.sendExchange("send-1", in)
	for attempt := 1; attempt <= component.MaxEgressSends; attempt++ {
		in.Report = &component.EgressReport{Attempt: attempt, Status: 200, Body: []byte(`{"code":401,"message":"please login first"}`)}
		if out := fx.sendExchange("send-1", in); out.Accept {
			break
		}
	}
	page := fx.page(false, http.MethodGet, "/pages/connections/", nil).Body.String()
	if strings.Contains(page, "it works") || !strings.Contains(page, "Not working") || !strings.Contains(page, "Replace the key") || !strings.Contains(page, "refused the credentials") {
		t.Fatalf("the member's page after a refused check = %s", page)
	}
}
