package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc-connections/provider"
	"github.com/luckylhb90/bnbloc/component"
)

// workerFixture: connector "issues" through a provider that signs in a
// worker without consent (tokens WORKER-<id>) and a member as themselves
// (MEMBER-<subject>), and an admin's form for a worker.
func workerFixture(t *testing.T) (*fixture, *[]provider.Call) {
	fx := newFixture(t)
	var mu sync.Mutex
	var calls []provider.Call
	prov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if provider.Verify(r.Header.Get(provider.SignatureHeader), "prov-secret", body, time.Now()) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var c provider.Call
		_ = json.Unmarshal(body, &c)
		mu.Lock()
		calls = append(calls, c)
		mu.Unlock()
		who := "MEMBER-" + c.Member
		if c.Principal != nil && c.Principal.Kind == provider.PrincipalWorker {
			who = "WORKER-" + c.Principal.Account
		}
		switch r.URL.Path {
		case "/p/connect":
			_ = json.NewEncoder(w).Encode(provider.Answer{Status: provider.Connected, Grant: "grant-" + who})
		case "/p/authorize":
			_ = json.NewEncoder(w).Encode(provider.Answer{Header: map[string]string{"Authorization": "Bearer " + who}, ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()})
		default:
			_ = json.NewEncoder(w).Encode(provider.Answer{Status: provider.Connected})
		}
	}))
	t.Cleanup(prov.Close)
	c := issues()
	c.Connect = connector.Connect{Kind: connector.KindProvider, Provider: &connector.Provider{URL: prov.URL + "/p", App: "app-1"}}
	fx.addConnector(c)
	_ = fx.svc.P.PutJSON(context.Background(), platform.Org("home"), secretsPrefix+"issues", connector.Secrets{ProviderSecret: "prov-secret"})
	return fx, &calls
}

func (fx *fixture) turnAs(requester, drive string, in component.EgressRequest) component.EgressResponse {
	fx.t.Helper()
	tr := turn(drive)
	tr.Requester = requester
	raw, _ := json.Marshal(in)
	rec := fx.do(http.MethodPost, component.ServiceEgressRequestPath, component.TurnHeader, tr, raw)
	var out component.EgressResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

// An admin adds a worker on the Digital workers page and connects it
// through the provider, which signs in as its account (no consent). A
// member who is not connected acts as it; a platform agent does when its
// audience takes platform agents, a borrowed one does not; a member with
// their own connection acts as themselves unless they chose the worker;
// someone outside the audience never does. The system sees the worker,
// the records name who asked, and the agent is told as whom it acts.
func TestDigitalWorkers(t *testing.T) {
	fx, calls := workerFixture(t)
	save := fx.page(true, http.MethodPost, "/pages/workers/save", url.Values{"id": {"release-bot"}, "displayName": {"Release bot"}, "account": {"+30001"},
		"owners": {"olga"}, "members": {"maya, jack"}, "drive": {"own", "platform"}})
	if save.Code != http.StatusSeeOther || auditOf(t, save).Action != "worker-save" {
		t.Fatalf("save = %d %s", save.Code, save.Header().Get("Location"))
	}
	if rec := fx.page(false, http.MethodPost, "/pages/workers/connect", url.Values{"id": {"release-bot"}, "system": {"issues"}}); !strings.Contains(rec.Header().Get("Location"), "err=1") {
		t.Fatalf("a member who neither owns nor manages it connected it: %s", rec.Header().Get("Location"))
	}
	if rec := fx.page(true, http.MethodPost, "/pages/workers/connect", url.Values{"id": {"release-bot"}, "system": {"issues"}}); strings.Contains(rec.Header().Get("Location"), "err=1") {
		t.Fatalf("connect = %s", rec.Header().Get("Location"))
	}
	last := (*calls)[len(*calls)-1]
	if last.Principal == nil || last.Principal.Kind != provider.PrincipalWorker || last.Principal.Account != "+30001" || last.Member != "maya" {
		t.Fatalf("the provider's connect = %+v", last)
	}

	read := component.EgressRequest{Method: "GET", URL: "https://example.com/api/issue/1"}
	if out := fx.turnAs("maya", component.DriveOwn, read); out.Status != 200 || fx.last().header.Get("Authorization") != "Bearer WORKER-+30001" {
		t.Fatalf("maya, not connected = %d %v", out.Status, fx.last().header)
	}
	n := fx.count()
	if out := fx.turnAs("jack", component.DrivePlatform, read); out.Status != 200 || fx.count() != n+1 || fx.last().header.Get("Authorization") != "Bearer WORKER-+30001" {
		t.Fatalf("jack's platform agent = %+v", out)
	}
	if out := fx.turnAs("jack", component.DriveBorrowed, read); out.Status != http.StatusForbidden || !strings.Contains(string(out.Body), "digital worker") {
		t.Fatalf("a borrowed agent = %d %s", out.Status, out.Body)
	}
	if out := fx.turnAs("olga", component.DrivePlatform, read); out.Status != http.StatusForbidden {
		t.Fatalf("outside the audience = %d %s", out.Status, out.Body)
	}

	// maya connects herself: she acts as herself, until she chooses the worker.
	_ = fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}})
	_ = fx.turnAs("maya", component.DriveOwn, read)
	if got := fx.last().header.Get("Authorization"); got != "Bearer MEMBER-maya" {
		t.Fatalf("maya connected = %q", got)
	}
	_ = fx.page(false, http.MethodPost, "/pages/connections/actas", url.Values{"system": {"issues"}, "worker": {"release-bot"}})
	_ = fx.turnAs("maya", component.DriveOwn, read)
	if got := fx.last().header.Get("Authorization"); got != "Bearer WORKER-+30001" {
		t.Fatalf("maya chose the worker = %q", got)
	}

	// The agent is told; the platform agent gets the host and the facts.
	tr := turn(component.DrivePlatform)
	tr.Requester = "jack"
	hosts := fx.do(http.MethodGet, component.ServiceEgressHostsPath, component.TurnHeader, tr, nil)
	facts := fx.do(http.MethodGet, component.ServiceFactsPath, component.TurnHeader, tr, nil)
	if !strings.Contains(hosts.Body.String(), "example.com") || strings.Contains(hosts.Body.String(), fx.svc.SelfHost()) ||
		!strings.Contains(facts.Body.String(), "issues (as Release bot)") || strings.Contains(facts.Body.String(), "DRAFTING.md") {
		t.Fatalf("platform hosts = %s facts = %s", hosts.Body, facts.Body)
	}

	// A change as the worker asks the person who asked, and is made as the worker.
	out := fx.turnAs("maya", component.DriveOwn, component.EgressRequest{Method: "POST", URL: "https://example.com/api/issue", Body: []byte(`{}`)})
	if out.Status != http.StatusAccepted || !strings.Contains(out.Card.Text, "as Release bot") {
		t.Fatalf("a change = %d %+v", out.Status, out.Card)
	}
	q, _ := url.ParseQuery(out.Card.Actions[0].Query)
	rec := fx.page(false, http.MethodPost, "/pages/approve/decide", url.Values{"id": {q.Get("id")}, "decision": {"allow"}})
	if rec.Code != 200 || fx.last().method != "POST" || fx.last().header.Get("Authorization") != "Bearer WORKER-+30001" || !strings.Contains(auditOf(t, rec).Detail, "as worker release-bot") {
		t.Fatalf("allowed = %d %s %v", rec.Code, rec.Body, fx.last().header)
	}

	var mine, its []Call
	_ = json.Unmarshal(fx.store.get("members/maya/activity:home"), &mine)
	_ = json.Unmarshal(fx.store.get("orgs/home/wactivity:release-bot"), &its)
	if len(mine) == 0 || mine[0].As != "release-bot" || len(its) == 0 || its[0].Member != "maya" {
		t.Fatalf("records: maya %+v, worker %+v", mine, its)
	}
	page := fx.page(true, http.MethodGet, "/pages/workers/", nil).Body.String()
	if !strings.Contains(page, "Release bot") || !strings.Contains(page, "Recent calls") {
		t.Fatalf("the workers page = %s", page)
	}

	if rec := fx.page(true, http.MethodPost, "/pages/workers/remove", url.Values{"id": {"release-bot"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("remove = %d", rec.Code)
	}
	if out := fx.turnAs("jack", component.DrivePlatform, read); out.Status != http.StatusForbidden {
		t.Fatalf("after its removal = %d", out.Status)
	}
	if fx.store.get("orgs/home/wgrant:release-bot:issues") != nil {
		t.Fatal("its grant outlived it")
	}
}

// A person's room allowance is theirs, for their own agents as themselves: a
// change that acts as a digital worker (whose credentials are not the person's)
// still asks, however the room was allowed. (docs/prd/2026-10-28-held-change-
// continues.md in bnbloc)
func TestARoomAllowanceDoesNotCoverADigitalWorkersChange(t *testing.T) {
	fx, _ := workerFixture(t)
	_ = fx.page(true, http.MethodPost, "/pages/workers/save", url.Values{"id": {"release-bot"}, "displayName": {"Release bot"}, "account": {"+30001"},
		"owners": {"olga"}, "members": {"maya"}, "drive": {"own"}})
	_ = fx.page(true, http.MethodPost, "/pages/workers/connect", url.Values{"id": {"release-bot"}, "system": {"issues"}})
	if err := fx.svc.allowRoom(context.Background(), "maya", "home", "room-1", "issues"); err != nil {
		t.Fatal(err)
	}
	change := component.EgressRequest{Method: "POST", URL: "https://example.com/api/issue", Body: []byte(`{}`)}
	n := fx.count()
	out := fx.turnAs("maya", component.DriveOwn, change)
	if out.Status != http.StatusAccepted || out.Card == nil || fx.count() != n {
		t.Fatalf("a worker's change under the person's room allowance = %d %+v (sent %d); it must be held", out.Status, out.Card, fx.count()-n)
	}
}
