package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc-connections/provider"
	"github.com/luckylhb90/bnbloc/component"
)

// A provider whose sign-in ends on a system only members' computers reach
// (docs/prd/2026-10-28-member-held-sessions.md in bnbloc): authorize asks
// for sign-in steps; the agent's request is answered with a Send of those
// steps (StepsOnly, a fresh session named for the member); with their
// report, authorize again with SignedIn makes the headers, and the request
// goes out with the held session. A connector sending from the server
// cannot use one (an admin's item).
func TestSignInOnTheMembersComputer(t *testing.T) {
	fx := newFixture(t)
	var mu sync.Mutex
	var calls []provider.Call
	prov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var c provider.Call
		_ = json.Unmarshal(body, &c)
		mu.Lock()
		calls = append(calls, c)
		mu.Unlock()
		a := provider.Answer{Status: provider.Connected, Grant: "g1"}
		if r.URL.Path == "/conn/authorize" {
			switch {
			case len(c.SignedIn) == 2 && strings.Contains(string(c.SignedIn[1].Body), `"T1"`):
				a = provider.Answer{Session: true, Header: map[string]string{"X-CSRF-TOKEN": "T1"}, ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()}
			default:
				a = provider.Answer{SignIn: []provider.Step{{URL: "https://example.com/signin?code=C"}, {URL: "https://example.com/config"}}}
			}
		}
		_ = json.NewEncoder(w).Encode(a)
	}))
	defer prov.Close()
	c := issues()
	c.SendFrom = connector.SendMember
	c.Connect = connector.Connect{Kind: connector.KindProvider, Provider: &connector.Provider{URL: prov.URL + "/conn", App: "app-1"}}
	fx.addConnector(c)
	_ = fx.svc.P.PutJSON(context.Background(), platform.Org("home"), secretsPrefix+"issues", connector.Secrets{ProviderSecret: "s"})
	fx.page(false, http.MethodPost, "/pages/connections/connect", map[string][]string{"system": {"issues"}})

	in := component.EgressRequest{Method: "GET", URL: "https://example.com/api/apps"}
	out, _ := fx.egress(component.DriveOwn, in.Method, in.URL, "", nil)
	if out.Send == nil || !out.Send.StepsOnly || !out.Send.EndSession || len(out.Send.Steps) != 2 || out.Send.Session != "connections:maya" || out.Send.Steps[0].Method != "GET" {
		t.Fatalf("first answer = %+v", out.Send)
	}
	in.Report = &component.EgressReport{Steps: []component.EgressStepReport{
		{URL: "https://example.com/signin?code=C", Status: 303},
		{URL: "https://example.com/config", Status: 200, Body: []byte(`csrf="T1"`)},
	}}
	out = fx.egressIn("room-1", in)
	if out.Send == nil || out.Send.StepsOnly || out.Send.Session != "connections:maya" || out.Send.Header["X-Csrf-Token"][0] != "T1" {
		t.Fatalf("after the sign-in = %+v", out.Send)
	}
	if last := calls[len(calls)-1]; len(last.SignedIn) != 2 || last.SignedIn[1].Status != 200 {
		t.Fatalf("authorize was not given the sign-in: %+v", last)
	}
	in.Report = &component.EgressReport{Attempt: 1, Status: 200, Body: []byte(`{"code":0}`)}
	if out := fx.egressIn("room-1", in); !out.Accept {
		t.Fatalf("the system's answer = %+v", out)
	}
	// The next request carries the cached headers and the session at once.
	in.Report = nil
	if out := fx.egressIn("room-1", in); out.Send == nil || out.Send.StepsOnly || out.Send.Session == "" {
		t.Fatalf("a later request = %+v", out.Send)
	}

	// A connector sending from the server cannot hold a member's session.
	c.SendFrom = ""
	fx.addConnector(c)
	fx.svc.dropAuth(grantKey{"maya", "home", "issues"})
	if out, _ := fx.egress(component.DriveOwn, "GET", "https://example.com/api/apps", "", nil); out.Status != http.StatusForbidden || !strings.Contains(string(out.Body), "members' computers") {
		t.Fatalf("server connector = %d %s", out.Status, out.Body)
	}
}
