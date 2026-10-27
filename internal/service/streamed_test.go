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

// A streamed request (its body larger than an envelope, not here;
// docs/prd/2026-10-27-streamed-member-sends.md in bnbloc): the component
// says it takes them; on a server-sending connector, or where a body rule
// could take it, it is refused with 413 and nothing is sent; from members'
// computers it is decided on method and path: a change is held, allowed
// once for the same method and URL, and a refused sign-in is never sent a
// second time (a key that cannot be renewed asks to connect again).
func TestStreamedRequests(t *testing.T) {
	fx := newFixture(t)
	c := issues()
	c.Policy.Read = append(c.Policy.Read, connector.Rule{Methods: []string{"POST"}, Paths: []string{"/api/search"}, Body: `^\{"query"`})
	fx.addConnector(c)
	_ = fx.svc.saveGrant(context.Background(), "maya", "home", Grant{Connector: "issues", Reach: connector.Read, APIKey: "KEY-9"})
	egress := func(in component.EgressRequest) component.EgressResponse {
		t.Helper()
		raw, _ := json.Marshal(in)
		var out component.EgressResponse
		_ = json.Unmarshal(fx.do(http.MethodPost, component.ServiceEgressRequestPath, component.TurnHeader, turn(component.DriveOwn), raw).Body.Bytes(), &out)
		return out
	}
	var hosts component.EgressHosts
	_ = json.Unmarshal(fx.do(http.MethodGet, component.ServiceEgressHostsPath, component.TurnHeader, turn(component.DriveOwn), nil).Body.Bytes(), &hosts)
	if !hosts.Streams {
		t.Fatalf("hosts = %+v, want streams", hosts)
	}

	push := component.EgressRequest{Method: "POST", URL: "https://example.com/api/repo.git/git-receive-pack", Streamed: true}
	if out := egress(push); out.Status != http.StatusRequestEntityTooLarge || !strings.Contains(string(out.Body), "send from members' computers") || fx.count() != 0 {
		t.Fatalf("server connector = %d %s (calls %d)", out.Status, out.Body, fx.count())
	}

	c.SendFrom = connector.SendMember
	fx.addConnector(c)
	if out := egress(component.EgressRequest{Method: "POST", URL: "https://example.com/api/search", Streamed: true}); out.Status != http.StatusRequestEntityTooLarge || !strings.Contains(string(out.Body), "depends on its body") {
		t.Fatalf("a body rule's path = %d %s", out.Status, out.Body)
	}
	if out := egress(component.EgressRequest{Method: "GET", URL: "https://example.com/api/repo.git/info/refs", Streamed: true}); out.Send == nil {
		t.Fatalf("a streamed read = %+v, want sent", out)
	}

	out := egress(push)
	if out.Status != http.StatusAccepted || out.Card == nil {
		t.Fatalf("a streamed change = %+v, want held", out)
	}
	q, _ := url.ParseQuery(out.Card.Actions[0].Query)
	if rec := fx.page(false, http.MethodPost, "/pages/approve/decide", url.Values{"id": {q.Get("id")}, "decision": {"allow"}}); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Allowed") {
		t.Fatalf("allow = %d %s", rec.Code, rec.Body)
	}
	if out := egress(push); out.Send == nil || out.Send.Header["Authorization"][0] != "Bearer KEY-9" {
		t.Fatalf("the allowed push = %+v, want sent", out)
	}
	if out := egress(push); out.Status != http.StatusAccepted {
		t.Fatalf("an allowance is spent once: %+v", out)
	}

	read := component.EgressRequest{Method: "GET", URL: "https://example.com/api/big", Streamed: true, Report: &component.EgressReport{Attempt: 1, Status: http.StatusUnauthorized}}
	if out := egress(read); out.Send != nil || out.Status != http.StatusForbidden || out.Card == nil {
		t.Fatalf("a refused sign-in of a streamed request = %+v, want no second send and a connect card", out)
	}
	if fx.count() != 0 {
		t.Fatalf("the component sent %d requests itself", fx.count())
	}
}
