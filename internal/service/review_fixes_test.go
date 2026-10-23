package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc/component"
)

// egressIn sends one egress request for maya's own turn in room.
func (fx *fixture) egressIn(room string, in component.EgressRequest) component.EgressResponse {
	fx.t.Helper()
	tr := turn(component.DriveOwn)
	tr.Room = room
	raw, _ := json.Marshal(in)
	rec := fx.do(http.MethodPost, component.ServiceEgressRequestPath, component.TurnHeader, tr, raw)
	var out component.EgressResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

// A path a server may read otherwise than the policy (.., encoded) is
// refused before the policy, and nothing is sent.
func TestAmbiguousPathsAreRefused(t *testing.T) {
	fx := newFixture(t)
	fx.addConnector(issues())
	_ = fx.svc.saveGrant(context.Background(), "maya", "home", Grant{Connector: "issues", Reach: connector.Read, APIKey: "k"})
	for _, p := range []string{"/api/%2e%2e/admin/users", "/api/../admin", "/api/x%2fy", "/api/..;/admin"} {
		out := fx.egressIn("room-1", component.EgressRequest{Method: "GET", URL: "https://example.com" + p})
		if out.Status != http.StatusBadRequest || !strings.Contains(string(out.Body), "encoded slash") {
			t.Errorf("%s = %d %s", p, out.Status, out.Body)
		}
	}
	if fx.count() != 0 {
		t.Fatalf("sent %d", fx.count())
	}
}

// Concurrent requests with no access token in memory refresh the grant
// once: a provider that detects refresh token reuse never sees one.
func TestConcurrentRequestsRefreshOnce(t *testing.T) {
	fx := newFixture(t)
	c := issues()
	c.Connect = connector.Connect{Kind: connector.KindOAuth2, OAuth2: &connector.OAuth2{
		AuthorizationEndpoint: "https://example.com/oauth/authorize", TokenEndpoint: "https://example.com/oauth/token",
		ClientID: "client-1", Scopes: connector.Scopes{Read: []string{"read"}},
	}}
	fx.addConnector(c)
	_ = fx.svc.saveGrant(context.Background(), "maya", "home", Grant{Connector: "issues", Reach: connector.Read, RefreshToken: "refresh-1"})
	var wg sync.WaitGroup
	statuses := make([]int, 6)
	for i := range statuses {
		wg.Add(1)
		go func() {
			defer wg.Done()
			statuses[i] = fx.egressIn("room-1", component.EgressRequest{Method: "GET", URL: "https://example.com/api/issue/1"}).Status
		}()
	}
	wg.Wait()
	refreshes := 0
	fx.mu.Lock()
	for _, call := range fx.calls {
		if call.path == "/oauth/token" {
			refreshes++
		}
	}
	fx.mu.Unlock()
	for _, st := range statuses {
		if st != 200 {
			t.Fatalf("statuses = %v", statuses)
		}
	}
	if refreshes != 1 {
		t.Fatalf("refreshed %d times", refreshes)
	}
}

// An allowed change sent from the member's computer is allowed in its own
// room only; a disconnect drops the member's waiting changes and
// allowances for that system; the Connections page lists what waits and
// decides it under its own address.
func TestWaitingChangesAreTheRoomsAndTheConnections(t *testing.T) {
	fx := newFixture(t)
	c := issues()
	c.SendFrom = connector.SendMember
	fx.addConnector(c)
	_ = fx.svc.saveGrant(context.Background(), "maya", "home", Grant{Connector: "issues", Reach: connector.Read, APIKey: "K"})
	write := component.EgressRequest{Method: "POST", URL: "https://example.com/api/issue", Body: []byte(`{"t":1}`)}
	out := fx.egressIn("room-1", write)
	q, _ := url.ParseQuery(out.Card.Actions[0].Query)
	page := fx.page(false, http.MethodGet, "/pages/connections/", nil).Body.String()
	if !strings.Contains(page, "Changes waiting for you") || !strings.Contains(page, "change?id="+q.Get("id")) {
		t.Fatalf("the page = %s", page)
	}
	if rec := fx.page(false, http.MethodGet, "/pages/connections/change?id="+q.Get("id"), nil); !strings.Contains(rec.Body.String(), "POST /api/issue") {
		t.Fatalf("the change from the page = %s", rec.Body)
	}
	if rec := fx.page(false, http.MethodPost, "/pages/connections/decide", url.Values{"id": {q.Get("id")}, "decision": {"allow"}}); !strings.Contains(rec.Body.String(), "Allowed") {
		t.Fatalf("decide from the page = %s", rec.Body)
	}
	if out := fx.egressIn("room-2", write); out.Status != http.StatusAccepted {
		t.Fatalf("the allowance in another room = %+v, want held", out)
	}
	if out := fx.egressIn("room-1", write); out.Send == nil {
		t.Fatalf("the allowance in its room = %+v, want sent", out)
	}
	_ = fx.egressIn("room-1", write) // held again
	if rec := fx.page(false, http.MethodPost, "/pages/connections/disconnect", url.Values{"system": {"issues"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("disconnect = %d", rec.Code)
	}
	if left := fx.svc.waiting(context.Background(), "maya", "home"); len(left) != 0 {
		t.Fatalf("waiting after a disconnect: %+v", left)
	}
}

// Allowing a change on an OAuth sign-in that granted reading only signs in
// again for the write scopes, the change kept waiting, and the sign-in
// says to allow it again.
func TestAllowingAChangeAsksTheWriteScopes(t *testing.T) {
	fx := newFixture(t)
	c := issues()
	c.Connect = connector.Connect{Kind: connector.KindOAuth2, OAuth2: &connector.OAuth2{
		AuthorizationEndpoint: "https://example.com/oauth/authorize", TokenEndpoint: "https://example.com/oauth/token",
		ClientID: "client-1", Scopes: connector.Scopes{Read: []string{"read"}, Write: []string{"write"}},
	}}
	fx.addConnector(c)
	_ = fx.svc.saveGrant(context.Background(), "maya", "home", Grant{Connector: "issues", Reach: connector.Read, RefreshToken: "refresh-1"})
	out := fx.egressIn("room-1", component.EgressRequest{Method: "POST", URL: "https://example.com/api/issue", Body: []byte(`{}`)})
	q, _ := url.ParseQuery(out.Card.Actions[0].Query)
	rec := fx.page(false, http.MethodPost, "/pages/approve/decide", url.Values{"id": {q.Get("id")}, "decision": {"allow"}})
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusSeeOther || loc.Path != "/oauth/authorize" || loc.Query().Get("scope") != "read write" {
		t.Fatalf("allow = %d %s", rec.Code, loc)
	}
	if _, ok := fx.svc.held(context.Background(), "maya", q.Get("id")); !ok {
		t.Fatal("the change stopped waiting")
	}
	done := fx.do(http.MethodGet, "/callbacks/oauth?code=CODE-1&state="+url.QueryEscape(loc.Query().Get("state")), component.CallbackHeader, component.Callback{}, nil)
	if !strings.Contains(done.Body.String(), "allow it") {
		t.Fatalf("callback = %s", done.Body)
	}
	g, _, _ := fx.svc.grant(context.Background(), "maya", "home", "issues")
	if !g.canChange(c) || g.Reach != connector.Read {
		t.Fatalf("grant = %+v", g)
	}
}

// A key exchanged for a short-lived token: the CLI's own exchange step is
// answered here, the system gets the exchanged token (once, then from
// memory), and a refusal exchanges again.
func TestKeyExchangeAndAnswers(t *testing.T) {
	fx := newFixture(t)
	exchanges := 0
	fx.answer = func(r *http.Request) (int, string) {
		if r.URL.Path == "/account/v1/personal_token/exchange" {
			exchanges++
			return 200, `{"data":{"token":"jwt-` + string(rune('0'+exchanges)) + `","expires_in":600}}`
		}
		if r.Header.Get("Authorization") == "Bearer jwt-1" && exchanges == 1 && r.URL.Path == "/api/stale" {
			return 401, `{}`
		}
		return 200, `{"ok":true}`
	}
	c := issues()
	c.Connect.APIKey = &connector.APIKey{In: "bearer", Exchange: &connector.Exchange{
		URL: "https://example.com/account/v1/personal_token/exchange", Body: map[string]string{"token": "{{key}}"}, Token: "data.token", ExpiresIn: "data.expires_in", In: "bearer",
	}}
	c.Answers = []connector.Answer{{Method: "POST", Path: "/account/v1/personal_token/exchange", Body: `{"data":{"token":"connected"}}`}}
	fx.addConnector(c)
	_ = fx.svc.saveGrant(context.Background(), "maya", "home", Grant{Connector: "issues", Reach: connector.Read, APIKey: "PAT-1"})
	out := fx.egressIn("room-1", component.EgressRequest{Method: "POST", URL: "https://example.com/account/v1/personal_token/exchange", Body: []byte(`{"token":"connected"}`)})
	if out.Status != 200 || string(out.Body) != `{"data":{"token":"connected"}}` || fx.count() != 0 {
		t.Fatalf("the CLI's exchange = %d %s (sent %d)", out.Status, out.Body, fx.count())
	}
	for i := 0; i < 2; i++ {
		if out := fx.egressIn("room-1", component.EgressRequest{Method: "GET", URL: "https://example.com/api/issue/1", Header: map[string][]string{"Authorization": {"Bearer connected"}}}); out.Status != 200 {
			t.Fatalf("a read = %+v", out)
		}
	}
	if exchanges != 1 || fx.last().header.Get("Authorization") != "Bearer jwt-1" {
		t.Fatalf("exchanges %d, sent %q", exchanges, fx.last().header.Get("Authorization"))
	}
	ex := fx.calls[0]
	if !strings.Contains(ex.body, `"token":"PAT-1"`) {
		t.Fatalf("the exchange sent %s", ex.body)
	}
	if out := fx.egressIn("room-1", component.EgressRequest{Method: "GET", URL: "https://example.com/api/stale"}); out.Status != 200 || exchanges != 2 {
		t.Fatalf("after a refusal = %d, exchanges %d", out.Status, exchanges)
	}
	c.SendFrom = connector.SendMember
	if err := c.Validate(); err == nil {
		t.Fatal("an exchanging connector sent from members' computers")
	}
}
