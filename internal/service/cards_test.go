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

func (fx *fixture) card(a component.CardAction) component.CardReply {
	fx.t.Helper()
	if a.Kind != component.CardCall {
		fx.t.Fatalf("action %+v is not a call", a)
	}
	rec := fx.do(http.MethodPost, component.ServiceCardsPrefix+a.Page+"?"+a.Query, component.MemberHeader, member(false), nil)
	var r component.CardReply
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || rec.Code != http.StatusOK {
		fx.t.Fatalf("card %s = %d %s", a.Page, rec.Code, rec.Body)
	}
	return r
}

// A held change is allowed or refused from its card, in place: the change
// is made (the card says the system's answer and is done); a second click
// finds it decided. An OAuth system's Connect opens the sign-in from the
// card; one connected by a key still opens the page.
func TestCardsActInPlace(t *testing.T) {
	fx := newFixture(t)
	fx.addConnector(issues())
	_ = fx.svc.saveGrant(context.Background(), "maya", "home", Grant{Connector: "issues", Reach: connector.Read, APIKey: "k"})
	out := fx.egressIn("room-1", component.EgressRequest{Method: "POST", URL: "https://example.com/api/issue", Body: []byte(`{"t":1}`)})
	if len(out.Card.Actions) != 3 || out.Card.Actions[0].Label != "Allow" || out.Card.Actions[2].Kind != component.CardOpen {
		t.Fatalf("held card = %+v", out.Card)
	}
	n := fx.count()
	r := fx.card(out.Card.Actions[0])
	if !r.Done || !strings.Contains(r.Text, "Done") || fx.count() != n+1 || fx.last().method != "POST" {
		t.Fatalf("allow = %+v (sent %d)", r, fx.count()-n)
	}
	if r := fx.card(out.Card.Actions[1]); !r.Done || !strings.Contains(r.Text, "no longer waiting") {
		t.Fatalf("after it was decided = %+v", r)
	}
	out = fx.egressIn("room-1", component.EgressRequest{Method: "POST", URL: "https://example.com/api/issue", Body: []byte(`{"t":2}`)})
	n = fx.count()
	if r := fx.card(out.Card.Actions[1]); !r.Done || !strings.Contains(r.Text, "Not made") || fx.count() != n {
		t.Fatalf("deny = %+v", r)
	}

	c := issues()
	c.Name, c.DisplayName, c.Hosts = "cal", "Calendar", []string{"cal.example.com"}
	c.Connect = connector.Connect{Kind: connector.KindOAuth2, OAuth2: &connector.OAuth2{
		AuthorizationEndpoint: "https://example.com/oauth/authorize", TokenEndpoint: "https://example.com/oauth/token",
		ClientID: "client-1", Scopes: connector.Scopes{Read: []string{"read"}},
	}}
	fx.addConnector(c)
	refused := fx.egressIn("room-1", component.EgressRequest{Method: "GET", URL: "https://cal.example.com/api/x"})
	r = fx.card(refused.Card.Actions[0])
	open, _ := url.Parse(r.Open)
	if r.Done || open.Path != "/oauth/authorize" || open.Query().Get("client_id") != "client-1" {
		t.Fatalf("connect in place = %+v", r)
	}
	_ = fx.svc.deleteGrant(context.Background(), "maya", "home", "issues")
	keyed := fx.egressIn("room-1", component.EgressRequest{Method: "GET", URL: "https://example.com/api/issue/1"})
	if keyed.Card.Actions[0].Kind != component.CardOpen {
		t.Fatalf("a key's connect = %+v", keyed.Card.Actions[0])
	}
}
