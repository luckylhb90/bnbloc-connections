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

// A consent given in the browser: Connect opens the provider's consent page
// (no chat card), the page waits and asks the provider only to check, and
// the connection completes on its own once the consent arrived, on the page
// or at the agent's next request; "Send it to me in chat again" asks the provider
// to prompt through its own channel.
func TestConsentInTheBrowser(t *testing.T) {
	fx := newFixture(t)
	var mu sync.Mutex
	consented := false
	var calls []provider.Call
	const page = "https://sso.example.com/ui/login/consent?app=app-1"
	prov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var c provider.Call
		_ = json.Unmarshal(body, &c)
		mu.Lock()
		calls = append(calls, c)
		ok := consented
		mu.Unlock()
		a := provider.Answer{Status: provider.Pending, Open: page}
		switch {
		case r.URL.Path == "/conn/connect" && ok:
			a = provider.Answer{Status: provider.Connected, Grant: "g1"}
		case r.URL.Path == "/conn/authorize":
			a = provider.Answer{Header: map[string]string{"Authorization": "Bearer x"}, ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()}
		}
		_ = json.NewEncoder(w).Encode(a)
	}))
	defer prov.Close()
	c := issues()
	c.Connect = connector.Connect{Kind: connector.KindProvider, Provider: &connector.Provider{URL: prov.URL + "/conn", App: "app-1"}}
	fx.addConnector(c)
	_ = fx.svc.P.PutJSON(context.Background(), platform.Org("home"), secretsPrefix+"issues", connector.Secrets{ProviderSecret: "prov-secret"})
	last := func() provider.Call { mu.Lock(); defer mu.Unlock(); return calls[len(calls)-1] }
	grant := func() []byte { return fx.store.get("members/maya/grant:home:issues") }

	rec := fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != page || last().Notify {
		t.Fatalf("connect = %d %s (notify %v), want the consent page", rec.Code, rec.Header().Get("Location"), last().Notify)
	}
	body := fx.page(false, http.MethodGet, "/pages/connections", nil).Body.String()
	if !strings.Contains(body, "waiting for your authorization") || !strings.Contains(body, `<meta name="live" content="issues:consent">`) || !strings.Contains(body, "Send it to me in chat again") {
		t.Fatalf("the waiting row:\n%s", body)
	}
	if c := last(); !c.Check || grant() != nil {
		t.Fatalf("the waiting page asked %+v (want a check only), grant %s", c, grant())
	}
	// The page's hidden follower answers what it waits for now.
	if live := fx.page(false, http.MethodGet, "/pages/connections?live=issues:consent", nil).Body.String(); !strings.Contains(live, `if ("issues:consent" !== "issues:consent")`) {
		t.Fatalf("the follower while waiting:\n%s", live)
	}
	mu.Lock()
	consented = true
	mu.Unlock()
	if live := fx.page(false, http.MethodGet, "/pages/connections?live=issues:consent", nil).Body.String(); !strings.Contains(live, `if ("" !== "issues:consent")`) || grant() == nil {
		t.Fatalf("the follower after the consent:\n%s", live)
	}
	if body := fx.page(false, http.MethodGet, "/pages/connections", nil).Body.String(); strings.Contains(body, "waiting for your authorization") || grant() == nil {
		t.Fatalf("the consent did not complete the connection on the page")
	}

	// The agent's request completes a waiting connection.
	fx.page(false, http.MethodPost, "/pages/connections/disconnect", url.Values{"system": {"issues"}})
	mu.Lock()
	consented = false
	mu.Unlock()
	fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}})
	mu.Lock()
	consented = true
	mu.Unlock()
	if out, _ := fx.egress(component.DriveOwn, "GET", "https://example.com/api/page/1", "", nil); out.Status != 200 || grant() == nil {
		t.Fatalf("the agent's request = %d %s, want it to complete the connection", out.Status, out.Body)
	}

	fx.page(false, http.MethodPost, "/pages/connections/disconnect", url.Values{"system": {"issues"}})
	mu.Lock()
	consented = false
	mu.Unlock()
	rec = fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}, "notify": {"1"}})
	if !last().Notify || rec.Header().Get("Location") == page {
		t.Fatalf("send in chat = notify %v, location %s", last().Notify, rec.Header().Get("Location"))
	}
}

// Where a member may be sent to consent: an https page (a new tab) or an
// app link (the app opens; the page stays); never a script or a browser
// internal address.
func TestOpenable(t *testing.T) {
	for open, want := range map[string][2]bool{
		"https://sso.example.com/consent?x=1":     {true, false},
		"chatapp://webview?url=https%3A%2F%2Fx.y": {true, true},
		"javascript:alert(1)":                     {false, false},
		"data:text/html,x":                        {false, false},
		"http://sso.example.com/consent":          {false, false},
		"file:///etc/passwd":                      {false, false},
	} {
		if ok, app := openable(open); ok != want[0] || app != want[1] {
			t.Errorf("openable(%q) = %v %v, want %v", open, ok, app, want)
		}
	}
}

// A provider connector names the browsers its consent page works in
// (provider.openIn): the Connect form carries it for the page's script, and
// a pattern that is not a regular expression is refused.
func TestProviderOpenIn(t *testing.T) {
	fx := newFixture(t)
	c := issues()
	c.Connect = connector.Connect{Kind: connector.KindProvider, Provider: &connector.Provider{URL: "https://provider.example.com/conn", App: "app-1", OpenIn: `ChatApp/\d`}}
	fx.addConnector(c)
	body := fx.page(false, http.MethodGet, "/pages/connections", nil).Body.String()
	if !strings.Contains(body, `data-open-in="ChatApp/\d"`) || !strings.Contains(body, `name="notify" value=""`) {
		t.Fatalf("the Connect form:\n%s", body)
	}
	c.Connect.Provider.OpenIn = "("
	if err := c.Validate(); err == nil {
		t.Fatal("a broken openIn pattern is valid")
	}
	c.Connect.Provider.OpenIn, c.Connect.Provider.OpenWith = "", []string{"hostBridge", "other_bridge"}
	fx.addConnector(c)
	if body := fx.page(false, http.MethodGet, "/pages/connections", nil).Body.String(); !strings.Contains(body, `data-open-with="hostBridge other_bridge"`) {
		t.Fatalf("the Connect form without openWith:\n%s", body)
	}
	c.Connect.Provider.OpenWith = []string{"alert(1)"}
	if err := c.Validate(); err == nil {
		t.Fatal("an openWith that is not a name is valid")
	}
}
