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
// or at the agent's next request; "Send it again" asks the provider
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
	if !strings.Contains(body, "waiting for your authorization") || !strings.Contains(body, `<meta name="live" content="issues:consent">`) || !strings.Contains(body, "Send it again") {
		t.Fatalf("the waiting row:\n%s", body)
	}
	if c := last(); !c.Check || grant() != nil {
		t.Fatalf("the waiting page asked %+v (want a check only), grant %s", c, grant())
	}
	mu.Lock()
	consented = true
	mu.Unlock()
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
