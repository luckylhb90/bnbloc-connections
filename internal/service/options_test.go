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

// A provider connector's member options: shown on the member's connected
// row as set (the default before they choose), changed by a click, and
// carried on every provider call; an option the connector does not declare
// is refused.
func TestProviderMemberOptions(t *testing.T) {
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
			a = provider.Answer{Header: map[string]string{"Authorization": "Basic x"}, ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()}
		}
		_ = json.NewEncoder(w).Encode(a)
	}))
	defer prov.Close()
	c := issues()
	c.Connect = connector.Connect{Kind: connector.KindProvider, Provider: &connector.Provider{URL: prov.URL + "/conn", App: "app-1",
		Options: []connector.ProviderOption{{Key: "autoRenew", Label: "Renew the token automatically", Default: true}}}}
	fx.addConnector(c)
	_ = fx.svc.P.PutJSON(context.Background(), platform.Org("home"), secretsPrefix+"issues", connector.Secrets{ProviderSecret: "prov-secret"})
	last := func() provider.Call {
		mu.Lock()
		defer mu.Unlock()
		return calls[len(calls)-1]
	}
	fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}})
	if got := last().Options["autoRenew"]; got != "true" {
		t.Fatalf("connect options = %v, want the default", last().Options)
	}
	if body := fx.page(false, http.MethodGet, "/pages/connections", nil).Body.String(); !strings.Contains(body, "Renew the token automatically: on") {
		t.Fatalf("the row does not show the option:\n%s", body)
	}
	fx.egress(component.DriveOwn, "GET", "https://example.com/api/page/1", "", nil)
	if got := last().Options["autoRenew"]; got != "true" {
		t.Fatalf("authorize options = %v", last().Options)
	}
	rec := fx.page(false, http.MethodPost, "/pages/connections/option", url.Values{"system": {"issues"}, "key": {"autoRenew"}, "value": {"false"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "saved") {
		t.Fatalf("set option = %d %s", rec.Code, loc)
	}
	if body := fx.page(false, http.MethodGet, "/pages/connections", nil).Body.String(); !strings.Contains(body, "Renew the token automatically: off") {
		t.Fatal("the row does not show the option off")
	}
	fx.svc.dropAuth(grantKey{"maya", "home", "issues"})
	fx.egress(component.DriveOwn, "GET", "https://example.com/api/page/1", "", nil)
	if got := last().Options["autoRenew"]; got != "false" {
		t.Fatalf("authorize after the change = %v", last().Options)
	}
	rec = fx.page(false, http.MethodPost, "/pages/connections/option", url.Values{"system": {"issues"}, "key": {"other"}, "value": {"true"}})
	if loc := rec.Header().Get("Location"); !strings.Contains(loc, "err=1") {
		t.Fatalf("an undeclared option = %s", loc)
	}

	bad := c
	bad.Connect.Provider = &connector.Provider{URL: prov.URL, Options: []connector.ProviderOption{{Key: "Auto Renew", Label: "x"}}}
	if err := bad.Validate(); err == nil {
		t.Fatal("an option key with a space is valid")
	}
}
