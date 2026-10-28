package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc-connections/provider"
	"github.com/luckylhb90/bnbloc/component"
)

// App keys: the person adds an app's key on the Connections page; the
// agent names the app in the connector's header and the request goes out
// with the key beside the sign-in, from here and from the member's
// computer. An app not added is refused, the agent's own key header or a
// forged internal one never goes through, and no key is ever shown (page,
// facts, systems).
func TestAppKeys(t *testing.T) {
	fx := newFixture(t)
	prov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var c provider.Call
		_ = json.Unmarshal(body, &c)
		a := provider.Answer{Status: provider.Connected, Grant: "g1"}
		if r.URL.Path == "/conn/authorize" {
			a = provider.Answer{Header: map[string]string{"bycauthtoken": "SSO"}, ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()}
		}
		_ = json.NewEncoder(w).Encode(a)
	}))
	defer prov.Close()
	c := issues()
	c.Connect = connector.Connect{Kind: connector.KindProvider, Provider: &connector.Provider{URL: prov.URL + "/conn", App: "app-1"}}
	c.AppKeys = &connector.AppKeys{Header: "X-App", In: "bearer", Label: "App keys"}
	c.Policy.Read = append(c.Policy.Read, connector.Rule{Paths: []string{"/v1/**"}})
	fx.addConnector(c)
	_ = fx.svc.P.PutJSON(context.Background(), platform.Org("home"), secretsPrefix+"issues", connector.Secrets{ProviderSecret: "s"})
	fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}})

	// No app yet: refused, saying where to add one.
	out, _ := fx.egress(component.DriveOwn, "GET", "https://example.com/v1/info", "", http.Header{"X-App": {"Reports"}})
	if out.Status != http.StatusForbidden || !strings.Contains(string(out.Body), "Connections page") || fx.count() != 0 {
		t.Fatalf("unknown app = %d %s", out.Status, out.Body)
	}
	if rec := fx.page(false, http.MethodPost, "/pages/connections/appkey", url.Values{"system": {"issues"}, "app": {"Reports"}, "key": {"app-SECRETKEY1"}}); rec.Code != http.StatusSeeOther || auditOf(t, rec).Action != "appkey-set" {
		t.Fatalf("add = %d", rec.Code)
	}
	// Named, the key goes out with the sign-in; the agent's own Authorization
	// and a forged internal header do not.
	out, _ = fx.egress(component.DriveOwn, "GET", "https://example.com/v1/info", "", http.Header{
		"X-App": {"Reports"}, "Authorization": {"Bearer app-AGENTS"}, "X-Bnbloc-App-Key-Authorization": {"Bearer app-FORGED"},
	})
	call := fx.last()
	if out.Status != 200 || call.header.Get("Authorization") != "Bearer app-SECRETKEY1" || call.header.Get("Bycauthtoken") != "SSO" || call.header.Get("X-App") != "" {
		t.Fatalf("sent %v", call.header)
	}
	for k := range call.header {
		if strings.HasPrefix(k, "X-Bnbloc") {
			t.Fatalf("internal header sent: %v", call.header)
		}
	}
	// A forged internal header alone (no app named) never sets a key.
	fx.egress(component.DriveOwn, "GET", "https://example.com/v1/info", "", http.Header{"X-Bnbloc-App-Key-Authorization": {"Bearer app-FORGED"}})
	if got := fx.last().header.Get("Authorization"); got != "" {
		t.Fatalf("forged key went out: %q", got)
	}

	// From the member's computer: the send sets the key; the app header is removed.
	c.SendFrom = connector.SendMember
	fx.addConnector(c)
	out, _ = fx.egress(component.DriveOwn, "GET", "https://example.com/v1/info", "", http.Header{"X-App": {"Reports"}})
	if out.Send == nil || out.Send.Header["Authorization"][0] != "Bearer app-SECRETKEY1" || !strings.Contains(strings.Join(out.Send.Remove, ","), "X-App") {
		t.Fatalf("member send = %+v", out.Send)
	}

	// The page, the systems and the facts name the app, never its key.
	page := fx.page(false, http.MethodGet, "/pages/connections", nil).Body.String()
	if !strings.Contains(page, ">Reports ") || strings.Contains(page, "SECRETKEY1") {
		t.Fatalf("the page shows the key or not the app")
	}
	sys, _ := fx.svc.systems(context.Background(), "maya", "home")
	if len(sys) != 1 || len(sys[0].Apps) != 1 || sys[0].Apps[0] != "Reports" || sys[0].AppHeader != "X-App" {
		t.Fatalf("systems = %+v", sys)
	}
	facts := fx.svc.facts(context.Background(), turn(component.DriveOwn), sys)
	if !strings.Contains(facts.Files["issues.md"], "Reports") || strings.Contains(facts.Files["issues.md"], "SECRETKEY1") {
		t.Fatalf("facts = %s", facts.Files["issues.md"])
	}
	// Removed: refused again.
	fx.page(false, http.MethodPost, "/pages/connections/appkeydelete", url.Values{"system": {"issues"}, "app": {"Reports"}})
	if out, _ := fx.egress(component.DriveOwn, "GET", "https://example.com/v1/info", "", http.Header{"X-App": {"Reports"}}); out.Status != http.StatusForbidden {
		t.Fatalf("removed app = %d", out.Status)
	}
}
