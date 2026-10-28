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

// A provider that signs each request (SignEach): every request, from here
// or from the member's computer, carries the signature the provider made
// over its exact method, path and query, and the provider is told whose
// request it signs. A connector claiming only some paths says so in its
// hosts answer, and a path outside them is never authenticated here.
func TestProviderSignsEachRequest(t *testing.T) {
	fx := newFixture(t)
	var mu sync.Mutex
	var signed []provider.SignRequest
	prov := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		switch r.URL.Path {
		case "/conn/sign":
			var sr provider.SignRequest
			_ = json.Unmarshal(body, &sr)
			mu.Lock()
			signed = append(signed, sr)
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(provider.Signed{Header: map[string]string{"X-Signature-signature": "SIG:" + sr.Method + " " + sr.Path + "?" + sr.Query}})
		case "/conn/authorize":
			_ = json.NewEncoder(w).Encode(provider.Answer{Header: map[string]string{"token": "SSO"}, SignEach: true, ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()})
		default:
			_ = json.NewEncoder(w).Encode(provider.Answer{Status: provider.Connected, Grant: "g1"})
		}
	}))
	defer prov.Close()
	c := issues()
	c.Connect = connector.Connect{Kind: connector.KindProvider, Provider: &connector.Provider{URL: prov.URL + "/conn", App: "app-1"}}
	c.Policy.Read = append(c.Policy.Read, connector.Rule{Paths: []string{"/v1/meeting/**"}})
	fx.addConnector(c)
	_ = fx.svc.P.PutJSON(context.Background(), platform.Org("home"), secretsPrefix+"issues", connector.Secrets{ProviderSecret: "s"})
	fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}})

	out, _ := fx.egress(component.DriveOwn, "GET", "https://example.com/v1/meeting/records?limit=5", "", http.Header{"X-Signature-signature": {"AGENT"}})
	call := fx.last()
	if out.Status != 200 || call.header.Get("X-Signature-signature") != "SIG:GET /v1/meeting/records?limit=5" || call.header.Get("Token") != "SSO" {
		t.Fatalf("sent %v", call.header)
	}
	if len(signed) != 1 || signed[0].Call.Member != "maya" || signed[0].Call.Grant != "g1" {
		t.Fatalf("signed %+v", signed)
	}

	// From the member's computer, on some paths only.
	c.SendFrom, c.Paths = connector.SendMember, []string{"/v1/meeting", "/v1/calendar"}
	fx.addConnector(c)
	out, _ = fx.egress(component.DriveOwn, "GET", "https://example.com/v1/meeting/records?limit=5", "", http.Header{"X-Signature-signature": {"AGENT"}})
	if out.Send == nil || out.Send.Header["X-Signature-Signature"][0] != "SIG:GET /v1/meeting/records?limit=5" || !strings.Contains(strings.Join(out.Send.Remove, ","), "X-Signature-signature") {
		t.Fatalf("member send = %+v", out.Send)
	}
	rec := fx.do(http.MethodGet, component.ServiceEgressHostsPath, component.TurnHeader, turn(component.DriveOwn), nil)
	var hosts component.EgressHosts
	_ = json.Unmarshal(rec.Body.Bytes(), &hosts)
	if strings.Join(hosts.Paths["example.com"], ",") != "/v1/meeting,/v1/calendar" {
		t.Fatalf("hosts = %+v", hosts)
	}
	if out, _ := fx.egress(component.DriveOwn, "GET", "https://example.com/v1/messages", "", nil); out.Status != http.StatusForbidden || !strings.Contains(string(out.Body), "update the bnbloc desktop") {
		t.Fatalf("an unclaimed path = %d %s", out.Status, out.Body)
	}
	// A connector sending from the service cannot claim only some paths.
	c.SendFrom = ""
	if c.Validate() == nil {
		t.Fatal("paths on a server connector passes")
	}
}
