package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
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

const testSecret = "whsec_test"

// fakeStore is the platform's store: it checks every call's signature like
// the gateway does and keeps values by component, scope and key.
type fakeStore struct {
	mu   sync.Mutex
	vals map[string][]byte
}

func newFakeStore(t *testing.T) (*fakeStore, *httptest.Server) {
	st := &fakeStore{vals: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		pq := r.URL.EscapedPath()
		if r.URL.RawQuery != "" {
			pq += "?" + r.URL.RawQuery
		}
		if r.Header.Get(component.ComponentHeader) != "service/connections" ||
			component.Verify(r.Header.Get(component.SignatureHeader), testSecret, component.SignedRequest(r.Method, pq, "", body), time.Now(), time.Minute) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		key := strings.TrimPrefix(r.URL.Path, component.ComponentStorePath)
		st.mu.Lock()
		defer st.mu.Unlock()
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(key, "/"):
			keys := []string{}
			for k := range st.vals {
				if rest, ok := strings.CutPrefix(k, key); ok && !strings.Contains(rest, "/") {
					keys = append(keys, rest)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string][]string{"keys": keys})
		case r.Method == http.MethodGet:
			v, ok := st.vals[key]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write(v)
		case r.Method == http.MethodPut:
			st.vals[key] = body
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete:
			delete(st.vals, key)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(srv.Close)
	return st, srv
}

func (st *fakeStore) get(key string) []byte {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.vals[key]
}

// upstreamCall is one request a connected system received.
type upstreamCall struct {
	method, path, query string
	header              http.Header
	body                string
}

type fixture struct {
	t     *testing.T
	svc   *Service
	h     http.Handler
	store *fakeStore
	mu    sync.Mutex
	calls []upstreamCall
	// answer is what the system answers (status, body).
	answer func(r *http.Request) (int, string)
	idp    *httptest.Server
}

// newFixture: a service with one TLS system "example.com" (any name dials
// it) that records its requests.
func newFixture(t *testing.T) *fixture {
	fx := &fixture{t: t, answer: func(*http.Request) (int, string) { return 200, `{"ok":true}` }}
	store, storeSrv := newFakeStore(t)
	fx.store = store
	sys := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fx.mu.Lock()
		fx.calls = append(fx.calls, upstreamCall{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Clone(), string(body)})
		fx.mu.Unlock()
		if strings.HasPrefix(r.URL.Path, "/oauth/") {
			fx.idpAnswer(w, r, body)
			return
		}
		status, out := fx.answer(r)
		w.Header().Set("Set-Cookie", "session=upstream")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, out)
	}))
	t.Cleanup(sys.Close)
	addr := sys.Listener.Addr().String()
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
			DisableCompression: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	fx.svc = &Service{P: platform.New(storeSrv.URL, "connections", testSecret), Upstream: client}
	fx.h = fx.svc.Handler()
	return fx
}

func (fx *fixture) last() upstreamCall {
	fx.t.Helper()
	fx.mu.Lock()
	defer fx.mu.Unlock()
	if len(fx.calls) == 0 {
		fx.t.Fatal("the system received nothing")
	}
	return fx.calls[len(fx.calls)-1]
}

func (fx *fixture) count() int {
	fx.mu.Lock()
	defer fx.mu.Unlock()
	return len(fx.calls)
}

// addConnector stores an enabled connector for org "home".
func (fx *fixture) addConnector(c connector.Connector) {
	fx.t.Helper()
	c.Enabled = true
	if err := c.Validate(); err != nil {
		fx.t.Fatal(err)
	}
	if err := fx.svc.saveConnector(context.Background(), "home", c); err != nil {
		fx.t.Fatal(err)
	}
}

func issues() connector.Connector {
	return connector.Connector{
		Name: "issues", DisplayName: "Issues", Purpose: "Bugs and tasks", Hosts: []string{"example.com"},
		Connect: connector.Connect{Kind: connector.KindAPIKey, APIKey: &connector.APIKey{In: "bearer"}},
		Policy: connector.Policy{
			Read:  []connector.Rule{{Paths: []string{"/api/**"}}},
			Write: []connector.Rule{{Methods: []string{"POST", "DELETE"}, Paths: []string{"/api/**"}}},
		},
		CLIEnv: map[string]string{"ISSUES_TOKEN": "connected"},
		Guide:  "curl https://example.com/api/issue/1",
	}
}

func turn(drive string) component.Turn {
	return component.Turn{Org: "home", Room: "room-1", Job: "job-1", Requester: "maya", AgentOwner: "maya", Drive: drive, Origin: "https://bnbloc.example.com"}
}

// do sends one signed platform call to the service.
func (fx *fixture) do(method, path, identityHeader string, identity any, body []byte) *httptest.ResponseRecorder {
	fx.t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	id := ""
	if identity != nil {
		id = component.EncodeHeader(identity)
		req.Header.Set(identityHeader, id)
	}
	req.Header.Set(component.SignatureHeader, component.Sign(testSecret, time.Now(), component.SignedRequest(method, path, id, body)))
	rec := httptest.NewRecorder()
	fx.h.ServeHTTP(rec, req)
	return rec
}

func (fx *fixture) egress(drive, method, rawURL, body string, header http.Header) (component.EgressResponse, *httptest.ResponseRecorder) {
	fx.t.Helper()
	raw, _ := json.Marshal(component.EgressRequest{Method: method, URL: rawURL, Header: header, Body: []byte(body)})
	rec := fx.do(http.MethodPost, component.ServiceEgressRequestPath, component.TurnHeader, turn(drive), raw)
	if rec.Code != http.StatusOK {
		fx.t.Fatalf("egress = %d %s", rec.Code, rec.Body)
	}
	var out component.EgressResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		fx.t.Fatal(err)
	}
	return out, rec
}

func member(admin bool) component.Member {
	return component.Member{Subject: "maya", Org: "home", Admin: admin, PageURL: "https://bnbloc.example.com/v1/component-pages/T/", Origin: "https://bnbloc.example.com"}
}

func (fx *fixture) page(admin bool, method, path string, form url.Values) *httptest.ResponseRecorder {
	fx.t.Helper()
	return fx.do(method, path, component.MemberHeader, member(admin), []byte(form.Encode()))
}

func auditOf(t *testing.T, rec *httptest.ResponseRecorder) component.Audit {
	t.Helper()
	var a component.Audit
	_ = component.DecodeHeader(rec.Header().Get(component.AuditHeader), &a)
	return a
}

// Unsigned calls are refused; discover and the health probe are open.
func TestCallsMustBeSigned(t *testing.T) {
	fx := newFixture(t)
	rec := httptest.NewRecorder()
	fx.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, component.ServiceEgressHostsPath, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned = %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	fx.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("healthz = %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	fx.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, component.ServiceDiscoverPath, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), component.ServiceContractV1) {
		t.Fatalf("discover = %d %s", rec.Code, rec.Body)
	}
}

// The person's own agent gets the enabled systems' hosts, the component's
// own and the placeholders; any other drive gets none, and its requests are
// refused.
func TestHostsAndFactsOnlyForTheOwnDrive(t *testing.T) {
	fx := newFixture(t)
	fx.addConnector(issues())
	var hosts component.EgressHosts
	_ = json.Unmarshal(fx.do(http.MethodGet, component.ServiceEgressHostsPath, component.TurnHeader, turn(component.DriveOwn), nil).Body.Bytes(), &hosts)
	if strings.Join(hosts.Hosts, ",") != "connections.bnbloc,example.com" || hosts.Env["ISSUES_TOKEN"] != "connected" {
		t.Fatalf("hosts = %+v", hosts)
	}
	_ = json.Unmarshal(fx.do(http.MethodGet, component.ServiceEgressHostsPath, component.TurnHeader, turn(component.DriveBorrowed), nil).Body.Bytes(), &hosts)
	if len(hosts.Hosts) != 0 {
		t.Fatalf("borrowed hosts = %+v", hosts)
	}
	out, _ := fx.egress(component.DriveBorrowed, "GET", "https://example.com/api/issue/1", "", nil)
	if out.Status != http.StatusForbidden || fx.count() != 0 {
		t.Fatalf("borrowed request = %d (calls %d)", out.Status, fx.count())
	}
	var facts component.Facts
	_ = json.Unmarshal(fx.do(http.MethodGet, component.ServiceFactsPath, component.TurnHeader, turn(component.DriveOwn), nil).Body.Bytes(), &facts)
	if err := component.CheckFacts(facts); err != nil || !strings.Contains(facts.Line, "issues") || facts.Files["INDEX.md"] == "" || !strings.Contains(facts.Files["issues.md"], "curl") || facts.Files["DRAFTING.md"] == "" {
		t.Fatalf("facts = %+v, %v", facts, err)
	}
	var none component.Facts
	_ = json.Unmarshal(fx.do(http.MethodGet, component.ServiceFactsPath, component.TurnHeader, turn(component.DrivePlatform), nil).Body.Bytes(), &none)
	if none.Line != "" || len(none.Files) != 0 {
		t.Fatalf("platform facts = %+v", none)
	}
}

// Not connected: 403 and a card to connect, nothing sent. Connected with a
// key: the request goes out with the member's key in place of anything the
// agent sent, without the system's cookie back, and is recorded. A change
// is held (202 and a card); the member's Allow makes it.
func TestAPIKeyConnectionReadsAndHeldChanges(t *testing.T) {
	fx := newFixture(t)
	fx.addConnector(issues())
	out, rec := fx.egress(component.DriveOwn, "GET", "https://example.com/api/issue/1", "", nil)
	if out.Status != http.StatusForbidden || out.Card == nil || out.Card.Actions[0].Page != "connections" || fx.count() != 0 {
		t.Fatalf("not connected = %+v", out)
	}
	if a := auditOf(t, rec); a.Outcome != "deny" || !strings.Contains(a.Target, "issues GET /api/issue/1") {
		t.Fatalf("audit = %+v", a)
	}
	page := fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}, "reach": {"read"}, "key": {"KEY-123"}})
	if page.Code != http.StatusSeeOther || !strings.HasPrefix(page.Header().Get("Location"), member(false).PageURL) {
		t.Fatalf("connect = %d %v", page.Code, page.Header())
	}
	if raw := fx.store.get("members/maya/grant:home:issues"); !strings.Contains(string(raw), "KEY-123") {
		t.Fatalf("grant = %s", raw)
	}
	out, _ = fx.egress(component.DriveOwn, "GET", "https://example.com/api/issue/1?x=1", "", http.Header{"Authorization": {"Bearer agent-made-up"}, "Accept": {"application/json"}})
	call := fx.last()
	if out.Status != 200 || string(out.Body) != `{"ok":true}` || out.Header["Set-Cookie"] != nil ||
		call.header.Get("Authorization") != "Bearer KEY-123" || call.query != "x=1" || call.header.Get("Accept") != "application/json" {
		t.Fatalf("read = %+v call = %+v", out, call)
	}
	before := fx.count()
	out, _ = fx.egress(component.DriveOwn, "POST", "https://example.com/api/issue", `{"title":"Ship it"}`, nil)
	if out.Status != http.StatusAccepted || out.Card == nil || fx.count() != before {
		t.Fatalf("change = %+v (sent %d)", out, fx.count()-before)
	}
	q, _ := url.ParseQuery(out.Card.Actions[0].Query)
	review := fx.page(false, http.MethodGet, "/pages/approve/?id="+q.Get("id"), nil)
	if review.Code != 200 || !strings.Contains(review.Body.String(), "Ship it") {
		t.Fatalf("review = %d %s", review.Code, review.Body)
	}
	done := fx.page(false, http.MethodPost, "/pages/approve/decide", url.Values{"id": {q.Get("id")}, "decision": {"allow"}})
	if done.Code != 200 || fx.count() != before+1 || fx.last().body != `{"title":"Ship it"}` || fx.last().header.Get("Authorization") != "Bearer KEY-123" {
		t.Fatalf("allow = %d %s", done.Code, done.Body)
	}
	if again := fx.page(false, http.MethodPost, "/pages/approve/decide", url.Values{"id": {q.Get("id")}, "decision": {"allow"}}); fx.count() != before+1 {
		t.Fatalf("a decided change runs twice (%d)", again.Code)
	}
	var calls []Call
	_ = json.Unmarshal(fx.store.get("members/maya/activity:home"), &calls)
	if len(calls) != 3 || calls[2].Outcome != "allowed" || calls[1].Outcome != "held" {
		t.Fatalf("activity = %+v", calls)
	}
}

// A system that keeps refusing the member's credential asks them to connect
// again after one retry; the connector's expiredWhen counts as a refusal.
func TestRefusedCredentialAsksToReconnect(t *testing.T) {
	fx := newFixture(t)
	c := issues()
	c.ExpiredWhen = []connector.Expired{{Status: 200, BodyContains: "<form id=\"login\""}}
	fx.addConnector(c)
	_ = fx.svc.saveGrant(context.Background(), "maya", "home", Grant{Connector: "issues", Reach: connector.Read, APIKey: "OLD"})
	fx.answer = func(*http.Request) (int, string) { return 200, `<html><form id="login">` }
	out, _ := fx.egress(component.DriveOwn, "GET", "https://example.com/api/issue/1", "", nil)
	if out.Status != http.StatusForbidden || out.Card == nil || !strings.Contains(out.Card.Title, "again") || fx.count() != 2 {
		t.Fatalf("expired = %+v (calls %d)", out, fx.count())
	}
}

// OAuth: Connect redirects to the provider with PKCE and the platform's
// callback; the callback exchanges the code with the verifier and keeps the
// refresh token; a request then carries the access token, and a refresh
// keeps a rotated refresh token.
func TestOAuthConnectExchangeAndRefresh(t *testing.T) {
	fx := newFixture(t)
	c := issues()
	c.Connect = connector.Connect{Kind: connector.KindOAuth2, OAuth2: &connector.OAuth2{
		AuthorizationEndpoint: "https://example.com/oauth/authorize", TokenEndpoint: "https://example.com/oauth/token",
		ClientID: "client-1", Scopes: connector.Scopes{Read: []string{"read"}, Write: []string{"write"}},
	}}
	fx.addConnector(c)
	_ = fx.svc.P.PutJSON(context.Background(), platform.Org("home"), secretsPrefix+"issues", connector.Secrets{ClientSecret: "client-secret"})
	page := fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}, "reach": {"read"}})
	loc, _ := url.Parse(page.Header().Get("Location"))
	q := loc.Query()
	if page.Code != http.StatusSeeOther || loc.Path != "/oauth/authorize" || q.Get("code_challenge_method") != "S256" || q.Get("scope") != "read" ||
		q.Get("redirect_uri") != "https://bnbloc.example.com/v1/component-callbacks/connections/oauth" || q.Get("client_id") != "client-1" {
		t.Fatalf("authorize = %d %s", page.Code, loc)
	}
	cb := "/callbacks/oauth?code=CODE-1&state=" + url.QueryEscape(q.Get("state"))
	done := fx.do(http.MethodGet, cb, component.CallbackHeader, component.Callback{Origin: "https://bnbloc.example.com"}, nil)
	if done.Code != 200 || !strings.Contains(done.Body.String(), "connected") {
		t.Fatalf("callback = %d %s", done.Code, done.Body)
	}
	tokenCall := fx.last()
	form, _ := url.ParseQuery(tokenCall.body)
	if form.Get("code") != "CODE-1" || form.Get("code_verifier") == "" || !strings.HasPrefix(tokenCall.header.Get("Authorization"), "Basic ") {
		t.Fatalf("token call = %+v", tokenCall)
	}
	if raw := fx.store.get("members/maya/grant:home:issues"); !strings.Contains(string(raw), "refresh-1") {
		t.Fatalf("grant = %s", raw)
	}
	if replay := fx.do(http.MethodGet, cb, component.CallbackHeader, component.Callback{}, nil); replay.Code != http.StatusBadRequest {
		t.Fatalf("a used state = %d", replay.Code)
	}
	out, _ := fx.egress(component.DriveOwn, "GET", "https://example.com/api/issue/1", "", nil)
	if out.Status != 200 || fx.last().header.Get("Authorization") != "Bearer access-1" {
		t.Fatalf("with the access token = %d %v", out.Status, fx.last().header)
	}
	fx.svc.dropAuth(grantKey{"maya", "home", "issues"})
	_, _ = fx.egress(component.DriveOwn, "GET", "https://example.com/api/issue/1", "", nil)
	if fx.last().header.Get("Authorization") != "Bearer access-2" || !strings.Contains(string(fx.store.get("members/maya/grant:home:issues")), "refresh-2") {
		t.Fatalf("after a refresh = %v %s", fx.last().header, fx.store.get("members/maya/grant:home:issues"))
	}
}

// idpAnswer is a token endpoint: the code once, then rotating refreshes.
func (fx *fixture) idpAnswer(w http.ResponseWriter, _ *http.Request, body []byte) {
	form, _ := url.ParseQuery(string(body))
	w.Header().Set("Content-Type", "application/json")
	switch {
	case form.Get("grant_type") == "authorization_code" && form.Get("code") == "CODE-1":
		_, _ = io.WriteString(w, `{"access_token":"access-1","refresh_token":"refresh-1","expires_in":3600}`)
	case form.Get("grant_type") == "refresh_token" && form.Get("refresh_token") == "refresh-1":
		_, _ = io.WriteString(w, `{"access_token":"access-2","refresh_token":"refresh-2","expires_in":3600}`)
	default:
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"invalid_grant"}`)
	}
}

// The agent drafts a connector through the component's own API; an admin
// adds it (disabled) from the Connectors page; a member who is not an admin
// cannot open that page.
func TestAgentDraftsAndAdminAdds(t *testing.T) {
	fx := newFixture(t)
	draft, _ := json.Marshal(issues())
	out, _ := fx.egress(component.DriveOwn, "POST", "https://connections.bnbloc/drafts", string(draft), nil)
	if out.Status != http.StatusCreated {
		t.Fatalf("draft = %d %s", out.Status, out.Body)
	}
	if rec := fx.page(false, http.MethodGet, "/pages/admin/", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("member on the admin page = %d", rec.Code)
	}
	list := fx.page(true, http.MethodGet, "/pages/admin/", nil)
	if list.Code != 200 || !strings.Contains(list.Body.String(), "Drafts from agents") {
		t.Fatalf("admin page = %d %s", list.Code, list.Body)
	}
	if rec := fx.page(true, http.MethodPost, "/pages/admin/draft", url.Values{"name": {"issues"}, "decision": {"accept"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("accept = %d %s", rec.Code, rec.Body)
	}
	var c connector.Connector
	_ = json.Unmarshal(fx.store.get("orgs/home/connector:issues"), &c)
	if c.Name != "issues" || c.Enabled {
		t.Fatalf("added = %+v (disabled)", c)
	}
	if rec := fx.page(true, http.MethodPost, "/pages/admin/toggle", url.Values{"name": {"issues"}, "enabled": {"1"}}); rec.Code != http.StatusSeeOther {
		t.Fatalf("enable = %d", rec.Code)
	}
	var sys struct {
		Systems []SystemView `json:"systems"`
	}
	out, _ = fx.egress(component.DriveOwn, "GET", "https://connections.bnbloc/systems", "", nil)
	_ = json.Unmarshal(out.Body, &sys)
	if len(sys.Systems) != 1 || sys.Systems[0].Connected {
		t.Fatalf("systems = %s", out.Body)
	}
}

// A provider connector: connect is pending until the member answers the
// provider's consent, then connected with the provider's grant; each request
// carries what the provider's authorize gives (headers, cookies) and a
// replaced grant is kept; a refusal the provider marks as an admin's is
// reported as such.
func TestProviderConnectAndAuthorize(t *testing.T) {
	fx := newFixture(t)
	var mu sync.Mutex
	consented, adminOnly := false, false
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
		ok, admin := consented, adminOnly
		mu.Unlock()
		var a provider.Answer
		switch {
		case r.URL.Path == "/conn/connect" && !ok:
			a = provider.Answer{Status: provider.Pending, Message: "Answer the consent card first."}
		case r.URL.Path == "/conn/connect":
			a = provider.Answer{Status: provider.Connected, Grant: "g1"}
		case r.URL.Path == "/conn/authorize" && admin:
			a = provider.Answer{Status: provider.Failed, Message: "the platform may not reach this system yet", Admin: true}
		case r.URL.Path == "/conn/authorize":
			a = provider.Answer{Header: map[string]string{"bycauthtoken": "AT"}, Cookies: map[string]string{"JSESSIONID": "s1", "a": "b"}, Grant: "g2", ExpiresAtMs: time.Now().Add(time.Hour).UnixMilli()}
		}
		_ = json.NewEncoder(w).Encode(a)
	}))
	defer prov.Close()
	c := issues()
	c.Connect = connector.Connect{Kind: connector.KindProvider, Provider: &connector.Provider{URL: prov.URL + "/conn", App: "app-1", Params: map[string]string{"authType": "cookies"}}}
	fx.addConnector(c)
	_ = fx.svc.P.PutJSON(context.Background(), platform.Org("home"), secretsPrefix+"issues", connector.Secrets{ProviderSecret: "prov-secret"})
	connect := func() string {
		rec := fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}})
		loc, _ := url.Parse(rec.Header().Get("Location"))
		return loc.Query().Get("msg")
	}
	if msg := connect(); !strings.Contains(msg, "consent card") || fx.store.get("members/maya/grant:home:issues") != nil {
		t.Fatalf("pending connect = %q", msg)
	}
	mu.Lock()
	consented = true
	mu.Unlock()
	if msg := connect(); !strings.Contains(msg, "connected") {
		t.Fatalf("connect = %q", msg)
	}
	out, _ := fx.egress(component.DriveOwn, "GET", "https://example.com/api/page/1", "", http.Header{"Cookie": {"agent=1"}})
	call := fx.last()
	if out.Status != 200 || call.header.Get("bycauthtoken") != "AT" || call.header.Get("Cookie") != "JSESSIONID=s1; a=b" {
		t.Fatalf("authorized call = %d %v", out.Status, call.header)
	}
	if !strings.Contains(string(fx.store.get("members/maya/grant:home:issues")), `"providerGrant":"g2"`) {
		t.Fatalf("replaced grant not kept: %s", fx.store.get("members/maya/grant:home:issues"))
	}
	mu.Lock()
	last := calls[len(calls)-1]
	adminOnly = true
	mu.Unlock()
	if last.App != "app-1" || last.Params["authType"] != "cookies" || last.Member != "maya" {
		t.Fatalf("provider call = %+v", last)
	}
	fx.svc.dropAuth(grantKey{"maya", "home", "issues"})
	out, _ = fx.egress(component.DriveOwn, "GET", "https://example.com/api/page/1", "", nil)
	if out.Status != http.StatusForbidden || !strings.Contains(string(out.Body), "administrator") || out.Card != nil {
		t.Fatalf("admin refusal = %d %s", out.Status, out.Body)
	}
}
