package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc/component"
)

// OAuth 2.0 authorization code with PKCE (RFC 7636), issuer discovery (RFC
// 8414, OIDC Discovery), the authorization response's issuer (RFC 9207),
// refresh token rotation and revocation (RFC 7009). The redirect is the
// component's callback at the platform (component.ComponentCallbackPath).

// stateTTL bounds a sign-in at the provider.
const stateTTL = 15 * time.Minute

// oauthState is one sign-in under way, kept in the component's scope under
// its random state.
type oauthState struct {
	Member    string `json:"member"`
	Org       string `json:"org"`
	Connector string `json:"connector"`
	Reach     string `json:"reach"`
	// Scopes: connector.Write when the sign-in asks the write scopes too;
	// Held: the held change the sign-in was started from.
	Scopes      string `json:"scopes,omitempty"`
	Held        string `json:"held,omitempty"`
	Verifier    string `json:"verifier"`
	RedirectURI string `json:"redirectUri"`
	Issuer      string `json:"issuer,omitempty"`
	CreatedAtMs int64  `json:"createdAtMs"`
}

// endpoints are a connector's OAuth endpoints, discovered when not given.
type endpoints struct {
	Issuer        string `json:"issuer"`
	Authorization string `json:"authorization_endpoint"`
	Token         string `json:"token_endpoint"`
	Revocation    string `json:"revocation_endpoint"`
}

var discovered sync.Map // issuer -> endpoints

func (s *Service) endpoints(ctx context.Context, o connector.OAuth2) (endpoints, error) {
	e := endpoints{Issuer: o.Issuer, Authorization: o.AuthorizationEndpoint, Token: o.TokenEndpoint, Revocation: o.RevocationEndpoint}
	if e.Authorization != "" && e.Token != "" {
		return e, nil
	}
	if v, ok := discovered.Load(o.Issuer); ok {
		d := v.(endpoints)
		return merge(e, d), nil
	}
	base := strings.TrimRight(o.Issuer, "/")
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		var d endpoints
		if err := s.getJSON(ctx, base+p, &d); err != nil || d.Authorization == "" || d.Token == "" {
			continue
		}
		if d.Issuer != "" && strings.TrimRight(d.Issuer, "/") != base {
			return endpoints{}, fmt.Errorf("the discovery document of %s names another issuer", o.Issuer)
		}
		discovered.Store(o.Issuer, d)
		return merge(e, d), nil
	}
	return endpoints{}, fmt.Errorf("no OAuth discovery document at %s", o.Issuer)
}

func merge(e, d endpoints) endpoints {
	if e.Authorization == "" {
		e.Authorization = d.Authorization
	}
	if e.Token == "" {
		e.Token = d.Token
	}
	if e.Revocation == "" {
		e.Revocation = d.Revocation
	}
	if e.Issuer == "" {
		e.Issuer = d.Issuer
	}
	return e
}

func (s *Service) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.upstream().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// redirectURI is the component's callback at the platform.
func (s *Service) redirectURI(origin string) string {
	return strings.TrimRight(origin, "/") + component.ComponentCallbackPath + url.PathEscape(s.P.Name) + "/oauth"
}

// authorizeURL starts a member's sign-in at the connector's provider and
// keeps its state: the reach the grant gets, the scopes asked (the write
// ones too for connector.Write) and the held change it started from.
func (s *Service) authorizeURL(ctx context.Context, c connector.Connector, m component.Member, reach, scopes, held string) (string, error) {
	o := *c.Connect.OAuth2
	e, err := s.endpoints(ctx, o)
	if err != nil {
		return "", err
	}
	verifier := randomToken(48)
	sum := sha256.Sum256([]byte(verifier))
	state := randomToken(24)
	st := oauthState{Member: m.Subject, Org: m.Org, Connector: c.Name, Reach: reach, Scopes: scopes, Held: held, Verifier: verifier,
		RedirectURI: s.redirectURI(m.Origin), Issuer: e.Issuer, CreatedAtMs: s.now().UnixMilli()}
	if err := s.P.PutJSON(ctx, platform.Shared, statePrefix+state, st); err != nil {
		return "", err
	}
	asked := append([]string(nil), o.Scopes.Read...)
	if scopes == connector.Write {
		asked = append(asked, o.Scopes.Write...)
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {o.ClientID},
		"redirect_uri":          {st.RedirectURI},
		"state":                 {state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	if len(asked) > 0 {
		sep := o.ScopeSeparator
		if sep == "" {
			sep = " "
		}
		q.Set("scope", strings.Join(asked, sep))
	}
	for k, v := range o.AuthParams {
		q.Set(k, v)
	}
	sep := "?"
	if strings.Contains(e.Authorization, "?") {
		sep = "&"
	}
	return e.Authorization + sep + q.Encode(), nil
}

// tokenAnswer is a token endpoint's answer.
type tokenAnswer struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	Error        string `json:"error"`
	Description  string `json:"error_description"`
}

// token calls the connector's token endpoint.
func (s *Service) token(ctx context.Context, c connector.Connector, org string, form url.Values) (tokenAnswer, error) {
	o := *c.Connect.OAuth2
	e, err := s.endpoints(ctx, o)
	if err != nil {
		return tokenAnswer{}, err
	}
	req, err := s.clientRequest(ctx, c, org, e.Token, form)
	if err != nil {
		return tokenAnswer{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.upstream().Do(req)
	if err != nil {
		return tokenAnswer{}, fmt.Errorf("the token endpoint is unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var t tokenAnswer
	if err := json.Unmarshal(raw, &t); err != nil {
		// Some providers answer form-encoded.
		v, _ := url.ParseQuery(string(raw))
		t = tokenAnswer{AccessToken: v.Get("access_token"), RefreshToken: v.Get("refresh_token"), Error: v.Get("error")}
	}
	if resp.StatusCode != http.StatusOK || t.AccessToken == "" {
		if t.Error == "invalid_grant" {
			return tokenAnswer{}, errReconnect
		}
		return tokenAnswer{}, fmt.Errorf("the token endpoint refused (%d %s %s)", resp.StatusCode, t.Error, t.Description)
	}
	return t, nil
}

// clientRequest is a form POST to a token or revocation endpoint carrying
// the client's credentials: in the form ("post"), as HTTP Basic otherwise,
// or the bare client_id for a client without a secret.
func (s *Service) clientRequest(ctx context.Context, c connector.Connector, org, endpoint string, form url.Values) (*http.Request, error) {
	o := c.Connect.OAuth2
	secret := s.secrets(ctx, org, c.Name).ClientSecret
	basic := o.ClientAuth != "post" && secret != ""
	if !basic {
		form.Set("client_id", o.ClientID)
		if secret != "" {
			form.Set("client_secret", secret)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic {
		req.SetBasicAuth(url.QueryEscape(o.ClientID), url.QueryEscape(secret))
	}
	return req, nil
}

func (s *Service) refresh(ctx context.Context, c connector.Connector, org, refresh string) (tokenAnswer, error) {
	return s.token(ctx, c, org, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refresh}})
}

// revoke revokes a grant at the provider (best-effort, RFC 7009).
func (s *Service) revoke(ctx context.Context, c connector.Connector, org string, g Grant) {
	o := c.Connect.OAuth2
	if o == nil {
		return
	}
	e, err := s.endpoints(ctx, *o)
	if err != nil || e.Revocation == "" {
		return
	}
	var req *http.Request
	if o.RevocationAuth == "bearer" {
		// The access token revokes itself: one from the grant (refreshed
		// when it holds none that lasts).
		access := g.AccessToken
		if g.RefreshToken != "" {
			if t, err := s.refresh(ctx, c, org, g.RefreshToken); err == nil {
				access = t.AccessToken
			}
		}
		if access == "" {
			return
		}
		if req, err = http.NewRequestWithContext(ctx, http.MethodPost, e.Revocation, nil); err != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+access)
	} else {
		tok := g.RefreshToken
		if tok == "" {
			tok = g.AccessToken
		}
		if req, err = s.clientRequest(ctx, c, org, e.Revocation, url.Values{"token": {tok}}); err != nil {
			return
		}
	}
	resp, err := s.upstream().Do(req)
	if err != nil {
		slog.Warn("connections: revoke failed", "connector", c.Name, "error", err)
		return
	}
	_ = resp.Body.Close()
}

// handleOAuthCallback finishes a sign-in: the state names the member and
// the connector; the code is exchanged with the PKCE verifier and the grant
// kept. Open (another system redirects a browser here), signed by the
// platform.
func (s *Service) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.read(w, r, component.CallbackHeader); !ok {
		return
	}
	ctx := r.Context()
	q := r.URL.Query()
	state := q.Get("state")
	var st oauthState
	ok, err := false, error(nil)
	if state != "" && len(state) < 100 {
		ok, err = s.P.GetJSON(ctx, platform.Shared, statePrefix+state, &st)
		_ = s.P.Delete(ctx, platform.Shared, statePrefix+state)
	}
	switch {
	case err != nil:
		s.callbackPage(w, http.StatusBadGateway, "Not connected", "The sign-in could not be checked right now. Try again from the connections page.")
		return
	case !ok || s.now().UnixMilli()-st.CreatedAtMs > stateTTL.Milliseconds():
		s.callbackPage(w, http.StatusBadRequest, "Not connected", "This sign-in expired or was already used. Start again from the connections page.")
		return
	}
	if e := q.Get("error"); e != "" {
		s.callbackPage(w, http.StatusOK, "Not connected", "The provider answered: "+e+". Nothing was connected.")
		return
	}
	if iss := q.Get("iss"); iss != "" && st.Issuer != "" && strings.TrimRight(iss, "/") != strings.TrimRight(st.Issuer, "/") {
		s.callbackPage(w, http.StatusBadRequest, "Not connected", "The answer came from another issuer than the one asked (RFC 9207). Nothing was connected.")
		return
	}
	c, found := s.connectorNamed(ctx, st.Org, st.Connector)
	if !found || c.Connect.OAuth2 == nil {
		s.callbackPage(w, http.StatusNotFound, "Not connected", "This system is no longer enabled.")
		return
	}
	tok, err := s.token(ctx, c, st.Org, url.Values{
		"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "redirect_uri": {st.RedirectURI}, "code_verifier": {st.Verifier},
	})
	if err != nil {
		slog.Warn("connections: code exchange failed", "connector", c.Name, "error", err)
		s.callbackPage(w, http.StatusBadGateway, "Not connected", "The provider did not give access: "+err.Error())
		return
	}
	g := Grant{Connector: c.Name, Reach: st.Reach, Scopes: st.Scopes, RefreshToken: tok.RefreshToken, ConnectedAtMs: s.now().UnixMilli()}
	if tok.RefreshToken == "" {
		g.AccessToken = tok.AccessToken
		if tok.ExpiresIn > 0 {
			g.ExpiresAtMs = s.now().Add(time.Duration(tok.ExpiresIn) * time.Second).UnixMilli()
		}
	}
	if err := s.saveGrant(ctx, st.Member, st.Org, g); err != nil {
		s.callbackPage(w, http.StatusBadGateway, "Not connected", "The connection could not be kept: "+err.Error())
		return
	}
	s.keepAuth(grantKey{st.Member, st.Org, c.Name}, cachedAuth{
		header: http.Header{"Authorization": {"Bearer " + tok.AccessToken}},
		until:  s.now().Add(time.Duration(max(tok.ExpiresIn, 60))*time.Second - 30*time.Second),
	})
	w.Header().Set(component.AuditHeader, component.EncodeHeader(component.Audit{Action: "connect", Target: c.Name, Outcome: "allow", Detail: st.Reach}))
	if st.Held != "" {
		s.callbackPage(w, http.StatusOK, c.DisplayName+" can take changes now", "Open the change from its card in the room again and allow it.")
		return
	}
	s.callbackPage(w, http.StatusOK, c.DisplayName+" is connected", "You can close this tab. Your own agents now reach "+c.DisplayName+" as you"+reachWords(st.Reach)+"."+s.answers(ctx, st.Org, asMember(st.Member), c))
}

func reachWords(reach string) string {
	if reach == connector.Write {
		return ", changes included"
	}
	return ", reading only; a change asks you first"
}

// connectorNamed is the organization's enabled connector of that name.
func (s *Service) connectorNamed(ctx context.Context, org, name string) (connector.Connector, bool) {
	list, err := s.enabled(ctx, org)
	if err != nil {
		return connector.Connector{}, false
	}
	for _, c := range list {
		if c.Name == name {
			return c, true
		}
	}
	return connector.Connector{}, false
}
