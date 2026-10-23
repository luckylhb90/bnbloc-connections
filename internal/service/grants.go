package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
)

// Grant is one member's connection to one connector of one organization,
// kept sealed in the platform (the member's scope). Derived credentials (an
// access token, a session) live in memory only (cachedAuth), except an
// access token the system gives without a refresh token.
type Grant struct {
	Connector string `json:"connector"`
	// Reach: connector.Read, or connector.Write (changes allowed without
	// asking each time).
	Reach string `json:"reach"`
	// Scopes: connector.Write when an OAuth sign-in granted the write
	// scopes too (a change can be made), else the read ones only.
	Scopes        string `json:"scopes,omitempty"`
	RefreshToken  string `json:"refreshToken,omitempty"`
	AccessToken   string `json:"accessToken,omitempty"`
	ExpiresAtMs   int64  `json:"expiresAtMs,omitempty"`
	APIKey        string `json:"apiKey,omitempty"`
	ProviderGrant string `json:"providerGrant,omitempty"`
	ConnectedAtMs int64  `json:"connectedAtMs"`
}

// canChange reports whether the grant's credentials can make a change in
// c: always, except an OAuth sign-in that did not grant c's write scopes.
func (g Grant) canChange(c connector.Connector) bool {
	if c.Connect.Kind != connector.KindOAuth2 || len(c.Connect.OAuth2.Scopes.Write) == 0 {
		return true
	}
	return g.Scopes == connector.Write
}

type grantKey struct{ member, org, connector string }

func grantStoreKey(org, name string) string { return grantPrefix + org + ":" + name }

func (s *Service) grant(ctx context.Context, member, org, name string) (Grant, bool, error) {
	var g Grant
	ok, err := s.P.GetJSON(ctx, platform.Member(member), grantStoreKey(org, name), &g)
	return g, ok, err
}

func (s *Service) saveGrant(ctx context.Context, member, org string, g Grant) error {
	return s.P.PutJSON(ctx, platform.Member(member), grantStoreKey(org, g.Connector), g)
}

func (s *Service) deleteGrant(ctx context.Context, member, org, name string) error {
	s.dropAuth(grantKey{member, org, name})
	return s.P.Delete(ctx, platform.Member(member), grantStoreKey(org, name))
}

// cachedAuth is what a request to the system carries, until it expires.
type cachedAuth struct {
	header http.Header
	query  url.Values
	until  time.Time
	at     time.Time
}

func (s *Service) cachedAuthFor(k grantKey) (cachedAuth, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.tokens[k]
	if !ok || !s.now().Before(a.until) {
		return cachedAuth{}, false
	}
	return a, true
}

func (s *Service) keepAuth(k grantKey, a cachedAuth) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tokens == nil {
		s.tokens = map[grantKey]cachedAuth{}
	}
	s.tokens[k] = a
}

func (s *Service) dropAuth(k grantKey) {
	s.mu.Lock()
	delete(s.tokens, k)
	s.mu.Unlock()
}

// grantLock serializes making one grant's credentials in this process, so
// two requests never spend one refresh token twice (a provider that
// detects reuse revokes the grant). Replicas do not share it: the
// component runs as one replica.
func (s *Service) grantLock(k grantKey) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.locks == nil {
		s.locks = map[grantKey]*sync.Mutex{}
	}
	if s.locks[k] == nil {
		s.locks[k] = &sync.Mutex{}
	}
	return s.locks[k]
}

// errReconnect: the grant no longer works; the member connects again.
var errReconnect = errors.New("the connection no longer works")

// credentials are what a request to c carries for the principal: from memory
// while they last, else made from the grant (an OAuth refresh, the key, the
// provider's authorization). force skips the memory (after a refusal),
// unless another request made them meanwhile. One grant's are made one at
// a time (grantLock), from the grant as stored then (a refresh token
// another request rotated).
func (s *Service) credentials(ctx context.Context, c connector.Connector, org string, p principal, g *Grant, force bool) (cachedAuth, error) {
	k := grantKey{p.key(), org, c.Name}
	start := s.now()
	if !force {
		if a, ok := s.cachedAuthFor(k); ok {
			return a, nil
		}
	}
	mu := s.grantLock(k)
	mu.Lock()
	defer mu.Unlock()
	if a, ok := s.cachedAuthFor(k); ok && (!force || !a.at.Before(start)) {
		return a, nil
	}
	if fresh, ok, err := s.grantOf(ctx, p, org, c.Name); err == nil && ok {
		*g = fresh
	}
	var a cachedAuth
	var err error
	switch c.Connect.Kind {
	case connector.KindAPIKey:
		if x := c.Connect.APIKey.Exchange; x != nil {
			a, err = s.exchangeKey(ctx, *x, g.APIKey)
			break
		}
		a = apiKeyAuth(*c.Connect.APIKey, g.APIKey)
		a.until = s.now().Add(time.Hour)
	case connector.KindOAuth2:
		a, err = s.oauthAuth(ctx, c, org, p, g, force)
	case connector.KindProvider:
		a, err = s.providerAuth(ctx, c, org, p, g, force)
	default:
		err = fmt.Errorf("unknown connect kind %q", c.Connect.Kind)
	}
	if err != nil {
		return cachedAuth{}, err
	}
	a.at = s.now()
	s.keepAuth(k, a)
	return a, nil
}

// apiKeyAuth carries a key the way the connector says.
func apiKeyAuth(spec connector.APIKey, key string) cachedAuth {
	return carry(spec.In, spec.Name, spec.Prefix, key)
}

// carry is a credential carried in, named name, after prefix.
func carry(in, name, prefix, key string) cachedAuth {
	a := cachedAuth{header: http.Header{}, query: url.Values{}}
	switch in {
	case "bearer":
		a.header.Set("Authorization", "Bearer "+key)
	case "header":
		a.header.Set(name, prefix+key)
	case "query":
		a.query.Set(name, key)
	case "basic":
		r := &http.Request{Header: http.Header{}}
		user, pass, _ := cutColon(key)
		r.SetBasicAuth(user, pass)
		a.header.Set("Authorization", r.Header.Get("Authorization"))
	}
	return a
}

func cutColon(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// oauthAuth is a bearer access token: refreshed with the grant's refresh
// token (a rotated one is kept), or the stored access token while it lasts.
func (s *Service) oauthAuth(ctx context.Context, c connector.Connector, org string, p principal, g *Grant, force bool) (cachedAuth, error) {
	bearer := func(tok string, until time.Time) cachedAuth {
		return cachedAuth{header: http.Header{"Authorization": {"Bearer " + tok}}, until: until}
	}
	if g.RefreshToken == "" {
		if g.AccessToken != "" && !force && (g.ExpiresAtMs == 0 || s.now().UnixMilli() < g.ExpiresAtMs-30_000) {
			until := s.now().Add(time.Hour)
			if g.ExpiresAtMs > 0 {
				until = time.UnixMilli(g.ExpiresAtMs - 30_000)
			}
			return bearer(g.AccessToken, until), nil
		}
		return cachedAuth{}, errReconnect
	}
	tok, err := s.refresh(ctx, c, org, g.RefreshToken)
	if err != nil {
		return cachedAuth{}, err
	}
	if tok.RefreshToken != "" && tok.RefreshToken != g.RefreshToken {
		g.RefreshToken = tok.RefreshToken
		if err := s.saveGrantOf(ctx, p, org, *g); err != nil {
			return cachedAuth{}, fmt.Errorf("keep the rotated refresh token: %w", err)
		}
	}
	life := time.Duration(tok.ExpiresIn) * time.Second
	if life <= 0 {
		life = 30 * time.Minute
	}
	return bearer(tok.AccessToken, s.now().Add(life-30*time.Second)), nil
}
