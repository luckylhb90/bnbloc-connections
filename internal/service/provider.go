package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/provider"
)

// providerError is a provider's refusal, in its words; admin when it is an
// administrator's to fix.
type providerError struct {
	msg   string
	admin bool
}

func (e *providerError) Error() string { return e.msg }

// callProvider sends one signed call to the connector's provider; the
// member's options (call.Options, from their grant) go with every declared
// option's default filled in.
func (s *Service) callProvider(ctx context.Context, c connector.Connector, org, path string, call provider.Call) (provider.Answer, error) {
	p := c.Connect.Provider
	call.App, call.Params, call.Options = p.App, p.Params, p.OptionValues(call.Options)
	body, _ := json.Marshal(call)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(p.URL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return provider.Answer{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(provider.SignatureHeader, provider.Sign(s.secrets(ctx, org, c.Name).ProviderSecret, s.now(), body))
	resp, err := s.providerClient().Do(req)
	if err != nil {
		return provider.Answer{}, fmt.Errorf("the %s provider is unreachable", c.DisplayName)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var a provider.Answer
	if err := json.Unmarshal(raw, &a); err != nil {
		return provider.Answer{}, fmt.Errorf("the %s provider answered %d without a provider answer", c.DisplayName, resp.StatusCode)
	}
	if resp.StatusCode >= 300 && a.Status == "" {
		a.Status = provider.Failed
	}
	return a, nil
}

// providerClient reaches providers: components on the operator's network,
// so private addresses are allowed (never loopback's metadata).
func (s *Service) providerClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// providerAuth is what the provider says one request carries.
func (s *Service) providerAuth(ctx context.Context, c connector.Connector, org string, p principal, g *Grant, force bool, signedIn []provider.Step) (cachedAuth, error) {
	a, err := s.callProvider(ctx, c, org, provider.AuthorizePath, provider.Call{Member: p.Member, Principal: p.forProvider(), Org: org, Grant: g.ProviderGrant, Reach: g.Reach, Force: force, Options: g.Options, SignedIn: signedIn, FromMember: c.FromMember()})
	if err != nil {
		return cachedAuth{}, err
	}
	if (a.Session || len(a.SignIn) > 0) && !c.FromMember() {
		return cachedAuth{}, &providerError{msg: c.DisplayName + "'s sign-in is kept on members' computers: the connector must send from members' computers", admin: true}
	}
	if len(a.SignIn) > 0 {
		if signedIn != nil {
			return cachedAuth{}, errors.New("the sign-in on your computer did not take")
		}
		return cachedAuth{}, &signInNeeded{steps: a.SignIn}
	}
	if a.Status == provider.Failed {
		if a.Reconnect {
			return cachedAuth{}, errReconnect
		}
		return cachedAuth{}, &providerError{msg: firstNonEmpty(a.Message, "the provider refused"), admin: a.Admin}
	}
	if a.Grant != "" && a.Grant != g.ProviderGrant {
		g.ProviderGrant = a.Grant
		if err := s.saveGrantOf(ctx, p, org, *g); err != nil {
			return cachedAuth{}, err
		}
	}
	out := cachedAuth{header: http.Header{}, session: a.Session}
	for k, v := range a.Header {
		out.header.Set(k, v)
	}
	if len(a.Cookies) > 0 {
		names := make([]string, 0, len(a.Cookies))
		for n := range a.Cookies {
			names = append(names, n)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, n := range names {
			parts = append(parts, n+"="+a.Cookies[n])
		}
		out.header.Set("Cookie", strings.Join(parts, "; "))
	}
	out.until = s.now().Add(10 * time.Minute)
	if a.ExpiresAtMs > 0 {
		out.until = time.UnixMilli(a.ExpiresAtMs - 30_000)
	}
	return out, nil
}

// signInNeeded: the provider asks for a sign-in's steps sent from the
// member's computer with their held session first
// (docs/prd/2026-10-28-member-held-sessions.md in bnbloc).
type signInNeeded struct{ steps []provider.Step }

func (e *signInNeeded) Error() string {
	return "a sign-in from the member's computer is needed first"
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
