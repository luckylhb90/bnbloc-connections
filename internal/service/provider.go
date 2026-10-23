package service

import (
	"bytes"
	"context"
	"encoding/json"
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

// callProvider sends one signed call to the connector's provider.
func (s *Service) callProvider(ctx context.Context, c connector.Connector, org, path string, call provider.Call) (provider.Answer, error) {
	p := c.Connect.Provider
	call.App, call.Params = p.App, p.Params
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
func (s *Service) providerAuth(ctx context.Context, c connector.Connector, org string, p principal, g *Grant, force bool) (cachedAuth, error) {
	a, err := s.callProvider(ctx, c, org, provider.AuthorizePath, provider.Call{Member: p.Member, Principal: p.forProvider(), Org: org, Grant: g.ProviderGrant, Reach: g.Reach, Force: force})
	if err != nil {
		return cachedAuth{}, err
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
	out := cachedAuth{header: http.Header{}}
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

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
