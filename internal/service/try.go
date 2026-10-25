package service

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc/component"
)

// Trying a connection (docs/prd/2026-10-25-ai-checks-its-work.md in
// bnbloc): the connector's test request, a read, sent with someone's own
// connection. It tells a member their connection works right after they
// connect; an admin's Try it that fails is reality's word the review is
// given, and the review proposes the fix. What the system answered is kept
// without any credential in it.

// tryResult is one try: for the connector as it was (Hash), whether the
// system answered 2xx, and one line saying what it answered.
type tryResult struct {
	Hash   string `json:"hash"`
	AtMs   int64  `json:"atMs"`
	OK     bool   `json:"ok"`
	Status int    `json:"status,omitempty"`
	Line   string `json:"line"`
}

const tryPrefix = "try:"

// errNoTry is a connection that cannot be tried here.
var errNoTry = errors.New("cannot be tried here")

// tryConnection sends c's test request as p. errNoTry when c names none,
// or its requests go out from the members' computers (tried on first use).
func (s *Service) tryConnection(ctx context.Context, org string, p principal, c connector.Connector) (tryResult, error) {
	if c.Test == nil || c.FromMember() {
		return tryResult{}, errNoTry
	}
	g, ok, err := s.grantOf(ctx, p, org, c.Name)
	if err != nil || !ok {
		return tryResult{}, errors.New("not connected")
	}
	method := c.Test.Method
	if method == "" {
		method = "GET"
	}
	u, err := url.Parse("https://" + c.Hosts[0] + c.Test.Path)
	if err != nil {
		return tryResult{}, err
	}
	out := tryResult{Hash: reviewHash(c), AtMs: s.now().UnixMilli()}
	auth, _ := s.credentials(ctx, c, org, p, &g, false)
	resp, err := s.call(ctx, c, org, p, &g, component.EgressRequest{Method: method, URL: u.String()}, u)
	switch {
	case errors.Is(err, errReconnect):
		out.Line = method + " " + c.Test.Path + ": the system refused the credentials (401, or a sign-in it no longer takes)"
	case err != nil:
		out.Line = method + " " + c.Test.Path + ": " + err.Error()
	default:
		out.Status, out.OK = resp.Status, resp.Status >= 200 && resp.Status < 300
		out.Line = fmt.Sprintf("%s %s answered %d", method, c.Test.Path, resp.Status)
		if !out.OK {
			if b := bodySummary(resp.Body); b != "" {
				out.Line += ": " + clip(b, 300)
			}
		}
	}
	out.Line = redact(out.Line, auth, g)
	return out, nil
}

// redact leaves out of a line every credential value a request carried
// (a system may echo a header back).
func redact(line string, auth cachedAuth, g Grant) string {
	var secrets []string
	for _, vs := range auth.header {
		for _, v := range vs {
			secrets = append(secrets, v, strings.TrimPrefix(v, "Bearer "))
		}
	}
	for _, vs := range auth.query {
		secrets = append(secrets, vs...)
	}
	secrets = append(secrets, auth.key, auth.secret, g.APIKey)
	for _, v := range g.Extra {
		secrets = append(secrets, v)
	}
	for _, v := range secrets {
		if len(v) >= 6 {
			line = strings.ReplaceAll(line, v, "[credential]")
			line = strings.ReplaceAll(line, url.QueryEscape(v), "[credential]")
		}
	}
	return line
}

// answers is the sentence a connect ends with: whether the system answers
// the connector's test as p ("" when there is nothing to try).
func (s *Service) answers(ctx context.Context, org string, p principal, c connector.Connector) string {
	t, err := s.tryConnection(ctx, org, p, c)
	switch {
	case err != nil:
		return ""
	case t.OK:
		return " It answers."
	}
	return " But it does not answer yet (" + t.Line + "): check what you entered, or tell an administrator."
}

func (s *Service) keepTry(ctx context.Context, org, name string, t tryResult) {
	_ = s.P.PutJSON(ctx, platform.Org(org), tryPrefix+name, t)
}

// lastTry is the latest try of connector name as it is now (hash).
func (s *Service) lastTry(ctx context.Context, org, name, hash string) (tryResult, bool) {
	var t tryResult
	ok, err := s.P.GetJSON(ctx, platform.Org(org), tryPrefix+name, &t)
	return t, ok && err == nil && t.Hash == hash
}

// docLinks are the https addresses an admin gave beside a description (at
// most 3).
func docLinks(v string) []string {
	var out []string
	for _, f := range splitList(v) {
		if u, err := url.Parse(f); err == nil && u.Scheme == "https" && u.Host != "" && len(out) < 3 {
			out = append(out, u.String())
		}
	}
	return out
}
