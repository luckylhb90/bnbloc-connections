package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
)

// exchangeKey trades a member's key for a short-lived token
// (connector.Exchange): a POST at one of the connector's hosts, the token
// read from the answer and carried as the exchange says, kept until it
// runs out. A refused key (401, 403) asks the member to connect again.
func (s *Service) exchangeKey(ctx context.Context, x connector.Exchange, key string) (cachedAuth, error) {
	var body io.Reader
	contentType := "application/json"
	if x.Form {
		form := url.Values{}
		for k, v := range x.Body {
			form.Set(k, strings.ReplaceAll(v, "{{key}}", key))
		}
		body, contentType = strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"
	} else {
		values := map[string]string{}
		for k, v := range x.Body {
			values[k] = strings.ReplaceAll(v, "{{key}}", key)
		}
		raw, _ := json.Marshal(values)
		body = strings.NewReader(string(raw))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, x.URL, body)
	if err != nil {
		return cachedAuth{}, err
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")
	resp, err := s.upstream().Do(req)
	if err != nil {
		return cachedAuth{}, fmt.Errorf("the key exchange is unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return cachedAuth{}, errReconnect
	case resp.StatusCode < 200 || resp.StatusCode > 299:
		return cachedAuth{}, fmt.Errorf("the key exchange answered %d", resp.StatusCode)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return cachedAuth{}, errors.New("the key exchange did not answer JSON")
	}
	tok, _ := dotted(doc, x.Token).(string)
	if tok == "" {
		return cachedAuth{}, fmt.Errorf("the key exchange's answer has no token at %q", x.Token)
	}
	life := time.Duration(x.TTLSeconds) * time.Second
	if n, ok := dotted(doc, x.ExpiresIn).(float64); ok && x.ExpiresIn != "" && n > 0 {
		life = time.Duration(n) * time.Second
	}
	if life <= 0 {
		life = 30 * time.Minute
	}
	a := carry(x.In, x.Name, x.Prefix, tok)
	a.until = s.now().Add(max(life-30*time.Second, life/2))
	return a, nil
}

// dotted is the value at a dotted path ("data.token") of a JSON document.
func dotted(doc any, path string) any {
	for _, part := range strings.Split(path, ".") {
		m, ok := doc.(map[string]any)
		if !ok {
			return nil
		}
		doc = m[part]
	}
	return doc
}
