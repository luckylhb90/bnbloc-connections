// Package platform is the connections component's side of the service
// component contract (github.com/luckylhb90/bnbloc/component): verifying
// the platform's signed calls and making its own signed calls to the
// platform's sealed store.
package platform

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/luckylhb90/bnbloc/component"
)

// Platform is one install of the component at one bnbloc gateway.
type Platform struct {
	// BaseURL is the gateway's address as this process reaches it.
	BaseURL string
	// Name is the component's install name (the service's name in
	// bnbloc); Secret its credential.
	Name   string
	Secret string
	HTTP   *http.Client
	Now    func() time.Time
}

func (p *Platform) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

func (p *Platform) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// ErrUnsigned is a call whose signature does not verify.
var ErrUnsigned = errors.New("the call is not signed by bnbloc")

// Verify checks a call from the platform: its signature over the method,
// the path and query (prefix, the component's base path, stripped), the
// identity header's value and the body.
func (p *Platform) Verify(r *http.Request, prefix, identityHeader string, body []byte) error {
	identity := ""
	if identityHeader != "" {
		identity = r.Header.Get(identityHeader)
	}
	pq := strings.TrimPrefix(r.URL.RequestURI(), prefix)
	if p.Secret == "" {
		return ErrUnsigned
	}
	for _, secret := range strings.Split(p.Secret, ",") {
		if component.Verify(r.Header.Get(component.SignatureHeader), strings.TrimSpace(secret), component.SignedRequest(r.Method, pq, identity, body), p.now(), component.SignatureTolerance) == nil {
			return nil
		}
	}
	return ErrUnsigned
}

// do sends one signed call to the platform.
func (p *Platform) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(p.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	secret := strings.TrimSpace(strings.Split(p.Secret, ",")[0])
	req.Header.Set(component.ComponentHeader, "service/"+p.Name)
	req.Header.Set(component.SignatureHeader, component.Sign(secret, p.now(), component.SignedRequest(method, path, "", body)))
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("bnbloc unreachable: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, component.MaxStoreValue+1<<10))
	return resp.StatusCode, raw, err
}

// Scope names a store scope: a member's, an organization's or the
// component's own (component.StoreMembers, StoreOrgs, StoreShared).
type Scope struct {
	Kind  string
	Owner string
}

// Member is a member's scope; Org an organization's; Shared the component's.
func Member(subject string) Scope { return Scope{component.StoreMembers, subject} }
func Org(org string) Scope        { return Scope{component.StoreOrgs, org} }

// Shared is the component's own scope.
var Shared = Scope{Kind: component.StoreShared}

// Get reads a value (found=false when there is none).
func (p *Platform) Get(ctx context.Context, s Scope, key string) ([]byte, bool, error) {
	code, raw, err := p.do(ctx, http.MethodGet, component.StorePath(s.Kind, s.Owner, key), nil)
	switch {
	case err != nil:
		return nil, false, err
	case code == http.StatusNotFound:
		return nil, false, nil
	case code != http.StatusOK:
		return nil, false, fmt.Errorf("bnbloc store answered %d: %s", code, strings.TrimSpace(string(raw)))
	}
	return raw, true, nil
}

// Put writes a value.
func (p *Platform) Put(ctx context.Context, s Scope, key string, value []byte) error {
	if len(value) > component.MaxStoreValue {
		return fmt.Errorf("a value is at most %d bytes", component.MaxStoreValue)
	}
	code, raw, err := p.do(ctx, http.MethodPut, component.StorePath(s.Kind, s.Owner, key), value)
	if err != nil {
		return err
	}
	if code != http.StatusNoContent && code != http.StatusOK {
		return fmt.Errorf("bnbloc store answered %d: %s", code, strings.TrimSpace(string(raw)))
	}
	return nil
}

// Delete removes a value.
func (p *Platform) Delete(ctx context.Context, s Scope, key string) error {
	code, raw, err := p.do(ctx, http.MethodDelete, component.StorePath(s.Kind, s.Owner, key), nil)
	if err != nil {
		return err
	}
	if code != http.StatusNoContent && code != http.StatusOK {
		return fmt.Errorf("bnbloc store answered %d: %s", code, strings.TrimSpace(string(raw)))
	}
	return nil
}

// Keys lists a scope's keys.
func (p *Platform) Keys(ctx context.Context, s Scope) ([]string, error) {
	code, raw, err := p.do(ctx, http.MethodGet, component.StorePath(s.Kind, s.Owner, ""), nil)
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("bnbloc store answered %d: %s", code, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Keys []string `json:"keys"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out.Keys, nil
}

// GetJSON reads a JSON value into v.
func (p *Platform) GetJSON(ctx context.Context, s Scope, key string, v any) (bool, error) {
	raw, ok, err := p.Get(ctx, s, key)
	if err != nil || !ok {
		return ok, err
	}
	return true, json.Unmarshal(raw, v)
}

// PutJSON writes v as JSON.
func (p *Platform) PutJSON(ctx context.Context, s Scope, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return p.Put(ctx, s, key, raw)
}
