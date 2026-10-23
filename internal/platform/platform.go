// Package platform is the connections component's view of bnbloc's
// service component client (component.ServiceClient): the store's scopes
// and JSON values.
package platform

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/luckylhb90/bnbloc/component"
)

// Platform is one install of the component at one bnbloc gateway.
type Platform struct {
	component.ServiceClient
}

// New is the component named name at the gateway baseURL.
func New(baseURL, name, secret string) *Platform {
	return &Platform{component.ServiceClient{BaseURL: baseURL, Name: name, Secret: secret}}
}

// Verify checks a call from the platform (component.ServiceClient.Verify).
func (p *Platform) Verify(r *http.Request, prefix, identityHeader string, body []byte) error {
	return p.ServiceClient.Verify(r, prefix, identityHeader, body)
}

// Scope names a store scope: a member's, an organization's or the
// component's own.
type Scope struct {
	Kind  string
	Owner string
}

// Member is a member's scope; Org an organization's.
func Member(subject string) Scope { return Scope{component.StoreMembers, subject} }
func Org(org string) Scope        { return Scope{component.StoreOrgs, org} }

// Shared is the component's own scope.
var Shared = Scope{Kind: component.StoreShared}

func (p *Platform) Get(ctx context.Context, s Scope, key string) ([]byte, bool, error) {
	return p.StoreGet(ctx, s.Kind, s.Owner, key)
}

func (p *Platform) Put(ctx context.Context, s Scope, key string, value []byte) error {
	return p.StorePut(ctx, s.Kind, s.Owner, key, value)
}

func (p *Platform) Delete(ctx context.Context, s Scope, key string) error {
	return p.StoreDelete(ctx, s.Kind, s.Owner, key)
}

func (p *Platform) Keys(ctx context.Context, s Scope) ([]string, error) {
	return p.StoreKeys(ctx, s.Kind, s.Owner)
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
