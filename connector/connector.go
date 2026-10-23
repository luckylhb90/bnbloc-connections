// Package connector is a connector: one system the connections component
// reaches as a member (its hosts, how one connects, which requests read
// and which change, its guide for agents). Connectors are an
// organization's content: each organization adds and enables its own.
package connector

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/luckylhb90/bnbloc/component"
)

// How a member connects.
const (
	KindOAuth2   = "oauth2"
	KindAPIKey   = "apiKey"
	KindProvider = "provider"
)

// Request classes (Policy).
const (
	Read  = "read"
	Write = "write"
)

// Connector is one system.
type Connector struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"displayName"`
	Purpose     string            `json:"purpose"`
	Hosts       []string          `json:"hosts"`
	Connect     Connect           `json:"connect"`
	Policy      Policy            `json:"policy"`
	ExpiredWhen []Expired         `json:"expiredWhen,omitempty"`
	CLIEnv      map[string]string `json:"cliEnv,omitempty"`
	Guide       string            `json:"guide,omitempty"`
	// SendFrom is where a request to the system goes out: SendServer (this
	// component's network, the default) or SendMember (the member's own
	// computer, through their bridge: a system the component's network does
	// not reach). Either way the credentials and the policy are this
	// component's.
	SendFrom string `json:"sendFrom,omitempty"`
	// Enabled: the organization's members may connect it and their agents
	// reach it.
	Enabled bool `json:"enabled,omitempty"`
}

// Where requests go out (Connector.SendFrom).
const (
	SendServer = "server"
	SendMember = "member"
)

// FromMember reports a connector whose requests go out from the member's
// computer.
func (c Connector) FromMember() bool { return c.SendFrom == SendMember }

// Connect is how a member connects the system.
type Connect struct {
	Kind     string    `json:"kind"`
	OAuth2   *OAuth2   `json:"oauth2,omitempty"`
	APIKey   *APIKey   `json:"apiKey,omitempty"`
	Provider *Provider `json:"provider,omitempty"`
}

// OAuth2 is an authorization code grant with PKCE. Endpoints the issuer's
// discovery document names may be left out. The client secret is not here:
// it is kept apart (Secrets).
type OAuth2 struct {
	Issuer                string            `json:"issuer,omitempty"`
	AuthorizationEndpoint string            `json:"authorizationEndpoint,omitempty"`
	TokenEndpoint         string            `json:"tokenEndpoint,omitempty"`
	RevocationEndpoint    string            `json:"revocationEndpoint,omitempty"`
	ClientID              string            `json:"clientId,omitempty"`
	Scopes                Scopes            `json:"scopes"`
	AuthParams            map[string]string `json:"authParams,omitempty"`
	// ClientAuth is how the client authenticates at the token endpoint:
	// "basic" (default) or "post".
	ClientAuth string `json:"clientAuth,omitempty"`
}

// Scopes are what a read-only connection asks, and what changes add.
type Scopes struct {
	Read  []string `json:"read"`
	Write []string `json:"write,omitempty"`
}

// APIKey is a key the member pastes and how a request carries it.
type APIKey struct {
	// In: "bearer" (Authorization: Bearer <key>), "header" (Name: Prefix+key),
	// "query" (Name=key), "basic" (the key as user:password).
	In     string `json:"in"`
	Name   string `json:"name,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	// Help tells the member where to make one.
	Help string `json:"help,omitempty"`
}

// Provider is another component that connects the member and authorizes
// each request (the provider contract, provider.go in the service).
type Provider struct {
	URL  string `json:"url"`
	App  string `json:"app,omitempty"`
	Help string `json:"help,omitempty"`
	// Params are the provider's per-system values (how the system takes
	// what the provider obtains), passed on every call.
	Params map[string]string `json:"params,omitempty"`
}

// Policy sorts a request into read or write; anything matching neither is
// refused.
type Policy struct {
	Read  []Rule `json:"read"`
	Write []Rule `json:"write,omitempty"`
}

// Rule matches requests: a method (empty = any of the rule's class's
// usual ones), a path glob ("*" one segment, "**" any), and optionally a
// regular expression the body must match (a search that is a POST).
type Rule struct {
	Methods []string `json:"methods,omitempty"`
	Paths   []string `json:"paths"`
	Body    string   `json:"body,omitempty"`
}

// Expired is how the system answers an access it no longer accepts when
// that is not a 401: a status and what its Location or body contains.
type Expired struct {
	Status           int    `json:"status"`
	LocationContains string `json:"locationContains,omitempty"`
	BodyContains     string `json:"bodyContains,omitempty"`
}

// Secrets are a connector's client values, kept apart from it (never shown
// back, never in its JSON).
type Secrets struct {
	ClientSecret   string `json:"clientSecret,omitempty"`
	ProviderSecret string `json:"providerSecret,omitempty"`
}

// Bounds.
const (
	MaxHosts     = 32
	MaxGuide     = 32 << 10
	MaxRules     = 64
	maxTextRunes = 200
)

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// ValidName reports a connector name.
func ValidName(n string) bool { return nameRE.MatchString(n) }

var methods = []string{"GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"}

// Validate reports the first thing wrong with c.
func (c Connector) Validate() error {
	if !ValidName(c.Name) {
		return errors.New("name: 1-32 of a-z, 0-9 and '-'")
	}
	if strings.TrimSpace(c.DisplayName) == "" || utf8.RuneCountInString(c.DisplayName) > 60 {
		return errors.New("displayName: required, at most 60 characters")
	}
	if utf8.RuneCountInString(c.Purpose) > maxTextRunes || strings.ContainsAny(c.Purpose, "\r\n") {
		return fmt.Errorf("purpose: one line of at most %d characters", maxTextRunes)
	}
	if len(c.Hosts) == 0 || len(c.Hosts) > MaxHosts {
		return fmt.Errorf("hosts: 1 to %d exact names", MaxHosts)
	}
	for _, h := range c.Hosts {
		if !component.ValidEgressHost(h) {
			return fmt.Errorf("host %q: an exact lower-case DNS name (no port, no address, no wildcard)", h)
		}
	}
	if c.SendFrom != "" && c.SendFrom != SendServer && c.SendFrom != SendMember {
		return errors.New(`sendFrom: "server" (default) or "member"`)
	}
	if err := c.Connect.validate(); err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	if len(c.Policy.Read) == 0 {
		return errors.New("policy.read: at least one rule")
	}
	if len(c.Policy.Read)+len(c.Policy.Write) > MaxRules {
		return fmt.Errorf("policy: at most %d rules", MaxRules)
	}
	for _, r := range append(append([]Rule(nil), c.Policy.Read...), c.Policy.Write...) {
		if err := r.validate(); err != nil {
			return fmt.Errorf("policy: %w", err)
		}
	}
	for k := range c.CLIEnv {
		if !envName(k) {
			return fmt.Errorf("cliEnv %q: an upper-case environment variable name", k)
		}
	}
	if len(c.Guide) > MaxGuide {
		return fmt.Errorf("guide: at most %d bytes", MaxGuide)
	}
	return nil
}

func envName(k string) bool {
	if k == "" || len(k) > 64 || strings.HasPrefix(k, "BNBLOC_") || strings.Contains(strings.ToUpper(k), "PROXY") {
		return false
	}
	for i, r := range k {
		if !(r == '_' || r >= 'A' && r <= 'Z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func (c Connect) validate() error {
	set := 0
	for _, b := range []bool{c.OAuth2 != nil, c.APIKey != nil, c.Provider != nil} {
		if b {
			set++
		}
	}
	if set != 1 {
		return errors.New("exactly one of oauth2, apiKey, provider")
	}
	switch c.Kind {
	case KindOAuth2:
		o := c.OAuth2
		if o == nil {
			return errors.New("kind oauth2 needs oauth2")
		}
		if o.Issuer == "" && (o.AuthorizationEndpoint == "" || o.TokenEndpoint == "") {
			return errors.New("oauth2: an issuer, or the authorization and token endpoints")
		}
		for _, u := range []string{o.Issuer, o.AuthorizationEndpoint, o.TokenEndpoint, o.RevocationEndpoint} {
			if u != "" && !httpsURL(u) {
				return fmt.Errorf("oauth2: %q is not an https URL", u)
			}
		}
		if o.ClientAuth != "" && o.ClientAuth != "basic" && o.ClientAuth != "post" {
			return errors.New(`oauth2.clientAuth: "basic" or "post"`)
		}
	case KindAPIKey:
		a := c.APIKey
		if a == nil {
			return errors.New("kind apiKey needs apiKey")
		}
		switch a.In {
		case "bearer", "basic":
		case "header", "query":
			if strings.TrimSpace(a.Name) == "" {
				return fmt.Errorf("apiKey in %s needs a name", a.In)
			}
		default:
			return errors.New(`apiKey.in: "bearer", "header", "query" or "basic"`)
		}
	case KindProvider:
		p := c.Provider
		if p == nil {
			return errors.New("kind provider needs provider")
		}
		u, err := url.Parse(p.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return errors.New("provider.url: an http(s) URL")
		}
	default:
		return errors.New(`kind: "oauth2", "apiKey" or "provider"`)
	}
	return nil
}

func httpsURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func (r Rule) validate() error {
	if len(r.Paths) == 0 {
		return errors.New("a rule needs paths")
	}
	for _, m := range r.Methods {
		if !slices.Contains(methods, m) {
			return fmt.Errorf("method %q", m)
		}
	}
	for _, p := range r.Paths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("path %q must start with /", p)
		}
	}
	if r.Body != "" {
		if _, err := regexp.Compile(r.Body); err != nil {
			return fmt.Errorf("body %q: %w", r.Body, err)
		}
	}
	return nil
}

// Handles reports whether host is one of the connector's.
func (c Connector) Handles(host string) bool { return slices.Contains(c.Hosts, host) }

// readMethods are a read rule's methods when it names none.
var readMethods = []string{"GET", "HEAD", "OPTIONS"}

// Classify sorts a request: Read, Write, or "" (refused). Read rules come
// first: a search that is a POST is a read.
func (c Connector) Classify(method, path string, body []byte) string {
	if c.Policy.matches(c.Policy.Read, readMethods, method, path, body) {
		return Read
	}
	if c.Policy.matches(c.Policy.Write, methods, method, path, body) {
		return Write
	}
	return ""
}

func (Policy) matches(rules []Rule, defaults []string, method, path string, body []byte) bool {
	for _, r := range rules {
		ms := r.Methods
		if len(ms) == 0 {
			ms = defaults
		}
		if !slices.Contains(ms, method) {
			continue
		}
		hit := false
		for _, p := range r.Paths {
			if Glob(p, path) {
				hit = true
				break
			}
		}
		if !hit {
			continue
		}
		if r.Body != "" {
			re, err := regexp.Compile(r.Body)
			if err != nil || !re.Match(body) {
				continue
			}
		}
		return true
	}
	return false
}

// Glob matches a path against a pattern: "*" is one segment, "**" any
// number of segments (none included); every other segment is literal.
func Glob(pattern, path string) bool {
	return glob(strings.Split(strings.Trim(pattern, "/"), "/"), strings.Split(strings.Trim(path, "/"), "/"))
}

func glob(p, s []string) bool {
	if len(p) == 1 && p[0] == "" {
		p = nil
	}
	if len(s) == 1 && s[0] == "" {
		s = nil
	}
	for len(p) > 0 {
		if p[0] == "**" {
			for i := 0; i <= len(s); i++ {
				if glob(p[1:], s[i:]) {
					return true
				}
			}
			return false
		}
		if len(s) == 0 || (p[0] != "*" && p[0] != s[0]) {
			return false
		}
		p, s = p[1:], s[1:]
	}
	return len(s) == 0
}

// IsExpired reports an answer matching one of the connector's expiredWhen.
func (c Connector) IsExpired(status int, location string, body []byte) bool {
	for _, e := range c.ExpiredWhen {
		if e.Status != status {
			continue
		}
		if e.LocationContains != "" && !strings.Contains(location, e.LocationContains) {
			continue
		}
		if e.BodyContains != "" && !strings.Contains(string(body), e.BodyContains) {
			continue
		}
		return true
	}
	return false
}

// CredentialHeaders are the request headers a credential may ride in: every
// one is removed from what an agent sends.
func (c Connector) CredentialHeaders() []string {
	out := []string{"Authorization", "Cookie", "Proxy-Authorization"}
	if a := c.Connect.APIKey; a != nil && a.In == "header" {
		out = append(out, a.Name)
	}
	return out
}
