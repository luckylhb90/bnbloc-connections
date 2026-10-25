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
	// Headers are set on every request to the system, whatever the agent
	// sent (a mode the system's API takes in a header, such as its
	// simulated trading).
	Headers map[string]string `json:"headers,omitempty"`
	// Answers are requests the component answers itself, never sending
	// them: a CLI's own sign-in step whose credential the component holds
	// (it exchanges the key itself, APIKey.Exchange).
	Answers []Answer `json:"answers,omitempty"`
	Guide   string   `json:"guide,omitempty"`
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
	// ScopeSeparator joins the scopes asked: " " (default, RFC 6749) or
	// "," (a provider that wants them comma-separated).
	ScopeSeparator string `json:"scopeSeparator,omitempty"`
	// RevocationAuth is how a revocation is sent: "" (RFC 7009: the token
	// in a form, with the client's credentials) or "bearer" (a POST
	// carrying the access token as a bearer, nothing else).
	RevocationAuth string `json:"revocationAuth,omitempty"`
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
	// Exchange: the key is not sent to the system as is; the component
	// trades it for a short-lived token first and sends that.
	Exchange *Exchange `json:"exchange,omitempty"`
	// Sign: the key is "<key>:<secret>"; the key is carried as In says and
	// the component signs requests with the secret (Sign).
	Sign *Sign `json:"sign,omitempty"`
	// Extra are values the member pastes beside the key (a passphrase).
	Extra []Extra `json:"extra,omitempty"`
}

// Sign signs a request with the member's secret. It applies to a request
// whose path matches Paths (every request when Paths is empty), or that
// already carries its signature (a client library that signed it with a
// placeholder secret, replaced here).
//
//   - In "query" (default): the signature goes in the query string as
//     Param, at its end; Timestamp names a query parameter added when the
//     request has none.
//   - In "header": the signature goes in the Header header and the time in
//     the Timestamp header; the query string is left as it is.
//
// Payload is what is signed: empty for the query string followed by the
// form body (signature left out of both); else a template of {timestamp},
// {method}, {path}, {query}, {pathQuery} (the path with "?query" when
// there is one), {body} and {key}, and literal text. TimestampFormat:
// "ms" (default), "s", "iso" (UTC with milliseconds, 2020-12-08T09:08:57.715Z).
// The secret's kind decides the algorithm: a shared secret HMAC-SHA256, a
// PEM private key Ed25519 or RSA PKCS#1 v1.5 SHA-256. Encoding: "hex" or
// "base64" (default: hex for HMAC, base64 for a private key).
type Sign struct {
	In              string   `json:"in,omitempty"`
	Param           string   `json:"param,omitempty"`
	Header          string   `json:"header,omitempty"`
	Timestamp       string   `json:"timestamp,omitempty"`
	TimestampFormat string   `json:"timestampFormat,omitempty"`
	Payload         string   `json:"payload,omitempty"`
	Encoding        string   `json:"encoding,omitempty"`
	Paths           []string `json:"paths,omitempty"`
}

// Extra is one more value a member pastes with their key (a passphrase),
// carried in Header on every request.
type Extra struct {
	Name   string `json:"name"`
	Label  string `json:"label"`
	Header string `json:"header"`
}

// Exchange trades a member's key for a short-lived token at one of the
// connector's hosts: a POST of Body (JSON, or a form) where "{{key}}"
// stands for the key, the token read at Token (a dotted path in the JSON
// answer) and carried as In/Name/Prefix say (like an APIKey's), kept
// until ExpiresIn (a dotted path to seconds) or TTLSeconds (default 1800)
// runs out.
type Exchange struct {
	URL        string            `json:"url"`
	Body       map[string]string `json:"body"`
	Form       bool              `json:"form,omitempty"`
	Token      string            `json:"token"`
	ExpiresIn  string            `json:"expiresIn,omitempty"`
	TTLSeconds int               `json:"ttlSeconds,omitempty"`
	In         string            `json:"in"`
	Name       string            `json:"name,omitempty"`
	Prefix     string            `json:"prefix,omitempty"`
}

// Answer is one request the component answers itself: its method and path
// glob, and the status, content type and body it answers.
type Answer struct {
	Method      string `json:"method"`
	Path        string `json:"path"`
	Status      int    `json:"status,omitempty"`
	ContentType string `json:"contentType,omitempty"`
	Body        string `json:"body"`
}

// MaxAnswerBody bounds an Answer's body.
const MaxAnswerBody = 16 << 10

// Answering is the answer c gives a request itself (ok false: none).
func (c Connector) Answering(method, path string) (Answer, bool) {
	for _, a := range c.Answers {
		if a.Method == method && Glob(a.Path, path) {
			if a.Status == 0 {
				a.Status = 200
			}
			if a.ContentType == "" {
				a.ContentType = "application/json"
			}
			return a, true
		}
	}
	return Answer{}, false
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
	for k, v := range c.Headers {
		if !headerName(k) || reservedHeader(k) || strings.ContainsAny(v, "\r\n") || len(v) > 256 {
			return fmt.Errorf("headers: %q: a header that is no credential, Host or length, with a one-line value", k)
		}
	}
	for _, a := range c.Answers {
		if !slices.Contains(methods, a.Method) || !strings.HasPrefix(a.Path, "/") {
			return fmt.Errorf("answers: %s %s: a method and a path starting with /", a.Method, a.Path)
		}
		if a.Status != 0 && (a.Status < 200 || a.Status > 599) || len(a.Body) > MaxAnswerBody || strings.ContainsAny(a.ContentType, "\r\n") {
			return fmt.Errorf("answers: %s %s: a status of 200 to 599, a body of at most %d bytes", a.Method, a.Path, MaxAnswerBody)
		}
	}
	if x := c.exchange(); x != nil {
		u, err := url.Parse(x.URL)
		if err != nil || u.Scheme != "https" || !c.Handles(u.Hostname()) || u.Port() != "" {
			return errors.New("apiKey.exchange.url: an https URL on one of the connector's hosts")
		}
		if c.FromMember() {
			return errors.New(`apiKey.exchange: the component exchanges the key itself, so its requests go out from the server (sendFrom "server")`)
		}
	}
	return nil
}

func (c Connector) exchange() *Exchange {
	if c.Connect.APIKey == nil {
		return nil
	}
	return c.Connect.APIKey.Exchange
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
		if o.ScopeSeparator != "" && o.ScopeSeparator != " " && o.ScopeSeparator != "," {
			return errors.New(`oauth2.scopeSeparator: " " (default) or ","`)
		}
		if o.RevocationAuth != "" && o.RevocationAuth != "bearer" {
			return errors.New(`oauth2.revocationAuth: "" (RFC 7009) or "bearer"`)
		}
	case KindAPIKey:
		a := c.APIKey
		if a == nil {
			return errors.New("kind apiKey needs apiKey")
		}
		if err := carried(a.In, a.Name, true); err != nil {
			return fmt.Errorf("apiKey: %w", err)
		}
		if sg := a.Sign; sg != nil {
			if err := sg.validate(); err != nil {
				return fmt.Errorf("apiKey.sign: %w", err)
			}
			if a.Exchange != nil || a.In == "basic" {
				return errors.New("apiKey.sign: no exchange, and a key not sent as basic")
			}
		}
		for _, x := range a.Extra {
			if !nameRE.MatchString(x.Name) || strings.TrimSpace(x.Label) == "" || !headerName(x.Header) {
				return fmt.Errorf("apiKey.extra %q: a name (a-z, 0-9, -), a label and a header", x.Name)
			}
		}
		if x := a.Exchange; x != nil {
			if err := carried(x.In, x.Name, false); err != nil {
				return fmt.Errorf("apiKey.exchange: %w", err)
			}
			if strings.TrimSpace(x.Token) == "" || len(x.Body) == 0 || x.TTLSeconds < 0 {
				return errors.New("apiKey.exchange: a body with {{key}}, the token's path, a TTL of 0 or more seconds")
			}
			has := false
			for _, v := range x.Body {
				has = has || strings.Contains(v, "{{key}}")
			}
			if !has {
				return errors.New("apiKey.exchange.body: a value holds {{key}}")
			}
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

func (sg Sign) validate() error {
	switch sg.In {
	case "", "query":
		if strings.TrimSpace(sg.Param) == "" {
			return errors.New("a query signature names its param")
		}
	case "header":
		if !headerName(sg.Header) || (sg.Timestamp != "" && !headerName(sg.Timestamp)) {
			return errors.New("a header signature names its header (and its timestamp's)")
		}
	default:
		return errors.New(`in: "query" or "header"`)
	}
	switch sg.TimestampFormat {
	case "", "ms", "s", "iso":
	default:
		return errors.New(`timestampFormat: "ms", "s" or "iso"`)
	}
	switch sg.Encoding {
	case "", "hex", "base64":
	default:
		return errors.New(`encoding: "hex" or "base64"`)
	}
	for _, p := range sg.Paths {
		if !strings.HasPrefix(p, "/") {
			return fmt.Errorf("paths: %q must start with /", p)
		}
	}
	return nil
}

// headerName reports an HTTP header name a connector may name.
func headerName(h string) bool {
	if h == "" || len(h) > 64 {
		return false
	}
	for _, r := range h {
		if !(r == '-' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// reservedHeader is a header a connector's Headers may not set.
func reservedHeader(h string) bool {
	switch strings.ToLower(h) {
	case "authorization", "cookie", "proxy-authorization", "host", "content-length", "transfer-encoding", "connection":
		return true
	}
	return false
}

// carried checks how a credential is carried: "bearer", "header" or
// "query" with a name, and "basic" when the key may be one.
func carried(in, name string, basic bool) error {
	switch in {
	case "bearer":
	case "basic":
		if !basic {
			return errors.New(`in: "bearer", "header" or "query"`)
		}
	case "header", "query":
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("in %s needs a name", in)
		}
	default:
		return errors.New(`in: "bearer", "header", "query" or "basic"`)
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

// ErrAmbiguousPath is a path a server may read otherwise than the policy.
var ErrAmbiguousPath = errors.New("a path with a . or .. segment, an encoded slash or a backslash is refused: send the path as the system names it")

// CheckPath refuses a request path whose meaning a server may read
// differently from how the policy reads it, so the path a rule matched is
// the path the system serves: a "." or ".." segment, also percent-encoded
// once or twice or before a ";" (a path parameter some servers strip), an
// encoded slash, or a backslash.
func CheckPath(u *url.URL) error {
	for _, seg := range strings.Split(u.EscapedPath(), "/") {
		once, err := url.PathUnescape(seg)
		if err != nil || ambiguous(once) {
			return ErrAmbiguousPath
		}
		if twice, err := url.PathUnescape(once); err == nil && ambiguous(twice) {
			return ErrAmbiguousPath
		}
	}
	return nil
}

func ambiguous(seg string) bool {
	name, _, _ := strings.Cut(seg, ";")
	return name == "." || name == ".." || strings.ContainsAny(seg, "/\\")
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
	if a := c.Connect.APIKey; a != nil {
		if a.In == "header" {
			out = append(out, a.Name)
		}
		if sg := a.Sign; sg != nil && sg.In == "header" {
			out = append(out, sg.Header)
			if sg.Timestamp != "" {
				out = append(out, sg.Timestamp)
			}
		}
		for _, x := range a.Extra {
			out = append(out, x.Header)
		}
	}
	return out
}
