// Package provider is the connections component's provider contract: a
// provider is another component that connects a member to systems by its
// own protocol (an organization's single sign-on, a vault) and authorizes
// each request with what that protocol gives. The connections component
// calls it; it never calls the connections component.
//
// Every call is a POST of JSON, signed with the secret the organization's
// admin set for the connector (Sign over the body, header SignatureHeader),
// answered with JSON. A provider keeps what it obtains itself, keyed by
// Grant, and never returns the member's long-lived credential: only what
// one request carries, until a given time.
package provider

import (
	"time"

	"github.com/luckylhb90/bnbloc/component"
)

// Contract paths, appended to the connector's provider URL.
const (
	ConnectPath   = "/connect"
	AuthorizePath = "/authorize"
	RevokePath    = "/revoke"
)

// SignatureHeader carries the call's signature (component.Sign over the
// raw body with the connector's provider secret).
const SignatureHeader = component.SignatureHeader

// Sign signs a body.
func Sign(secret string, now time.Time, body []byte) string { return component.Sign(secret, now, body) }

// Verify checks a body's signature (component.SignatureTolerance).
func Verify(header, secret string, body []byte, now time.Time) error {
	return component.Verify(header, secret, body, now, component.SignatureTolerance)
}

// Call is what every call carries: the member (their subject in bnbloc and
// organization), the connector's app (the provider's name for the system),
// the reach asked (read or write), and the grant the provider gave at
// connect ("" on a first connect).
type Call struct {
	Member string `json:"member"`
	Org    string `json:"org"`
	App    string `json:"app"`
	Reach  string `json:"reach,omitempty"`
	Grant  string `json:"grant,omitempty"`
	// Force: authorize again (the system refused what was given).
	Force bool `json:"force,omitempty"`
	// Params are the connector's per-system values for the provider.
	Params map[string]string `json:"params,omitempty"`
}

// Connect states.
const (
	Connected = "connected"
	// Pending: the member must do something outside bnbloc first (answer a
	// consent card); connect again later.
	Pending = "pending"
	Failed  = "failed"
)

// Answer is a provider's answer. Connect: Status (Grant when connected),
// Message for the member. Authorize: Header and Cookies one request
// carries until ExpiresAtMs (a Grant replaces the one kept); Status Failed
// with Reconnect when the grant no longer works. Admin marks a refusal that is an administrator's to fix
// (the platform's access to a system not arranged yet), never the member's.
type Answer struct {
	Status      string            `json:"status"`
	Message     string            `json:"message,omitempty"`
	Grant       string            `json:"grant,omitempty"`
	Header      map[string]string `json:"header,omitempty"`
	Cookies     map[string]string `json:"cookies,omitempty"`
	ExpiresAtMs int64             `json:"expiresAtMs,omitempty"`
	Reconnect   bool              `json:"reconnect,omitempty"`
	Admin       bool              `json:"admin,omitempty"`
}
