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
// organization) and who it signs in as, the connector's app (the provider's name for the system),
// the reach asked (read or write), and the grant the provider gave at
// connect ("" on a first connect).
type Call struct {
	Member string `json:"member"`
	Org    string `json:"org"`
	// Principal is who the call signs in as; nil: the member. For a
	// digital worker, Member is the person who asked.
	Principal *Principal `json:"principal,omitempty"`
	App       string     `json:"app"`
	Reach     string     `json:"reach,omitempty"`
	Grant     string     `json:"grant,omitempty"`
	// Force: authorize again (the system refused what was given).
	Force bool `json:"force,omitempty"`
	// Check (connect): only report where the connection stands, never
	// prompt the member (a page waiting for their consent asks again).
	Check bool `json:"check,omitempty"`
	// Notify (connect): also prompt the member through the provider's own
	// channel (a chat card), beside the page it answers in Open.
	Notify bool `json:"notify,omitempty"`
	// Params are the connector's per-system values for the provider.
	Params map[string]string `json:"params,omitempty"`
	// Options are the member's choices on this connection, every option
	// the connector declares ("true" or "false"; connector.ProviderOption).
	Options map[string]string `json:"options,omitempty"`
	// SignedIn (authorize): the answers to the SignIn steps the provider
	// asked for, sent from the member's computer with their held session,
	// in order. The provider answers the request's headers from them.
	SignedIn []Step `json:"signedIn,omitempty"`
}

// Step is one sign-in request a member's computer sends with their held
// session (Answer.SignIn), and its answer (Call.SignedIn): Status,
// Location and the start of Body.
type Step struct {
	Method   string `json:"method"`
	URL      string `json:"url"`
	Status   int    `json:"status,omitempty"`
	Location string `json:"location,omitempty"`
	Body     []byte `json:"body,omitempty"`
}

// Principal is who a call signs in as: a member (Kind PrincipalMember, ID
// their subject) or a digital worker of the organization (Kind
// PrincipalWorker, ID its id in connections, Account its name in the
// provider's directory). A provider keeps a worker's grants apart from any
// person's.
type Principal struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Account string `json:"account,omitempty"`
}

// Principal kinds.
const (
	PrincipalMember = "member"
	PrincipalWorker = "worker"
)

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
	// Open (connect, Pending): an https page the member opens in their
	// browser to do what Pending asks (a consent page); the connection
	// completes when the provider later answers Connected.
	Open string `json:"open,omitempty"`
	// Session (authorize): the request also carries the member's session
	// held on their own computer for this connector's host
	// (docs/prd/2026-10-28-member-held-sessions.md in bnbloc), beside
	// Header; only on a connector that sends from members' computers.
	// SignIn: the steps (GET, the connector's host) their computer sends
	// with that session first, fresh; connections then asks authorize
	// again with Call.SignedIn.
	Session bool   `json:"session,omitempty"`
	SignIn  []Step `json:"signIn,omitempty"`
}
