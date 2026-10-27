package service

import (
	"context"
	"net/url"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc-connections/provider"
)

// A provider's consent the member gives outside bnbloc (a chat card, or the
// page provider.Answer.Open names): the connection waits for it, and
// completes without another click when the provider answers a check
// Connected: on the Connections page (which refreshes while one waits) or
// at the member's agent's next request to that system.

// consentWaitTTL is how long a connection waits for its consent; then the
// member presses Connect again.
const consentWaitTTL = 15 * time.Minute

// consentWait is one connection waiting for the member's consent.
type consentWait struct {
	Open string `json:"open"`
	AtMs int64  `json:"atMs"`
}

func consentWaitKey(org, name string) string { return "consentwait:" + org + ":" + name }

// noteWait records that member's connection to name waits for their
// consent, given at open (an https page; "" when the provider prompts them
// its own way, a chat card).
func (s *Service) noteWait(ctx context.Context, member, org, name, open string) {
	if u, err := url.Parse(open); open != "" && (err != nil || u.Scheme != "https" || u.Host == "") {
		open = ""
	}
	_ = s.P.PutJSON(ctx, platform.Member(member), consentWaitKey(org, name), consentWait{Open: open, AtMs: s.now().UnixMilli()})
}

// consentWaitFor is the member's live wait for name (ok false: none, or
// expired and dropped).
func (s *Service) consentWaitFor(ctx context.Context, member, org, name string) (consentWait, bool) {
	var w consentWait
	if ok, err := s.P.GetJSON(ctx, platform.Member(member), consentWaitKey(org, name), &w); err != nil || !ok {
		return consentWait{}, false
	}
	if s.now().UnixMilli()-w.AtMs > consentWaitTTL.Milliseconds() {
		_ = s.P.Delete(ctx, platform.Member(member), consentWaitKey(org, name))
		return consentWait{}, false
	}
	return w, true
}

// settleWait asks the provider, without prompting the member, whether the
// consent c's connection waits for has arrived, and connects the member
// when it has. It reports whether they are connected now.
func (s *Service) settleWait(ctx context.Context, member, org string, c connector.Connector) bool {
	if c.Connect.Kind != connector.KindProvider {
		return false
	}
	if _, ok := s.consentWaitFor(ctx, member, org, c.Name); !ok {
		return false
	}
	a, err := s.callProvider(ctx, c, org, provider.ConnectPath, provider.Call{Member: member, Org: org, Reach: connector.Read, Check: true})
	if err != nil || a.Status != provider.Connected {
		return false
	}
	if err := s.saveGrant(ctx, member, org, Grant{Connector: c.Name, Reach: connector.Read, ProviderGrant: a.Grant, ConnectedAtMs: s.now().UnixMilli()}); err != nil {
		return false
	}
	_ = s.P.Delete(ctx, platform.Member(member), consentWaitKey(org, c.Name))
	return true
}
