package service

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
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

// appScheme is an app link's scheme (a chat app's own link that opens its
// consent screen); browser-internal and script schemes never are.
var appScheme = regexp.MustCompile(`^[a-z][a-z0-9+.-]{1,31}$`)

var notAppSchemes = []string{"http", "https", "javascript", "data", "file", "vbscript", "about", "blob", "filesystem", "view-source", "chrome", "intent"}

// openable reports where the member may be sent to consent: an https page,
// or an app link (app: the member's own app opens it; the page stays).
func openable(open string) (ok, app bool) {
	u, err := url.Parse(open)
	if err != nil {
		return false, false
	}
	scheme := strings.ToLower(u.Scheme)
	switch {
	case scheme == "https" && u.Host != "":
		return true, false
	case appScheme.MatchString(scheme) && !slices.Contains(notAppSchemes, scheme):
		return true, true
	}
	return false, false
}

// noteWait records that member's connection to name waits for their
// consent, given at open (openable; "" when the provider prompts them its
// own way only, a chat card).
func (s *Service) noteWait(ctx context.Context, member, org, name, open string) {
	if ok, _ := openable(open); !ok {
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

// liveTemplate answers the hidden frame that follows a page's waits
// (layout.html): it reloads itself every 5 seconds and tells the page when
// what it waits for changed. A sandboxed page cannot read itself with
// fetch (its origin is opaque); a message between frames needs no origin.
var liveTemplate = template.Must(template.New("live").Parse(`<!doctype html><meta http-equiv="refresh" content="5"><script>if ({{.State}} !== {{.Expect}}) parent.postMessage("bnbloc-live-changed", "*");</script>`))

// writeLive answers a page's hidden follower: state is what the page waits
// for now, expect what the page showed.
func writeLive(w http.ResponseWriter, state, expect string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = liveTemplate.Execute(w, map[string]string{"State": state, "Expect": expect})
}
