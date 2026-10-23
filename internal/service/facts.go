package service

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc/component"
)

// handleFacts gives the turn its line and files: the systems the agent
// reaches and as whom (INDEX.md), each one's guide, the person's recent
// calls in this room (ACTIVITY.md), and, for the person's own agent, how
// to draft a connector. A borrowed or platform agent gets only the systems
// a digital worker serves it at; an organization with nothing enabled,
// nothing.
func (s *Service) handleFacts(w http.ResponseWriter, r *http.Request, t component.Turn, _ []byte) {
	systems, err := s.systemsFor(r.Context(), t)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "connectors unreadable"})
		return
	}
	if t.Drive != component.DriveOwn {
		systems = slices.DeleteFunc(systems, func(v SystemView) bool { return !v.Connected })
	}
	if len(systems) == 0 {
		writeJSON(w, http.StatusOK, component.Facts{})
		return
	}
	writeJSON(w, http.StatusOK, s.facts(r.Context(), t, systems))
}

func (s *Service) facts(ctx context.Context, t component.Turn, systems []SystemView) component.Facts {
	names := make([]string, 0, len(systems))
	shown := map[string]bool{}
	for _, v := range systems {
		shown[v.Name] = true
		if v.As != "" {
			names = append(names, v.Name+" (as "+v.As+")")
			continue
		}
		names = append(names, v.Name)
	}
	line := fmt.Sprintf("systems you reach as %s with plain HTTPS (curl, scripts, CLIs): %s; INDEX.md says what each is for", t.Requester, strings.Join(names, ", "))
	if len([]rune(line)) > component.MaxFactsLine {
		line = fmt.Sprintf("%d systems you reach with plain HTTPS; INDEX.md lists them and as whom", len(names))
	}
	files := map[string]string{"INDEX.md": s.index(t, systems)}
	if t.Drive == component.DriveOwn {
		files["DRAFTING.md"] = s.drafting()
	}
	list, _ := s.enabled(ctx, t.Org)
	budget := component.MaxFactsBytes - len(files["INDEX.md"]) - len(files["DRAFTING.md"]) - 8<<10
	for _, c := range list {
		if !shown[c.Name] {
			continue
		}
		g := guide(c)
		if len(g) > budget || len(files) >= component.MaxFactsFiles-1 {
			continue
		}
		budget -= len(g)
		files[c.Name+".md"] = g
	}
	if a := activityFile(s.activity(ctx, t.Requester, t.Org), t.Room); len(a) <= budget+8<<10 {
		files["ACTIVITY.md"] = a
	}
	return component.Facts{Line: line, Files: files}
}

func (s *Service) index(t component.Turn, systems []SystemView) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Systems you reach as %s\n\n", t.Requester)
	b.WriteString("Call them with ordinary HTTPS (curl, a script, a CLI): bnbloc authenticates each request as the person on its way out. Never ask for a token and never send one: any credential you send is replaced.\n\n")
	b.WriteString("- Not connected: the call answers 403 and the person gets a card to connect it. Tell them, and continue after they do.\n")
	b.WriteString("- A change (`changes: asked`) answers 202 `held`: the person gets a card to allow it. It is not made until they do; say so, do not retry.\n\n")
	b.WriteString("| System | Hosts | For | Connected | Changes | As |\n|---|---|---|---|---|---|\n")
	for _, v := range systems {
		conn, changes, as := "no", "-", "-"
		if v.Connected {
			conn, changes, as = "yes", v.Changes, t.Requester
			if v.As != "" {
				as = v.As + " (a digital worker; " + t.Requester + " asked)"
			}
		}
		fmt.Fprintf(&b, "| %s (`%s`, guide: %s.md) | %s | %s | %s | %s | %s |\n", v.DisplayName, v.Name, v.Name, strings.Join(v.Hosts, ", "), v.Purpose, conn, changes, as)
	}
	if t.Drive == component.DriveOwn {
		fmt.Fprintf(&b, "\nThe connections API itself is `https://%s/` (GET / lists it): the systems' state, the person's recent calls, and connector drafts (DRAFTING.md).\n", s.SelfHost())
	}
	return b.String()
}

func guide(c connector.Connector) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n%s\n\nHosts: %s\n\n", c.DisplayName, c.Purpose, strings.Join(c.Hosts, ", "))
	if strings.TrimSpace(c.Guide) != "" {
		b.WriteString(strings.TrimSpace(c.Guide))
		b.WriteString("\n")
	}
	return b.String()
}

func activityFile(calls []Call, room string) string {
	var b strings.Builder
	b.WriteString("# Recent calls through connections in this room\n\nNewest last; method and path only.\n\n")
	n := 0
	for _, c := range calls {
		if c.Room != room {
			continue
		}
		n++
		status := ""
		if c.Status > 0 {
			status = fmt.Sprintf(" %d", c.Status)
		}
		fmt.Fprintf(&b, "- %s %s %s %s%s (%s)\n", time.UnixMilli(c.AtMs).UTC().Format("2006-01-02 15:04Z"), c.Connector, c.Method, c.Path, status, c.Outcome)
	}
	if n == 0 {
		b.WriteString("None yet.\n")
	}
	return b.String()
}

func (s *Service) drafting() string {
	return "# Drafting a connector\n\n" +
		"When the person asks to connect a system that INDEX.md does not list, read the system's API description and draft a connector: " +
		"`POST https://" + s.SelfHost() + "/drafts` with its JSON. An admin of the organization reviews it and enables it or not; nothing is reachable before that.\n\n" +
		"```json\n" + draftExample + "\n```\n\n" +
		"- `hosts`: exact names. `connect.kind`: `oauth2` (issuer or endpoints, scopes read/write), `apiKey` (`in`: bearer, header, query or basic), or `provider`.\n" +
		"- `policy.read`: what reads (a POST search can be one, with a `body` regexp); `policy.write`: what changes. Anything else is refused.\n" +
		"- `expiredWhen`: how the system says a sign-in ended when that is not a 401.\n" +
		"- `guide`: Markdown with curl examples for agents.\n"
}

const draftExample = `{
  "name": "issues",
  "displayName": "Issue tracker",
  "purpose": "Bugs and tasks",
  "hosts": ["issues.example.com"],
  "connect": {"kind": "apiKey", "apiKey": {"in": "bearer", "help": "Profile → Tokens"}},
  "policy": {
    "read": [{"paths": ["/api/**"]}, {"methods": ["POST"], "paths": ["/api/search"]}],
    "write": [{"methods": ["POST", "PUT", "DELETE"], "paths": ["/api/**"]}]
  },
  "guide": "curl https://issues.example.com/api/issue/PROJ-1"
}`
