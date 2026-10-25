package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc/component"
)

// The component's own AI, for the admin (docs/prd/2026-10-23-connections-ai.md
// in bnbloc): a review of every connector before it is enabled, and rules
// proposed from how a connector is used. Both run through the platform's
// assist primitive (component.ServiceClient.Assist) on the organization's
// model, off every request's path, and only propose: an admin decides.
// Nothing here reaches an agent.

// The tasks, named after the component (component.ServiceAssistTask); the
// prompts are content (content/ in this repository).
const (
	taskReview  = "review-connector"
	taskPropose = "propose-rules"
)

func (s *Service) task(name string) string { return s.P.Name + "-" + name }

// Store keys of the AI's records, all in the organization's scope.
const (
	reviewPrefix      = "review:"      // a connector's Review
	draftReviewPrefix = "draftreview:" // a draft's Review
	signalsPrefix     = "signals:"     // a connector's []Signal
	proposalPrefix    = "proposal:"    // a connector's Proposal
)

// aiPending bounds how long a run is taken to be under way; a failed
// review is tried again after retryFailed.
const (
	aiPending   = 2 * time.Minute
	retryFailed = 10 * time.Minute
)

// later runs f off the request (tests run it at once).
func (s *Service) later(f func()) {
	if s.Later != nil {
		s.Later(f)
		return
	}
	go f()
}

// aiContext is a run's own context, apart from the request that started it.
func aiContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), aiPending)
}

// assist runs one of the component's tasks for org, for member.
func (s *Service) assist(ctx context.Context, task, org, member, text string) (map[string]any, error) {
	if len([]rune(text)) > component.MaxServiceAssistText {
		text = string([]rune(text)[:component.MaxServiceAssistText])
	}
	return s.P.Assist(ctx, s.task(task), component.ServiceAssistRequest{Org: org, Member: member, Text: text})
}

// assistChecked runs one of the component's tasks and checks its answer
// with check (code, or reality), revising it with the problems found
// (component.ServiceClient.AssistChecked, at most 3 rounds). It answers
// the last fields and the problems still left (none: they passed).
func (s *Service) assistChecked(ctx context.Context, task, org, member, text string, urls []string, check func(map[string]any) []string) (map[string]any, []string, error) {
	if len([]rune(text)) > component.MaxServiceAssistText {
		text = string([]rune(text)[:component.MaxServiceAssistText])
	}
	return s.P.AssistChecked(ctx, s.task(task), component.ServiceAssistRequest{Org: org, Member: member, Text: text, URLs: urls}, check, component.MaxAssistRounds)
}

// aiError is what a page says about a run that did not happen.
func aiError(err error) string {
	if errors.Is(err, component.ErrAssistUnavailable) {
		return "AI is not available here: " + strings.TrimPrefix(err.Error(), component.ErrAssistUnavailable.Error()+": ")
	}
	return "the AI run failed: " + err.Error()
}

// Reply readers: a model's reply, held to what a page shows.

func textField(f map[string]any, name string, max int) string {
	v, _ := f[name].(string)
	return clip(strings.TrimSpace(v), max)
}

func listField(f map[string]any, name string, max int) []string {
	raw, _ := f[name].([]any)
	var out []string
	for _, v := range raw {
		if s, _ := v.(string); strings.TrimSpace(s) != "" && len(out) < max {
			out = append(out, clip(strings.TrimSpace(s), 300))
		}
	}
	return out
}

func itemsField(f map[string]any, name string, max int) []map[string]string {
	raw, _ := f[name].([]any)
	var out []map[string]string
	for _, v := range raw {
		obj, _ := v.(map[string]any)
		if obj == nil || len(out) >= max {
			continue
		}
		item := map[string]string{}
		for k, x := range obj {
			if s, ok := x.(string); ok {
				item[k] = strings.TrimSpace(s)
			}
		}
		out = append(out, item)
	}
	return out
}

// ---- The review --------------------------------------------------------

// Review is the AI's review of one connector as it was (Hash): what agents
// can do with it, and what looks wrong.
type Review struct {
	Hash    string `json:"hash"`
	AtMs    int64  `json:"atMs"`
	Pending bool   `json:"pending,omitempty"`
	Error   string `json:"error,omitempty"`
	Summary string `json:"summary,omitempty"`
	// Tried is the failed test the review was given (Try it).
	Tried    string    `json:"tried,omitempty"`
	Reads    []string  `json:"reads,omitempty"`
	Changes  []string  `json:"changes,omitempty"`
	Findings []Finding `json:"findings,omitempty"`
}

// Finding is one problem the review found.
type Finding struct {
	Severity string `json:"severity"`
	About    string `json:"about"`
	Why      string `json:"why"`
	// Fix is a JSON merge patch (RFC 7386) of the connector the review
	// proposes, kept only when it makes a valid connector (fixed).
	Fix string `json:"fix,omitempty"`
}

// Severities, most severe first.
var severities = []string{"high", "medium", "low"}

// High counts the review's high findings.
func (r Review) High() int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == "high" {
			n++
		}
	}
	return n
}

// stale reports a review that no longer describes the connector, a run
// that stopped, or a failed run worth trying again.
func (r Review) stale(hash string, now time.Time) bool {
	age := now.UnixMilli() - r.AtMs
	switch {
	case r.Hash != hash:
		return true
	case r.Pending:
		return age > aiPending.Milliseconds()
	case r.Error != "":
		return age > retryFailed.Milliseconds()
	}
	return false
}

// reviewed is what a review reads: the connector without whether it is
// enabled or where its requests go out from.
func reviewed(c connector.Connector) connector.Connector {
	c.Enabled, c.SendFrom = false, ""
	return c
}

func reviewHash(c connector.Connector) string {
	raw, _ := json.Marshal(reviewed(c))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:8])
}

func reviewKey(name string, draft bool) string {
	if draft {
		return draftReviewPrefix + name
	}
	return reviewPrefix + name
}

// review is the stored review of a connector or a draft.
func (s *Service) review(ctx context.Context, org, name string, draft bool) Review {
	var r Review
	_, _ = s.P.GetJSON(ctx, platform.Org(org), reviewKey(name, draft), &r)
	return r
}

// ensureReview starts a review of c unless one describes it (force: again
// anyway), and answers the review as it stands.
func (s *Service) ensureReview(ctx context.Context, org, member string, c connector.Connector, draft, force bool) Review {
	r := s.review(ctx, org, c.Name, draft)
	hash := reviewHash(c)
	if !force && !r.stale(hash, s.now()) {
		return r
	}
	r = Review{Hash: hash, AtMs: s.now().UnixMilli(), Pending: true}
	if err := s.P.PutJSON(ctx, platform.Org(org), reviewKey(c.Name, draft), r); err != nil {
		slog.Warn("connections: review not started", "connector", c.Name, "error", err)
		return Review{}
	}
	s.later(func() { s.runReview(org, member, c, draft, hash) })
	return s.review(ctx, org, c.Name, draft)
}

func (s *Service) runReview(org, member string, c connector.Connector, draft bool, hash string) {
	ctx, cancel := aiContext()
	defer cancel()
	raw, _ := json.MarshalIndent(reviewed(c), "", "  ")
	out := Review{Hash: hash, AtMs: s.now().UnixMilli()}
	text := "The connector an administrator is about to enable (JSON):\n" + string(raw)
	if t, ok := s.lastTry(ctx, org, c.Name, hash); ok && !t.OK && !draft {
		// Reality's word: what the system answered the connector's test.
		text += "\n\nThe connector's test request was tried with the administrator's own connection and failed:\n" + t.Line
		out.Tried = t.Line
	}
	// A fix is checked like any connector: one that does not make a valid
	// connector goes back to the model with why.
	check := func(f map[string]any) []string {
		var problems []string
		for i, it := range itemsField(f, "findings", 12) {
			if fx := strings.TrimSpace(it["fix"]); fx != "" {
				if _, err := fixed(c, fx); err != nil {
					problems = append(problems, fmt.Sprintf("finding %d (%s): its fix does not make a valid connector: %v", i+1, clip(it["about"], 60), err))
				}
			}
		}
		return problems
	}
	fields, _, err := s.assistChecked(ctx, taskReview, org, member, text, nil, check)
	if err != nil {
		slog.Warn("connections: review failed", "connector", c.Name, "error", err)
		out.Error = aiError(err)
	} else {
		out.Summary = textField(fields, "summary", 600)
		out.Reads = listField(fields, "reads", 12)
		out.Changes = listField(fields, "changes", 12)
		for _, it := range itemsField(fields, "findings", 12) {
			sev := strings.ToLower(it["severity"])
			if !slices.Contains(severities, sev) || it["why"] == "" {
				continue
			}
			f := Finding{Severity: sev, About: clip(it["about"], 200), Why: clip(it["why"], 500)}
			if fx := strings.TrimSpace(it["fix"]); fx != "" && len(fx) <= 8<<10 {
				if _, err := fixed(c, fx); err == nil {
					f.Fix = fx
				}
			}
			out.Findings = append(out.Findings, f)
		}
		sort.SliceStable(out.Findings, func(i, j int) bool {
			return slices.Index(severities, out.Findings[i].Severity) < slices.Index(severities, out.Findings[j].Severity)
		})
	}
	// A newer edit started its own review: this one is not kept.
	if cur := s.review(ctx, org, c.Name, draft); cur.Hash != hash {
		return
	}
	if err := s.P.PutJSON(ctx, platform.Org(org), reviewKey(c.Name, draft), out); err != nil {
		slog.Warn("connections: review not kept", "connector", c.Name, "error", err)
	}
}

// ---- Signals and proposals ---------------------------------------------

// Signal is one request shape seen for a connector: a request no rule
// classifies (refused) or a held change members allowed (allowed); the
// method and path only, never the query or the body.
type Signal struct {
	Method   string `json:"method"`
	Path     string `json:"path"`
	Outcome  string `json:"outcome"`
	Count    int    `json:"count"`
	LastAtMs int64  `json:"lastAtMs"`
}

// Signal outcomes.
const (
	signalRefused = "refused"
	signalAllowed = "allowed"
)

// maxSignals bounds the shapes kept per connector (the oldest go first);
// allowedAgain is how many allows of one change prompt a proposal;
// proposeEvery is how often a connector's proposal may run on its own.
const (
	maxSignals   = 50
	allowedAgain = 3
	proposeEvery = time.Hour
)

var signalsMu sync.Mutex

func (s *Service) signals(ctx context.Context, org, name string) []Signal {
	var list []Signal
	_, _ = s.P.GetJSON(ctx, platform.Org(org), signalsPrefix+name, &list)
	return list
}

// signal records one request shape and, when it is news (a new refused
// shape, or a change allowed allowedAgain times), proposes rules.
func (s *Service) signal(ctx context.Context, org string, c connector.Connector, method, path, outcome string) {
	signalsMu.Lock()
	list := s.signals(ctx, org, c.Name)
	path = clip(path, 200)
	i := slices.IndexFunc(list, func(x Signal) bool { return x.Method == method && x.Path == path && x.Outcome == outcome })
	if i < 0 {
		list = append(list, Signal{Method: method, Path: path, Outcome: outcome})
		i = len(list) - 1
	}
	list[i].Count++
	list[i].LastAtMs = s.now().UnixMilli()
	news := (outcome == signalRefused && list[i].Count == 1) || (outcome == signalAllowed && list[i].Count == allowedAgain)
	if len(list) > maxSignals {
		sort.SliceStable(list, func(a, b int) bool { return list[a].LastAtMs > list[b].LastAtMs })
		list = list[:maxSignals]
	}
	err := s.P.PutJSON(ctx, platform.Org(org), signalsPrefix+c.Name, list)
	signalsMu.Unlock()
	if err != nil {
		slog.Warn("connections: signal not kept", "connector", c.Name, "error", err)
		return
	}
	if news && s.now().UnixMilli()-s.proposal(ctx, org, c.Name).AtMs > proposeEvery.Milliseconds() {
		s.startProposal(ctx, org, "", c)
	}
}

// Proposal is the AI's last proposal of rules for one connector.
type Proposal struct {
	AtMs    int64          `json:"atMs"`
	Pending bool           `json:"pending,omitempty"`
	Error   string         `json:"error,omitempty"`
	Rules   []ProposedRule `json:"rules,omitempty"`
	Notes   string         `json:"notes,omitempty"`
}

// ProposedRule is one rule the AI proposes: a read or a change, the
// method and the path glob, why, and how many recorded requests it
// classifies.
type ProposedRule struct {
	ID      string `json:"id"`
	Class   string `json:"class"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Why     string `json:"why"`
	Matches int    `json:"matches"`
}

func (s *Service) proposal(ctx context.Context, org, name string) Proposal {
	var p Proposal
	_, _ = s.P.GetJSON(ctx, platform.Org(org), proposalPrefix+name, &p)
	return p
}

// startProposal runs a proposal for c unless one is under way.
func (s *Service) startProposal(ctx context.Context, org, member string, c connector.Connector) {
	if p := s.proposal(ctx, org, c.Name); p.Pending && s.now().UnixMilli()-p.AtMs <= aiPending.Milliseconds() {
		return
	}
	if len(s.signals(ctx, org, c.Name)) == 0 {
		return
	}
	if err := s.P.PutJSON(ctx, platform.Org(org), proposalPrefix+c.Name, Proposal{AtMs: s.now().UnixMilli(), Pending: true}); err != nil {
		slog.Warn("connections: proposal not started", "connector", c.Name, "error", err)
		return
	}
	s.later(func() { s.runProposal(org, member, c.Name) })
}

func (s *Service) runProposal(org, member, name string) {
	ctx, cancel := aiContext()
	defer cancel()
	var c connector.Connector
	if found, err := s.P.GetJSON(ctx, platform.Org(org), connectorPrefix+name, &c); err != nil || !found {
		_ = s.P.Delete(ctx, platform.Org(org), proposalPrefix+name)
		return
	}
	signals := s.signals(ctx, org, name)
	out := Proposal{AtMs: s.now().UnixMilli()}
	fields, err := s.assist(ctx, taskPropose, org, member, proposalInput(c, signals))
	if err != nil {
		slog.Warn("connections: proposal failed", "connector", name, "error", err)
		out.Error = aiError(err)
	} else {
		out.Notes = textField(fields, "notes", 600)
		for _, it := range itemsField(fields, "rules", 12) {
			if r, ok := proposedRule(c, signals, it); ok && !slices.ContainsFunc(out.Rules, func(x ProposedRule) bool { return x.ID == r.ID }) {
				out.Rules = append(out.Rules, r)
			}
		}
	}
	if err := s.P.PutJSON(ctx, platform.Org(org), proposalPrefix+name, out); err != nil {
		slog.Warn("connections: proposal not kept", "connector", name, "error", err)
	}
}

// proposalInput is what a proposal reads: the connector's policy and the
// requests seen.
func proposalInput(c connector.Connector, signals []Signal) string {
	raw, _ := json.MarshalIndent(map[string]any{"name": c.Name, "purpose": c.Purpose, "hosts": c.Hosts, "policy": c.Policy}, "", "  ")
	var b strings.Builder
	b.WriteString("The connector and its policy (JSON):\n")
	b.Write(raw)
	b.WriteString("\n\nRequests seen (method, path, what happened, how often):\n")
	for _, sig := range signals {
		what := "refused: no rule classifies it"
		if sig.Outcome == signalAllowed {
			what = "a change that members allowed"
		}
		fmt.Fprintf(&b, "- %s %s: %s (%d)\n", sig.Method, sig.Path, what, sig.Count)
	}
	return b.String()
}

// proposedRule holds one proposed rule to what an admin can add: a read or
// a change, one method, a path the connector's rules accept, classifying a
// recorded request the policy does not already classify that way.
func proposedRule(c connector.Connector, signals []Signal, it map[string]string) (ProposedRule, bool) {
	r := ProposedRule{Class: strings.ToLower(it["class"]), Method: strings.ToUpper(it["method"]), Path: it["path"], Why: clip(it["why"], 400)}
	if r.Class != connector.Read && r.Class != connector.Write {
		return ProposedRule{}, false
	}
	if _, err := withRule(c, r); err != nil {
		return ProposedRule{}, false
	}
	for _, sig := range signals {
		if sig.Method == r.Method && connector.Glob(r.Path, sig.Path) && c.Classify(sig.Method, sig.Path, nil) != r.Class {
			r.Matches += sig.Count
		}
	}
	if r.Matches == 0 {
		return ProposedRule{}, false
	}
	sum := sha256.Sum256([]byte(r.Class + " " + r.Method + " " + r.Path))
	r.ID = hex.EncodeToString(sum[:6])
	return r, true
}

// withRule is c with r added to its policy, checked like any connector.
func withRule(c connector.Connector, r ProposedRule) (connector.Connector, error) {
	rule := connector.Rule{Methods: []string{r.Method}, Paths: []string{r.Path}}
	p := c.Policy
	if r.Class == connector.Read {
		p.Read = append(slices.Clone(p.Read), rule)
	} else {
		p.Write = append(slices.Clone(p.Write), rule)
	}
	c.Policy = p
	return c, c.Validate()
}

// addProposedRule adds one proposed rule to the connector, drops the
// signals it now classifies and the rule from the proposal.
func (s *Service) addProposedRule(ctx context.Context, org, name, id string) (connector.Connector, ProposedRule, error) {
	var c connector.Connector
	if found, err := s.P.GetJSON(ctx, platform.Org(org), connectorPrefix+name, &c); err != nil || !found {
		return c, ProposedRule{}, errors.New("no such connector")
	}
	p := s.proposal(ctx, org, name)
	i := slices.IndexFunc(p.Rules, func(r ProposedRule) bool { return r.ID == id })
	if i < 0 {
		return c, ProposedRule{}, errors.New("that suggestion is gone")
	}
	r := p.Rules[i]
	next, err := withRule(c, r)
	if err != nil {
		return c, r, err
	}
	if err := s.saveConnector(ctx, org, next); err != nil {
		return c, r, err
	}
	p.Rules = slices.Delete(p.Rules, i, i+1)
	_ = s.P.PutJSON(ctx, platform.Org(org), proposalPrefix+name, p)
	signalsMu.Lock()
	defer signalsMu.Unlock()
	kept := slices.DeleteFunc(s.signals(ctx, org, name), func(sig Signal) bool {
		return sig.Method == r.Method && connector.Glob(r.Path, sig.Path)
	})
	_ = s.P.PutJSON(ctx, platform.Org(org), signalsPrefix+name, kept)
	return next, r, nil
}

// dismissProposedRule drops one proposed rule.
func (s *Service) dismissProposedRule(ctx context.Context, org, name, id string) {
	p := s.proposal(ctx, org, name)
	p.Rules = slices.DeleteFunc(p.Rules, func(r ProposedRule) bool { return r.ID == id })
	_ = s.P.PutJSON(ctx, platform.Org(org), proposalPrefix+name, p)
}

// forgetAI drops a removed connector's review, signals and proposal.
func (s *Service) forgetAI(ctx context.Context, org, name string) {
	for _, k := range []string{reviewPrefix, signalsPrefix, proposalPrefix} {
		_ = s.P.Delete(ctx, platform.Org(org), k+name)
	}
}
