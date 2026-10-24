package service

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc/component"
)

// Configuration, AI first (docs/prd/2026-10-25-connections-smooth.md in
// bnbloc): an admin describes the system in their words and the AI drafts
// the connector (a draft, reviewed like an agent's); a review finding comes
// with the change that fixes it, which the admin applies in one click. The
// JSON stays the manual path beside both; nothing is enabled or changed
// without the admin's click.

const taskDraft = "draft-connector"

// draftFromDescription asks the AI for a connector from the admin's words
// (and anything pasted: an API's documentation), kept as a draft.
func (s *Service) draftFromDescription(ctx context.Context, m component.Member, description string) (Draft, error) {
	description = strings.TrimSpace(description)
	if description == "" {
		return Draft{}, errors.New("describe the system first")
	}
	fields, err := s.assist(ctx, taskDraft, m.Org, m.Subject, "What the administrator wants to connect, in their words (and anything they pasted):\n"+description)
	if err != nil {
		return Draft{}, errors.New(aiError(err))
	}
	raw := strings.TrimSpace(textField(fields, "connector", 16<<10))
	raw = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(raw, "```json"), "```"), "```")
	var c connector.Connector
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return Draft{}, errors.New("the AI's draft is not a connector's JSON: " + err.Error())
	}
	c.Enabled = false
	if err := c.Validate(); err != nil {
		return Draft{}, errors.New("the AI's draft is not a valid connector (" + err.Error() + "): describe it again, or paste the JSON")
	}
	d := Draft{Connector: c, DraftedBy: m.Subject + " (described, drafted by AI)", CreatedAtMs: s.now().UnixMilli()}
	if notes := textField(fields, "notes", 600); notes != "" {
		d.Notes = notes
	}
	if err := s.P.PutJSON(ctx, platform.Org(m.Org), draftPrefix+c.Name, d); err != nil {
		return Draft{}, err
	}
	s.ensureReview(ctx, m.Org, m.Subject, c, true, true)
	return d, nil
}

// fixed is c with a review's fix (a JSON merge patch) applied, valid; a fix
// never enables, disables or moves where requests go out from.
func fixed(c connector.Connector, patch string) (connector.Connector, error) {
	var p map[string]any
	if err := json.Unmarshal([]byte(patch), &p); err != nil || len(p) == 0 {
		return c, errors.New("not a JSON merge patch")
	}
	for _, k := range []string{"enabled", "sendFrom", "name"} {
		if _, ok := p[k]; ok {
			return c, errors.New("a fix does not change " + k)
		}
	}
	raw, _ := json.Marshal(c)
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	merged, _ := json.Marshal(mergePatch(doc, p))
	var out connector.Connector
	if err := json.Unmarshal(merged, &out); err != nil {
		return c, err
	}
	out.Enabled, out.SendFrom, out.Name = c.Enabled, c.SendFrom, c.Name
	return out, out.Validate()
}

// mergePatch applies an RFC 7386 merge patch.
func mergePatch(doc, patch map[string]any) map[string]any {
	if doc == nil {
		doc = map[string]any{}
	}
	for k, v := range patch {
		switch pv := v.(type) {
		case nil:
			delete(doc, k)
		case map[string]any:
			sub, _ := doc[k].(map[string]any)
			doc[k] = mergePatch(sub, pv)
		default:
			doc[k] = v
		}
	}
	return doc
}

// applyFix applies the review's fix i of connector name.
func (s *Service) applyFix(ctx context.Context, org, name string, i int) (connector.Connector, error) {
	var c connector.Connector
	if found, err := s.P.GetJSON(ctx, platform.Org(org), connectorPrefix+name, &c); err != nil || !found {
		return c, errors.New("no such connector")
	}
	r := s.review(ctx, org, name, false)
	if r.Hash != reviewHash(c) || i < 0 || i >= len(r.Findings) || r.Findings[i].Fix == "" {
		return c, errors.New("that fix is gone: the connector changed since the review")
	}
	next, err := fixed(c, r.Findings[i].Fix)
	if err != nil {
		return c, err
	}
	return next, s.saveConnector(ctx, org, next)
}
