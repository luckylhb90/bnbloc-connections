package service

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
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
	c, err := parseDraft([]byte(raw))
	if err != nil {
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

// drafting is a draft from a description under way (organization scope),
// or why it failed (Error).
type drafting struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	By          string `json:"by"`
	AtMs        int64  `json:"atMs"`
	Error       string `json:"error,omitempty"`
}

const draftingPrefix = "drafting:"

// startDrafting keeps a drafting under way and runs it off the request.
func (s *Service) startDrafting(ctx context.Context, m component.Member, description string) error {
	description = strings.TrimSpace(description)
	if description == "" {
		return errors.New("describe the system first")
	}
	d := drafting{ID: randomToken(8), Description: clip(strings.Join(strings.Fields(description), " "), 160), By: m.Subject, AtMs: s.now().UnixMilli()}
	if err := s.P.PutJSON(ctx, platform.Org(m.Org), draftingPrefix+d.ID, d); err != nil {
		return err
	}
	s.later(func() {
		ctx, cancel := aiContext()
		defer cancel()
		if _, err := s.draftFromDescription(ctx, m, description); err != nil {
			d.Error = err.Error()
			_ = s.P.PutJSON(ctx, platform.Org(m.Org), draftingPrefix+d.ID, d)
			return
		}
		_ = s.P.Delete(ctx, platform.Org(m.Org), draftingPrefix+d.ID)
	})
	return nil
}

// draftings are the organization's draftings: under way (a run that
// stopped long ago is dropped) or failed, newest first.
func (s *Service) draftings(ctx context.Context, org string) []drafting {
	keys, err := s.P.Keys(ctx, platform.Org(org))
	if err != nil {
		return nil
	}
	var out []drafting
	for _, k := range keys {
		if !strings.HasPrefix(k, draftingPrefix) {
			continue
		}
		var d drafting
		if ok, _ := s.P.GetJSON(ctx, platform.Org(org), k, &d); !ok {
			continue
		}
		if d.Error == "" && s.now().UnixMilli()-d.AtMs > aiPending.Milliseconds() {
			_ = s.P.Delete(ctx, platform.Org(org), k)
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].AtMs > out[j].AtMs })
	return out
}

// parseDraft reads an AI's connector strictly: a field connectors do not
// take is an error, never silently lost (a signature in the wrong place is
// a connector that cannot sign). The one misplacement a model makes, the
// key's sign and extra beside apiKey instead of in it, is put right first.
func parseDraft(raw []byte) (connector.Connector, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return connector.Connector{}, err
	}
	if conn, ok := doc["connect"].(map[string]any); ok {
		if key, ok := conn["apiKey"].(map[string]any); ok {
			for _, f := range []string{"sign", "extra", "exchange"} {
				if v, ok := conn[f]; ok {
					if _, has := key[f]; !has {
						key[f] = v
					}
					delete(conn, f)
				}
			}
		}
	}
	fixed, _ := json.Marshal(doc)
	dec := json.NewDecoder(strings.NewReader(string(fixed)))
	dec.DisallowUnknownFields()
	var c connector.Connector
	if err := dec.Decode(&c); err != nil {
		return connector.Connector{}, err
	}
	return c, nil
}
