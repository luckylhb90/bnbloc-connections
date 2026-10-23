package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc/component"
)

// The component's own API for the person's agent, at SelfHost through
// egress like any system: the systems and their state, the person's recent
// calls, and connector drafts an admin reviews.

// SystemView is one system as the agent sees it.
type SystemView struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Purpose     string   `json:"purpose"`
	Hosts       []string `json:"hosts"`
	Connected   bool     `json:"connected"`
	// Changes: "allowed" (made without asking), "asked" (each one waits for
	// the person), "" when not connected.
	Changes string `json:"changes,omitempty"`
}

// Draft is a connector an agent drafted, waiting for an admin.
type Draft struct {
	Connector   connector.Connector `json:"connector"`
	DraftedBy   string              `json:"draftedBy"`
	Room        string              `json:"room"`
	CreatedAtMs int64               `json:"createdAtMs"`
}

func jsonAnswer(status int, v any) component.EgressResponse {
	raw, _ := json.MarshalIndent(v, "", "  ")
	return component.EgressResponse{Status: status, Header: map[string][]string{"Content-Type": {"application/json"}}, Body: raw}
}

func (s *Service) systems(ctx context.Context, member, org string) ([]SystemView, error) {
	list, err := s.enabled(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]SystemView, 0, len(list))
	for _, c := range list {
		v := SystemView{Name: c.Name, DisplayName: c.DisplayName, Purpose: c.Purpose, Hosts: c.Hosts}
		if g, ok, _ := s.grant(ctx, member, org, c.Name); ok {
			v.Connected, v.Changes = true, "asked"
			if g.Reach == connector.Write {
				v.Changes = "allowed"
			}
		}
		out = append(out, v)
	}
	return out, nil
}

func (s *Service) selfAPI(ctx context.Context, t component.Turn, in component.EgressRequest, u *url.URL) component.EgressResponse {
	switch {
	case in.Method == http.MethodGet && (u.Path == "/" || u.Path == ""):
		return jsonAnswer(http.StatusOK, map[string]any{
			"about": "bnbloc connections: the systems you reach as " + t.Requester + " with plain HTTPS",
			"endpoints": map[string]string{
				"GET /systems":  "the systems, connected or not",
				"GET /activity": "the person's recent calls through connections (?room= for this room)",
				"POST /drafts":  "a connector draft (JSON, see .room/" + s.P.Name + "/DRAFTING.md) for an admin to review",
			},
		})
	case in.Method == http.MethodGet && u.Path == "/systems":
		list, err := s.systems(ctx, t.Requester, t.Org)
		if err != nil {
			return refusal(http.StatusBadGateway, "the systems cannot be read right now", nil, nil)
		}
		return jsonAnswer(http.StatusOK, map[string]any{"systems": list})
	case in.Method == http.MethodGet && u.Path == "/activity":
		calls := s.activity(ctx, t.Requester, t.Org)
		if room := u.Query().Get("room"); room != "" {
			kept := calls[:0:0]
			for _, c := range calls {
				if c.Room == room {
					kept = append(kept, c)
				}
			}
			calls = kept
		}
		return jsonAnswer(http.StatusOK, map[string]any{"calls": calls})
	case in.Method == http.MethodPost && u.Path == "/drafts":
		var c connector.Connector
		if err := json.Unmarshal(in.Body, &c); err != nil {
			return refusal(http.StatusBadRequest, "a draft is a connector's JSON: "+err.Error(), nil, nil)
		}
		c.Enabled = false
		if err := c.Validate(); err != nil {
			return refusal(http.StatusBadRequest, "the draft is not a valid connector: "+err.Error(), nil, nil)
		}
		d := Draft{Connector: c, DraftedBy: t.Requester, Room: t.Room, CreatedAtMs: s.now().UnixMilli()}
		if err := s.P.PutJSON(ctx, platform.Org(t.Org), draftPrefix+c.Name, d); err != nil {
			return refusal(http.StatusBadGateway, "the draft could not be kept: "+err.Error(), nil, nil)
		}
		s.ensureReview(ctx, t.Org, t.Requester, c, true, true)
		return jsonAnswer(http.StatusCreated, map[string]string{
			"status":  "draft saved",
			"message": "An admin of the organization reviews it on the Connectors page (Components) and enables it or not. Tell " + t.Requester + " it waits there.",
		})
	}
	return refusal(http.StatusNotFound, in.Method+" "+u.Path+" is not part of the connections API (GET / lists it)", nil, nil)
}

// drafts are the organization's connector drafts.
func (s *Service) drafts(ctx context.Context, org string) []Draft {
	keys, err := s.P.Keys(ctx, platform.Org(org))
	if err != nil {
		return nil
	}
	var out []Draft
	for _, k := range keys {
		if !strings.HasPrefix(k, draftPrefix) {
			continue
		}
		var d Draft
		if ok, _ := s.P.GetJSON(ctx, platform.Org(org), k, &d); ok {
			out = append(out, d)
		}
	}
	return out
}
