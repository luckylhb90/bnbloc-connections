package service

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc/component"
)

// A card's actions in place (component.CardCall): the platform calls
// /cards/<page>?<query> as the member, for the card's room, and the card
// shows the reply. Nothing opens but a sign-in the person starts.
//
//	approve?id=&decision=allow|room|deny   decide a held change (decide.go);
//	                                  room: and every change in that system in
//	                                  this room until stopped
//	connect?system=                   connect: a sign-in to open, or the
//	                                  provider's connect (a key is pasted
//	                                  on the page)
func (s *Service) handleCard(w http.ResponseWriter, r *http.Request, m component.Member, _ []byte) {
	ctx := r.Context()
	q := r.URL.Query()
	switch strings.TrimPrefix(r.URL.Path, component.ServiceCardsPrefix) {
	case "approve":
		hc, why := s.heldFor(ctx, m, q.Get("id"))
		switch {
		case why != "":
			writeJSON(w, http.StatusOK, component.CardReply{Text: why, Done: true})
			return
		case hc == nil:
			writeJSON(w, http.StatusOK, component.CardReply{Text: "This change is no longer waiting: it was decided, or it expired after a day.", Done: true})
			return
		}
		reach := allowOnce
		if q.Get("decision") == "room" {
			reach = allowRoom
		}
		d := s.decide(ctx, m, *hc, q.Get("decision") != "deny", reach)
		if d.audit != nil {
			audit(w, *d.audit)
		}
		text := d.heading + ". " + d.text
		if d.result != nil {
			if b := bodySummary(d.result.Body); b != "" {
				text += "\n" + clip(b, 300)
			}
		}
		// The agent's turn ended when the change was held: the decision tells it to go on, so the
		// person does not have to (docs/prd/2026-10-28-held-change-continues.md in bnbloc).
		writeJSON(w, http.StatusOK, component.CardReply{Text: text, Open: d.open, Done: d.open == "",
			Continue: d.carryOn, ContinueJob: hc.h.Job, ContinueKey: hc.h.ID + ":" + q.Get("decision")})
	case "connect":
		res := s.connectTo(ctx, m, q.Get("system"), connector.Read, "", nil, false)
		if res.audit != nil {
			audit(w, *res.audit)
		}
		writeJSON(w, http.StatusOK, component.CardReply{Text: res.msg, Open: res.open, Done: !res.err && res.open == ""})
	default:
		writeJSON(w, http.StatusNotFound, component.CardReply{Text: "This action is not known here."})
	}
}

// callAction is a card action in place.
func callAction(label, page string, q url.Values) component.CardAction {
	return component.CardAction{Kind: component.CardCall, Label: label, Page: page, Query: q.Encode()}
}
