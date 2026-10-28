package service

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc/component"
)

// A connector that sends from members' computers, as the CI system that
// started this: its change is held, and allowing it only stores an allowance.
func memberSendIssues() connector.Connector {
	c := issues()
	c.SendFrom = connector.SendMember
	return c
}

func (fx *fixture) heldTurn(room, job, drive string, in component.EgressRequest) component.EgressResponse {
	fx.t.Helper()
	tr := turn(drive)
	tr.Room, tr.Job = room, job
	raw, _ := json.Marshal(in)
	rec := fx.do(http.MethodPost, component.ServiceEgressRequestPath, component.TurnHeader, tr, raw)
	var out component.EgressResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

func trigger(path string) component.EgressRequest {
	return component.EgressRequest{Method: "POST", URL: "https://example.com/api/" + path, Body: []byte(`{"branch":"main"}`)}
}

func (fx *fixture) cardIn(room string, a component.CardAction) component.CardReply {
	fx.t.Helper()
	m := member(false)
	m.Room = room
	rec := fx.do(http.MethodPost, component.ServiceCardsPrefix+a.Page+"?"+a.Query, component.MemberHeader, m, nil)
	var r component.CardReply
	if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil || rec.Code != http.StatusOK {
		fx.t.Fatalf("card %s = %d %s", a.Page, rec.Code, rec.Body)
	}
	return r
}

func (fx *fixture) connectedMemberSend() {
	fx.t.Helper()
	fx.addConnector(memberSendIssues())
	_ = fx.svc.saveGrant(context.Background(), "maya", "home", Grant{Connector: "issues", Reach: connector.Read, APIKey: "k"})
}

// The same request held again is the one change: the same id, the same card,
// not a stack of them (seen 2026-10-28: an agent that retried a held change
// made a new card each time).
func TestTheSameHeldRequestIsOneChange(t *testing.T) {
	fx := newFixture(t)
	fx.connectedMemberSend()
	first := fx.heldTurn("room-1", "job-1", component.DriveOwn, trigger("a"))
	again := fx.heldTurn("room-1", "job-2", component.DriveOwn, trigger("a"))
	other := fx.heldTurn("room-1", "job-2", component.DriveOwn, trigger("b"))
	key := func(r component.EgressResponse) string { return r.Card.Actions[0].Query }
	if first.Card == nil || key(first) != key(again) || key(first) == key(other) {
		t.Fatalf("cards: first %v, retried %v, another request %v; want the retry to share the first's id and another request not to", first.Card, again.Card, other.Card)
	}
	if held := fx.svc.waiting(context.Background(), "maya", "home"); len(held) != 2 {
		t.Fatalf("%d changes waiting, want 2 (a, b)", len(held))
	}
	// The change waits under the newest turn's job: deciding it continues that one.
	hc, _ := fx.svc.heldFor(context.Background(), component.Member{Subject: "maya", Org: "home"}, strings.TrimPrefix(key(first), "decision=allow&id="))
	if hc == nil || hc.h.Job != "job-2" {
		t.Fatalf("held change = %+v, want it under job-2", hc)
	}
}

// Allow continues the agent: the reply asks the platform to post "go on" to the
// agent of the job the change was held under (never to another), once per decision.
func TestAllowAsksThePlatformToContinueTheHeldJobsAgent(t *testing.T) {
	fx := newFixture(t)
	fx.connectedMemberSend()
	out := fx.heldTurn("room-1", "job-held", component.DriveOwn, trigger("a"))
	r := fx.cardIn("room-1", out.Card.Actions[0])
	if r.ContinueJob != "job-held" || !strings.Contains(r.Continue, "POST /api/a") || !strings.Contains(r.Continue, "allowed") || r.ContinueKey == "" || len(r.Continue) > component.MaxCardContinue {
		t.Fatalf("allow = %+v", r)
	}
	if strings.Contains(r.Continue, "branch") {
		t.Fatalf("the message carries the request body: %q", r.Continue)
	}
	deny := fx.heldTurn("room-1", "job-held", component.DriveOwn, trigger("b"))
	if r := fx.cardIn("room-1", deny.Card.Actions[2]); r.Continue != "" {
		t.Fatalf("a refusal asks the agent to go on: %+v", r)
	}
}

// Allow in this room: this change goes, and so does every other change of the
// system in the room, for the person's own agents, until they stop it.
func TestAllowInThisRoomLetsTheRoomsChangesThrough(t *testing.T) {
	fx := newFixture(t)
	fx.connectedMemberSend()
	out := fx.heldTurn("room-1", "job-1", component.DriveOwn, trigger("a"))
	r := fx.cardIn("room-1", out.Card.Actions[1])
	if !strings.Contains(r.Text, "until you stop it") || r.Continue == "" || !r.Done {
		t.Fatalf("allow in this room = %+v", r)
	}
	if !fx.svc.roomAllows(context.Background(), "maya", "home", "room-1", "issues") {
		t.Fatal("the allowance was not kept")
	}
	// Other changes (other URLs) of the system in this room are not held.
	for _, p := range []string{"b", "c", "d"} {
		if next := fx.heldTurn("room-1", "job-2", component.DriveOwn, trigger(p)); next.Card != nil || next.Send == nil {
			t.Fatalf("change %s was held or not sent: %+v", p, next)
		}
	}
	// Another room, and a borrowed drive, still ask.
	if elsewhere := fx.heldTurn("room-2", "job-3", component.DriveOwn, trigger("b")); elsewhere.Card == nil {
		t.Fatal("another room's change went through")
	}
	if borrowed := fx.heldTurn("room-1", "job-4", component.DriveBorrowed, trigger("b")); borrowed.Send != nil {
		t.Fatal("a borrowed drive's change went through under the person's allowance")
	}
}

// Stop ends it: the next change asks again. The audit says a change went under the allowance.
func TestStoppingTheRoomAllowanceMakesChangesAskAgain(t *testing.T) {
	fx := newFixture(t)
	fx.connectedMemberSend()
	out := fx.heldTurn("room-1", "job-1", component.DriveOwn, trigger("a"))
	fx.cardIn("room-1", out.Card.Actions[1])
	m := member(false)
	m.Room = "room-1"
	rec := fx.do(http.MethodPost, "/pages/connections/stoproom", component.MemberHeader, m, []byte("system=issues"))
	if a := auditOf(t, rec); a.Action != "room-allowance" || a.Outcome != "stopped" || fx.svc.roomAllows(context.Background(), "maya", "home", "room-1", "issues") {
		t.Fatalf("stop = %d %+v; the allowance is still there or unaudited", rec.Code, a)
	}
	if next := fx.heldTurn("room-1", "job-2", component.DriveOwn, trigger("z")); next.Card == nil {
		t.Fatal("a change went through after the allowance was stopped")
	}
	// Stopping what is not there says so and audits nothing.
	if again := fx.do(http.MethodPost, "/pages/connections/stoproom", component.MemberHeader, m, []byte("system=issues")); again.Header().Get(component.AuditHeader) != "" {
		t.Fatal("stopping an allowance that was not there was audited")
	}
}

// A room allowance is the person's from the room they decided in: a decision
// made from the Review page opened for another room, or for a change held in
// another room, never allows this one.
func TestARoomAllowanceIsOfTheRoomItWasHeldIn(t *testing.T) {
	fx := newFixture(t)
	fx.connectedMemberSend()
	out := fx.heldTurn("room-1", "job-1", component.DriveOwn, trigger("a"))
	r := fx.cardIn("room-2", out.Card.Actions[1])
	if fx.svc.roomAllows(context.Background(), "maya", "home", "room-2", "issues") || fx.svc.roomAllows(context.Background(), "maya", "home", "room-1", "issues") {
		t.Fatalf("an allowance was made across rooms: %+v", r)
	}
	if !strings.Contains(r.Text, "this once") {
		t.Fatalf("the person is not told it was only this once: %q", r.Text)
	}
}

// Disconnecting the system drops its allowances: reconnecting asks again.
func TestDisconnectDropsTheRoomAllowance(t *testing.T) {
	fx := newFixture(t)
	fx.connectedMemberSend()
	out := fx.heldTurn("room-1", "job-1", component.DriveOwn, trigger("a"))
	fx.cardIn("room-1", out.Card.Actions[1])
	fx.svc.dropWaiting(context.Background(), "maya", "home", "issues")
	if fx.svc.roomAllows(context.Background(), "maya", "home", "room-1", "issues") {
		t.Fatal("the allowance outlived the disconnect")
	}
}

// A change made under the person's room allowance says so in its audit row, as
// a change the connection's own reach lets through does not (it is the person's
// standing setting, not this room's allowance).
func TestAChangeUnderTheRoomAllowanceIsAudited(t *testing.T) {
	fx := newFixture(t)
	fx.addConnector(issues()) // sends from the server: the change is made here
	_ = fx.svc.saveGrant(context.Background(), "maya", "home", Grant{Connector: "issues", Reach: connector.Read, APIKey: "k"})
	if err := fx.svc.allowRoom(context.Background(), "maya", "home", "room-1", "issues"); err != nil {
		t.Fatal(err)
	}
	tr := turn(component.DriveOwn)
	raw, _ := json.Marshal(trigger("a"))
	rec := fx.do(http.MethodPost, component.ServiceEgressRequestPath, component.TurnHeader, tr, raw)
	if a := auditOf(t, rec); a.Outcome != "allow" || !strings.Contains(a.Detail, "room allowance") {
		t.Fatalf("audit = %+v, want the allow row to say it went under the room allowance", a)
	}
	_ = fx.svc.saveGrant(context.Background(), "maya", "home", Grant{Connector: "issues", Reach: connector.Write, APIKey: "k"})
	rec = fx.do(http.MethodPost, component.ServiceEgressRequestPath, component.TurnHeader, tr, raw)
	if a := auditOf(t, rec); strings.Contains(a.Detail, "room allowance") {
		t.Fatalf("a change under the connection's own reach is attributed to the room allowance: %+v", a)
	}
}
