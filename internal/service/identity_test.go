package service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/luckylhb90/bnbloc/component"
)

// pageIn is a page call by subject, opened for room with role.
func (fx *fixture) pageIn(subject, room, role string, method, path string, form url.Values) *httptest.ResponseRecorder {
	fx.t.Helper()
	m := component.Member{Subject: subject, Org: "home", Room: room, RoomRole: role, PageURL: "https://bnbloc.example.com/v1/component-pages/T/", Origin: "https://bnbloc.example.com"}
	return fx.do(method, path, component.MemberHeader, m, []byte(form.Encode()))
}

func turnIn(requester, room, drive string) component.Turn {
	t := turn(drive)
	t.Requester, t.Room = requester, room
	return t
}

func (fx *fixture) turnWith(t component.Turn, in component.EgressRequest) component.EgressResponse {
	fx.t.Helper()
	raw, _ := json.Marshal(in)
	rec := fx.do(http.MethodPost, component.ServiceEgressRequestPath, component.TurnHeader, t, raw)
	var out component.EgressResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

func (fx *fixture) authAs(t component.Turn) (int, string) {
	fx.t.Helper()
	out := fx.turnWith(t, component.EgressRequest{Method: "GET", URL: "https://example.com/api/issue/1"})
	if out.Status != 200 {
		return out.Status, string(out.Body)
	}
	return out.Status, fx.last().header.Get("Authorization")
}

// A room's owner sets a worker for everyone in the room, by default (a
// member may still act as themselves there) or required (no one may); a
// member chooses for themselves in a room; only the owner sets the room's,
// only from the room's page; a worker the room requires that is not
// connected refuses without falling back to the person.
func TestRoomIdentity(t *testing.T) {
	fx, _ := workerFixture(t)
	_ = fx.page(true, http.MethodPost, "/pages/workers/save", url.Values{"id": {"release-bot"}, "displayName": {"Release bot"}, "account": {"+30001"},
		"owners": {"olga"}, "members": {"*"}, "drive": {"own", "platform"}})
	_ = fx.page(true, http.MethodPost, "/pages/workers/connect", url.Values{"id": {"release-bot"}, "system": {"issues"}})
	_ = fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}}) // maya as herself
	worker, maya := "Bearer WORKER-+30001", "Bearer MEMBER-maya"
	expect := func(tr component.Turn, want string) {
		t.Helper()
		if _, got := fx.authAs(tr); got != want {
			t.Fatalf("%s in %s = %q, want %q", tr.Requester, tr.Room, got, want)
		}
	}
	expect(turnIn("maya", "room-1", component.DriveOwn), maya)

	saved := func(rec interface{ Header() http.Header }) bool { return !strings.Contains(rec.Header().Get("Location"), "err=1") }
	if saved(fx.pageIn("jack", "room-1", "member", http.MethodPost, "/pages/connections/roomidentity", url.Values{"system": {"issues"}, "worker": {"release-bot"}, "mode": {"default"}})) {
		t.Fatal("a member set the room's identity")
	}
	if saved(fx.pageIn("maya", "", "", http.MethodPost, "/pages/connections/roomidentity", url.Values{"system": {"issues"}, "worker": {"release-bot"}, "mode": {"default"}})) {
		t.Fatal("the room's identity was set outside the room")
	}
	if !saved(fx.pageIn("maya", "room-1", component.RoomOwner, http.MethodPost, "/pages/connections/roomidentity", url.Values{"system": {"issues"}, "worker": {"release-bot"}, "mode": {"default"}})) {
		t.Fatal("the owner could not set the room's identity")
	}
	expect(turnIn("maya", "room-1", component.DriveOwn), worker)
	expect(turnIn("maya", "room-2", component.DriveOwn), maya)
	expect(turnIn("jack", "room-1", component.DriveOwn), worker)
	expect(turnIn("jack", "room-1", component.DrivePlatform), worker)

	if !saved(fx.pageIn("maya", "room-1", component.RoomOwner, http.MethodPost, "/pages/connections/myidentity", url.Values{"system": {"issues"}, "worker": {"self"}})) {
		t.Fatal("maya could not choose herself")
	}
	expect(turnIn("maya", "room-1", component.DriveOwn), maya)
	expect(turnIn("jack", "room-1", component.DriveOwn), worker)
	page := fx.pageIn("maya", "room-1", component.RoomOwner, http.MethodGet, "/pages/connections/", nil).Body.String()
	if !strings.Contains(page, "In this room") || !strings.Contains(page, `value="self" selected`) {
		t.Fatalf("the room's page = %s", page)
	}

	_ = fx.pageIn("maya", "room-1", component.RoomOwner, http.MethodPost, "/pages/connections/roomidentity", url.Values{"system": {"issues"}, "worker": {"release-bot"}, "mode": {"required"}})
	expect(turnIn("maya", "room-1", component.DriveOwn), worker)
	if saved(fx.pageIn("jack", "room-1", "member", http.MethodPost, "/pages/connections/myidentity", url.Values{"system": {"issues"}, "worker": {"self"}})) {
		t.Fatal("a member left a required worker")
	}
	_ = fx.page(true, http.MethodPost, "/pages/workers/disconnect", url.Values{"id": {"release-bot"}, "system": {"issues"}})
	if code, body := fx.authAs(turnIn("maya", "room-1", component.DriveOwn)); code != http.StatusForbidden || !strings.Contains(body, "acts as Release bot") {
		t.Fatalf("a required worker not connected = %d %s", code, body)
	}

	tr := turnIn("maya", "room-1", component.DriveOwn)
	_ = fx.pageIn("maya", "room-1", component.RoomOwner, http.MethodPost, "/pages/connections/roomidentity", url.Values{"system": {"issues"}, "worker": {""}})
	expect(tr, maya)
}
