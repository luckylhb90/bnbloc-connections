package service

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc/component"
)

// The signature is the exchange's documented example (HMAC-SHA256 of the
// query string, hex); a placeholder signature a library sent is replaced;
// a timestamp is added when there is none; the form body is signed after
// the query; a request it does not apply to is sent as it is.
func TestSigned(t *testing.T) {
	sg := &connector.Sign{Param: "signature", Timestamp: "timestamp", Paths: []string{"/api/v3/order", "/api/v3/account"}}
	secret := "NhqPtmdSJYdKjVHjA7PZj4Mge3R5YNiP1e3UZjInClVN65XAbvqqM6A7H5fATj0j"
	q := "symbol=LTCBTC&side=BUY&type=LIMIT&timeInForce=GTC&quantity=1&price=0.1&recvWindow=5000&timestamp=1499827319559"
	want := q + "&signature=c8db56825ae71d6d79447849e617115f4a920fa2acdcab2b053c4b2838bd6b71"
	if got, _, ok := signed(sg, secret, "/api/v3/order", q, nil, false, time.Now()); !ok || got != want {
		t.Fatalf("signed = %s", got)
	}
	if got, _, _ := signed(sg, secret, "/api/v3/order", "symbol=LTCBTC&side=BUY&type=LIMIT&timeInForce=GTC&quantity=1&signature=fake&price=0.1&recvWindow=5000&timestamp=1499827319559", nil, false, time.Now()); got != want {
		t.Fatalf("re-signed = %s", got)
	}
	got, _, _ := signed(sg, secret, "/api/v3/account", "", nil, false, time.UnixMilli(1700000000000))
	if !strings.HasPrefix(got, "timestamp=1700000000000&signature=") {
		t.Fatalf("with a timestamp added = %s", got)
	}
	got, body, _ := signed(sg, secret, "/api/v3/order", "symbol=X", []byte("quantity=1&signature=fake&timestamp=5"), true, time.Now())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("symbol=X" + "quantity=1&timestamp=5"))
	if got != "symbol=X&signature="+hex.EncodeToString(mac.Sum(nil)) || string(body) != "quantity=1&timestamp=5" {
		t.Fatalf("form = %s / %s", got, body)
	}
	if got, _, ok := signed(sg, secret, "/api/v3/ticker/price", "symbol=X", nil, false, time.Now()); ok || got != "symbol=X" {
		t.Fatalf("a public request = %s %v", got, ok)
	}
}

// A signing connector: the member pastes the key and its secret; the
// system gets the key in its header (never the agent's placeholder) and a
// request signed with the secret; the secret is never sent.
func TestSigningConnector(t *testing.T) {
	fx := newFixture(t)
	c := issues()
	c.Connect = connector.Connect{Kind: connector.KindAPIKey, APIKey: &connector.APIKey{In: "header", Name: "X-Key",
		Sign: &connector.Sign{Param: "signature", Timestamp: "timestamp", Paths: []string{"/api/account"}}}}
	fx.addConnector(c)
	if rec := fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}, "key": {"KEY-1"}}); !strings.Contains(rec.Header().Get("Location"), "err=1") {
		t.Fatal("connected without the secret")
	}
	_ = fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}, "key": {"KEY-1"}, "secret": {"SECRET-1"}})
	out := fx.egressIn("room-1", component.EgressRequest{Method: "GET", URL: "https://example.com/api/account?recvWindow=5000", Header: map[string][]string{"X-Key": {"connected"}}})
	call := fx.last()
	if out.Status != 200 || call.header.Get("X-Key") != "KEY-1" || strings.Contains(call.query+call.body+strings.Join(call.header.Values("X-Key"), ""), "SECRET") {
		t.Fatalf("sent = %+v", call)
	}
	v, _ := url.ParseQuery(call.query)
	mac := hmac.New(sha256.New, []byte("SECRET-1"))
	mac.Write([]byte("recvWindow=5000&timestamp=" + v.Get("timestamp")))
	if v.Get("signature") != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("signature = %s (query %s)", v.Get("signature"), call.query)
	}
	if g, _, _ := fx.svc.grant(context.Background(), "maya", "home", "issues"); g.APIKey != "KEY-1:SECRET-1" {
		t.Fatalf("grant = %+v", g)
	}
	c.SendFrom = connector.SendMember
	if c.Validate() == nil {
		t.Fatal("a signing connector sent from members' computers")
	}
}
