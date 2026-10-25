package service

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
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
	if got, _, ok := sq(sg, secret, "/api/v3/order", q, nil, false, time.Now()); !ok || got != want {
		t.Fatalf("signed = %s", got)
	}
	if got, _, _ := sq(sg, secret, "/api/v3/order", "symbol=LTCBTC&side=BUY&type=LIMIT&timeInForce=GTC&quantity=1&signature=fake&price=0.1&recvWindow=5000&timestamp=1499827319559", nil, false, time.Now()); got != want {
		t.Fatalf("re-signed = %s", got)
	}
	got, _, _ := sq(sg, secret, "/api/v3/account", "", nil, false, time.UnixMilli(1700000000000))
	if !strings.HasPrefix(got, "timestamp=1700000000000&signature=") {
		t.Fatalf("with a timestamp added = %s", got)
	}
	got, body, _ := sq(sg, secret, "/api/v3/order", "symbol=X", []byte("quantity=1&signature=fake&timestamp=5"), true, time.Now())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("symbol=X" + "quantity=1&timestamp=5"))
	if got != "symbol=X&signature="+hex.EncodeToString(mac.Sum(nil)) || string(body) != "quantity=1&timestamp=5" {
		t.Fatalf("form = %s / %s", got, body)
	}
	if got, _, ok := sq(sg, secret, "/api/v3/ticker/price", "symbol=X", nil, false, time.Now()); ok || got != "symbol=X" {
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
	// Sent from the member's computer: the bridge gets the signed query.
	c.SendFrom = connector.SendMember
	fx.addConnector(c)
	sent := fx.egressIn("room-1", component.EgressRequest{Method: "GET", URL: "https://example.com/api/account?recvWindow=5000"})
	if sent.Send == nil || !strings.HasPrefix(sent.Send.RawQuery, "recvWindow=5000&timestamp=") || !strings.Contains(sent.Send.RawQuery, "&signature=") ||
		sent.Send.Header["X-Key"][0] != "KEY-1" || sent.Send.ReplaceBody {
		t.Fatalf("send = %+v", sent.Send)
	}
}

// A PEM private key, pasted on one line, signs Ed25519 or RSA (base64,
// escaped in the query); a key that does not read is refused at connect.
func TestSignedWithAPrivateKey(t *testing.T) {
	sg := &connector.Sign{Param: "signature", Timestamp: "timestamp", Paths: []string{"/api/v3/account"}}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	pemKey := strings.ReplaceAll(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "\n", " ")
	q, _, ok := sq(sg, pemKey, "/api/v3/account", "timestamp=1", nil, false, time.Now())
	v, _ := url.ParseQuery(q)
	sig, _ := base64.StdEncoding.DecodeString(v.Get("signature"))
	if !ok || !ed25519.Verify(pub, []byte("timestamp=1"), sig) {
		t.Fatalf("ed25519 = %s", q)
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ = x509.MarshalPKCS8PrivateKey(rk)
	q, _, _ = sq(sg, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), "/api/v3/account", "timestamp=1", nil, false, time.Now())
	v, _ = url.ParseQuery(q)
	sig, _ = base64.StdEncoding.DecodeString(v.Get("signature"))
	sum := sha256.Sum256([]byte("timestamp=1"))
	if rsa.VerifyPKCS1v15(&rk.PublicKey, crypto.SHA256, sum[:], sig) != nil {
		t.Fatalf("rsa = %s", q)
	}
	if checkSecret("-----BEGIN PRIVATE KEY----- bm90IGEga2V5 -----END PRIVATE KEY-----") == nil || checkSecret("hmac-secret") != nil {
		t.Fatal("checkSecret")
	}
}

// sq signs in the query (the connector.Sign default) and answers the
// query, the body and whether it signed.
func sq(sg *connector.Sign, secret, path, q string, body []byte, form bool, now time.Time) (string, []byte, bool) {
	out := signed(sg, signRequestIn{method: "POST", path: path, rawQuery: q, body: body, form: form, secret: secret, now: now})
	return out.rawQuery, out.body, out.ok
}

// A signature in headers over a template: OKX's (base64 HMAC of the ISO
// time, the method, the path with its query and the body) and Bybit's (hex
// HMAC of the time in milliseconds, the key, a literal window and the
// query); the query string is sent as it is.
func TestSignedInHeaders(t *testing.T) {
	now := time.Date(2020, 12, 8, 9, 8, 57, 715_000_000, time.UTC)
	okx := &connector.Sign{In: "header", Header: "OK-ACCESS-SIGN", Timestamp: "OK-ACCESS-TIMESTAMP", TimestampFormat: "iso", Encoding: "base64"}
	out := signed(okx, signRequestIn{method: "get", path: "/api/v5/account/balance", rawQuery: "ccy=BTC", key: "K", secret: "S", now: now})
	mac := hmac.New(sha256.New, []byte("S"))
	mac.Write([]byte("2020-12-08T09:08:57.715ZGET/api/v5/account/balance?ccy=BTC"))
	if !out.ok || out.rawQuery != "ccy=BTC" || out.headers.Get("OK-ACCESS-TIMESTAMP") != "2020-12-08T09:08:57.715Z" ||
		out.headers.Get("OK-ACCESS-SIGN") != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("okx = %+v", out)
	}
	bybit := &connector.Sign{In: "header", Header: "X-BAPI-SIGN", Timestamp: "X-BAPI-TIMESTAMP", Payload: "{timestamp}{key}5000{query}{body}"}
	out = signed(bybit, signRequestIn{method: "GET", path: "/v5/account/wallet-balance", rawQuery: "accountType=UNIFIED", key: "K", secret: "S", now: now})
	mac = hmac.New(sha256.New, []byte("S"))
	mac.Write([]byte("1607418537715K5000accountType=UNIFIED"))
	if out.headers.Get("X-BAPI-SIGN") != hex.EncodeToString(mac.Sum(nil)) || out.headers.Get("X-BAPI-TIMESTAMP") != "1607418537715" {
		t.Fatalf("bybit = %+v", out)
	}
}

// A connector's headers, the member's extra values and a header signature
// reach the system, whatever the agent sent; the passphrase is asked at
// connect.
func TestHeadersAndExtras(t *testing.T) {
	fx := newFixture(t)
	c := issues()
	c.Headers = map[string]string{"x-simulated-trading": "1"}
	c.Connect = connector.Connect{Kind: connector.KindAPIKey, APIKey: &connector.APIKey{In: "header", Name: "OK-ACCESS-KEY",
		Extra: []connector.Extra{{Name: "passphrase", Label: "Passphrase", Header: "OK-ACCESS-PASSPHRASE"}},
		Sign:  &connector.Sign{In: "header", Header: "OK-ACCESS-SIGN", Timestamp: "OK-ACCESS-TIMESTAMP", TimestampFormat: "iso", Encoding: "base64"}}}
	fx.addConnector(c)
	if rec := fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}, "key": {"K"}, "secret": {"S"}}); !strings.Contains(rec.Header().Get("Location"), "err=1") {
		t.Fatal("connected without the passphrase")
	}
	_ = fx.page(false, http.MethodPost, "/pages/connections/connect", url.Values{"system": {"issues"}, "key": {"K"}, "secret": {"S"}, "extra-passphrase": {"P"}})
	out := fx.egressIn("room-1", component.EgressRequest{Method: "GET", URL: "https://example.com/api/x?a=1", Header: map[string][]string{"x-simulated-trading": {"0"}, "OK-ACCESS-SIGN": {"agent"}}})
	h := fx.last().header
	if out.Status != 200 || h.Get("OK-ACCESS-KEY") != "K" || h.Get("OK-ACCESS-PASSPHRASE") != "P" || h.Get("X-Simulated-Trading") != "1" ||
		h.Get("OK-ACCESS-SIGN") == "agent" || h.Get("OK-ACCESS-SIGN") == "" || fx.last().query != "a=1" {
		t.Fatalf("sent %v %s", h, fx.last().query)
	}
	c.Headers = map[string]string{"Authorization": "x"}
	if c.Validate() == nil {
		t.Fatal("a connector header that is a credential")
	}
}
