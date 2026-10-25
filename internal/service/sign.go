package service

import (
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
)

// A signing connector's key (connector.Sign) is "<key>:<secret>": the key
// is carried like any, the secret signs each request it applies to.

// splitKeySecret parts a pasted "<key>:<secret>".
func splitKeySecret(v string) (key, secret string) {
	key, secret, _ = cutColon(v)
	return strings.TrimSpace(key), strings.TrimSpace(secret)
}

// withoutParam is a query string or form body with param left out, the
// rest as sent (its order and encoding signed as they are).
func withoutParam(raw, param string) (string, bool) {
	if raw == "" {
		return "", false
	}
	var kept []string
	found := false
	for _, part := range strings.Split(raw, "&") {
		name, _, _ := strings.Cut(part, "=")
		if n, err := url.QueryUnescape(name); err == nil && n == param {
			found = true
			continue
		}
		kept = append(kept, part)
	}
	return strings.Join(kept, "&"), found
}

func hasParam(raw, name string) bool {
	for _, part := range strings.Split(raw, "&") {
		n, _, _ := strings.Cut(part, "=")
		if u, err := url.QueryUnescape(n); err == nil && u == name {
			return true
		}
	}
	return false
}

// signRequestIn is one request to sign: its method, path, query string
// and body (form: a form body), the member's key and secret, the time.
type signRequestIn struct {
	method, path, rawQuery string
	body                   []byte
	form                   bool
	key, secret            string
	now                    time.Time
}

// signOut is a request as signed: the query string and body to send, the
// headers to set, whether it was signed.
type signOut struct {
	rawQuery string
	body     []byte
	headers  http.Header
	ok       bool
}

// signed signs one request when the connector's Sign applies to it
// (connector.Sign: where the signature goes, what is signed, how).
func signed(sg *connector.Sign, in signRequestIn) signOut {
	out := signOut{rawQuery: in.rawQuery, body: in.body}
	if in.secret == "" {
		return out
	}
	q, b := in.rawQuery, string(in.body)
	carried := false
	if sg.In == "header" {
		carried = false // a placeholder signature header is replaced anyway
	} else {
		var inQuery, inBody bool
		q, inQuery = withoutParam(q, sg.Param)
		if in.form {
			b, inBody = withoutParam(b, sg.Param)
		}
		carried = inQuery || inBody
	}
	applies := carried || len(sg.Paths) == 0
	for _, p := range sg.Paths {
		applies = applies || connector.Glob(p, in.path)
	}
	if !applies {
		return out
	}
	ts := timestamp(sg.TimestampFormat, in.now)
	if sg.In != "header" && sg.Timestamp != "" && !hasParam(q, sg.Timestamp) && !(in.form && hasParam(b, sg.Timestamp)) {
		q = joinQuery(q, sg.Timestamp+"="+url.QueryEscape(ts))
	}
	payload := q
	if in.form {
		payload += b
	}
	if sg.Payload != "" || sg.In == "header" {
		tmpl := sg.Payload
		if tmpl == "" {
			tmpl = "{timestamp}{method}{pathQuery}{body}"
		}
		pathQuery := in.path
		if q != "" {
			pathQuery += "?" + q
		}
		payload = strings.NewReplacer("{timestamp}", ts, "{method}", strings.ToUpper(in.method), "{path}", in.path,
			"{query}", q, "{pathQuery}", pathQuery, "{body}", b, "{key}", in.key).Replace(tmpl)
	}
	value, err := signature(in.secret, []byte(payload), sg.Encoding)
	if err != nil {
		return out
	}
	out.ok = true
	if sg.In == "header" {
		out.headers = http.Header{}
		out.headers.Set(sg.Header, value)
		if sg.Timestamp != "" {
			out.headers.Set(sg.Timestamp, ts)
		}
		return out
	}
	out.rawQuery = joinQuery(q, sg.Param+"="+url.QueryEscape(value))
	if in.form {
		out.body = []byte(b)
	}
	return out
}

func joinQuery(q, part string) string {
	if q == "" {
		return part
	}
	return q + "&" + part
}

// timestamp is the time a signature carries: milliseconds (default),
// seconds, or ISO 8601 UTC with milliseconds.
func timestamp(format string, now time.Time) string {
	switch format {
	case "s":
		return strconv.FormatInt(now.Unix(), 10)
	case "iso":
		return now.UTC().Format("2006-01-02T15:04:05.000Z")
	}
	return strconv.FormatInt(now.UnixMilli(), 10)
}

// headerValue is a request header's first value, any case of its name.
func headerValue(h map[string][]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// signature signs payload with the secret, by its kind: a PEM private key
// signs Ed25519 or RSA PKCS#1 v1.5 SHA-256 (base64 by default); any other
// secret is an HMAC-SHA256 key (hex by default). encoding "hex" or
// "base64" chooses.
func signature(secret string, payload []byte, encoding string) (string, error) {
	var raw []byte
	pem := strings.Contains(secret, "-----BEGIN")
	if !pem {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload)
		raw = mac.Sum(nil)
	} else {
		key, err := privateKey(secret)
		if err != nil {
			return "", err
		}
		switch k := key.(type) {
		case ed25519.PrivateKey:
			raw = ed25519.Sign(k, payload)
		case *rsa.PrivateKey:
			sum := sha256.Sum256(payload)
			if raw, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:]); err != nil {
				return "", err
			}
		default:
			return "", errors.New("the private key is neither Ed25519 nor RSA")
		}
	}
	if encoding == "base64" || (encoding == "" && pem) {
		return base64.StdEncoding.EncodeToString(raw), nil
	}
	return hex.EncodeToString(raw), nil
}

// privateKey reads a PEM private key as pasted: its line breaks may have
// become spaces (a one-line field), so the base64 between the markers is
// read whatever its spacing.
func privateKey(secret string) (any, error) {
	start := strings.Index(secret, "-----BEGIN")
	if start < 0 {
		return nil, errors.New("no private key")
	}
	rest := secret[start:]
	head := strings.Index(rest[len("-----BEGIN"):], "-----")
	end := strings.Index(rest, "-----END")
	if head < 0 || end < 0 {
		return nil, errors.New("the private key is not whole")
	}
	body := rest[len("-----BEGIN")+head+len("-----") : end]
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
	if err != nil {
		return nil, errors.New("the private key is not PEM")
	}
	if k, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return k, nil
	}
	return nil, errors.New("the private key is not PKCS#8 or PKCS#1")
}

// checkSecret refuses a secret a signing connector cannot sign with.
func checkSecret(secret string) error {
	if strings.Contains(secret, "-----BEGIN") {
		_, err := privateKey(secret)
		return err
	}
	return nil
}

// signRequest is a request as a signing connector sends it (unchanged for
// another connector): the credentials' query added, then signed with their
// secret. changed reports a body other than in's.
func signRequest(c connector.Connector, auth cachedAuth, method string, u *url.URL, in []byte, contentType string, now time.Time) (rawQuery string, body []byte, headers http.Header, changed bool) {
	rawQuery, body = u.RawQuery, in
	if len(auth.query) > 0 {
		rawQuery = joinQuery(rawQuery, auth.query.Encode())
	}
	if a := c.Connect.APIKey; a != nil && a.Sign != nil {
		form := strings.HasPrefix(strings.ToLower(contentType), "application/x-www-form-urlencoded")
		out := signed(a.Sign, signRequestIn{method: method, path: u.Path, rawQuery: rawQuery, body: in, form: form, key: auth.key, secret: auth.secret, now: now})
		return out.rawQuery, out.body, out.headers, out.ok && form && a.Sign.In != "header"
	}
	return rawQuery, body, nil, false
}
