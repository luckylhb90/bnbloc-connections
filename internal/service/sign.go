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

// signed signs one request (rawQuery, its form body) when the connector's
// Sign applies to it, answering the query and the body to send.
func signed(sg *connector.Sign, secret, path, rawQuery string, body []byte, form bool, now time.Time) (string, []byte, bool) {
	q, inQuery := withoutParam(rawQuery, sg.Param)
	b := string(body)
	inBody := false
	if form {
		b, inBody = withoutParam(b, sg.Param)
	}
	applies := inQuery || inBody
	for _, p := range sg.Paths {
		applies = applies || connector.Glob(p, path)
	}
	if !applies || secret == "" {
		return rawQuery, body, false
	}
	if sg.Timestamp != "" && !hasParam(q, sg.Timestamp) && !(form && hasParam(b, sg.Timestamp)) {
		ts := sg.Timestamp + "=" + strconv.FormatInt(now.UnixMilli(), 10)
		if q == "" {
			q = ts
		} else {
			q += "&" + ts
		}
	}
	payload := q
	if form {
		payload += b
	}
	value, err := signature(secret, []byte(payload))
	if err != nil {
		return rawQuery, body, false
	}
	sig := sg.Param + "=" + url.QueryEscape(value)
	if q == "" {
		q = sig
	} else {
		q += "&" + sig
	}
	if form {
		return q, []byte(b), true
	}
	return q, body, true
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
// signs Ed25519 or RSA PKCS#1 v1.5 SHA-256 (base64); any other secret is
// an HMAC-SHA256 key (hex).
func signature(secret string, payload []byte) (string, error) {
	if !strings.Contains(secret, "-----BEGIN") {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload)
		return hex.EncodeToString(mac.Sum(nil)), nil
	}
	key, err := privateKey(secret)
	if err != nil {
		return "", err
	}
	switch k := key.(type) {
	case ed25519.PrivateKey:
		return base64.StdEncoding.EncodeToString(ed25519.Sign(k, payload)), nil
	case *rsa.PrivateKey:
		sum := sha256.Sum256(payload)
		sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
		return base64.StdEncoding.EncodeToString(sig), err
	}
	return "", errors.New("the private key is neither Ed25519 nor RSA")
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

// signRequest is the query string and body a signing connector sends for
// in (unchanged for another connector): the credentials' query added, then
// signed with their secret. changed reports a body other than in's.
func signRequest(c connector.Connector, auth cachedAuth, u *url.URL, in []byte, contentType string, now time.Time) (rawQuery string, body []byte, changed bool) {
	rawQuery, body = u.RawQuery, in
	if len(auth.query) > 0 {
		extra := auth.query.Encode()
		if rawQuery == "" {
			rawQuery = extra
		} else {
			rawQuery += "&" + extra
		}
	}
	if a := c.Connect.APIKey; a != nil && a.Sign != nil {
		form := strings.HasPrefix(strings.ToLower(contentType), "application/x-www-form-urlencoded")
		var ok bool
		rawQuery, body, ok = signed(a.Sign, auth.secret, u.Path, rawQuery, in, form, now)
		changed = ok && form
	}
	return rawQuery, body, changed
}
