package service

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := sg.Param + "=" + hex.EncodeToString(mac.Sum(nil))
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
