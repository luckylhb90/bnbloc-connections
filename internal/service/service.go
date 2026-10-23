// Package service is the connections component: a bnbloc service component
// (github.com/luckylhb90/bnbloc/component, docs/architecture/service-components.md
// in bnbloc) that lets a member's own agent reach the systems the member
// connected, as the member. It answers the platform's turn calls (egress
// hosts, egress requests, room facts), serves the member's and the admin's
// pages, and takes OAuth redirects at its callback. Everything it keeps is
// in the platform's sealed store.
package service

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/luckylhb90/bnbloc-connections/connector"
	"github.com/luckylhb90/bnbloc-connections/internal/platform"
	"github.com/luckylhb90/bnbloc/component"
)

// Service is one connections component.
type Service struct {
	P *platform.Platform
	// BasePath is the path prefix the platform reaches this process at
	// ("" when it is the root).
	BasePath string
	// Upstream is the client of the connected systems (Guarded by default).
	Upstream *http.Client
	Now      func() time.Time
	// Later runs the component's AI work off the request that started it
	// (nil: a goroutine).
	Later func(func())

	mu      sync.Mutex
	orgs    map[string]orgCache
	tokens  map[grantKey]cachedAuth
	limiter limiter
}

type orgCache struct {
	at         time.Time
	connectors []connector.Connector
}

// orgTTL is how long an organization's connectors are kept in memory.
const orgTTL = 30 * time.Second

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// SelfHost is the host the agents reach this component's own API at,
// through egress like any connected system (connectors, drafts, activity).
func (s *Service) SelfHost() string { return s.P.Name + ".bnbloc" }

// Handler serves the component contract.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+component.ServiceDiscoverPath, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"name": s.P.Name, "contract": component.ServiceContractV1})
	})
	// The liveness and readiness probe of the process (unsigned, no data).
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET "+component.ServiceEgressHostsPath, s.turn(s.handleHosts))
	mux.HandleFunc("POST "+component.ServiceEgressRequestPath, s.turn(s.handleEgress))
	mux.HandleFunc("GET "+component.ServiceFactsPath, s.turn(s.handleFacts))
	mux.HandleFunc("GET "+component.ServicePagesPath, s.member(s.handlePageList))
	mux.HandleFunc(component.ServicePagesPath+"/", s.member(s.handlePage))
	mux.HandleFunc(component.ServiceCallbackPrefix+"oauth", s.handleOAuthCallback)
	if s.BasePath == "" {
		return mux
	}
	return http.StripPrefix(strings.TrimRight(s.BasePath, "/"), mux)
}

// turnHandler serves one turn call: the attested turn and the body.
type turnHandler func(w http.ResponseWriter, r *http.Request, t component.Turn, body []byte)

// memberHandler serves one page call: the attested member and the body.
type memberHandler func(w http.ResponseWriter, r *http.Request, m component.Member, body []byte)

// maxBody bounds what a call carries (an egress envelope).
const maxBody = component.MaxEgressBody + 2<<20

func (s *Service) read(w http.ResponseWriter, r *http.Request, header string) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "request too large"})
		return nil, false
	}
	if err := s.P.Verify(r, strings.TrimRight(s.BasePath, "/"), header, body); err != nil {
		why := s.whyUnsigned(r, header, body)
		slog.Warn("connections: a call is not signed by bnbloc", "method", r.Method, "uri", r.URL.RequestURI(), "why", why)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error(), "why": why})
		return nil, false
	}
	return body, true
}

// whyUnsigned names what is wrong with a call's signature, never a value:
// no credential set here, no signature, a timestamp off this clock, or a
// mismatch (another credential, or a call changed on its way: the path
// verified is in the log line).
func (s *Service) whyUnsigned(r *http.Request, header string, body []byte) string {
	sig := r.Header.Get(component.SignatureHeader)
	switch {
	case strings.TrimSpace(s.P.Secret) == "":
		return "no credential is set in this process (BNBLOC_CONNECTIONS_SECRET)"
	case sig == "":
		return "the call carries no signature"
	case header != "" && r.Header.Get(header) == "":
		return "the call carries no " + header
	}
	for _, part := range strings.Split(sig, ",") {
		if ts, ok := strings.CutPrefix(strings.TrimSpace(part), "t="); ok {
			if unix, err := strconv.ParseInt(ts, 10, 64); err == nil {
				if d := s.now().Sub(time.Unix(unix, 0)); d > component.SignatureTolerance || d < -component.SignatureTolerance {
					return "the signature's time is " + d.Round(time.Second).String() + " off this clock"
				}
			}
		}
	}
	return "the signature does not match: another credential than bnbloc's, or a path changed on its way (verified " + r.Method + " " + strings.TrimPrefix(r.URL.RequestURI(), strings.TrimRight(s.BasePath, "/")) + ")"
}

func (s *Service) turn(h turnHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.read(w, r, component.TurnHeader)
		if !ok {
			return
		}
		var t component.Turn
		if err := component.DecodeHeader(r.Header.Get(component.TurnHeader), &t); err != nil || t.Org == "" || t.Requester == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no attested turn"})
			return
		}
		h(w, r, t, body)
	}
}

func (s *Service) member(h memberHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, ok := s.read(w, r, component.MemberHeader)
		if !ok {
			return
		}
		var m component.Member
		if err := component.DecodeHeader(r.Header.Get(component.MemberHeader), &m); err != nil || m.Org == "" || m.Subject == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no attested member"})
			return
		}
		h(w, r, m, body)
	}
}

// Store keys.
const (
	connectorPrefix = "connector:"
	secretsPrefix   = "secrets:"
	draftPrefix     = "draft:"
	grantPrefix     = "grant:"
	heldPrefix      = "held:"
	activityPrefix  = "activity:"
	statePrefix     = "state:"
	allowPrefix     = "allow:"
)

// connectors are the organization's connectors, sorted by name (cached).
func (s *Service) connectors(ctx context.Context, org string) ([]connector.Connector, error) {
	s.mu.Lock()
	if c, ok := s.orgs[org]; ok && s.now().Sub(c.at) < orgTTL {
		s.mu.Unlock()
		return c.connectors, nil
	}
	s.mu.Unlock()
	keys, err := s.P.Keys(ctx, platform.Org(org))
	if err != nil {
		return nil, err
	}
	var out []connector.Connector
	for _, k := range keys {
		if !strings.HasPrefix(k, connectorPrefix) {
			continue
		}
		var c connector.Connector
		if ok, err := s.P.GetJSON(ctx, platform.Org(org), k, &c); err != nil || !ok {
			slog.Warn("connections: connector unreadable", "org", org, "key", k, "error", err)
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	s.mu.Lock()
	if s.orgs == nil {
		s.orgs = map[string]orgCache{}
	}
	s.orgs[org] = orgCache{at: s.now(), connectors: out}
	s.mu.Unlock()
	return out, nil
}

// enabled are the organization's enabled connectors.
func (s *Service) enabled(ctx context.Context, org string) ([]connector.Connector, error) {
	all, err := s.connectors(ctx, org)
	if err != nil {
		return nil, err
	}
	out := all[:0:0]
	for _, c := range all {
		if c.Enabled {
			out = append(out, c)
		}
	}
	return out, nil
}

// forget drops an organization's cached connectors (after an admin change).
func (s *Service) forget(org string) {
	s.mu.Lock()
	delete(s.orgs, org)
	s.mu.Unlock()
}

// saveConnector stores a connector of the organization.
func (s *Service) saveConnector(ctx context.Context, org string, c connector.Connector) error {
	defer s.forget(org)
	return s.P.PutJSON(ctx, platform.Org(org), connectorPrefix+c.Name, c)
}

func (s *Service) secrets(ctx context.Context, org, name string) connector.Secrets {
	var sec connector.Secrets
	if _, err := s.P.GetJSON(ctx, platform.Org(org), secretsPrefix+name, &sec); err != nil {
		slog.Warn("connections: connector secrets unreadable", "org", org, "connector", name, "error", err)
	}
	return sec
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// audit sets the audit row the platform records with this answer.
func audit(w http.ResponseWriter, a component.Audit) {
	w.Header().Set(component.AuditHeader, component.EncodeHeader(a))
}
