// Package admin is the platform owner's side: the password sign-in, the
// admin JSON API the web UI calls (docs/admin-api.md is its contract), the
// UI's page routes, and the API behind the OAuth consent page.
package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/config"
	"github.com/ImSingee/mcp-webhook-events/internal/core"
	"github.com/ImSingee/mcp-webhook-events/internal/httpx"
	"github.com/ImSingee/mcp-webhook-events/internal/idgen"
	"github.com/ImSingee/mcp-webhook-events/internal/oauth"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
	"github.com/ImSingee/mcp-webhook-events/internal/version"
	"github.com/ImSingee/mcp-webhook-events/internal/web"
)

// CookieName is the admin session cookie.
const CookieName = "mwe_session"

// SessionTTL is how long a sign-in lasts.
const SessionTTL = 30 * 24 * time.Hour

// Server is the admin side.
type Server struct {
	Cfg   config.Config
	Core  *core.Service
	Store *store.Store
	OAuth *oauth.Server
	Web   *web.Handler
	Log   *slog.Logger
	// Ping is how often the admin event stream sends a comment.
	Ping time.Duration
	// Base ends with the server, closing the admin event streams.
	Base context.Context

	mu       sync.Mutex
	failures map[string]*failure
}

type failure struct {
	count int
	last  time.Time
	until time.Time
}

// New is the admin side over svc.
func New(cfg config.Config, svc *core.Service, auth *oauth.Server, w *web.Handler, log *slog.Logger) *Server {
	return &Server{Cfg: cfg, Core: svc, Store: svc.Store, OAuth: auth, Web: w, Log: log, Ping: 20 * time.Second, Base: context.Background(), failures: map[string]*failure{}}
}

// apiError writes the API's error shape.
func apiError(w http.ResponseWriter, status int, code, msg string) {
	httpx.WriteJSON(w, status, map[string]any{"error": map[string]any{"code": code, "message": msg}})
}

// fail maps an operation's error to its response.
func (s *Server) fail(w http.ResponseWriter, err error, what string) {
	switch {
	case core.IsInvalid(err):
		apiError(w, http.StatusBadRequest, "invalid_argument", err.Error())
	case errors.Is(err, store.ErrNotFound):
		apiError(w, http.StatusNotFound, "not_found", what+" not found")
	case errors.Is(err, store.ErrConflict):
		apiError(w, http.StatusConflict, "conflict", what+" already exists")
	default:
		s.Log.Error("admin request", "what", what, "err", err)
		apiError(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

// signedIn reports whether the request carries a live session.
func (s *Server) signedIn(r *http.Request) bool {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return false
	}
	ok, err := s.Store.SessionValid(r.Context(), idgen.Hash(c.Value))
	return err == nil && ok
}

// sameOrigin reports whether a state-changing request comes from the
// platform's own pages: its Origin (or, without one, Sec-Fetch-Site) says
// so. A request from outside a browser sends neither and passes, since
// it can't carry the session cookie unless its sender already has it.
func (s *Server) sameOrigin(r *http.Request) bool {
	if o := r.Header.Get("Origin"); o != "" {
		return strings.EqualFold(o, s.Cfg.PublicURL)
	}
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	}
	return false
}

// api wraps an API handler with the CSRF rule (every non-GET request
// carries X-MWE-Request: 1 from the same origin) and, unless open, the
// sign-in check.
func (s *Server) api(open bool, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if r.Header.Get("X-MWE-Request") != "1" || !s.sameOrigin(r) {
				apiError(w, http.StatusForbidden, "forbidden", "cross-site request refused: send X-MWE-Request: 1 from the platform's own origin")
				return
			}
		}
		if !open && !s.signedIn(r) {
			apiError(w, http.StatusUnauthorized, "unauthorized", "sign in first")
			return
		}
		h(w, r)
	}
}

// Routes adds the pages and the admin API to mux.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /{$}", s.page(web.IndexPage, true))
	mux.HandleFunc("GET /index.html", func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "/", http.StatusFound) })
	mux.HandleFunc("GET /login", s.page(web.LoginPage, false))
	mux.HandleFunc("GET /consent", s.page(web.ConsentPage, true))
	// "/" with no method, so the more specific /mcp, /hooks/ and /api/
	// patterns (any method) don't conflict with it
	mux.Handle("/", getOnly(s.Web.Static()))

	mux.HandleFunc("POST /api/login", s.api(true, s.login))
	mux.HandleFunc("POST /api/logout", s.api(true, s.logout))
	mux.HandleFunc("GET /api/meta", s.api(true, s.meta))

	mux.HandleFunc("GET /api/identities", s.api(false, s.listIdentities))
	mux.HandleFunc("POST /api/identities", s.api(false, s.createIdentity))
	mux.HandleFunc("GET /api/identities/{id}", s.api(false, s.getIdentity))
	mux.HandleFunc("PATCH /api/identities/{id}", s.api(false, s.renameIdentity))
	mux.HandleFunc("DELETE /api/identities/{id}", s.api(false, s.deleteIdentity))

	mux.HandleFunc("GET /api/identities/{iid}/webhooks", s.api(false, s.listWebhooks))
	mux.HandleFunc("POST /api/identities/{iid}/webhooks", s.api(false, s.createWebhook))
	mux.HandleFunc("PATCH /api/identities/{iid}/webhooks/{wid}", s.api(false, s.updateWebhook))
	mux.HandleFunc("POST /api/identities/{iid}/webhooks/{wid}/rotate-key", s.api(false, s.rotateWebhook))
	mux.HandleFunc("DELETE /api/identities/{iid}/webhooks/{wid}", s.api(false, s.deleteWebhook))

	mux.HandleFunc("GET /api/identities/{iid}/channels", s.api(false, s.listChannels))
	mux.HandleFunc("POST /api/identities/{iid}/channels", s.api(false, s.createChannel))
	mux.HandleFunc("PATCH /api/identities/{iid}/channels/{cid}", s.api(false, s.updateChannel))
	mux.HandleFunc("DELETE /api/identities/{iid}/channels/{cid}", s.api(false, s.deleteChannel))

	mux.HandleFunc("GET /api/identities/{iid}/authorizations", s.api(false, s.listAuthorizations))
	mux.HandleFunc("DELETE /api/identities/{iid}/authorizations/{aid}", s.api(false, s.revokeAuthorization))

	mux.HandleFunc("GET /api/identities/{iid}/subscriptions", s.api(false, s.listSubscriptions))
	mux.HandleFunc("DELETE /api/identities/{iid}/subscriptions/{sid}", s.api(false, s.deleteSubscription))

	mux.HandleFunc("GET /api/events", s.api(false, s.listEvents))
	mux.HandleFunc("GET /api/events/stream", s.api(false, s.eventStream))
	mux.HandleFunc("POST /api/broadcast", s.api(false, s.broadcast))

	mux.HandleFunc("GET /api/oauth/requests/{id}", s.api(false, s.getRequest))
	mux.HandleFunc("POST /api/oauth/requests/{id}/approve", s.api(false, s.approve))
	mux.HandleFunc("POST /api/oauth/requests/{id}/deny", s.api(false, s.deny))

	mux.HandleFunc("/api/", s.api(true, func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "not_found", "no such API endpoint")
	}))
}

func getOnly(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// page serves one of the UI's pages; a page that needs the sign-in sends
// a signed-out browser to /login, to come back after.
func (s *Server) page(name string, signIn bool) http.HandlerFunc {
	h := s.Web.Page(name)
	return func(w http.ResponseWriter, r *http.Request) {
		if signIn && !s.signedIn(r) {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		h.ServeHTTP(w, r)
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := httpx.DecodeJSON(r, 64<<10, v); err != nil {
		apiError(w, http.StatusBadRequest, "invalid_argument", "invalid JSON body: "+err.Error())
		return false
	}
	return true
}

// Login backoff: after loginFree failures from an address, each further
// failure locks it out for longer, doubling up to loginMaxLock; a quiet
// loginReset clears it.
const (
	loginFree    = 5
	loginBase    = 30 * time.Second
	loginMaxLock = 15 * time.Minute
	loginReset   = time.Hour
)

func (s *Server) lockedFor(ip string, now time.Time) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[ip]
	if f == nil || !now.Before(f.until) {
		return 0
	}
	return f.until.Sub(now)
}

func (s *Server) recordFailure(ip string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.failures[ip]
	if f == nil || now.Sub(f.last) > loginReset {
		f = &failure{}
		s.failures[ip] = f
	}
	f.count++
	f.last = now
	if f.count >= loginFree {
		lock := time.Duration(float64(loginBase) * math.Pow(2, float64(f.count-loginFree)))
		f.until = now.Add(min(lock, loginMaxLock))
	}
	// keep the table small
	for k, v := range s.failures {
		if now.Sub(v.last) > loginReset {
			delete(s.failures, k)
		}
	}
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := httpx.ClientIP(r, s.Cfg.TrustProxy)
	now := time.Now()
	if d := s.lockedFor(ip, now); d > 0 {
		secs := int(math.Ceil(d.Seconds()))
		httpx.WriteJSON(w, http.StatusTooManyRequests, map[string]any{"error": map[string]any{"code": "rate_limited", "message": "too many failed sign-ins; try again later", "retry_after_seconds": secs}})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &body) {
		return
	}
	a, b := sha256.Sum256([]byte(body.Password)), sha256.Sum256([]byte(s.Cfg.Password))
	if subtle.ConstantTimeCompare(a[:], b[:]) != 1 {
		s.recordFailure(ip, now)
		s.Log.Warn("failed admin sign-in", "ip", ip)
		apiError(w, http.StatusUnauthorized, "unauthorized", "wrong password")
		return
	}
	s.mu.Lock()
	delete(s.failures, ip)
	s.mu.Unlock()
	id := idgen.Secret("")
	if err := s.Store.CreateSession(r.Context(), idgen.Hash(id), s.Store.Now().Add(SessionTTL)); err != nil {
		s.fail(w, err, "session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: id, Path: "/", MaxAge: int(SessionTTL / time.Second), HttpOnly: true, Secure: s.Cfg.Secure(), SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
		_ = s.Store.DeleteSession(r.Context(), idgen.Hash(c.Value))
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.Cfg.Secure(), SameSite: http.SameSiteLaxMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) meta(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"version": version.Version, "public_url": s.Cfg.PublicURL, "mcp_url": s.Cfg.MCPResource()})
}
