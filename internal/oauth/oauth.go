// Package oauth is the platform's own OAuth 2.1 authorization server and
// the resource-server side of the MCP endpoint's bearer check.
//
// It does what MCP's 2026-07-28 authorization spec asks of an
// authorization server that registers clients dynamically:
//   - Protected Resource Metadata (RFC 9728) for the MCP endpoint, and
//     Authorization Server Metadata (RFC 8414, also served as OpenID
//     Connect discovery);
//   - Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-
//     document, cimd.go): a client_id that is an https URL names its own
//     metadata, fetched and cached through the SSRF guard;
//   - Dynamic Client Registration (RFC 7591), deprecated by MCP but still
//     offered, redirect URIs https or loopback http only;
//   - the authorization code grant with PKCE S256 required, exact redirect
//     URI matching (a loopback redirect's port ignored, RFC 8252 §7.3),
//     the resource indicator checked (RFC 8707), and iss in every
//     redirect back (RFC 9207);
//   - refresh tokens rotated on every use, a reused one revoking its whole
//     family; token revocation (RFC 7009).
//
// The user approves on the consent page (internal/admin), choosing the
// identity the grant is bound to.
package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/config"
	"github.com/ImSingee/mcp-webhook-events/internal/core"
	"github.com/ImSingee/mcp-webhook-events/internal/httpx"
	"github.com/ImSingee/mcp-webhook-events/internal/idgen"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
)

// Scope is the one scope the server grants.
const Scope = "mcp"

// Server is the authorization server.
type Server struct {
	Cfg   config.Config
	Store *store.Store
	Core  *core.Service
	Log   *slog.Logger

	AccessTTL  time.Duration
	RefreshTTL time.Duration
	CodeTTL    time.Duration
	RequestTTL time.Duration

	// MetadataClient fetches client ID metadata documents; its transport
	// must refuse non-public addresses (MetadataHTTPClient).
	MetadataClient     *http.Client
	MetadataMinTTL     time.Duration
	MetadataDefaultTTL time.Duration
	MetadataMaxTTL     time.Duration

	regMu   sync.Mutex
	regSeen map[string][]time.Time // registrations per IP in the last hour

	fetchMu  sync.Mutex
	fetching map[string]*fetchCall // metadata fetches in flight, by client_id
}

// New is a server with the token lifetimes the platform uses.
func New(cfg config.Config, st *store.Store, svc *core.Service, log *slog.Logger) *Server {
	return &Server{
		Cfg: cfg, Store: st, Core: svc, Log: log,
		AccessTTL:  time.Hour,
		RefreshTTL: 90 * 24 * time.Hour,
		CodeTTL:    60 * time.Second,
		RequestTTL: 10 * time.Minute,

		MetadataClient:     MetadataHTTPClient(false, nil, nil),
		MetadataMinTTL:     DefaultMetadataMinTTL,
		MetadataDefaultTTL: DefaultMetadataDefaultTTL,
		MetadataMaxTTL:     DefaultMetadataMaxTTL,

		regSeen:  map[string][]time.Time{},
		fetching: map[string]*fetchCall{},
	}
}

// Issuer is the authorization server's issuer identifier.
func (s *Server) Issuer() string { return s.Cfg.PublicURL }

// ResourceMetadataURL is the Protected Resource Metadata of the MCP
// endpoint, named in every 401 from it.
func (s *Server) ResourceMetadataURL() string {
	return s.Cfg.PublicURL + "/.well-known/oauth-protected-resource/mcp"
}

// Routes adds the authorization server's endpoints to mux.
func (s *Server) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.cors(s.resourceMetadata))
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", s.cors(s.resourceMetadata))
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.cors(s.serverMetadata))
	mux.HandleFunc("GET /.well-known/openid-configuration", s.cors(s.serverMetadata))
	mux.HandleFunc("POST /oauth/register", s.cors(s.register))
	mux.HandleFunc("GET /oauth/authorize", s.authorize)
	mux.HandleFunc("POST /oauth/token", s.cors(s.token))
	mux.HandleFunc("POST /oauth/revoke", s.cors(s.revoke))
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server", "/.well-known/openid-configuration", "/oauth/register", "/oauth/token", "/oauth/revoke"} {
		mux.HandleFunc("OPTIONS "+p, s.cors(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	}
}

// cors lets browser-based MCP clients read the metadata and use the
// registration and token endpoints, which carry no cookies.
func (s *Server) cors(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
		w.Header().Set("Access-Control-Max-Age", "86400")
		h(w, r)
	}
}

func (s *Server) resourceMetadata(w http.ResponseWriter, r *http.Request) {
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.Cfg.MCPResource(),
		"authorization_servers":    []string{s.Issuer()},
		"scopes_supported":         []string{Scope},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "mcp-webhook-events",
	})
}

func (s *Server) serverMetadata(w http.ResponseWriter, r *http.Request) {
	pub := s.Cfg.PublicURL
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         pub,
		"authorization_endpoint":                         pub + "/oauth/authorize",
		"token_endpoint":                                 pub + "/oauth/token",
		"registration_endpoint":                          pub + "/oauth/register",
		"revocation_endpoint":                            pub + "/oauth/revoke",
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":               []string{"S256"},
		"token_endpoint_auth_methods_supported":          []string{"none", "client_secret_post", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":     []string{"none", "client_secret_post", "client_secret_basic"},
		"scopes_supported":                               []string{Scope},
		"authorization_response_iss_parameter_supported": true,
		"client_id_metadata_document_supported":          true,
	})
}

// oauthError writes an OAuth error response (RFC 6749 §5.2).
func oauthError(w http.ResponseWriter, status int, code, desc string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="mwe"`)
	}
	httpx.WriteJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// IsLoopback reports whether a redirect URI's host is a loopback address,
// whose port the client picks at run time (RFC 8252 §7.3).
func IsLoopback(u *url.URL) bool {
	return u.Scheme == "http" && config.IsLoopbackHost(u.Hostname())
}

// checkRedirectURI is a registered redirect URI's rule: absolute https, or
// http on a loopback host; no fragment.
func checkRedirectURI(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return errors.New("redirect URI " + raw + " is not an absolute URL")
	}
	if u.Fragment != "" {
		return errors.New("redirect URI " + raw + " has a fragment")
	}
	if u.Scheme != "https" && !IsLoopback(u) {
		return errors.New("redirect URI " + raw + " must use https, or http on localhost, 127.0.0.1 or [::1]")
	}
	return nil
}

// RedirectMatches reports whether requested matches a registered URI:
// exactly, or for loopback http, everything but the port.
func RedirectMatches(registered, requested string) bool {
	if registered == requested {
		return true
	}
	a, err1 := url.Parse(registered)
	b, err2 := url.Parse(requested)
	if err1 != nil || err2 != nil || !IsLoopback(a) || !IsLoopback(b) {
		return false
	}
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && a.EscapedPath() == b.EscapedPath() && a.RawQuery == b.RawQuery && b.Fragment == ""
}

// allowRegistration rate-limits registrations per client IP.
func (s *Server) allowRegistration(ip string) bool {
	s.regMu.Lock()
	defer s.regMu.Unlock()
	now := time.Now()
	recent := s.regSeen[ip][:0]
	for _, t := range s.regSeen[ip] {
		if now.Sub(t) < time.Hour {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 30 {
		s.regSeen[ip] = recent
		return false
	}
	s.regSeen[ip] = append(recent, now)
	return true
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.allowRegistration(httpx.ClientIP(r, s.Cfg.TrustProxy)) {
		oauthError(w, http.StatusTooManyRequests, "invalid_request", "too many client registrations from this address; try again later")
		return
	}
	var m map[string]any
	b, err := httpx.ReadBody(r, 64<<10)
	if err == nil {
		err = json.Unmarshal(b, &m)
	}
	if err != nil || m == nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "the body must be a JSON object of client metadata")
		return
	}
	uris := strings_(m["redirect_uris"])
	if len(uris) == 0 || len(uris) > 10 {
		oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", "redirect_uris must list 1 to 10 URIs")
		return
	}
	for _, u := range uris {
		if err := checkRedirectURI(u); err != nil {
			oauthError(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}
	method, _ := m["token_endpoint_auth_method"].(string)
	if method == "" {
		method = "client_secret_basic"
	}
	if !slices.Contains([]string{"none", "client_secret_post", "client_secret_basic"}, method) {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "token_endpoint_auth_method must be none, client_secret_post or client_secret_basic")
		return
	}
	grants := strings_(m["grant_types"])
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}
	for _, g := range grants {
		if g != "authorization_code" && g != "refresh_token" {
			oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "grant_types may only hold authorization_code and refresh_token")
			return
		}
	}
	responses := strings_(m["response_types"])
	if len(responses) == 0 {
		responses = []string{"code"}
	}
	if len(responses) != 1 || responses[0] != "code" {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", `response_types must be ["code"]`)
		return
	}
	name, _ := m["client_name"].(string)
	name = strings.TrimSpace(name)
	if name == "" {
		name = "Unnamed client"
	}
	if r := []rune(name); len(r) > 200 {
		name = string(r[:200])
	}
	c := store.Client{ID: idgen.ID("cli"), Name: name, RedirectURIs: uris, TokenAuthMethod: method, GrantTypes: grants, CreatedAt: s.Store.Now()}
	var secret string
	if method != "none" {
		secret = idgen.Secret("mwecs_")
		c.SecretHash = idgen.Hash(secret)
	}
	if err := s.Store.CreateClient(r.Context(), c); err != nil {
		s.Log.Error("register client", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "could not register the client")
		return
	}
	out := map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        c.CreatedAt.Unix(),
		"client_name":                c.Name,
		"redirect_uris":              c.RedirectURIs,
		"token_endpoint_auth_method": c.TokenAuthMethod,
		"grant_types":                c.GrantTypes,
		"response_types":             responses,
	}
	if secret != "" {
		out["client_secret"] = secret
		out["client_secret_expires_at"] = 0
	}
	for _, k := range []string{"application_type", "client_uri", "logo_uri", "software_id", "software_version"} {
		if v, ok := m[k].(string); ok {
			out[k] = v
		}
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

// strings_ is a JSON array of strings, or nil.
func strings_(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, ok := x.(string)
		if !ok {
			return nil
		}
		out = append(out, s)
	}
	return out
}

// errorPage is shown when an authorization request can't be sent back to
// the client safely (no known client or redirect URI).
func errorPage(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>授权请求无效</title>` +
		`<body style="font:15px/1.6 system-ui,sans-serif;max-width:40rem;margin:4rem auto;padding:0 1rem"><h1 style="font-size:1.3rem">授权请求无效</h1><p>` +
		html.EscapeString(msg) + `</p><p>请回到发起登录的应用重新尝试。</p></body>`))
}

// Redirect is the URL a client's redirect URI gets back, with params and
// iss added to its query.
func (s *Server) Redirect(redirectURI string, params url.Values) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	for k, vs := range params {
		for _, v := range vs {
			if v != "" {
				q.Set(k, v)
			}
		}
	}
	q.Set("iss", s.Issuer())
	u.RawQuery = q.Encode()
	return u.String()
}

var verifierRe = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	c, err := s.ResolveClient(r.Context(), clientID, false)
	var merr *MetadataError
	switch {
	case errors.As(err, &merr):
		// CIMD §6.1: never redirect to a client whose metadata failed
		errorPage(w, "无法使用该应用的客户端元数据文档（"+clientID+"）："+merr.Msg)
		return
	case err != nil:
		errorPage(w, "未知的 client_id。应用需要用一个托管了客户端元数据文档的 https URL 作为 client_id，或先通过动态注册（/oauth/register）获得 client_id。")
		return
	}
	redirect := q.Get("redirect_uri")
	if redirect == "" && len(c.RedirectURIs) == 1 && !IsLoopback(mustURL(c.RedirectURIs[0])) {
		redirect = c.RedirectURIs[0]
	}
	matched := false
	for _, reg := range c.RedirectURIs {
		if redirectMatches(c, reg, redirect) {
			matched = true
			break
		}
	}
	if !matched {
		errorPage(w, "redirect_uri 与该应用注册的回调地址不匹配。")
		return
	}
	state := q.Get("state")
	fail := func(code, desc string) {
		http.Redirect(w, r, s.Redirect(redirect, url.Values{"error": {code}, "error_description": {desc}, "state": {state}}), http.StatusFound)
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "response_type must be code")
		return
	}
	challenge := q.Get("code_challenge")
	if challenge == "" || q.Get("code_challenge_method") != "S256" {
		fail("invalid_request", "PKCE is required: send code_challenge with code_challenge_method=S256")
		return
	}
	if len(challenge) != 43 || !verifierRe.MatchString(challenge) {
		fail("invalid_request", "code_challenge must be the base64url SHA-256 of the code verifier")
		return
	}
	resource := q.Get("resource")
	if resource != "" && !sameResource(resource, s.Cfg.MCPResource()) {
		fail("invalid_target", "resource must be "+s.Cfg.MCPResource())
		return
	}
	ar := store.AuthRequest{
		ID: idgen.ID("ar"), ClientID: c.ID, RedirectURI: redirect, State: state, CodeChallenge: challenge,
		Scope: Scope, Resource: s.Cfg.MCPResource(), CreatedAt: s.Store.Now(), ExpiresAt: s.Store.Now().Add(s.RequestTTL),
	}
	if err := s.Store.CreateAuthRequest(r.Context(), ar); err != nil {
		s.Log.Error("store authorization request", "err", err)
		fail("server_error", "could not start the authorization")
		return
	}
	http.Redirect(w, r, "/consent?request="+url.QueryEscape(ar.ID), http.StatusFound)
}

func mustURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		return &url.URL{}
	}
	return u
}

// sameResource compares resource indicators, taking the scheme and host
// case-insensitively and ignoring one trailing slash (MCP's canonical URI
// guidance).
func sameResource(a, b string) bool {
	norm := func(s string) string {
		u, err := url.Parse(s)
		if err != nil {
			return s
		}
		u.Scheme, u.Host = strings.ToLower(u.Scheme), strings.ToLower(u.Host)
		u.Path = strings.TrimSuffix(u.Path, "/")
		return u.String()
	}
	return norm(a) == norm(b)
}

// Pending is an authorization request as the consent page shows it.
type Pending struct {
	Request store.AuthRequest
	Client  store.Client
}

// PendingRequest is a live authorization request and its client.
func (s *Server) PendingRequest(ctx context.Context, id string) (Pending, error) {
	ar, err := s.Store.GetAuthRequest(ctx, id)
	if err != nil {
		return Pending{}, err
	}
	c, err := s.Store.GetClient(ctx, ar.ClientID)
	if err != nil {
		return Pending{}, err
	}
	return Pending{Request: ar, Client: c}, nil
}

// Approve answers a pending request with a code for identityID, and
// returns the client's redirect URL carrying it.
func (s *Server) Approve(ctx context.Context, id, identityID string) (string, error) {
	ar, err := s.Store.GetAuthRequest(ctx, id)
	if err != nil {
		return "", err
	}
	if err := s.Store.TakeAuthRequest(ctx, id); err != nil {
		return "", err
	}
	code := idgen.Secret("mwec_")
	if err := s.Store.CreateCode(ctx, store.Code{
		Hash: idgen.Hash(code), ClientID: ar.ClientID, IdentityID: identityID, RedirectURI: ar.RedirectURI,
		CodeChallenge: ar.CodeChallenge, Scope: ar.Scope, Resource: ar.Resource, ExpiresAt: s.Store.Now().Add(s.CodeTTL),
	}); err != nil {
		return "", err
	}
	return s.Redirect(ar.RedirectURI, url.Values{"code": {code}, "state": {ar.State}}), nil
}

// Deny answers a pending request with access_denied.
func (s *Server) Deny(ctx context.Context, id string) (string, error) {
	ar, err := s.Store.GetAuthRequest(ctx, id)
	if err != nil {
		return "", err
	}
	if err := s.Store.TakeAuthRequest(ctx, id); err != nil {
		return "", err
	}
	return s.Redirect(ar.RedirectURI, url.Values{"error": {"access_denied"}, "error_description": {"the user denied the request"}, "state": {ar.State}}), nil
}

// authFail is a token or revocation request refused for its client.
type authFail struct {
	status int
	code   string
	desc   string
}

func (f *authFail) write(w http.ResponseWriter) { oauthError(w, f.status, f.code, f.desc) }

func badClient(desc string) *authFail {
	return &authFail{status: http.StatusUnauthorized, code: "invalid_client", desc: desc}
}

// clientAuth authenticates the client of a token or revocation request:
// HTTP Basic, client_secret in the form, or just client_id for a public
// client. A CIMD client is public and must present no credentials
// (CIMD §5); resolve has its document checked, from the cache or fetched,
// the token endpoint answering 503 to a transient failure with no good
// snapshot to fall back on and invalid_client to a terminal one (§6.1).
func (s *Server) clientAuth(r *http.Request, resolve bool) (store.Client, *authFail) {
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id == "" {
		return store.Client{}, badClient("client_id is required")
	}
	if IsClientIDURL(id) {
		if basic || secret != "" || r.PostForm.Get("client_assertion") != "" {
			return store.Client{}, badClient("a client identified by its metadata document URL is a public client and must not send client credentials")
		}
		if !resolve {
			c, err := s.Store.GetClient(r.Context(), id)
			if err != nil || c.Kind != store.ClientCIMD {
				return store.Client{}, badClient("unknown client")
			}
			return c, nil
		}
		c, err := s.ResolveClient(r.Context(), id, true)
		var merr *MetadataError
		switch {
		case errors.As(err, &merr) && merr.Transient:
			return store.Client{}, &authFail{status: http.StatusServiceUnavailable, code: "temporarily_unavailable", desc: merr.Msg}
		case errors.As(err, &merr):
			return store.Client{}, badClient(merr.Msg)
		case err != nil:
			s.Log.Error("resolve client", "client_id", id, "err", err)
			return store.Client{}, &authFail{status: http.StatusInternalServerError, code: "server_error", desc: "could not load the client"}
		}
		return c, nil
	}
	c, err := s.Store.GetClient(r.Context(), id)
	if err != nil || c.Kind != store.ClientDCR {
		return store.Client{}, badClient("unknown client")
	}
	if c.TokenAuthMethod == "none" {
		return c, nil
	}
	if secret == "" || !idgen.HashEqual(secret, c.SecretHash) {
		return store.Client{}, badClient("client authentication failed")
	}
	return c, nil
}

// refreshAllowed says whether a client gets refresh tokens: a CIMD client
// only when its document lists the refresh_token grant (MCP clients
// "SHOULD include refresh_token in their grant_types"); a dynamically
// registered one always, as before.
func refreshAllowed(c store.Client) bool {
	return c.Kind != store.ClientCIMD || slices.Contains(c.GrantTypes, "refresh_token")
}

func (s *Server) parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the body must be application/x-www-form-urlencoded")
		return false
	}
	return true
}

func (s *Server) issue() (access, refresh string, tokens []store.Token) {
	access, refresh = idgen.Secret("mwea_"), idgen.Secret("mwer_")
	now := s.Store.Now()
	return access, refresh, []store.Token{
		{Hash: idgen.Hash(access), Kind: "access", ExpiresAt: now.Add(s.AccessTTL)},
		{Hash: idgen.Hash(refresh), Kind: "refresh", ExpiresAt: now.Add(s.RefreshTTL)},
	}
}

func (s *Server) tokenResponse(w http.ResponseWriter, access, refresh, scope string) {
	w.Header().Set("Pragma", "no-cache")
	out := map[string]any{
		"access_token": access,
		"token_type":   "Bearer",
		"expires_in":   int(s.AccessTTL / time.Second),
		"scope":        scope,
	}
	if refresh != "" {
		out["refresh_token"] = refresh
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// grantError is a token request the grant check refused.
type grantError struct{ code, desc string }

func (e *grantError) Error() string { return e.desc }

func pkceS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	c, fail := s.clientAuth(r, true)
	if fail != nil {
		fail.write(w)
		return
	}
	f := r.PostForm
	resource := f.Get("resource")
	if resource != "" && !sameResource(resource, s.Cfg.MCPResource()) {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource must be "+s.Cfg.MCPResource())
		return
	}
	switch f.Get("grant_type") {
	case "authorization_code":
		code, verifier, redirect := f.Get("code"), f.Get("code_verifier"), f.Get("redirect_uri")
		if code == "" || verifier == "" {
			oauthError(w, http.StatusBadRequest, "invalid_request", "code and code_verifier are required")
			return
		}
		fam := store.Family{ID: idgen.ID("auf")}
		access, refresh, tokens := s.issue()
		if !refreshAllowed(c) {
			refresh, tokens = "", tokens[:1]
		}
		revoked, err := s.Store.RedeemCode(r.Context(), idgen.Hash(code), func(cd store.Code) error {
			switch {
			case cd.ClientID != c.ID:
				return &grantError{"invalid_grant", "the code was issued to another client"}
			case redirect != cd.RedirectURI:
				return &grantError{"invalid_grant", "redirect_uri does not match the authorization request"}
			case !verifierRe.MatchString(verifier) || !idgen.Equal(pkceS256(verifier), cd.CodeChallenge):
				return &grantError{"invalid_grant", "code_verifier does not match the code_challenge"}
			case resource != "" && !sameResource(resource, cd.Resource):
				return &grantError{"invalid_target", "resource does not match the authorization request"}
			}
			return nil
		}, fam, tokens...)
		if revoked != "" {
			s.Core.FamilyRevoked(r.Context(), revoked)
		}
		if err != nil {
			s.grantFailed(w, err, "authorization code")
			return
		}
		s.tokenResponse(w, access, refresh, Scope)
	case "refresh_token":
		rt := f.Get("refresh_token")
		if rt == "" {
			oauthError(w, http.StatusBadRequest, "invalid_request", "refresh_token is required")
			return
		}
		if !refreshAllowed(c) {
			oauthError(w, http.StatusBadRequest, "unauthorized_client", "the client's metadata document doesn't list the refresh_token grant")
			return
		}
		if sc := f.Get("scope"); sc != "" {
			for _, v := range strings.Fields(sc) {
				if v != Scope {
					oauthError(w, http.StatusBadRequest, "invalid_scope", "the refresh token was granted scope "+Scope)
					return
				}
			}
		}
		access, refresh, tokens := s.issue()
		fam, err := s.Store.RotateRefresh(r.Context(), idgen.Hash(rt), func(f store.Family) error {
			if f.ClientID != c.ID {
				return &grantError{"invalid_grant", "the refresh token was issued to another client"}
			}
			if resource != "" && !sameResource(resource, f.Resource) {
				return &grantError{"invalid_target", "resource does not match the grant"}
			}
			return nil
		}, tokens...)
		if errors.Is(err, store.ErrReplay) {
			s.Log.Warn("refresh token reused: revoked its authorization", "family", fam.ID, "client", c.ID)
			s.Core.FamilyRevoked(r.Context(), fam.ID)
		}
		if err != nil {
			s.grantFailed(w, err, "refresh token")
			return
		}
		s.tokenResponse(w, access, refresh, fam.Scope)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
	}
}

func (s *Server) grantFailed(w http.ResponseWriter, err error, what string) {
	var ge *grantError
	switch {
	case errors.As(err, &ge):
		oauthError(w, http.StatusBadRequest, ge.code, ge.desc)
	case errors.Is(err, store.ErrNotFound):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown "+what)
	case errors.Is(err, store.ErrExpired):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the "+what+" has expired")
	case errors.Is(err, store.ErrRevoked):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the "+what+" has been revoked")
	case errors.Is(err, store.ErrReplay):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "the "+what+" was already used; the authorization has been revoked")
	default:
		s.Log.Error("token request", "err", err)
		oauthError(w, http.StatusInternalServerError, "server_error", "could not issue tokens")
	}
}

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) {
		return
	}
	c, fail := s.clientAuth(r, false)
	if fail != nil {
		fail.write(w)
		return
	}
	if t := r.PostForm.Get("token"); t != "" {
		fam, err := s.Store.RevokeTokenByHash(r.Context(), idgen.Hash(t), c.ID)
		if err != nil {
			s.Log.Error("revoke token", "err", err)
			oauthError(w, http.StatusInternalServerError, "server_error", "could not revoke the token")
			return
		}
		if fam != "" {
			s.Core.FamilyRevoked(r.Context(), fam)
		}
	}
	w.WriteHeader(http.StatusOK)
}

// Principal is who an MCP request's access token speaks for.
type Principal struct {
	IdentityID   string
	IdentityName string
	ClientID     string
	ClientName   string
	FamilyID     string
	Scope        string
}

// Bearer errors.
var (
	ErrNoToken      = errors.New("no bearer token")
	ErrInvalidToken = errors.New("the access token is invalid or expired")
)

// Authenticate checks a request's bearer token: issued by this server,
// live, and for this MCP endpoint (its audience, RFC 8707).
func (s *Server) Authenticate(r *http.Request) (Principal, error) {
	h := r.Header.Get("Authorization")
	scheme, tok, ok := strings.Cut(h, " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || strings.TrimSpace(tok) == "" {
		return Principal{}, ErrNoToken
	}
	g, err := s.Store.LookupAccess(r.Context(), idgen.Hash(strings.TrimSpace(tok)))
	if errors.Is(err, store.ErrNotFound) {
		return Principal{}, ErrInvalidToken
	}
	if err != nil {
		return Principal{}, err
	}
	if !sameResource(g.Family.Resource, s.Cfg.MCPResource()) {
		return Principal{}, ErrInvalidToken
	}
	if g.Family.LastUsedAt == nil || s.Store.Now().Sub(*g.Family.LastUsedAt) > time.Minute {
		_ = s.Store.TouchFamily(r.Context(), g.Family.ID)
	}
	return Principal{
		IdentityID: g.Family.IdentityID, IdentityName: g.IdentityName,
		ClientID: g.Family.ClientID, ClientName: g.ClientName, FamilyID: g.Family.ID, Scope: g.Family.Scope,
	}, nil
}

// Challenge writes the 401 an MCP request without a valid token gets,
// pointing the client at the resource metadata (RFC 9728 §5.1).
func (s *Server) Challenge(w http.ResponseWriter, err error) {
	v := `Bearer resource_metadata="` + s.ResourceMetadataURL() + `", scope="` + Scope + `"`
	desc := "authorization required"
	if errors.Is(err, ErrInvalidToken) {
		v = `Bearer error="invalid_token", error_description="` + err.Error() + `", resource_metadata="` + s.ResourceMetadataURL() + `", scope="` + Scope + `"`
		desc = err.Error()
	}
	w.Header().Set("WWW-Authenticate", v)
	httpx.WriteJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "error_description": desc})
}

// RedirectHost is the host a redirect URI sends the user back to, as the
// consent page and the authorization list show it.
func RedirectHost(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	h := u.Hostname()
	if ip := net.ParseIP(h); ip != nil && ip.To4() == nil {
		return "[" + h + "]"
	}
	return h
}
