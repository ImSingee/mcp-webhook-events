// Package apptest runs the whole server in-process for tests, and plays
// its clients: the admin's browser (sign-in, consent), an OAuth client,
// and an MCP client of the 2026-07-28 wire.
package apptest

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/app"
	"github.com/ImSingee/mcp-webhook-events/internal/config"
	"github.com/ImSingee/mcp-webhook-events/internal/delivery"
)

// Password is the test server's admin password.
const Password = "correct horse battery staple"

// Assets stand in for the UI, whose content the server's tests don't
// depend on.
var Assets = fstest.MapFS{
	"index.html":   {Data: []byte(`<!doctype html><script src="/app.js"></script>`)},
	"login.html":   {Data: []byte(`<!doctype html><p>login</p>`)},
	"consent.html": {Data: []byte(`<!doctype html><p>consent</p>`)},
	"app.js":       {Data: []byte(`1`)},
}

// Server is a running test server.
type Server struct {
	T    testing.TB
	URL  string
	App  *app.App
	HTTP *httptest.Server
}

// Option adjusts the server's config or app before it starts.
type Option func(*config.Config, *app.Options)

// AllowPrivate turns on MWE_ALLOW_PRIVATE_CALLBACKS.
func AllowPrivate() Option {
	return func(c *config.Config, _ *app.Options) { c.AllowPrivateCallbacks = true }
}

// WithResolver replaces the delivery guard's DNS.
func WithResolver(r delivery.Resolver) Option {
	return func(_ *config.Config, o *app.Options) { o.Resolver = r }
}

// WithConfig edits the config.
func WithConfig(f func(*config.Config)) Option {
	return func(c *config.Config, _ *app.Options) { f(c) }
}

// WithAssets serves other UI files.
func WithAssets(a fs.FS) Option {
	return func(_ *config.Config, o *app.Options) { o.Assets = a }
}

// Start runs a server on a loopback port with fast timings: heartbeats
// every 200ms and retries after 100ms.
func Start(t testing.TB, opts ...Option) *Server {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pub := "http://" + ln.Addr().String()
	cfg := config.Config{
		Password: Password, PublicURL: pub, Addr: ln.Addr().String(), DataDir: t.TempDir(),
		EventRetention: 168 * time.Hour, MaxBodyBytes: 4096, LogLevel: slog.LevelError,
	}
	o := app.Options{Assets: Assets}
	for _, f := range opts {
		f(&cfg, &o)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(&tlog{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	a, err := app.New(context.Background(), cfg, log, o)
	if err != nil {
		t.Fatal(err)
	}
	a.MCP.Heartbeat = 200 * time.Millisecond
	a.Worker.Retries = []time.Duration{100 * time.Millisecond, 200 * time.Millisecond}
	a.Worker.Tick = 50 * time.Millisecond
	a.Worker.Timeout = 2 * time.Second
	hs := httptest.NewUnstartedServer(a.Handler)
	hs.Listener.Close()
	hs.Listener = ln
	a.Start()
	hs.Start()
	s := &Server{T: t, URL: pub, App: a, HTTP: hs}
	t.Cleanup(func() {
		a.Stop()
		hs.CloseClientConnections()
		hs.Close()
		a.Store.Close()
	})
	return s
}

type tlog struct{ t testing.TB }

func (l *tlog) Write(b []byte) (int, error) {
	l.t.Log(strings.TrimSpace(string(b)))
	return len(b), nil
}

// Browser is an admin's browser: a cookie jar that doesn't follow
// redirects.
type Browser struct {
	S      *Server
	Client *http.Client
}

// Browser is a fresh, signed-out browser.
func (s *Server) Browser() *Browser {
	jar, _ := cookiejar.New(nil)
	return &Browser{S: s, Client: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// Do sends a request; JSON bodies for the API get the CSRF header and
// the same-origin Origin.
func (b *Browser) Do(method, path string, body any) (*http.Response, []byte) {
	b.S.T.Helper()
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	u := path
	if strings.HasPrefix(path, "/") {
		u = b.S.URL + path
	}
	req, err := http.NewRequest(method, u, rd)
	if err != nil {
		b.S.T.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("X-MWE-Request", "1")
		req.Header.Set("Origin", b.S.URL)
	}
	resp, err := b.Client.Do(req)
	if err != nil {
		b.S.T.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

// SignIn signs the browser in with the password.
func (b *Browser) SignIn() {
	b.S.T.Helper()
	resp, body := b.Do(http.MethodPost, "/api/login", map[string]string{"password": Password})
	if resp.StatusCode != http.StatusNoContent {
		b.S.T.Fatalf("sign in: %d %s", resp.StatusCode, body)
	}
}

// JSON decodes a response body.
func JSON(t testing.TB, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return v
}

// OAuthClient is a dynamically registered public client.
type OAuthClient struct {
	S           *Server
	ID          string
	RedirectURI string
	HTTP        *http.Client
}

// Register registers a public client with one loopback redirect URI.
func (s *Server) Register(name string) *OAuthClient {
	s.T.Helper()
	redirect := "http://127.0.0.1:9/callback"
	body, _ := json.Marshal(map[string]any{"client_name": name, "redirect_uris": []string{redirect}, "token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}})
	resp, err := http.Post(s.URL+"/oauth/register", "application/json", bytes.NewReader(body))
	if err != nil {
		s.T.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		s.T.Fatalf("register: %d %s", resp.StatusCode, b)
	}
	return &OAuthClient{S: s, ID: JSON(s.T, b)["client_id"].(string), RedirectURI: redirect, HTTP: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

// PKCE is a verifier and its S256 challenge.
func PKCE() (verifier, challenge string) {
	verifier = strings.Repeat("v", 20) + fmt.Sprint(time.Now().UnixNano()) + "-abcdefghijklmnopqrstuvwxyz"
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthorizeURL is an authorization request for the client. redirect ""
// is the registered one (on another port, which loopback ignores).
func (c *OAuthClient) AuthorizeURL(challenge, redirect, resource string) string {
	if redirect == "" {
		redirect = "http://127.0.0.1:54321/callback"
	}
	q := url.Values{"response_type": {"code"}, "client_id": {c.ID}, "redirect_uri": {redirect}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"st-1"}, "scope": {"mcp"}}
	if resource != "" {
		q.Set("resource", resource)
	}
	return c.S.URL + "/oauth/authorize?" + q.Encode()
}

// Consent runs an authorization request through the consent API as the
// signed-in admin, binding identity (an existing one by id, else a new
// one by that name), and returns the redirect URL the client gets back.
func (b *Browser) Consent(authorizeURL, identityID, newName string) string {
	t := b.S.T
	t.Helper()
	resp, body := b.Do(http.MethodGet, authorizeURL, nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d %s", resp.StatusCode, body)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	ar := loc.Query().Get("request")
	if ar == "" {
		t.Fatalf("authorize redirected to %s, not the consent page", loc)
	}
	payload := map[string]string{"identity_id": identityID}
	if identityID == "" {
		payload = map[string]string{"new_identity_name": newName}
	}
	resp, body = b.Do(http.MethodPost, "/api/oauth/requests/"+ar+"/approve", payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("approve: %d %s", resp.StatusCode, body)
	}
	return JSON(t, body)["redirect_url"].(string)
}

// Token posts a form to the token endpoint.
func (c *OAuthClient) Token(form url.Values) (int, map[string]any) {
	c.S.T.Helper()
	if form.Get("client_id") == "" {
		form.Set("client_id", c.ID)
	}
	resp, err := http.PostForm(c.S.URL+"/oauth/token", form)
	if err != nil {
		c.S.T.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, JSON(c.S.T, b)
}

// Tokens is an access and refresh token pair.
type Tokens struct {
	Access, Refresh string
	IdentityID      string
}

// Authorize runs the whole flow for a new or existing identity and
// returns the tokens.
func (s *Server) Authorize(b *Browser, c *OAuthClient, identityID, newName string) Tokens {
	s.T.Helper()
	verifier, challenge := PKCE()
	red := b.Consent(c.AuthorizeURL(challenge, "", s.URL+"/mcp"), identityID, newName)
	u, _ := url.Parse(red)
	st, tok := c.Token(url.Values{"grant_type": {"authorization_code"}, "code": {u.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1:54321/callback"}, "resource": {s.URL + "/mcp"}})
	if st != http.StatusOK {
		s.T.Fatalf("token: %d %v", st, tok)
	}
	out := Tokens{Access: tok["access_token"].(string), Refresh: tok["refresh_token"].(string)}
	m := s.MCP(out.Access)
	who := m.Tool("whoami", nil)
	out.IdentityID = who["identity"].(map[string]any)["id"].(string)
	return out
}

// NewAgent signs a new identity in and returns its MCP client.
func (s *Server) NewAgent(name string) *MCP {
	s.T.Helper()
	b := s.Browser()
	b.SignIn()
	tok := s.Authorize(b, s.Register(name+"-client"), "", name)
	m := s.MCP(tok.Access)
	m.IdentityID = tok.IdentityID
	return m
}

// MCP is a 2026-07-28 client with a bearer token.
type MCP struct {
	S          *Server
	Token      string
	IdentityID string
	id         int
}

// MCP is a client with that token.
func (s *Server) MCP(token string) *MCP { return &MCP{S: s, Token: token} }

// Meta is the per-request _meta of a 2026-07-28 request.
func Meta() map[string]any {
	return map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28", "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
}

// Raw sends a body with headers as given and returns the response.
func (m *MCP) Raw(body any, headers map[string]string) (*http.Response, []byte) {
	m.S.T.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, m.S.URL+"/mcp", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if m.Token != "" {
		req.Header.Set("Authorization", "Bearer "+m.Token)
	}
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		m.S.T.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

// Request is a well-formed 2026-07-28 request and its headers.
func (m *MCP) Request(method string, params map[string]any) (map[string]any, map[string]string) {
	m.id++
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = Meta()
	h := map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": method}
	if n, ok := params["name"].(string); ok {
		h["Mcp-Name"] = n
	}
	return map[string]any{"jsonrpc": "2.0", "id": m.id, "method": method, "params": params}, h
}

// Call sends a request and returns its result, failing on an error.
func (m *MCP) Call(method string, params map[string]any) map[string]any {
	m.S.T.Helper()
	res, err := m.Try(method, params)
	if err != nil {
		m.S.T.Fatalf("%s: %v", method, err)
	}
	return res
}

// RPCError is a JSON-RPC error answer.
type RPCError struct {
	Status  int
	Code    int
	Message string
	Data    map[string]any
}

func (e *RPCError) Error() string {
	return fmt.Sprintf("HTTP %d, %d %s %v", e.Status, e.Code, e.Message, e.Data)
}

// Try sends a request and returns its result or its error.
func (m *MCP) Try(method string, params map[string]any) (map[string]any, *RPCError) {
	m.S.T.Helper()
	body, h := m.Request(method, params)
	resp, b := m.Raw(body, h)
	v := JSON(m.S.T, b)
	if e, ok := v["error"].(map[string]any); ok {
		re := &RPCError{Status: resp.StatusCode, Code: int(e["code"].(float64)), Message: fmt.Sprint(e["message"])}
		re.Data, _ = e["data"].(map[string]any)
		return nil, re
	}
	res, _ := v["result"].(map[string]any)
	return res, nil
}

// Tool calls a tool and returns its structured content, failing on an
// error result.
func (m *MCP) Tool(name string, args map[string]any) map[string]any {
	m.S.T.Helper()
	if args == nil {
		args = map[string]any{}
	}
	res := m.Call("tools/call", map[string]any{"name": name, "arguments": args})
	if res["isError"] == true {
		m.S.T.Fatalf("tool %s: %v", name, res["content"])
	}
	return res["structuredContent"].(map[string]any)
}

// Stream is an open SSE response.
type Stream struct {
	Resp   *http.Response
	Frames chan map[string]any
	cancel context.CancelFunc
	t      testing.TB
}

// Open sends a streaming request (events/stream) and reads its frames.
func (m *MCP) Open(method string, params map[string]any) *Stream {
	m.S.T.Helper()
	body, h := m.Request(method, params)
	b, _ := json.Marshal(body)
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, m.S.URL+"/mcp", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+m.Token)
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		m.S.T.Fatal(err)
	}
	s := &Stream{Resp: resp, Frames: make(chan map[string]any, 1000), cancel: cancel, t: m.S.T}
	go func() {
		defer close(s.Frames)
		defer resp.Body.Close()
		if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
			b, _ := io.ReadAll(resp.Body)
			var v map[string]any
			_ = json.Unmarshal(b, &v)
			s.Frames <- v
			return
		}
		r := bufio.NewReader(resp.Body)
		for {
			line, err := r.ReadString('\n')
			if strings.HasPrefix(line, "data: ") {
				var v map[string]any
				if json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), "data: ")), &v) == nil {
					s.Frames <- v
				}
			} else if strings.HasPrefix(line, ":") {
				s.Frames <- map[string]any{"comment": strings.TrimSpace(line)}
			}
			if err != nil {
				return
			}
		}
	}()
	t := m.S.T
	t.Cleanup(cancel)
	return s
}

// Close aborts the stream, as a client cancels.
func (s *Stream) Close() { s.cancel() }

// Next is the next frame, failing after timeout.
func (s *Stream) Next(timeout time.Duration) map[string]any {
	s.t.Helper()
	select {
	case f, ok := <-s.Frames:
		if !ok {
			s.t.Fatal("the stream ended")
		}
		return f
	case <-time.After(timeout):
		s.t.Fatalf("no frame within %s", timeout)
	}
	return nil
}

// NextMethod skips frames until one with the method (heartbeats in
// between are skipped unless asked for).
func (s *Stream) NextMethod(method string, timeout time.Duration) map[string]any {
	s.t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case f, ok := <-s.Frames:
			if !ok {
				s.t.Fatalf("the stream ended before %s", method)
			}
			if f["method"] == method {
				return f
			}
			if f["method"] != "notifications/events/heartbeat" && method != "" {
				s.t.Fatalf("got %v while waiting for %s", f, method)
			}
		case <-deadline:
			s.t.Fatalf("no %s within %s", method, timeout)
		}
	}
}

// Quiet reports whether no event notification arrives within d.
func (s *Stream) Quiet(d time.Duration) (map[string]any, bool) {
	deadline := time.After(d)
	for {
		select {
		case f, ok := <-s.Frames:
			if !ok {
				return nil, true
			}
			if f["method"] == "notifications/events/event" {
				return f, false
			}
		case <-deadline:
			return nil, true
		}
	}
}

// Webhook creates a webhook through MCP and returns its URL and key.
func (m *MCP) Webhook(identifier string) (url, key string) {
	m.S.T.Helper()
	v := m.Tool("webhook_create", map[string]any{"identifier": identifier})
	return v["url"].(string), v["key"].(string)
}

// Send posts a body to a webhook with the key in the header.
func Send(t testing.TB, url, key, body string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("X-Webhook-Key", key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("webhook: %d %s", resp.StatusCode, b)
	}
	return JSON(t, b)["event_id"].(string)
}

// EventData is an event notification's data.
func EventData(f map[string]any) map[string]any {
	p, _ := f["params"].(map[string]any)
	d, _ := p["data"].(map[string]any)
	return d
}

// Params is a frame's params.
func Params(f map[string]any) map[string]any {
	p, _ := f["params"].(map[string]any)
	return p
}
