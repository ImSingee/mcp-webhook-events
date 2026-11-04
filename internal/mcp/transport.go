// Package mcp is the platform's MCP endpoint (/mcp), JSON-RPC over
// Streamable HTTP written on the standard library.
//
// Its main path is the stateless 2026-07-28 revision: every request
// carries its protocol version and client capabilities in _meta, mirrored
// in the MCP-Protocol-Version, Mcp-Method and Mcp-Name headers, and the
// server offers server/discover, tools, and the SEP-3415 events extension
// (io.modelcontextprotocol/events). Clients of 2025-06-18 and 2025-11-25
// get the legacy initialize handshake and the tools, with no session and
// no events, which the extension doesn't define before 2026-07-28.
//
// Every request needs a bearer token from the platform's own
// authorization server; the identity it is bound to scopes everything the
// request can see.
package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/config"
	"github.com/ImSingee/mcp-webhook-events/internal/core"
	"github.com/ImSingee/mcp-webhook-events/internal/delivery"
	"github.com/ImSingee/mcp-webhook-events/internal/events"
	"github.com/ImSingee/mcp-webhook-events/internal/httpx"
	"github.com/ImSingee/mcp-webhook-events/internal/oauth"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
	"github.com/ImSingee/mcp-webhook-events/internal/version"
)

// Protocol versions.
const (
	Modern = "2026-07-28"
)

// Legacy are the initialize-era versions the endpoint still serves tools
// to, newest first.
var Legacy = []string{"2025-11-25", "2025-06-18"}

// Reserved _meta keys.
const (
	metaProtocolVersion = "io.modelcontextprotocol/protocolVersion"
	metaClientCaps      = "io.modelcontextprotocol/clientCapabilities"
	metaServerInfo      = "io.modelcontextprotocol/serverInfo"
	metaSubscriptionID  = "io.modelcontextprotocol/subscriptionId"
	// ExtensionID is SEP-3415's extension identifier.
	ExtensionID = "io.modelcontextprotocol/events"
)

// JSON-RPC and MCP error codes.
const (
	codeParse          = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternal       = -32603
	codeHeaderMismatch = -32020
	codeUnsupportedVer = -32022
)

// Server is the MCP endpoint.
type Server struct {
	Cfg    config.Config
	Core   *core.Service
	Store  *store.Store
	Hub    *events.Hub
	OAuth  *oauth.Server
	Worker *delivery.Worker
	Log    *slog.Logger

	// Heartbeat is how often an events/stream sends
	// notifications/events/heartbeat (SEP-3415: at least every 30s).
	Heartbeat time.Duration
	// Keepalive is how often a subscriptions/listen stream sends an SSE
	// comment.
	Keepalive time.Duration
	// NextPollMs is the poll interval events/poll recommends.
	NextPollMs int
	// Base ends with the server: open streams then close gracefully with
	// their final result.
	Base context.Context
}

// New is an endpoint with the platform's timings.
func New(cfg config.Config, svc *core.Service, auth *oauth.Server, w *delivery.Worker, log *slog.Logger) *Server {
	return &Server{
		Cfg: cfg, Core: svc, Store: svc.Store, Hub: svc.Hub, OAuth: auth, Worker: w, Log: log,
		Heartbeat: 20 * time.Second, Keepalive: 20 * time.Second, NextPollMs: 5000, Base: context.Background(),
	}
}

// message is one JSON-RPC message as received.
type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// rpcError is a JSON-RPC error with the HTTP status it goes out with.
type rpcError struct {
	Status  int
	Code    int
	Message string
	Data    any
}

func (e *rpcError) Error() string { return e.Message }

func errInvalidParams(msg string) *rpcError {
	return &rpcError{Status: http.StatusOK, Code: codeInvalidParams, Message: msg}
}

// request is a validated request on its way to a method.
type request struct {
	id        json.RawMessage
	method    string
	params    map[string]json.RawMessage
	modern    bool
	version   string
	principal oauth.Principal
	r         *http.Request
}

func writeRPC(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func errorBody(id json.RawMessage, code int, msg string, data any) map[string]any {
	e := map[string]any{"code": code, "message": msg}
	if data != nil {
		e["data"] = data
	}
	out := map[string]any{"jsonrpc": "2.0", "error": e}
	if len(id) > 0 {
		out["id"] = id
	}
	return out
}

func writeError(w http.ResponseWriter, id json.RawMessage, e *rpcError) {
	status := e.Status
	if status == 0 {
		status = http.StatusOK
	}
	writeRPC(w, status, errorBody(id, e.Code, e.Message, e.Data))
}

// serverInfo is the implementation the server reports itself as.
func serverInfo() map[string]any {
	return map[string]any{"name": "mcp-webhook-events", "title": "MCP Webhook Events", "version": version.Version}
}

// finish is a method's result as sent: with resultType and serverInfo on
// the modern path.
func (q *request) finish(result map[string]any) map[string]any {
	if result == nil {
		result = map[string]any{}
	}
	if q.modern {
		result["resultType"] = "complete"
		meta, _ := result["_meta"].(map[string]any)
		if meta == nil {
			meta = map[string]any{}
		}
		if _, ok := meta[metaServerInfo]; !ok {
			meta[metaServerInfo] = serverInfo()
		}
		result["_meta"] = meta
	}
	return map[string]any{"jsonrpc": "2.0", "id": q.id, "result": result}
}

// allowedOrigin is the Origin rule: absent (not a browser), the
// platform's own origin, or, for a server on a loopback URL, any loopback
// origin (a page DNS rebinding sends here carries its own, non-loopback
// origin).
func (s *Server) allowedOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" || strings.EqualFold(o, s.Cfg.PublicURL) {
		return true
	}
	pub, err1 := url.Parse(s.Cfg.PublicURL)
	ou, err2 := url.Parse(o)
	return err1 == nil && err2 == nil && config.IsLoopbackHost(pub.Hostname()) &&
		(ou.Scheme == "http" || ou.Scheme == "https") && config.IsLoopbackHost(ou.Hostname())
}

// allowedHost guards a server reached on a loopback URL against DNS
// rebinding: a request whose Host isn't a loopback name was sent to some
// other name that resolved here.
func (s *Server) allowedHost(r *http.Request) bool {
	u, err := url.Parse(s.Cfg.PublicURL)
	if err != nil || !config.IsLoopbackHost(u.Hostname()) {
		return true
	}
	host := r.Host
	if h, _, ok := strings.Cut(strings.TrimPrefix(host, "["), "]"); ok {
		host = h
	} else if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return config.IsLoopbackHost(host)
}

const maxRequest = 1 << 20

// ServeHTTP is the MCP endpoint.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeRPC(w, http.StatusMethodNotAllowed, errorBody(nil, codeInvalidRequest, "the MCP endpoint takes POST only (2026-07-28 Streamable HTTP has no GET stream or session to DELETE)", nil))
		return
	}
	if !s.allowedOrigin(r) || !s.allowedHost(r) {
		writeRPC(w, http.StatusForbidden, errorBody(nil, codeInvalidRequest, "origin not allowed", nil))
		return
	}
	p, err := s.OAuth.Authenticate(r)
	if errors.Is(err, oauth.ErrNoToken) || errors.Is(err, oauth.ErrInvalidToken) {
		s.OAuth.Challenge(w, err)
		return
	}
	if err != nil {
		s.Log.Error("authenticate MCP request", "err", err)
		writeRPC(w, http.StatusInternalServerError, errorBody(nil, codeInternal, "internal error", nil))
		return
	}
	body, err := httpx.ReadBody(r, maxRequest)
	if errors.Is(err, httpx.ErrTooLarge) {
		writeRPC(w, http.StatusRequestEntityTooLarge, errorBody(nil, codeInvalidRequest, "request body larger than 1 MiB", nil))
		return
	}
	if err != nil {
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		writeRPC(w, http.StatusBadRequest, errorBody(nil, codeInvalidRequest, "JSON-RPC batches are not supported: send one message per POST", nil))
		return
	}
	var m message
	if err := json.Unmarshal(trimmed, &m); err != nil {
		writeRPC(w, http.StatusBadRequest, errorBody(nil, codeParse, "parse error: "+err.Error(), nil))
		return
	}
	if m.JSONRPC != "2.0" {
		writeRPC(w, http.StatusBadRequest, errorBody(m.ID, codeInvalidRequest, `invalid request: jsonrpc must be "2.0"`, nil))
		return
	}
	if m.Method == "" {
		writeRPC(w, http.StatusBadRequest, errorBody(m.ID, codeInvalidRequest, "invalid request: the body must be a request or a notification; clients don't send responses", nil))
		return
	}
	if len(m.ID) == 0 {
		// notifications (notifications/initialized, notifications/cancelled)
		// need no answer; a stream is cancelled by closing it
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if string(m.ID) == "null" || !(m.ID[0] == '"' || m.ID[0] == '-' || (m.ID[0] >= '0' && m.ID[0] <= '9')) {
		writeRPC(w, http.StatusBadRequest, errorBody(nil, codeInvalidRequest, "invalid request: id must be a string or an integer", nil))
		return
	}
	q := &request{id: m.ID, method: m.Method, principal: p, r: r}
	if len(m.Params) > 0 && string(m.Params) != "null" {
		if err := json.Unmarshal(m.Params, &q.params); err != nil {
			writeError(w, m.ID, &rpcError{Status: http.StatusBadRequest, Code: codeInvalidParams, Message: "invalid params: params must be an object"})
			return
		}
	}
	if q.params == nil {
		q.params = map[string]json.RawMessage{}
	}
	hdr := r.Header.Get("MCP-Protocol-Version")
	var meta map[string]json.RawMessage
	_ = json.Unmarshal(q.params["_meta"], &meta)
	var metaVer string
	_ = json.Unmarshal(meta[metaProtocolVersion], &metaVer)
	switch {
	case metaVer == "" && slices.Contains(Legacy, hdr), metaVer == "" && hdr == "" && m.Method == "initialize":
		q.version = hdr
		s.legacy(w, q)
		return
	}
	if e := s.validateModern(r, q, hdr, meta, metaVer); e != nil {
		writeError(w, m.ID, e)
		return
	}
	q.modern, q.version = true, metaVer
	s.modern(w, q)
}

// nameSource is the body field Mcp-Name mirrors for each method that
// needs it.
var nameSource = map[string]string{
	"tools/call":         "name",
	"prompts/get":        "name",
	"resources/read":     "uri",
	"events/poll":        "name",
	"events/stream":      "name",
	"events/subscribe":   "name",
	"events/unsubscribe": "name",
}

// headerSafe reports whether v is a header value Mcp-* headers may carry
// as is: visible ASCII and spaces, no leading or trailing space.
func headerSafe(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; c != ' ' && c != '\t' && (c < 0x21 || c > 0x7e) {
			return false
		}
	}
	return true
}

// decodeHeader undoes the Base64 sentinel encoding (=?base64?…?=).
func decodeHeader(v string) (string, bool) {
	inner, ok := strings.CutPrefix(v, "=?base64?")
	if !ok {
		return v, true
	}
	inner, ok = strings.CutSuffix(inner, "?=")
	if !ok {
		return v, true
	}
	b, err := base64.StdEncoding.DecodeString(inner)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// validateModern checks a 2026-07-28 request's per-request metadata and
// its mirror in the headers, in the order the transport spec gives.
func (s *Server) validateModern(r *http.Request, q *request, hdr string, meta map[string]json.RawMessage, metaVer string) *rpcError {
	bad := func(code int, msg string, data any) *rpcError {
		return &rpcError{Status: http.StatusBadRequest, Code: code, Message: msg, Data: data}
	}
	if hdr == "" {
		return bad(codeHeaderMismatch, "Header mismatch: the MCP-Protocol-Version header is required", nil)
	}
	if meta == nil || metaVer == "" {
		return bad(codeInvalidParams, "Invalid params: _meta[\""+metaProtocolVersion+"\"] is required", nil)
	}
	if hdr != metaVer {
		return bad(codeHeaderMismatch, "Header mismatch: MCP-Protocol-Version header value '"+hdr+"' does not match body value '"+metaVer+"'", nil)
	}
	if metaVer != Modern {
		return bad(codeUnsupportedVer, "Unsupported protocol version", map[string]any{"supported": supportedVersions(), "requested": metaVer})
	}
	if caps, ok := meta[metaClientCaps]; !ok || len(caps) == 0 || caps[0] != '{' {
		return bad(codeInvalidParams, "Invalid params: _meta[\""+metaClientCaps+"\"] is required and must be an object", nil)
	}
	mh := r.Header.Values("Mcp-Method")
	if len(mh) == 0 {
		return bad(codeHeaderMismatch, "Header mismatch: the Mcp-Method header is required", nil)
	}
	if len(mh) > 1 || mh[0] != q.method {
		return bad(codeHeaderMismatch, "Header mismatch: Mcp-Method header value '"+strings.Join(mh, ",")+"' does not match body value '"+q.method+"'", nil)
	}
	field, ok := nameSource[q.method]
	if !ok {
		return nil
	}
	raw, present := q.params[field]
	var want string
	if present && json.Unmarshal(raw, &want) != nil {
		// a non-string name is the method's own invalid params
		return nil
	}
	nh := r.Header.Values("Mcp-Name")
	if !present && len(nh) == 0 {
		return nil
	}
	if len(nh) == 0 {
		return bad(codeHeaderMismatch, "Header mismatch: the Mcp-Name header is required for "+q.method, nil)
	}
	got := strings.TrimSpace(nh[0])
	if len(nh) > 1 || !headerSafe(got) {
		return bad(codeHeaderMismatch, "Header mismatch: the Mcp-Name header is malformed", nil)
	}
	got, ok = decodeHeader(got)
	if !ok {
		return bad(codeHeaderMismatch, "Header mismatch: the Mcp-Name header's Base64 value is malformed", nil)
	}
	if got != want {
		return bad(codeHeaderMismatch, "Header mismatch: Mcp-Name header value '"+got+"' does not match body value '"+want+"'", nil)
	}
	return nil
}

func supportedVersions() []string { return append([]string{Modern}, Legacy...) }
