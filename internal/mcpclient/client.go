package mcpclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/version"
)

// ProtocolVersion is the MCP revision the CLI speaks.
const ProtocolVersion = "2026-07-28"

// ErrNotSignedIn is a profile with no sign-in, or one the server no longer
// takes.
var ErrNotSignedIn = errors.New("not signed in")

// Session is a profile's sign-in in use: it hands out its access token,
// renewing it (under the credentials lock, re-reading the file first, so
// another mwe process's renewal is reused) when it is about to expire.
type Session struct {
	Dir     string
	Name    string
	HTTP    *http.Client
	mu      sync.Mutex
	profile Profile
}

// OpenSession loads a profile.
func OpenSession(dir, name string, hc *http.Client) (*Session, error) {
	f, err := Load(dir)
	if err != nil {
		return nil, err
	}
	p, ok := f.Profiles[name]
	if !ok || p.AccessToken == "" {
		return nil, fmt.Errorf("%w: profile %q has no sign-in; run `mwe login <server-url>%s`", ErrNotSignedIn, name, profileFlag(name))
	}
	return &Session{Dir: dir, Name: name, HTTP: hc, profile: *p}, nil
}

func profileFlag(name string) string {
	if name == DefaultProfile {
		return ""
	}
	return " --profile " + name
}

// Profile is the session's current profile.
func (s *Session) Profile() Profile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.profile
}

// Token is a live access token.
func (s *Session) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	p := s.profile
	s.mu.Unlock()
	if time.Until(p.ExpiresAt) > time.Minute {
		return p.AccessToken, nil
	}
	return s.renew(ctx, p.AccessToken)
}

// Renew renews the token after the server refused stale; a token another
// process already replaced is reused rather than renewed again.
func (s *Session) Renew(ctx context.Context, stale string) (string, error) {
	return s.renew(ctx, stale)
}

func (s *Session) renew(ctx context.Context, stale string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var tok string
	err := Update(s.Dir, func(f *File) (bool, error) {
		p, ok := f.Profiles[s.Name]
		if !ok {
			return false, fmt.Errorf("%w: profile %q was signed out", ErrNotSignedIn, s.Name)
		}
		if p.AccessToken != stale && time.Until(p.ExpiresAt) > time.Minute {
			s.profile, tok = *p, p.AccessToken
			return false, nil
		}
		if err := Refresh(ctx, s.HTTP, p); err != nil {
			var te *TokenError
			if errors.As(err, &te) && (te.Code == "invalid_grant" || te.Code == "invalid_client") {
				return false, fmt.Errorf("%w: the server refused the saved sign-in (%v); run `mwe login %s%s` again", ErrNotSignedIn, err, p.Server, profileFlag(s.Name))
			}
			return false, err
		}
		s.profile, tok = *p, p.AccessToken
		return true, nil
	})
	return tok, err
}

// Client is an MCP client of one profile's server.
type Client struct {
	Session    *Session
	HTTP       *http.Client
	ClientName string
	nextID     atomic.Int64
}

// NewClient is a client over a session; streams need an http.Client with
// no overall timeout, so hc should have none.
func NewClient(s *Session, hc *http.Client) *Client {
	return &Client{Session: s, HTTP: hc, ClientName: "mwe"}
}

// RPCError is a JSON-RPC error from the server.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string {
	s := fmt.Sprintf("%s (%d)", e.Message, e.Code)
	if len(e.Data) > 0 && string(e.Data) != "null" {
		s += " " + string(e.Data)
	}
	return s
}

// headerSafe reports whether v can go in an Mcp-* header as is.
func headerSafe(v string) bool {
	if v == "" || strings.TrimSpace(v) != v || (strings.HasPrefix(v, "=?base64?") && strings.HasSuffix(v, "?=")) {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; c != '\t' && (c < 0x20 || c > 0x7e) {
			return false
		}
	}
	return true
}

// EncodeHeader is v as an Mcp-Name or Mcp-Param value: as is when safe,
// else in the Base64 sentinel form.
func EncodeHeader(v string) string {
	if headerSafe(v) {
		return v
	}
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(v)) + "?="
}

func setHeaders(h http.Header, protocol, method, name string) {
	h.Set("Content-Type", "application/json")
	h.Set("Accept", "application/json, text/event-stream")
	h.Set("User-Agent", "mwe/"+version.Version)
	if protocol != "" {
		h.Set("MCP-Protocol-Version", protocol)
	}
	if method != "" {
		h.Set("Mcp-Method", method)
	}
	if name != "" {
		h.Set("Mcp-Name", EncodeHeader(name))
	}
}

// nameMethods are the methods whose params.name (or uri) Mcp-Name carries.
var nameMethods = map[string]string{
	"tools/call": "name", "prompts/get": "name", "resources/read": "uri",
	"events/poll": "name", "events/stream": "name", "events/subscribe": "name", "events/unsubscribe": "name",
}

// RoutingHeaders are the request metadata headers for a JSON-RPC message:
// the protocol version (from _meta, else fallback), the method, and the
// name for the methods that mirror it.
func RoutingHeaders(msg []byte, fallback string) (protocol, method, name string) {
	var m struct {
		Method string                     `json:"method"`
		Params map[string]json.RawMessage `json:"params"`
	}
	_ = json.Unmarshal(msg, &m)
	method = m.Method
	protocol = fallback
	var meta map[string]json.RawMessage
	if json.Unmarshal(m.Params["_meta"], &meta) == nil {
		var v string
		if json.Unmarshal(meta["io.modelcontextprotocol/protocolVersion"], &v) == nil && v != "" {
			protocol = v
		}
	}
	if f, ok := nameMethods[method]; ok {
		_ = json.Unmarshal(m.Params[f], &name)
	}
	return protocol, method, name
}

// Post sends one JSON-RPC message with the bearer token and the routing
// headers, renewing the token and sending again once on a 401.
func (c *Client) Post(ctx context.Context, msg []byte, protocol, method, name string) (*http.Response, error) {
	tok, err := c.Session.Token(ctx)
	if err != nil {
		return nil, err
	}
	do := func(tok string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Session.Profile().MCPURL, bytes.NewReader(msg))
		if err != nil {
			return nil, err
		}
		setHeaders(req.Header, protocol, method, name)
		req.Header.Set("Authorization", "Bearer "+tok)
		return c.HTTP.Do(req)
	}
	resp, err := do(tok)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	if tok, err = c.Session.Renew(ctx, tok); err != nil {
		return nil, err
	}
	resp, err = do(tok)
	if err == nil && resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		return nil, fmt.Errorf("%w: the server refused a freshly renewed token; run `mwe login` again", ErrNotSignedIn)
	}
	return resp, err
}

// request builds a 2026-07-28 request message.
func (c *Client) request(method string, params map[string]any) (json.RawMessage, []byte) {
	if params == nil {
		params = map[string]any{}
	}
	params["_meta"] = map[string]any{
		"io.modelcontextprotocol/protocolVersion":    ProtocolVersion,
		"io.modelcontextprotocol/clientInfo":         map[string]any{"name": c.ClientName, "version": version.Version},
		"io.modelcontextprotocol/clientCapabilities": map[string]any{"extensions": map[string]any{"io.modelcontextprotocol/events": map[string]any{}}},
	}
	id := json.RawMessage(fmt.Sprint(c.nextID.Add(1)))
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	return id, b
}

// Message is one JSON-RPC message from the server.
type Message struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *RPCError       `json:"error,omitempty"`
}

// ReadMessages reads a response's JSON-RPC messages, a JSON body or an SSE
// stream, calling f with each message's raw bytes until the stream ends,
// f returns an error, or ctx ends.
func ReadMessages(resp *http.Response, f func(raw []byte) error) error {
	ct, _, _ := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if ct != "text/event-stream" {
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		if err != nil {
			return err
		}
		b = bytes.TrimSpace(b)
		if len(b) == 0 {
			return nil
		}
		return f(b)
	}
	r := bufio.NewReaderSize(resp.Body, 64<<10)
	var data bytes.Buffer
	event := ""
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			line = bytes.TrimRight(line, "\r\n")
			switch {
			case len(line) == 0:
				if data.Len() > 0 && (event == "" || event == "message") {
					if ferr := f(bytes.Clone(data.Bytes())); ferr != nil {
						return ferr
					}
				}
				data.Reset()
				event = ""
			case line[0] == ':':
			default:
				field, value, _ := bytes.Cut(line, []byte(":"))
				value = bytes.TrimPrefix(value, []byte(" "))
				switch string(field) {
				case "data":
					if data.Len() > 0 {
						data.WriteByte('\n')
					}
					data.Write(value)
				case "event":
					event = string(value)
				}
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// Call sends a request and returns its result, or its JSON-RPC error as an
// *RPCError.
func (c *Client) Call(ctx context.Context, method, name string, params map[string]any) (json.RawMessage, error) {
	id, msg := c.request(method, params)
	resp, err := c.Post(ctx, msg, ProtocolVersion, method, name)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out json.RawMessage
	var rpcErr *RPCError
	err = ReadMessages(resp, func(raw []byte) error {
		var m Message
		if json.Unmarshal(raw, &m) != nil || !bytes.Equal(bytes.TrimSpace(m.ID), id) {
			return nil
		}
		if m.Error != nil {
			rpcErr = m.Error
		} else {
			out = m.Result
		}
		return io.EOF
	})
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if rpcErr != nil {
		return nil, rpcErr
	}
	if out == nil {
		return nil, fmt.Errorf("%s: the server answered %s with no JSON-RPC response", method, resp.Status)
	}
	return out, nil
}

// ToolError is a tool's own error result (isError).
type ToolError struct{ Message string }

func (e *ToolError) Error() string { return e.Message }

// CallTool calls a tool and returns its structured content.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (json.RawMessage, error) {
	if args == nil {
		args = map[string]any{}
	}
	res, err := c.Call(ctx, "tools/call", name, map[string]any{"name": name, "arguments": args})
	if err != nil {
		return nil, err
	}
	var r struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent json.RawMessage `json:"structuredContent"`
		IsError           bool            `json:"isError"`
	}
	if err := json.Unmarshal(res, &r); err != nil {
		return nil, err
	}
	if r.IsError {
		var msg []string
		for _, c := range r.Content {
			if c.Type == "text" {
				msg = append(msg, c.Text)
			}
		}
		return nil, &ToolError{Message: strings.Join(msg, "\n")}
	}
	return r.StructuredContent, nil
}

// Stream sends a request whose response is a stream (events/stream) and
// calls f with each message on it, until the server ends it, f returns an
// error, or ctx ends.
func (c *Client) Stream(ctx context.Context, method, name string, params map[string]any, f func(Message) error) error {
	_, msg := c.request(method, params)
	resp, err := c.Post(ctx, msg, ProtocolVersion, method, name)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return ReadMessages(resp, func(raw []byte) error {
		var m Message
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil
		}
		return f(m)
	})
}
