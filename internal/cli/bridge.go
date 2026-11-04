package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/ImSingee/mcp-webhook-events/internal/mcpclient"
)

func bridgeCmd(ctx context.Context, env Env, args []string) error {
	f := newFlags(env, "mcp")
	if _, err := f.parse(args); err != nil {
		return err
	}
	b := &Bridge{Out: env.Stdout, Log: env.Stderr}
	c, err := client(env, *f.profile)
	if err != nil {
		// keep serving, so the MCP client shows the reason on each call
		b.ClientErr = err
		fmt.Fprintln(env.Stderr, "mwe mcp:", err)
	}
	b.Client = c
	return b.Run(ctx, env.Stdin)
}

// Bridge is the stdio-to-HTTP bridge: it reads newline-delimited JSON-RPC
// messages from stdin, sends each request as its own POST to the server
// (with the bearer token, renewed as needed, and the routing headers the
// message calls for), and writes every JSON response or SSE message back
// to stdout as one line. Requests run concurrently, so a long-lived
// events/stream never holds up the others; notifications/cancelled aborts
// the request it names, which is how HTTP cancels.
type Bridge struct {
	Client    *mcpclient.Client
	ClientErr error // why there is no client
	Out       io.Writer
	Log       io.Writer

	outMu    sync.Mutex
	mu       sync.Mutex
	inflight map[string]*call
	wg       sync.WaitGroup
	// legacy is the protocol version an initialize negotiated, sent as
	// MCP-Protocol-Version on the requests after it that carry no _meta.
	legacy atomic.Value
}

type call struct {
	cancel context.CancelFunc
	// long marks a request whose response is an open-ended stream; it is
	// cancelled, not waited for, when stdin closes.
	long bool
	// cancelled is set before cancel, so a response racing it isn't
	// written.
	cancelled atomic.Bool
}

type inbound struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// write writes one message to stdout as a single line.
func (b *Bridge) write(msg []byte, c *call) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, msg); err != nil {
		return
	}
	buf.WriteByte('\n')
	b.outMu.Lock()
	defer b.outMu.Unlock()
	if c != nil && c.cancelled.Load() {
		return
	}
	_, _ = b.Out.Write(buf.Bytes())
}

// errorFor writes a local error for a request. Its code is the JSON-RPC
// internal error and its data says it came from the bridge, not the server.
func (b *Bridge) errorFor(id json.RawMessage, c *call, msg string) {
	out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32603, "message": msg, "data": map[string]any{"source": "mwe-bridge"}}})
	b.write(out, c)
}

// Run serves until stdin ends, then waits for the requests in flight
// (cancelling open streams) and returns.
func (b *Bridge) Run(ctx context.Context, in io.Reader) error {
	b.inflight = map[string]*call{}
	b.legacy.Store("")
	r := bufio.NewReaderSize(in, 1<<20)
	for {
		line, err := r.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			b.handle(ctx, bytes.TrimSpace(line))
		}
		if err != nil {
			break
		}
	}
	b.mu.Lock()
	for _, c := range b.inflight {
		if c.long {
			c.cancelled.Store(true)
			c.cancel()
		}
	}
	b.mu.Unlock()
	b.wg.Wait()
	return nil
}

// streams are the methods whose response stays open.
var streams = map[string]bool{"events/stream": true, "subscriptions/listen": true}

func (b *Bridge) handle(ctx context.Context, line []byte) {
	var m inbound
	if err := json.Unmarshal(line, &m); err != nil {
		out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": "parse error: " + err.Error()}})
		b.write(out, nil)
		return
	}
	if m.Method == "" {
		// a response to a server request; this server sends none
		return
	}
	if len(m.ID) == 0 {
		if m.Method == "notifications/cancelled" {
			var p struct {
				RequestID json.RawMessage `json:"requestId"`
			}
			_ = json.Unmarshal(m.Params, &p)
			b.mu.Lock()
			c := b.inflight[string(bytes.TrimSpace(p.RequestID))]
			b.mu.Unlock()
			if c != nil {
				c.cancelled.Store(true)
				c.cancel()
			}
			return
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			b.forward(ctx, m, line, nil)
		}()
		return
	}
	key := string(m.ID)
	cctx, cancel := context.WithCancel(ctx)
	c := &call{cancel: cancel, long: streams[m.Method]}
	b.mu.Lock()
	b.inflight[key] = c
	b.mu.Unlock()
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		defer func() {
			cancel()
			b.mu.Lock()
			if b.inflight[key] == c {
				delete(b.inflight, key)
			}
			b.mu.Unlock()
		}()
		b.forward(cctx, m, line, c)
	}()
}

// forward POSTs one message and relays what comes back.
func (b *Bridge) forward(ctx context.Context, m inbound, line []byte, c *call) {
	isRequest := c != nil
	if b.Client == nil {
		if isRequest {
			b.errorFor(m.ID, c, fmt.Sprintf("mwe: %v", b.ClientErr))
		}
		return
	}
	protocol, method, name := mcpclient.RoutingHeaders(line, b.legacy.Load().(string))
	resp, err := b.Client.Post(ctx, line, protocol, method, name)
	if err != nil {
		if !isRequest || ctx.Err() != nil {
			return
		}
		if errors.Is(err, mcpclient.ErrNotSignedIn) {
			b.errorFor(m.ID, c, fmt.Sprintf("mwe: %v", err))
		} else {
			b.errorFor(m.ID, c, "mwe: couldn't reach the server: "+err.Error())
		}
		return
	}
	defer resp.Body.Close()
	if !isRequest {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		return
	}
	got := false
	err = mcpclient.ReadMessages(resp, func(raw []byte) error {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var reply struct {
			ID     json.RawMessage `json:"id"`
			Result *struct {
				ProtocolVersion string `json:"protocolVersion"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		if json.Unmarshal(raw, &reply) != nil {
			return nil
		}
		if len(reply.ID) > 0 && (reply.Result != nil || reply.Error != nil) {
			got = true
			if m.Method == "initialize" && reply.Result != nil && reply.Result.ProtocolVersion != "" {
				b.legacy.Store(reply.Result.ProtocolVersion)
			}
		}
		b.write(raw, c)
		return nil
	})
	if ctx.Err() != nil || got {
		return
	}
	if resp.StatusCode/100 != 2 {
		b.errorFor(m.ID, c, fmt.Sprintf("mwe: the server answered %s", resp.Status))
		return
	}
	if err != nil && !errors.Is(err, io.EOF) {
		b.errorFor(m.ID, c, "mwe: the server's response broke off: "+err.Error())
		return
	}
	if !streams[m.Method] && resp.StatusCode != http.StatusAccepted {
		b.errorFor(m.ID, c, "mwe: the server sent no response")
	}
}
