package mcp_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/ImSingee/mcp-webhook-events/internal/apptest"
)

func errOf(t *testing.T, b []byte) (int, string, map[string]any) {
	t.Helper()
	v := apptest.JSON(t, b)
	e, ok := v["error"].(map[string]any)
	if !ok {
		t.Fatalf("no error in %s", b)
	}
	d, _ := e["data"].(map[string]any)
	return int(e["code"].(float64)), e["message"].(string), d
}

// The 2026-07-28 header and _meta rules, each with its HTTP status and
// JSON-RPC code (Streamable HTTP "Server Validation", basic "_meta",
// Versioning).
func TestHeaderAndVersionErrors(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	meta := apptest.Meta()
	discover := func(params map[string]any) map[string]any {
		return map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": params}
	}
	good := map[string]string{"MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "server/discover"}
	with := func(edit map[string]string) map[string]string {
		h := map[string]string{}
		for k, v := range good {
			h[k] = v
		}
		for k, v := range edit {
			h[k] = v
		}
		return h
	}
	cases := []struct {
		name    string
		body    any
		headers map[string]string
		status  int
		code    int
	}{
		{"missing MCP-Protocol-Version", discover(map[string]any{"_meta": meta}), with(map[string]string{"MCP-Protocol-Version": ""}), 400, -32020},
		{"missing _meta", discover(nil), good, 400, -32602},
		{"missing protocolVersion in _meta", discover(map[string]any{"_meta": map[string]any{"io.modelcontextprotocol/clientCapabilities": map[string]any{}}}), good, 400, -32602},
		{"missing clientCapabilities", discover(map[string]any{"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": "2026-07-28"}}), good, 400, -32602},
		{"header and _meta disagree", discover(map[string]any{"_meta": meta}), with(map[string]string{"MCP-Protocol-Version": "2099-01-01"}), 400, -32020},
		{"missing Mcp-Method", discover(map[string]any{"_meta": meta}), with(map[string]string{"Mcp-Method": ""}), 400, -32020},
		{"wrong Mcp-Method", discover(map[string]any{"_meta": meta}), with(map[string]string{"Mcp-Method": "tools/list"}), 400, -32020},
		{"Mcp-Method in another case", discover(map[string]any{"_meta": meta}), with(map[string]string{"Mcp-Method": "SERVER/DISCOVER"}), 400, -32020},
		{"unknown method", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "resources/list", "params": map[string]any{"_meta": meta}}, with(map[string]string{"Mcp-Method": "resources/list"}), 404, -32601},
		{"initialize on the modern wire", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"_meta": meta}}, with(map[string]string{"Mcp-Method": "initialize"}), 404, -32601},
		{"tools/call without Mcp-Name", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"_meta": meta, "name": "whoami"}}, with(map[string]string{"Mcp-Method": "tools/call"}), 400, -32020},
		{"tools/call with another Mcp-Name", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"_meta": meta, "name": "whoami"}}, with(map[string]string{"Mcp-Method": "tools/call", "Mcp-Name": "webhook_list"}), 400, -32020},
		{"events/poll without Mcp-Name", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "events/poll", "params": map[string]any{"_meta": meta, "name": "webhook.received", "arguments": map[string]any{"channel": "x"}}}, with(map[string]string{"Mcp-Method": "events/poll"}), 400, -32020},
		{"events/stream with another Mcp-Name", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "events/stream", "params": map[string]any{"_meta": meta, "name": "webhook.received", "arguments": map[string]any{"channel": "x"}}}, with(map[string]string{"Mcp-Method": "events/stream", "Mcp-Name": "webhook.received-mismatch"}), 400, -32020},
		{"id null", map[string]any{"jsonrpc": "2.0", "id": nil, "method": "server/discover", "params": map[string]any{"_meta": meta}}, good, 400, -32600},
		{"batch", []any{discover(map[string]any{"_meta": meta})}, good, 400, -32600},
	}
	for _, tc := range cases {
		resp, b := m.Raw(tc.body, tc.headers)
		code, msg, _ := errOf(t, b)
		if resp.StatusCode != tc.status || code != tc.code {
			t.Errorf("%s: HTTP %d code %d (%s), want %d %d", tc.name, resp.StatusCode, code, msg, tc.status, tc.code)
		}
	}
	// an unsupported version lists the supported ones
	resp, b := m.Raw(discover(map[string]any{"_meta": map[string]any{"io.modelcontextprotocol/protocolVersion": "1900-01-01", "io.modelcontextprotocol/clientCapabilities": map[string]any{}}}), with(map[string]string{"MCP-Protocol-Version": "1900-01-01"}))
	code, _, data := errOf(t, b)
	if resp.StatusCode != 400 || code != -32022 || data["requested"] != "1900-01-01" || data["supported"].([]any)[0] != "2026-07-28" {
		t.Errorf("unsupported version: %d %d %v", resp.StatusCode, code, data)
	}
	// a name outside the header-safe set travels Base64-encoded
	resp, b = m.Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"_meta": meta, "name": "whoami"}}, with(map[string]string{"Mcp-Method": "tools/call", "Mcp-Name": "=?base64?d2hvYW1p?="}))
	if resp.StatusCode != 200 || strings.Contains(string(b), `"error"`) {
		t.Errorf("Base64 Mcp-Name: %d %s", resp.StatusCode, b)
	}
	// a poll with no name at all is the method's invalid params, not a header error
	resp, b = m.Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "events/poll", "params": map[string]any{"_meta": meta, "arguments": map[string]any{}}}, with(map[string]string{"Mcp-Method": "events/poll"}))
	if code, _, _ := errOf(t, b); code != -32602 {
		t.Errorf("poll without a name: %d %d", resp.StatusCode, code)
	}
	// notifications are accepted with 202 and no body
	resp, b = m.Raw(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": 1}}, nil)
	if resp.StatusCode != http.StatusAccepted || len(b) != 0 {
		t.Errorf("notification: %d %q", resp.StatusCode, b)
	}
	// GET and DELETE: there is no stream or session
	for _, method := range []string{"GET", "DELETE"} {
		req, _ := http.NewRequest(method, s.URL+"/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+m.Token)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		r.Body.Close()
		if r.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s /mcp = %d, want 405", method, r.StatusCode)
		}
	}
	// a cross-site Origin is refused; a loopback server takes loopback origins
	for origin, want := range map[string]int{"https://evil.example": 403, "http://localhost.evil.example": 403, "http://127.0.0.1:1234": 200, "http://localhost:3000": 200, s.URL: 200} {
		resp, _ = m.Raw(discover(map[string]any{"_meta": meta}), with(map[string]string{"Origin": origin}))
		if resp.StatusCode != want {
			t.Errorf("Origin %s: %d, want %d", origin, resp.StatusCode, want)
		}
	}
	// a loopback server refuses a Host that isn't loopback (DNS rebinding)
	body, h := m.Request("server/discover", nil)
	h["Host"] = ""
	req, _ := http.NewRequest("POST", s.URL+"/mcp", strings.NewReader(mustJSON(body)))
	for k, v := range h {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	req.Header.Set("Authorization", "Bearer "+m.Token)
	req.Host = "evil.example"
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusForbidden {
		t.Errorf("Host evil.example: %d, want 403", r.StatusCode)
	}
}

// server/discover declares the events extension both ways: in
// capabilities.extensions (SEP-3415) and as a top-level capabilities.events
// (the design sketch clients such as ChatGPT read). Every result carries
// resultType and serverInfo.
func TestDiscover(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	res := m.Call("server/discover", nil)
	caps := res["capabilities"].(map[string]any)
	ext := caps["extensions"].(map[string]any)
	if _, ok := ext["io.modelcontextprotocol/events"].(map[string]any); !ok {
		t.Errorf("extensions = %v", ext)
	}
	if _, ok := caps["events"].(map[string]any); !ok {
		t.Errorf("no top-level events capability: %v", caps)
	}
	if res["resultType"] != "complete" || res["ttlMs"] == nil || res["cacheScope"] == nil {
		t.Errorf("discover = %v", res)
	}
	if v := res["supportedVersions"].([]any); v[0] != "2026-07-28" {
		t.Errorf("supportedVersions = %v", v)
	}
	if res["_meta"].(map[string]any)["io.modelcontextprotocol/serverInfo"] == nil {
		t.Error("no serverInfo")
	}
	if !strings.Contains(res["instructions"].(string), "reserved") {
		t.Error("instructions don't mention reserved identifiers")
	}
	tl := m.Call("tools/list", nil)
	if tl["resultType"] != "complete" || tl["ttlMs"] == nil || tl["cacheScope"] == nil || len(tl["tools"].([]any)) != 10 {
		t.Errorf("tools/list = %v", tl)
	}
	for _, x := range tl["tools"].([]any) {
		tool := x.(map[string]any)
		if tool["inputSchema"].(map[string]any)["type"] != "object" || tool["outputSchema"] == nil || tool["description"] == "" {
			t.Errorf("tool %v lacks a schema or description", tool["name"])
		}
	}
	// unknown tool: a protocol error
	if _, err := m.Try("tools/call", map[string]any{"name": "nope", "arguments": map[string]any{}}); err == nil || err.Code != -32602 {
		t.Errorf("unknown tool: %v", err)
	}
}

// ping is gone from 2026-07-28: a modern request for it is an unknown
// method (404, -32601), while the legacy revisions that define it still
// get an answer.
func TestPingByEra(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	body, h := m.Request("ping", nil)
	resp, b := m.Raw(body, h)
	code, _, _ := errOf(t, b)
	if resp.StatusCode != http.StatusNotFound || code != -32601 {
		t.Errorf("modern ping: HTTP %d code %d (%s), want 404 -32601", resp.StatusCode, code, b)
	}
	for _, v := range []string{"2025-06-18", "2025-11-25"} {
		resp, b := m.Raw(map[string]any{"jsonrpc": "2.0", "id": 9, "method": "ping"}, map[string]string{"MCP-Protocol-Version": v})
		res, ok := apptest.JSON(t, b)["result"].(map[string]any)
		if resp.StatusCode != http.StatusOK || !ok || len(res) != 0 {
			t.Errorf("legacy %s ping: HTTP %d %s, want 200 with an empty result", v, resp.StatusCode, b)
		}
	}
}

// Legacy clients (initialize) get the tools, no session, and no events.
func TestLegacy(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	for _, v := range []string{"2025-06-18", "2025-11-25"} {
		resp, b := m.Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": v, "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "old", "version": "1"}}}, nil)
		res := apptest.JSON(t, b)["result"].(map[string]any)
		if resp.StatusCode != 200 || res["protocolVersion"] != v || resp.Header.Get("Mcp-Session-Id") != "" {
			t.Fatalf("initialize %s: %d %s session %q", v, resp.StatusCode, b, resp.Header.Get("Mcp-Session-Id"))
		}
		caps := res["capabilities"].(map[string]any)
		if caps["extensions"] != nil || caps["events"] != nil || caps["tools"] == nil {
			t.Errorf("legacy capabilities = %v", caps)
		}
		h := map[string]string{"MCP-Protocol-Version": v}
		if resp, _ := m.Raw(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"}, h); resp.StatusCode != 202 {
			t.Errorf("initialized: %d", resp.StatusCode)
		}
		_, b = m.Raw(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "webhook_list", "arguments": map[string]any{}}}, h)
		r := apptest.JSON(t, b)["result"].(map[string]any)
		if r["structuredContent"] == nil || r["resultType"] != nil {
			t.Errorf("legacy tools/call = %s", b)
		}
		_, b = m.Raw(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "events/list", "params": map[string]any{}}, h)
		if code, msg, _ := errOf(t, b); code != -32601 || !strings.Contains(msg, "2026-07-28") {
			t.Errorf("legacy events/list: %d %s", code, msg)
		}
		_, b = m.Raw(map[string]any{"jsonrpc": "2.0", "id": 4, "method": "ping"}, h)
		if apptest.JSON(t, b)["result"] == nil {
			t.Errorf("legacy ping: %s", b)
		}
	}
	// an initialize for an older revision is answered with one we serve
	_, b := m.Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-03-26"}}, nil)
	if v := apptest.JSON(t, b)["result"].(map[string]any)["protocolVersion"]; v != "2025-11-25" {
		t.Errorf("initialize 2025-03-26 negotiated %v", v)
	}
}

func TestTools(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	k := m.Tool("webhook_create", map[string]any{"identifier": "github-push", "name": "GitHub", "description": "pushes"})
	if !strings.HasPrefix(k["url"].(string), s.URL+"/hooks/") || !strings.HasPrefix(k["key"].(string), "mwek_") || !strings.Contains(k["usage"].(string), "X-Webhook-Key") {
		t.Fatalf("webhook_create = %v", k)
	}
	res := m.Call("tools/call", map[string]any{"name": "webhook_create", "arguments": map[string]any{"identifier": "github-push"}})
	if res["isError"] != true {
		t.Errorf("duplicate identifier: %v", res)
	}
	res = m.Call("tools/call", map[string]any{"name": "webhook_create", "arguments": map[string]any{"identifier": "Bad_Id"}})
	if res["isError"] != true {
		t.Errorf("invalid identifier: %v", res)
	}
	res = m.Call("tools/call", map[string]any{"name": "webhook_create", "arguments": map[string]any{"identifier": "x", "bogus": 1}})
	if res["isError"] != true {
		t.Errorf("unknown argument: %v", res)
	}
	ws := m.Tool("webhook_list", nil)["webhooks"].([]any)
	if len(ws) != 1 || ws[0].(map[string]any)["key"] != nil {
		t.Fatalf("webhook_list = %v", ws)
	}
	u := m.Tool("webhook_update", map[string]any{"identifier": "github-push", "name": "GH"})["webhook"].(map[string]any)
	if u["name"] != "GH" || u["description"] != "pushes" {
		t.Errorf("webhook_update = %v", u)
	}
	old := k["key"].(string)
	nk := m.Tool("webhook_rotate_key", map[string]any{"identifier": "github-push"})
	if nk["key"] == old {
		t.Error("rotate kept the key")
	}
	c := m.Tool("channel_create", map[string]any{"name": "ci", "mode": "include", "identifiers": []any{"github-push", ":system"}})["channel"].(map[string]any)
	if c["mode"] != "include" || len(c["identifiers"].([]any)) != 2 {
		t.Errorf("channel_create = %v", c)
	}
	res = m.Call("tools/call", map[string]any{"name": "channel_create", "arguments": map[string]any{"name": "all2", "mode": "all", "identifiers": []any{"x"}}})
	if res["isError"] != true {
		t.Errorf("mode all with identifiers: %v", res)
	}
	c = m.Tool("channel_update", map[string]any{"name": "ci", "mode": "all"})["channel"].(map[string]any)
	if c["mode"] != "all" || len(c["identifiers"].([]any)) != 0 {
		t.Errorf("channel_update to all = %v", c)
	}
	if n := len(m.Tool("channel_list", nil)["channels"].([]any)); n != 1 {
		t.Errorf("channel_list = %d", n)
	}
	if m.Tool("channel_delete", map[string]any{"name": "ci"})["deleted"] != "ci" || m.Tool("webhook_delete", map[string]any{"identifier": "github-push"})["deleted"] != "github-push" {
		t.Error("delete")
	}
	// another identity sees none of it
	other := s.NewAgent("other")
	if n := len(other.Tool("webhook_list", nil)["webhooks"].([]any)); n != 0 {
		t.Errorf("another identity sees %d webhooks", n)
	}
}

func mustJSON(v any) string {
	b, _ := jsonMarshal(v)
	return string(b)
}
