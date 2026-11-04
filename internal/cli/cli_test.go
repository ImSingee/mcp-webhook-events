package cli_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/apptest"
	"github.com/ImSingee/mcp-webhook-events/internal/cli"
	"github.com/ImSingee/mcp-webhook-events/internal/mcpclient"
)

// syncBuffer is a bytes.Buffer safe to read while a command writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fixture is a server and a CLI environment signed in to it.
type fixture struct {
	s   *apptest.Server
	env cli.Env
	dir string
}

// browserFor plays the user's browser for mwe login: it signs in, approves
// the consent page's request for identity, and follows the redirect back
// to the CLI's loopback.
func browserFor(t *testing.T, s *apptest.Server, identity string) func(string) error {
	return func(authURL string) error {
		b := s.Browser()
		b.SignIn()
		var payload map[string]string
		_, body := b.Do("GET", "/api/identities", nil)
		for _, x := range apptest.JSON(t, body)["identities"].([]any) {
			if x.(map[string]any)["name"] == identity {
				payload = map[string]string{"identity_id": x.(map[string]any)["id"].(string)}
			}
		}
		if payload == nil {
			payload = map[string]string{"new_identity_name": identity}
		}
		resp, _ := b.Do("GET", authURL, nil)
		loc, _ := url.Parse(resp.Header.Get("Location"))
		resp, body = b.Do("POST", "/api/oauth/requests/"+loc.Query().Get("request")+"/approve", payload)
		if resp.StatusCode != 200 {
			t.Errorf("approve: %d %s", resp.StatusCode, body)
			return nil
		}
		// The CLI's callback server is already listening and its handler
		// never blocks, so the browser leg can run synchronously.
		r, err := http.Get(apptest.JSON(t, body)["redirect_url"].(string))
		if err != nil {
			t.Errorf("callback: %v", err)
			return nil
		}
		page, _ := io.ReadAll(r.Body)
		r.Body.Close()
		// A page without its own icon makes the browser fetch /favicon.ico
		// from the callback server after it has shut down.
		if !strings.Contains(string(page), `<link rel="icon" href="data:,">`) {
			t.Errorf("callback page declares no inline icon: %s", page)
		}
		return nil
	}
}

func run(t *testing.T, env cli.Env, args ...string) (int, string, string) {
	t.Helper()
	var out, errb syncBuffer
	env.Stdout, env.Stderr = &out, &errb
	code := cli.Run(context.Background(), env, args)
	return code, out.String(), errb.String()
}

func signedIn(t *testing.T, opts ...apptest.Option) *fixture {
	s := apptest.Start(t, opts...)
	dir := t.TempDir()
	env := cli.Env{ConfigDir: dir, HTTP: &http.Client{}, OpenBrowser: browserFor(t, s, "cli-agent"), Stdin: strings.NewReader("")}
	code, out, errs := run(t, env, "login", s.URL)
	if code != 0 || !strings.Contains(out, `identity "cli-agent"`) || !strings.Contains(errs, "/oauth/authorize?") {
		t.Fatalf("login: %d %q %q", code, out, errs)
	}
	return &fixture{s: s, env: env, dir: dir}
}

func TestLoginAndManage(t *testing.T) {
	f := signedIn(t)
	file, err := mcpclient.Load(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	p := file.Profiles["default"]
	if p == nil || p.MCPURL != f.s.URL+"/mcp" || p.Issuer != f.s.URL || p.RefreshToken == "" || p.IdentityName != "cli-agent" {
		t.Fatalf("saved profile = %+v", p)
	}
	code, out, _ := run(t, f.env, "status")
	if code != 0 || !strings.Contains(out, "cli-agent") {
		t.Errorf("status: %d %s", code, out)
	}
	code, out, _ = run(t, f.env, "webhooks", "create", "github-push", "--name", "GitHub")
	if code != 0 || !strings.Contains(out, "mwek_") || !strings.Contains(out, "/hooks/") {
		t.Fatalf("webhooks create: %d %s", code, out)
	}
	code, out, _ = run(t, f.env, "webhooks", "list", "--json")
	var list struct {
		Webhooks []map[string]any `json:"webhooks"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &list) != nil || len(list.Webhooks) != 1 || list.Webhooks[0]["name"] != "GitHub" {
		t.Fatalf("webhooks list: %d %s", code, out)
	}
	if code, out, _ := run(t, f.env, "webhooks", "update", "github-push", "--description", "pushes"); code != 0 || !strings.Contains(out, "pushes") {
		t.Errorf("webhooks update: %d %s", code, out)
	}
	if code, out, _ := run(t, f.env, "webhooks", "rotate-key", "github-push"); code != 0 || !strings.Contains(out, "mwek_") {
		t.Errorf("rotate-key: %d %s", code, out)
	}
	if code, out, _ := run(t, f.env, "channels", "create", "ci", "--mode", "include", "--identifiers", "github-push,:system"); code != 0 || !strings.Contains(out, "include") {
		t.Errorf("channels create: %d %s", code, out)
	}
	if code, out, _ := run(t, f.env, "channels", "update", "ci", "--mode", "exclude"); code != 0 || !strings.Contains(out, "exclude") {
		t.Errorf("channels update: %d %s", code, out)
	}
	if code, out, _ := run(t, f.env, "channels", "list"); code != 0 || !strings.Contains(out, "github-push,:system") {
		t.Errorf("channels list: %d %s", code, out)
	}
	if code, _, errs := run(t, f.env, "webhooks", "create", "Bad_Id"); code != 1 || !strings.Contains(errs, "invalid") {
		t.Errorf("invalid identifier: %d %s", code, errs)
	}
	if code, _, _ := run(t, f.env, "channels", "delete", "ci"); code != 0 {
		t.Errorf("channels delete: %d", code)
	}
	if code, _, _ := run(t, f.env, "webhooks", "delete", "github-push"); code != 0 {
		t.Errorf("webhooks delete: %d", code)
	}
	// a second login for the same identity under another profile
	code, out, _ = run(t, f.env, "login", f.s.URL, "--profile", "work")
	if code != 0 || !strings.Contains(out, `"cli-agent"`) {
		t.Fatalf("second login: %d %s", code, out)
	}
	// logout revokes at the server
	tok := mustProfile(t, f.dir, "work").AccessToken
	if code, out, _ := run(t, f.env, "logout", "--profile", "work"); code != 0 || !strings.Contains(out, "Signed out") {
		t.Errorf("logout: %d %s", code, out)
	}
	resp, _ := f.s.MCP(tok).Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, nil)
	if resp.StatusCode != 401 {
		t.Errorf("token after logout: %d", resp.StatusCode)
	}
	if code, _, errs := run(t, f.env, "status", "--profile", "work"); code != 1 || !strings.Contains(errs, "mwe login") {
		t.Errorf("status after logout: %d %s", code, errs)
	}
}

func mustProfile(t *testing.T, dir, name string) *mcpclient.Profile {
	t.Helper()
	file, err := mcpclient.Load(dir)
	if err != nil || file.Profiles[name] == nil {
		t.Fatalf("profile %s: %v", name, err)
	}
	return file.Profiles[name]
}

// expire makes the saved access token look expired, so the next command
// renews it.
func expire(t *testing.T, dir string) {
	t.Helper()
	if err := mcpclient.Update(dir, func(f *mcpclient.File) (bool, error) {
		f.Profiles["default"].ExpiresAt = time.Now().Add(-time.Minute)
		return true, nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Two processes renewing at once rotate the refresh token once: the
// second sees the first's new token instead of replaying the old one
// (which would revoke the sign-in).
func TestConcurrentRefresh(t *testing.T) {
	f := signedIn(t)
	before := mustProfile(t, f.dir, "default")
	expire(t, f.dir)
	var wg sync.WaitGroup
	codes := make([]int, 4)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i], _, _ = run(t, f.env, "status")
		}(i)
	}
	wg.Wait()
	for i, c := range codes {
		if c != 0 {
			t.Errorf("status %d exited %d", i, c)
		}
	}
	after := mustProfile(t, f.dir, "default")
	if after.RefreshToken == before.RefreshToken || after.AccessToken == before.AccessToken {
		t.Fatal("the token wasn't renewed")
	}
	if code, _, errs := run(t, f.env, "status"); code != 0 {
		t.Fatalf("after concurrent renewals the sign-in is gone: %s", errs)
	}
}

func TestTail(t *testing.T) {
	f := signedIn(t)
	run(t, f.env, "webhooks", "create", "gh")
	run(t, f.env, "channels", "create", "ci")
	m := f.s.MCP(mustProfile(t, f.dir, "default").AccessToken)
	url, key := m.Webhook("other")
	ctx, cancel := context.WithCancel(context.Background())
	var out, errb syncBuffer
	env := f.env
	env.Stdout, env.Stderr = &out, &errb
	done := make(chan int)
	go func() { done <- cli.Run(ctx, env, []string{"events", "tail", "--channel", "ci"}) }()
	waitFor(t, "following", func() bool { return strings.Contains(errb.String(), "following channel ci") })
	apptest.Send(t, url, key, `{"hello":"tail"}`)
	waitFor(t, "the event", func() bool { return strings.Contains(out.String(), `{"hello":"tail"}`) })
	m.Tool("channel_update", map[string]any{"name": "ci", "mode": "exclude", "identifiers": []any{"other"}})
	apptest.Send(t, url, key, `{"hidden":true}`)
	b := f.s.Browser()
	b.SignIn()
	b.Do("POST", "/api/broadcast", map[string]any{"message": "to everyone"})
	waitFor(t, "the broadcast", func() bool { return strings.Contains(out.String(), "broadcast: to everyone") })
	if strings.Contains(out.String(), "hidden") {
		t.Errorf("an excluded event was printed: %s", out.String())
	}
	cancel()
	if code := <-done; code != 0 {
		t.Errorf("tail exited %d: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "last cursor: ") {
		t.Errorf("no last cursor: %s", errb.String())
	}
	// poll resumes from a cursor
	cursor := strings.TrimSpace(strings.TrimPrefix(errb.String()[strings.LastIndex(errb.String(), "last cursor: "):], "last cursor: "))
	apptest.Send(t, url+"?key="+key, "", "")
	code, pout, perr := run(t, f.env, "events", "poll", "--channel", "ci", "--cursor", cursor, "--json")
	if code != 0 || pout != "" || !strings.Contains(perr, "cursor: ") {
		t.Errorf("poll after an excluded event: %d %q %q", code, pout, perr)
	}
	// deleting the channel ends a tail with an error
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	var out2, err2 syncBuffer
	env.Stdout, env.Stderr = &out2, &err2
	go func() { done <- cli.Run(ctx2, env, []string{"events", "tail", "--channel", "ci"}) }()
	waitFor(t, "following", func() bool { return strings.Contains(err2.String(), "following channel ci") })
	m.Tool("channel_delete", map[string]any{"name": "ci"})
	select {
	case code := <-done:
		if code != 1 || !strings.Contains(err2.String(), "ended the subscription") {
			t.Errorf("tail after channel delete: %d %s", code, err2.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("tail didn't end after its channel was deleted")
	}
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The bridge relays concurrent requests, keeps a stream open beside them,
// stops a stream on notifications/cancelled, and renews an expired token.
func TestBridge(t *testing.T) {
	f := signedIn(t)
	run(t, f.env, "channels", "create", "ci")
	m := f.s.MCP(mustProfile(t, f.dir, "default").AccessToken)
	url, key := m.Webhook("gh")
	expire(t, f.dir)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	env := f.env
	env.Stdin, env.Stdout, env.Stderr = inR, outW, io.Discard
	done := make(chan int)
	go func() { done <- cli.Run(context.Background(), env, []string{"mcp"}) }()
	lines := make(chan map[string]any, 100)
	go func() {
		sc := bufio.NewScanner(outR)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var v map[string]any
			if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
				t.Errorf("bridge wrote a non-JSON line: %q", sc.Text())
				continue
			}
			lines <- v
		}
		close(lines)
	}()
	send := func(v map[string]any) {
		b, _ := json.Marshal(v)
		inW.Write(append(b, '\n'))
	}
	meta := apptest.Meta()
	next := func(match func(map[string]any) bool) map[string]any {
		t.Helper()
		deadline := time.After(3 * time.Second)
		for {
			select {
			case v, ok := <-lines:
				if !ok {
					t.Fatal("the bridge's output ended")
				}
				if match(v) {
					return v
				}
			case <-deadline:
				t.Fatal("timed out reading the bridge")
			}
		}
	}
	send(map[string]any{"jsonrpc": "2.0", "id": "stream-1", "method": "events/stream", "params": map[string]any{"name": "webhook.received", "arguments": map[string]any{"channel": "ci"}, "cursor": nil, "_meta": meta}})
	active := next(func(v map[string]any) bool { return v["method"] == "notifications/events/active" })
	if apptest.Params(active)["_meta"].(map[string]any)["io.modelcontextprotocol/subscriptionId"] != "stream-1" {
		t.Fatalf("active = %v", active)
	}
	// requests alongside the open stream, answered by id
	send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": map[string]any{"_meta": meta}})
	send(map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "whoami", "arguments": map[string]any{}, "_meta": meta}})
	got := map[float64]bool{}
	for len(got) < 2 {
		v := next(func(v map[string]any) bool { _, ok := v["id"].(float64); return ok })
		if v["result"] == nil {
			t.Fatalf("request failed through the bridge: %v", v)
		}
		got[v["id"].(float64)] = true
	}
	apptest.Send(t, url, key, `{"via":"bridge"}`)
	e := next(func(v map[string]any) bool { return v["method"] == "notifications/events/event" })
	if apptest.EventData(e)["request"].(map[string]any)["body"].(map[string]any)["via"] != "bridge" {
		t.Errorf("event = %v", e)
	}
	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/cancelled", "params": map[string]any{"requestId": "stream-1"}})
	time.Sleep(200 * time.Millisecond)
	apptest.Send(t, url, key, `{"after":"cancel"}`)
	send(map[string]any{"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": map[string]any{"_meta": meta}})
	v := next(func(v map[string]any) bool { return v["id"] != nil || v["method"] == "notifications/events/event" })
	if v["id"] != float64(3) {
		t.Fatalf("after cancelling the stream the bridge wrote %v", v)
	}
	// a header error from the server is relayed as is
	send(map[string]any{"jsonrpc": "2.0", "id": 4, "method": "events/poll", "params": map[string]any{"arguments": map[string]any{}, "_meta": meta}})
	v = next(func(v map[string]any) bool { return v["id"] == float64(4) })
	if v["error"].(map[string]any)["code"] != float64(-32602) {
		t.Errorf("poll without name = %v", v)
	}
	// a modern ping is an unknown method at the server: its 404 error
	// comes back to the stdio client as the JSON-RPC error it is
	send(map[string]any{"jsonrpc": "2.0", "id": 7, "method": "ping", "params": map[string]any{"_meta": meta}})
	v = next(func(v map[string]any) bool { return v["id"] == float64(7) })
	if e, _ := v["error"].(map[string]any); e == nil || e["code"] != float64(-32601) {
		t.Errorf("modern ping through the bridge = %v, want error -32601", v)
	}
	// a legacy client: initialize, then requests with no _meta
	send(map[string]any{"jsonrpc": "2.0", "id": 5, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "old", "version": "1"}}})
	next(func(v map[string]any) bool { return v["id"] == float64(5) })
	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})
	send(map[string]any{"jsonrpc": "2.0", "id": 6, "method": "tools/list"})
	v = next(func(v map[string]any) bool { return v["id"] == float64(6) })
	if v["result"] == nil {
		t.Errorf("legacy tools/list through the bridge = %v", v)
	}
	inW.Close()
	select {
	case code := <-done:
		if code != 0 {
			t.Errorf("bridge exited %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the bridge didn't exit when stdin closed")
	}
}

// Without a sign-in the bridge still answers, with an error that says
// what to do.
func TestBridgeNotSignedIn(t *testing.T) {
	env := cli.Env{ConfigDir: t.TempDir(), HTTP: &http.Client{}}
	var out bytes.Buffer
	env.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}` + "\n")
	env.Stdout, env.Stderr = &out, io.Discard
	if code := cli.Run(context.Background(), env, []string{"mcp"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || !strings.Contains(v["error"].(map[string]any)["message"].(string), "mwe login") {
		t.Fatalf("output = %q", out.String())
	}
}
