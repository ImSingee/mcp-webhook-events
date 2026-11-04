package mcpclient

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestReadMessagesSSE(t *testing.T) {
	stream := ": comment\n\n" +
		"data: {\"a\":1}\n\n" +
		"event: other\ndata: {\"skipped\":true}\n\n" +
		"data: {\"b\":\ndata: 2}\n\n" +
		"event: message\r\ndata: {\"c\":3}\r\n\r\n" +
		"data: {\"tail\":true}"
	resp := &http.Response{Header: http.Header{"Content-Type": {"text/event-stream; charset=utf-8"}}, Body: io.NopCloser(strings.NewReader(stream))}
	var got []string
	if err := ReadMessages(resp, func(b []byte) error { got = append(got, string(b)); return nil }); err != nil {
		t.Fatal(err)
	}
	want := []string{`{"a":1}`, "{\"b\":\n2}", `{"c":3}`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("messages = %q, want %q", got, want)
	}
	resp = &http.Response{Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(" {\"x\":1}\n"))}
	got = nil
	ReadMessages(resp, func(b []byte) error { got = append(got, string(b)); return nil })
	if len(got) != 1 || got[0] != `{"x":1}` {
		t.Fatalf("json body = %q", got)
	}
}

func TestRoutingHeaders(t *testing.T) {
	p, m, n := RoutingHeaders([]byte(`{"jsonrpc":"2.0","id":1,"method":"events/stream","params":{"name":"webhook.received","_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`), "2025-06-18")
	if p != "2026-07-28" || m != "events/stream" || n != "webhook.received" {
		t.Errorf("modern = %q %q %q", p, m, n)
	}
	p, m, n = RoutingHeaders([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`), "2025-06-18")
	if p != "2025-06-18" || m != "tools/list" || n != "" {
		t.Errorf("legacy = %q %q %q", p, m, n)
	}
	_, _, n = RoutingHeaders([]byte(`{"method":"resources/read","params":{"uri":"file:///x"}}`), "")
	if n != "file:///x" {
		t.Errorf("resources/read name = %q", n)
	}
	for in, want := range map[string]string{
		"whoami":             "whoami",
		"Hello, 世界":          "=?base64?SGVsbG8sIOS4lueVjA==?=",
		" padded ":           "=?base64?IHBhZGRlZCA=?=",
		"line1\nline2":       "=?base64?bGluZTEKbGluZTI=?=",
		"=?base64?literal?=": "=?base64?PT9iYXNlNjQ/bGl0ZXJhbD89?=",
	} {
		if got := EncodeHeader(in); got != want {
			t.Errorf("EncodeHeader(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCredentialsFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "mwe")
	f, err := Load(dir)
	if err != nil || len(f.Profiles) != 0 {
		t.Fatalf("missing file = %v, %v", f, err)
	}
	f.Profiles["default"] = &Profile{MCPURL: "https://x/mcp", AccessToken: "a", ExpiresAt: time.Now()}
	if err := Save(dir, f); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		st, _ := os.Stat(filepath.Join(dir, "credentials.json"))
		if st.Mode().Perm() != 0o600 {
			t.Errorf("credentials mode = %v", st.Mode().Perm())
		}
		dst, _ := os.Stat(dir)
		if dst.Mode().Perm() != 0o700 {
			t.Errorf("dir mode = %v", dst.Mode().Perm())
		}
	}
	g, err := Load(dir)
	if err != nil || g.Profiles["default"].AccessToken != "a" {
		t.Fatalf("reload = %v, %v", g, err)
	}
	// a file that doesn't parse is an error, and Update doesn't write over it
	os.WriteFile(filepath.Join(dir, "credentials.json"), []byte("{broken"), 0o600)
	if _, err := Load(dir); err == nil {
		t.Fatal("a broken file loaded")
	}
	if err := Update(dir, func(*File) (bool, error) { return true, nil }); err == nil {
		t.Fatal("Update wrote over a broken file")
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "credentials.json")); string(b) != "{broken" {
		t.Fatalf("the broken file was replaced: %q", b)
	}
}

func TestMCPURL(t *testing.T) {
	for in, want := range map[string]string{
		"https://x.example":         "https://x.example/mcp",
		"https://x.example/":        "https://x.example/mcp",
		"x.example":                 "https://x.example/mcp",
		"http://localhost:8080":     "http://localhost:8080/mcp",
		"https://x.example/mcp":     "https://x.example/mcp",
		"https://x.example/a/mcp?q": "https://x.example/a/mcp",
	} {
		if got, err := MCPURL(in); err != nil || got != want {
			t.Errorf("MCPURL(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}
