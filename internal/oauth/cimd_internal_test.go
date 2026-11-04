package oauth

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/config"
)

func testServer() *Server {
	return &Server{
		Cfg:                config.Config{PublicURL: "https://events.example.com"},
		MetadataMinTTL:     DefaultMetadataMinTTL,
		MetadataDefaultTTL: DefaultMetadataDefaultTTL,
		MetadataMaxTTL:     DefaultMetadataMaxTTL,
	}
}

// CIMD §6.2: cache headers are honored within the floor and ceiling; no
// directive means the default; Expires is ignored.
func TestMetadataTTL(t *testing.T) {
	s := testServer()
	for _, tc := range []struct {
		headers map[string]string
		want    time.Duration
	}{
		{nil, 10 * time.Minute},
		{map[string]string{"Expires": "Wed, 21 Oct 2099 07:28:00 GMT"}, 10 * time.Minute},
		{map[string]string{"Cache-Control": "public, max-age=300"}, 5 * time.Minute},
		{map[string]string{"Cache-Control": "max-age=300", "Age": "60"}, 4 * time.Minute},
		{map[string]string{"Cache-Control": "max-age=300, s-maxage=1800"}, 30 * time.Minute},
		{map[string]string{"Cache-Control": "max-age=5"}, time.Minute},
		{map[string]string{"Cache-Control": "no-store"}, time.Minute},
		{map[string]string{"Cache-Control": "no-cache, max-age=600"}, time.Minute},
		{map[string]string{"Cache-Control": "max-age=31536000"}, 24 * time.Hour},
		{map[string]string{"Cache-Control": `max-age="120"`}, 2 * time.Minute},
		{map[string]string{"Cache-Control": "max-age=junk"}, 10 * time.Minute},
	} {
		h := http.Header{}
		for k, v := range tc.headers {
			h.Set(k, v)
		}
		if got := s.metadataTTL(h); got != tc.want {
			t.Errorf("metadataTTL(%v) = %v, want %v", tc.headers, got, tc.want)
		}
	}
}

func TestCheckClientIDURL(t *testing.T) {
	s := testServer()
	good := []string{
		"https://client.example/client.json",
		"https://client.example:8443/a/b",
		"https://client.example/client?v=1",
		"https://claude.ai/oauth/claude-code-client-metadata",
	}
	bad := []string{
		"http://client.example/client.json",
		"HTTPS://client.example/client.json",
		"https://client.example",
		"https://client.example/",
		"https://client.example/client.json#x",
		"https://client.example/client.json#",
		"https://u:p@client.example/client.json",
		"https://client.example/a/../b",
		"https://client.example/./b",
		"https://client.example/%2E%2E/b",
		"https://events.example.com/mcp",
		"https://",
		"https:client.example/x",
	}
	for _, u := range good {
		if err := s.CheckClientIDURL(u); err != nil {
			t.Errorf("CheckClientIDURL(%q) = %v", u, err)
		}
	}
	for _, u := range bad {
		if err := s.CheckClientIDURL(u); err == nil {
			t.Errorf("CheckClientIDURL(%q) took it", u)
		}
	}
	if IsClientIDURL("cli_abc") || !IsClientIDURL("https://x/y") || !IsClientIDURL("http://x/y") {
		t.Error("IsClientIDURL")
	}
}

// Claude Code's own metadata document, as https://claude.ai/oauth/claude-code-client-metadata
// served it (2026-11-04): portless loopback redirect URIs, auth method none.
const claudeCodeDoc = `{"client_id":"https://claude.ai/oauth/claude-code-client-metadata","client_name":"Claude Code","client_uri":"https://claude.ai","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`

func TestClaudeCodeDocument(t *testing.T) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(claudeCodeDoc), &doc); err != nil {
		t.Fatal(err)
	}
	c, err := ValidateMetadata("https://claude.ai/oauth/claude-code-client-metadata", doc)
	if err != nil {
		t.Fatalf("ValidateMetadata = %v", err)
	}
	if c.Name != "Claude Code" || c.TokenAuthMethod != "none" || len(c.GrantTypes) != 2 || c.ClientURI != "https://claude.ai" {
		t.Fatalf("client = %+v", c)
	}
	match := func(requested string) bool {
		for _, reg := range c.RedirectURIs {
			if redirectMatches(c, reg, requested) {
				return true
			}
		}
		return false
	}
	for _, ok := range []string{"http://localhost:53122/callback", "http://127.0.0.1:61000/callback", "http://localhost/callback"} {
		if !match(ok) {
			t.Errorf("Claude Code's redirect %s refused", ok)
		}
	}
	for _, no := range []string{"http://localhost:53122/callback/x", "http://LOCALHOST:53122/callback", "http://127.0.0.2:61000/callback", "https://localhost:53122/callback", "http://localhost:53122/callback?x", "http://localhost:53122/callback#f", "http://evil.example/callback", "http://[::1]:5000/callback"} {
		if match(no) {
			t.Errorf("redirect %s accepted", no)
		}
	}
}

// CIMD's redirect rule is simple string comparison but for a loopback
// redirect's port; the DCR rule stays as it was (host case-insensitive).
func TestCIMDRedirectMatches(t *testing.T) {
	for _, tc := range []struct {
		reg, req string
		want     bool
	}{
		{"https://app.example/cb", "https://app.example/cb", true},
		{"https://app.example/cb", "https://APP.example/cb", false},
		{"https://app.example:443/cb", "https://app.example/cb", false},
		{"https://app.example/cb", "https://app.example:8443/cb", false},
		{"http://[::1]/cb", "http://[::1]:4000/cb", true},
		{"http://127.0.0.1:3000/cb", "http://127.0.0.1:4000/cb", true},
		{"http://127.0.0.1/cb", "http://localhost:4000/cb", false},
		{"http://127.0.0.1/cb?a=1", "http://127.0.0.1:4000/cb?a=1", true},
		{"http://127.0.0.1/cb?a=1", "http://127.0.0.1:4000/cb?a=2", false},
		{"http://127.0.0.1/cb", "http://u@127.0.0.1:4000/cb", false},
	} {
		if got := CIMDRedirectMatches(tc.reg, tc.req); got != tc.want {
			t.Errorf("CIMDRedirectMatches(%q, %q) = %v, want %v", tc.reg, tc.req, got, tc.want)
		}
	}
	if !RedirectMatches("http://127.0.0.1/cb", "http://127.0.0.1:4000/cb") {
		t.Error("the DCR rule changed")
	}
}
