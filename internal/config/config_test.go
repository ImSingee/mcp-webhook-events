package config

import (
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestParseDefaults(t *testing.T) {
	c, err := Parse(env(map[string]string{"MWE_PASSWORD": "pw", "MWE_PUBLIC_URL": "http://localhost:8080/"}))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "http://localhost:8080" || c.MCPResource() != "http://localhost:8080/mcp" {
		t.Errorf("public URL = %q, resource %q", c.PublicURL, c.MCPResource())
	}
	if c.Addr != ":8080" || c.DataDir != "./data" || c.EventRetention != 168*time.Hour || c.MaxBodyBytes != 262144 {
		t.Errorf("defaults = %+v", c)
	}
	if c.Secure() {
		t.Error("an http URL is Secure")
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]map[string]string{
		"no password":     {"MWE_PUBLIC_URL": "https://x.example"},
		"no public url":   {"MWE_PASSWORD": "pw"},
		"http non-local":  {"MWE_PASSWORD": "pw", "MWE_PUBLIC_URL": "http://x.example"},
		"path":            {"MWE_PASSWORD": "pw", "MWE_PUBLIC_URL": "https://x.example/mwe"},
		"bad retention":   {"MWE_PASSWORD": "pw", "MWE_PUBLIC_URL": "https://x.example", "MWE_EVENT_RETENTION": "soon"},
		"bad body":        {"MWE_PASSWORD": "pw", "MWE_PUBLIC_URL": "https://x.example", "MWE_MAX_BODY_BYTES": "-1"},
		"bad bool":        {"MWE_PASSWORD": "pw", "MWE_PUBLIC_URL": "https://x.example", "MWE_TRUST_PROXY": "maybe"},
		"relative public": {"MWE_PASSWORD": "pw", "MWE_PUBLIC_URL": "x.example"},
	}
	for name, m := range cases {
		if _, err := Parse(env(m)); err == nil {
			t.Errorf("%s: Parse took %v", name, m)
		}
	}
}

func TestParseOverrides(t *testing.T) {
	c, err := Parse(env(map[string]string{
		"MWE_PASSWORD": "pw", "MWE_PUBLIC_URL": "https://Events.Example.com",
		"MWE_ADDR": "127.0.0.1:9000", "MWE_DATA_DIR": "/tmp/x", "MWE_EVENT_RETENTION": "24h",
		"MWE_MAX_BODY_BYTES": "1024", "MWE_TRUST_PROXY": "true", "MWE_ALLOW_PRIVATE_CALLBACKS": "1",
		"MWE_LOG_LEVEL": "debug",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "https://events.example.com" || !c.Secure() || !c.TrustProxy || !c.AllowPrivateCallbacks || c.MaxBodyBytes != 1024 || c.EventRetention != 24*time.Hour {
		t.Errorf("parsed = %+v", c)
	}
	if !strings.HasSuffix(c.DBPath(), "mwe.db") {
		t.Errorf("DBPath = %q", c.DBPath())
	}
}

func TestCallbackAllowlist(t *testing.T) {
	c, err := Parse(env(map[string]string{"MWE_PASSWORD": "pw", "MWE_PUBLIC_URL": "https://x.example", "MWE_CALLBACK_ALLOWLIST": "https://Hooks.Example.com, https://gw.example:8443/"}))
	if err != nil {
		t.Fatal(err)
	}
	for u, want := range map[string]bool{
		"https://hooks.example.com/a/b": true,
		"https://gw.example:8443/x":     true,
		"https://gw.example/x":          false,
		"http://hooks.example.com/a":    false,
		"https://evil.example/":         false,
	} {
		if got := c.CallbackAllowed(u); got != want {
			t.Errorf("CallbackAllowed(%q) = %v, want %v", u, got, want)
		}
	}
	if _, err := Parse(env(map[string]string{"MWE_PASSWORD": "pw", "MWE_PUBLIC_URL": "https://x.example", "MWE_CALLBACK_ALLOWLIST": "https://x.example/path"})); err == nil {
		t.Error("an allowlist entry with a path was taken")
	}
}
