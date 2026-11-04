package web

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"
)

var fake = fstest.MapFS{
	"index.html":   {Data: []byte(`<!doctype html><link rel="stylesheet" href="/app.css"><script src="/app.js"></script><script src="/missing.js"></script>`)},
	"login.html":   {Data: []byte(`<!doctype html><script src="login.js"></script>`)},
	"consent.html": {Data: []byte(`<!doctype html><p>consent</p>`)},
	"app.js":       {Data: []byte(`console.log(1)`)},
	"app.css":      {Data: []byte(`body{}`)},
	"login.js":     {Data: []byte(`1`)},
}

func get(t *testing.T, h http.Handler, target string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("GET", target, nil)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestPageNamesFilesByHash(t *testing.T) {
	h := &Handler{fsys: fake}
	w := get(t, h.Page(IndexPage), "/", nil)
	body := w.Body.String()
	if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("page: %d %q", w.Code, w.Header().Get("Content-Type"))
	}
	m := regexp.MustCompile(`src="/app\.js\?v=([0-9a-f]{12})"`).FindStringSubmatch(body)
	if m == nil || !strings.Contains(body, `href="/app.css?v=`) {
		t.Fatalf("page doesn't name its files by hash: %s", body)
	}
	if !strings.Contains(body, `src="/missing.js"`) {
		t.Errorf("a file not among the assets was renamed: %s", body)
	}
	// the hashed name is cached for good, the plain one revalidated
	s := h.Static()
	if c := get(t, s, "/app.js?v="+m[1], nil).Header().Get("Cache-Control"); !strings.Contains(c, "immutable") {
		t.Errorf("hashed app.js Cache-Control = %q", c)
	}
	plain := get(t, s, "/app.js", nil)
	if c := plain.Header().Get("Cache-Control"); c != "no-cache" {
		t.Errorf("plain app.js Cache-Control = %q", c)
	}
	if get(t, s, "/app.js?v=000000000000", nil).Header().Get("Cache-Control") != "no-cache" {
		t.Error("a stale hash was cached for good")
	}
	// an unchanged file is a 304
	if c := get(t, s, "/app.js", map[string]string{"If-None-Match": plain.Header().Get("ETag")}).Code; c != http.StatusNotModified {
		t.Errorf("If-None-Match = %d, want 304", c)
	}
	if lp := get(t, h.Page(LoginPage), "/login", nil).Body.String(); !strings.Contains(lp, `src="login.js?v=`) {
		t.Errorf("relative refs aren't versioned: %s", lp)
	}
}

func TestStaticRefusesDirsAndMissing(t *testing.T) {
	h := &Handler{fsys: fake}
	for _, p := range []string{"/", "/nope.js", "/../web.go", "/.env"} {
		if c := get(t, h.Static(), p, nil).Code; c != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", p, c)
		}
	}
}

// The real embedded assets hold the three pages the server routes to, once
// the UI is there; the tests above don't depend on their content.
func TestEmbeddedHasIndex(t *testing.T) {
	if _, err := fs.Stat(Assets(), IndexPage); err != nil {
		t.Fatalf("assets have no %s: %v", IndexPage, err)
	}
}
