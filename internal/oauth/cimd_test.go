package oauth_test

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/apptest"
	"github.com/ImSingee/mcp-webhook-events/internal/config"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
)

// metaServer is a client's https host serving its Client ID Metadata
// Document, as the test sets it.
type metaServer struct {
	srv    *httptest.Server
	caPath string
	hits   atomic.Int32

	mu       sync.Mutex
	doc      map[string]any // marshaled as the body unless raw is set
	raw      []byte
	status   int
	ctype    string
	cache    string
	location string
}

func newMetaServer(t *testing.T) *metaServer {
	m := &metaServer{status: 200, ctype: "application/json", cache: "max-age=3600"}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.hits.Add(1)
		m.mu.Lock()
		defer m.mu.Unlock()
		if r.Header.Get("Accept") != "application/json" {
			t.Errorf("metadata fetched with Accept %q", r.Header.Get("Accept"))
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("metadata fetch sent credentials: %v", r.Header)
		}
		if r.URL.Path == "/redirect-target.json" {
			t.Error("a metadata redirect was followed")
		}
		if m.location != "" {
			w.Header().Set("Location", m.location)
		}
		if m.cache != "" {
			w.Header().Set("Cache-Control", m.cache)
		}
		w.Header().Set("Content-Type", m.ctype)
		w.WriteHeader(m.status)
		body := m.raw
		if body == nil {
			body, _ = json.Marshal(m.doc)
		}
		w.Write(body)
	}))
	t.Cleanup(m.srv.Close)
	m.caPath = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(m.caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: m.srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	m.set(nil)
	return m
}

// clientID is the document's URL on the server: https://127.0.0.1:<port>/client.json.
func (m *metaServer) clientID() string { return m.srv.URL + "/client.json" }

// set resets the document to a valid one for clientID, then applies edit.
func (m *metaServer) set(edit func(doc map[string]any)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.doc = map[string]any{
		"client_id":                  m.srv.URL + "/client.json",
		"client_name":                "Test CIMD Client",
		"client_uri":                 "https://client.example",
		"logo_uri":                   "https://client.example/logo.png",
		"redirect_uris":              []string{"http://127.0.0.1/callback", "https://client.example/callback"},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	}
	m.raw, m.status, m.ctype, m.cache, m.location = nil, 200, "application/json", "max-age=3600", ""
	if edit != nil {
		edit(m.doc)
	}
}

func (m *metaServer) with(f func(m *metaServer)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f(m)
}

// startCIMD is a server that can fetch documents from the test's loopback
// TLS server: the development exception on, the server's certificate
// trusted through MWE_EXTRA_CA_FILE.
func startCIMD(t *testing.T, opts ...apptest.Option) (*apptest.Server, *metaServer) {
	m := newMetaServer(t)
	opts = append([]apptest.Option{apptest.AllowPrivate(), apptest.WithConfig(func(c *config.Config) { c.ExtraCAFile = m.caPath })}, opts...)
	return apptest.Start(t, opts...), m
}

// cimdClient is the OAuth client of a CIMD client_id (nothing to register).
func cimdClient(s *apptest.Server, id string) *apptest.OAuthClient {
	return &apptest.OAuthClient{S: s, ID: id, RedirectURI: "http://127.0.0.1:54321/callback"}
}

// refused asserts that an authorization request got the error page, never
// a redirect (CIMD §6.1), and returns its text.
func refused(t *testing.T, b *apptest.Browser, authorizeURL string) string {
	t.Helper()
	resp, body := b.Do("GET", authorizeURL, nil)
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Location") != "" || !strings.Contains(string(body), "授权请求无效") {
		t.Fatalf("GET %s = %d Location %q, want the error page", authorizeURL, resp.StatusCode, resp.Header.Get("Location"))
	}
	return string(body)
}

// accepted asserts that an authorization request reached the consent page
// and returns its request id.
func accepted(t *testing.T, b *apptest.Browser, authorizeURL string) string {
	t.Helper()
	resp, body := b.Do("GET", authorizeURL, nil)
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "/consent?request=ar_") {
		t.Fatalf("GET %s = %d %q %s, want the consent page", authorizeURL, resp.StatusCode, loc, body)
	}
	return strings.TrimPrefix(loc, "/consent?request=")
}

func TestCIMDAdvertised(t *testing.T) {
	s := apptest.Start(t)
	m := get(t, s.URL+"/.well-known/oauth-authorization-server")
	if m["client_id_metadata_document_supported"] != true || m["registration_endpoint"] != s.URL+"/oauth/register" {
		t.Fatalf("metadata = %v", m)
	}
}

// The whole CIMD flow: authorize with the document URL as client_id, the
// consent page shows the document's client and where it came from, the
// code is exchanged without credentials, and the refresh token rotates.
func TestCIMDFullFlow(t *testing.T) {
	s, ms := startCIMD(t)
	b := s.Browser()
	b.SignIn()
	c := cimdClient(s, ms.clientID())
	verifier, challenge := apptest.PKCE()
	ar := accepted(t, b, c.AuthorizeURL(challenge, "", s.URL+"/mcp"))
	_, body := b.Do("GET", "/api/oauth/requests/"+ar, nil)
	cl := apptest.JSON(t, body)["client"].(map[string]any)
	host := strings.TrimPrefix(ms.srv.URL, "https://")
	warnings := cl["warnings"].([]any)
	if cl["id"] != ms.clientID() || cl["name"] != "Test CIMD Client" || cl["registration"] != "cimd" || cl["metadata_host"] != host ||
		cl["redirect_host"] != "127.0.0.1" || len(warnings) != 1 || warnings[0].(map[string]any)["code"] != "localhost_redirect" {
		t.Fatalf("consent client = %v", cl)
	}
	resp, body := b.Do("POST", "/api/oauth/requests/"+ar+"/approve", map[string]string{"new_identity_name": "cimd-agent"})
	if resp.StatusCode != 200 {
		t.Fatalf("approve: %d %s", resp.StatusCode, body)
	}
	red, _ := url.Parse(apptest.JSON(t, body)["redirect_url"].(string))
	if red.Host != "127.0.0.1:54321" || red.Query().Get("iss") != s.URL {
		t.Fatalf("redirect = %s", red)
	}
	st, tok := c.Token(url.Values{"grant_type": {"authorization_code"}, "code": {red.Query().Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1:54321/callback"}, "resource": {s.URL + "/mcp"}})
	if st != 200 || tok["refresh_token"] == nil {
		t.Fatalf("token: %d %v", st, tok)
	}
	who := s.MCP(tok["access_token"].(string)).Tool("whoami", nil)
	if who["client"].(map[string]any)["name"] != "Test CIMD Client" || who["client"].(map[string]any)["id"] != ms.clientID() {
		t.Fatalf("whoami = %v", who)
	}
	st, next := c.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}})
	if st != 200 || next["refresh_token"] == tok["refresh_token"] {
		t.Fatalf("refresh: %d %v", st, next)
	}
	identity := who["identity"].(map[string]any)["id"].(string)
	_, body = b.Do("GET", "/api/identities/"+identity+"/authorizations", nil)
	auth := apptest.JSON(t, body)["authorizations"].([]any)[0].(map[string]any)
	if auth["registration"] != "cimd" || auth["metadata_host"] != host || auth["client_name"] != "Test CIMD Client" {
		t.Fatalf("authorization = %v", auth)
	}
	// one fetch served the whole flow: the document said max-age=3600
	if n := ms.hits.Load(); n != 1 {
		t.Errorf("metadata fetched %d times, want 1", n)
	}
	saved, err := s.App.Store.GetClient(context.Background(), ms.clientID())
	if err != nil || saved.Kind != store.ClientCIMD || saved.ClientURI != "https://client.example" || saved.LogoURI != "https://client.example/logo.png" || saved.MetadataFetchedAt == nil || len(saved.Metadata) == 0 {
		t.Fatalf("snapshot = %+v, %v", saved, err)
	}
	// a dynamically registered client is told apart
	dcr := s.Register("dcr-client")
	_, ch := apptest.PKCE()
	ar = accepted(t, b, dcr.AuthorizeURL(ch, "", ""))
	_, body = b.Do("GET", "/api/oauth/requests/"+ar, nil)
	cl = apptest.JSON(t, body)["client"].(map[string]any)
	if cl["registration"] != "dcr" || cl["metadata_host"] != nil || len(cl["warnings"].([]any)) != 0 {
		t.Fatalf("DCR consent client = %v", cl)
	}
}

// Client Identifier URLs that break CIMD §3 or §10.1 are refused before
// anything is fetched.
func TestCIMDRejectsClientIDURLs(t *testing.T) {
	s, ms := startCIMD(t)
	b := s.Browser()
	b.SignIn()
	_, challenge := apptest.PKCE()
	host := strings.TrimPrefix(ms.srv.URL, "https://")
	for id, why := range map[string]string{
		"http://" + host + "/client.json":          "https scheme",
		ms.clientID() + "#frag":                    "fragment",
		ms.clientID() + "#":                        "fragment",
		"https://user:pw@" + host + "/client.json": "user information",
		"https://" + host:                          "path other than /",
		"https://" + host + "/":                    "path other than /",
		"https://" + host + "/a/../client.json":    ". or .. path segments",
		"https://" + host + "/./client.json":       ". or .. path segments",
		"https://" + host + "/%2e%2e/client.json":  ". or .. path segments",
		"ftp://" + host + "/client.json":           "https scheme",
	} {
		if body := refused(t, b, cimdClient(s, id).AuthorizeURL(challenge, "", "")); !strings.Contains(body, why) {
			t.Errorf("client_id %s refused, but not for %q: %s", id, why, body)
		}
	}
	if n := ms.hits.Load(); n != 0 {
		t.Fatalf("invalid client_id URLs were fetched %d times", n)
	}
}

// Documents that CIMD §4, §4.1, §5, §6 or MCP's required fields refuse:
// the authorization request gets the error page and nothing is cached.
func TestCIMDRejectsDocuments(t *testing.T) {
	s, ms := startCIMD(t)
	b := s.Browser()
	b.SignIn()
	_, challenge := apptest.PKCE()
	authorize := cimdClient(s, ms.clientID()).AuthorizeURL(challenge, "", "")
	cases := map[string]func(doc map[string]any){
		"client_id mismatch": func(d map[string]any) { d["client_id"] = "https://other.example/client.json" },
		"client_id normalized": func(d map[string]any) {
			d["client_id"] = strings.Replace(ms.clientID(), "client.json", "./client.json", 1)
		},
		"no client_id":               func(d map[string]any) { delete(d, "client_id") },
		"no client_name":             func(d map[string]any) { delete(d, "client_name") },
		"blank client_name":          func(d map[string]any) { d["client_name"] = "  " },
		"no redirect_uris":           func(d map[string]any) { delete(d, "redirect_uris") },
		"empty redirect_uris":        func(d map[string]any) { d["redirect_uris"] = []string{} },
		"http redirect off loopback": func(d map[string]any) { d["redirect_uris"] = []string{"http://client.example/cb"} },
		"private_key_jwt only": func(d map[string]any) {
			d["token_endpoint_auth_method"] = "private_key_jwt"
			d["jwks_uri"] = "https://client.example/jwks"
		},
		"supported without none": func(d map[string]any) {
			delete(d, "token_endpoint_auth_method")
			d["token_endpoint_auth_methods_supported"] = []string{"private_key_jwt", "tls_client_auth"}
		},
		"client_secret_basic": func(d map[string]any) { d["token_endpoint_auth_method"] = "client_secret_basic" },
		"client_secret_post offered": func(d map[string]any) {
			d["token_endpoint_auth_methods_supported"] = []string{"none", "client_secret_post"}
		},
		"method outside supported list": func(d map[string]any) { d["token_endpoint_auth_methods_supported"] = []string{"private_key_jwt"} },
		"client_secret present":         func(d map[string]any) { d["client_secret"] = "s3cret" },
		"jwks and jwks_uri": func(d map[string]any) {
			d["jwks"] = map[string]any{"keys": []any{}}
			d["jwks_uri"] = "https://client.example/jwks"
		},
		"no authorization_code grant": func(d map[string]any) { d["grant_types"] = []string{"client_credentials"} },
		"no code response type":       func(d map[string]any) { d["response_types"] = []string{"token"} },
		"redirect_uris not strings":   func(d map[string]any) { d["redirect_uris"] = []any{1, 2} },
	}
	for name, edit := range cases {
		ms.set(edit)
		body := refused(t, b, authorize)
		if strings.Contains(body, "redirect_uri 与") {
			t.Errorf("%s: refused for the redirect URI, not the document", name)
		}
		if _, err := s.App.Store.GetClient(context.Background(), ms.clientID()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s: a refused document was saved (%v)", name, err)
		}
	}
	// no refusal was cached: every request fetched the document anew
	if n := ms.hits.Load(); int(n) != len(cases) {
		t.Fatalf("%d fetches for %d refused documents", n, len(cases))
	}
	// the redirect URI must be one the document lists; a loopback one may
	// change its port, but nothing else
	ms.set(nil)
	for _, red := range []string{"http://127.0.0.1:54321/other", "http://localhost:54321/callback", "https://client.example/callback/x", "http://127.0.0.1:54321/callback?x=1"} {
		body := refused(t, b, cimdClient(s, ms.clientID()).AuthorizeURL(challenge, red, ""))
		if !strings.Contains(body, "redirect_uri 与") {
			t.Errorf("redirect %s: refused for another reason", red)
		}
	}
	for _, red := range []string{"http://127.0.0.1:1/callback", "http://127.0.0.1/callback", "https://client.example/callback"} {
		accepted(t, b, cimdClient(s, ms.clientID()).AuthorizeURL(challenge, red, ""))
	}
	// a client offering none beside a method this server lacks is a
	// public client here (CIMD §5: pick a supported one)
	ms.set(func(d map[string]any) {
		delete(d, "token_endpoint_auth_method")
		d["token_endpoint_auth_methods_supported"] = []string{"private_key_jwt", "none"}
		d["jwks_uri"] = "https://client.example/jwks"
	})
	s.App.Store.DB().Exec(`UPDATE oauth_clients SET metadata_fresh_until = 0`)
	accepted(t, b, authorize)
	// neither auth field: none is assumed (§5)
	ms.set(func(d map[string]any) { delete(d, "token_endpoint_auth_method") })
	s.App.Store.DB().Exec(`UPDATE oauth_clients SET metadata_fresh_until = 0`)
	accepted(t, b, authorize)
}

// How the document is served: 200 JSON of at most 5 KiB, never through a
// redirect.
func TestCIMDFetchRules(t *testing.T) {
	s, ms := startCIMD(t)
	b := s.Browser()
	b.SignIn()
	_, challenge := apptest.PKCE()
	authorize := cimdClient(s, ms.clientID()).AuthorizeURL(challenge, "", "")
	cases := map[string]struct {
		edit func(m *metaServer)
		why  string
	}{
		"html":      {func(m *metaServer) { m.ctype = "text/html" }, "not JSON"},
		"no type":   {func(m *metaServer) { m.ctype = "" }, "not JSON"},
		"not json":  {func(m *metaServer) { m.raw = []byte("{not json") }, "not a JSON object"},
		"array":     {func(m *metaServer) { m.raw = []byte("[]") }, "not a JSON object"},
		"too large": {func(m *metaServer) { m.doc["padding"] = strings.Repeat("x", 5<<10) }, "larger than 5120 bytes"},
		"redirect": {func(m *metaServer) {
			m.status, m.location = http.StatusFound, m.srv.URL+"/redirect-target.json"
		}, "redirects are not followed"},
		"404": {func(m *metaServer) { m.status = 404 }, "answered 404"},
		"500": {func(m *metaServer) { m.status = 500 }, "answered 500"},
	}
	for name, tc := range cases {
		ms.set(nil)
		ms.with(tc.edit)
		if body := refused(t, b, authorize); !strings.Contains(body, tc.why) {
			t.Errorf("%s: refused, but not for %q: %s", name, tc.why, body)
		}
		if _, err := s.App.Store.GetClient(context.Background(), ms.clientID()); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s: a failed fetch was saved", name)
		}
	}
	// application/<x>+json is JSON too (CIMD §4), and exactly 5 KiB is in
	ms.set(func(d map[string]any) {})
	ms.with(func(m *metaServer) {
		m.ctype = "application/client-metadata+json"
		base, _ := json.Marshal(m.doc)
		m.doc["padding"] = strings.Repeat("x", 5<<10-len(base)-len(`,"padding":""`))
	})
	accepted(t, b, authorize)
}

// staticResolver answers every lookup with one address.
type staticResolver struct{ addr string }

func (r staticResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr(r.addr)}, nil
}

// The SSRF guard: a name resolving to a private address is refused before
// anything connects, and loopback is reachable only under the development
// exception.
func TestCIMDSSRF(t *testing.T) {
	ms := newMetaServer(t)
	port := ms.srv.URL[strings.LastIndex(ms.srv.URL, ":")+1:]
	// the test server's certificate is good for example.com, so a name can
	// stand for it
	byName := "https://example.com:" + port + "/client.json"
	ms.set(func(d map[string]any) { d["client_id"] = byName })
	trust := apptest.WithConfig(func(c *config.Config) { c.ExtraCAFile = ms.caPath })
	_, challenge := apptest.PKCE()

	private := apptest.Start(t, apptest.AllowPrivate(), trust, apptest.WithResolver(staticResolver{"10.0.0.9"}))
	b := private.Browser()
	b.SignIn()
	body := refused(t, b, cimdClient(private, byName).AuthorizeURL(challenge, "", ""))
	if !strings.Contains(body, "not globally routable") {
		t.Errorf("private address: %s", body)
	}

	strict := apptest.Start(t, trust, apptest.WithResolver(staticResolver{"127.0.0.1"}))
	b = strict.Browser()
	b.SignIn()
	refused(t, b, cimdClient(strict, byName).AuthorizeURL(challenge, "", ""))
	refused(t, b, cimdClient(strict, ms.clientID()).AuthorizeURL(challenge, "", ""))
	if n := ms.hits.Load(); n != 0 {
		t.Fatalf("the guard let %d fetches through", n)
	}

	dev := apptest.Start(t, apptest.AllowPrivate(), trust, apptest.WithResolver(staticResolver{"127.0.0.1"}))
	b = dev.Browser()
	b.SignIn()
	accepted(t, b, cimdClient(dev, byName).AuthorizeURL(challenge, "", ""))
}

// The cache keeps a document as long as its headers say, a failure never
// replaces or extends a good snapshot, and the token endpoint falls back
// on the last good one only for a transient failure.
func TestCIMDCacheAndRefresh(t *testing.T) {
	s, ms := startCIMD(t)
	b := s.Browser()
	b.SignIn()
	ctx := context.Background()
	c := cimdClient(s, ms.clientID())
	tok := s.Authorize(b, c, "", "agent")
	if n := ms.hits.Load(); n != 1 {
		t.Fatalf("hits after one flow = %d", n)
	}
	expire := func() {
		if _, err := s.App.Store.DB().Exec(`UPDATE oauth_clients SET metadata_fresh_until = 0 WHERE client_id = ?`, ms.clientID()); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := s.App.Store.GetClient(ctx, ms.clientID())
	_, challenge := apptest.PKCE()
	authorize := c.AuthorizeURL(challenge, "", "")

	// fresh: no fetch
	accepted(t, b, authorize)
	if n := ms.hits.Load(); n != 1 {
		t.Fatalf("a fresh document was fetched again (%d)", n)
	}
	// expired, and the host fails: refused, the snapshot untouched
	expire()
	ms.set(func(map[string]any) {})
	ms.with(func(m *metaServer) { m.status = 503 })
	refused(t, b, authorize)
	after, _ := s.App.Store.GetClient(ctx, ms.clientID())
	if !after.MetadataFetchedAt.Equal(*before.MetadataFetchedAt) || after.MetadataFreshUntil.After(time.Now()) {
		t.Fatalf("a failed fetch touched the snapshot: %v -> %v, fresh until %v", before.MetadataFetchedAt, after.MetadataFetchedAt, after.MetadataFreshUntil)
	}
	// the failure wasn't cached: the next request fetches again
	hits := ms.hits.Load()
	refused(t, b, authorize)
	if ms.hits.Load() != hits+1 {
		t.Fatal("a failed fetch was cached")
	}
	// the token endpoint rides out the outage on the last good snapshot
	refresh := func(rt string) (int, map[string]any) {
		return c.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
	}
	st, next := refresh(tok.Refresh)
	if st != 200 {
		t.Fatalf("refresh during a transient outage: %d %v", st, next)
	}
	// a new document is fetched, saved and used
	ms.set(func(d map[string]any) { d["client_name"] = "Renamed Client" })
	accepted(t, b, authorize)
	if got, _ := s.App.Store.GetClient(ctx, ms.clientID()); got.Name != "Renamed Client" || !got.MetadataFreshUntil.After(time.Now()) {
		t.Fatalf("snapshot after a good refetch = %+v", got)
	}
	// a document that drops the refresh grant ends refreshing
	expire()
	ms.set(func(d map[string]any) { d["grant_types"] = []string{"authorization_code"} })
	if st, out := refresh(next["refresh_token"].(string)); st != 400 || out["error"] != "unauthorized_client" {
		t.Fatalf("refresh without the grant: %d %v", st, out)
	}
	// and gets no refresh token at the next code exchange
	tok2 := s.AuthorizeRaw(b, c, tok.IdentityID, "")
	if tok2["refresh_token"] != nil {
		t.Fatalf("a client without the refresh grant got a refresh token: %v", tok2)
	}
	// a terminal failure at the token endpoint is invalid_client
	ms.set(nil)
	expire()
	accepted(t, b, authorize) // fresh again, with the refresh grant
	tok3 := s.Authorize(b, c, tok.IdentityID, "")
	expire()
	ms.set(func(d map[string]any) { delete(d, "client_name") })
	if st, out := refresh(tok3.Refresh); st != 401 || out["error"] != "invalid_client" {
		t.Fatalf("refresh against a broken document: %d %v", st, out)
	}
	// a client_id mismatch revokes what the client holds (CIMD §6.1)
	ms.set(func(d map[string]any) { d["client_id"] = "https://evil.example/client.json" })
	if st, _ := refresh(tok3.Refresh); st != 401 {
		t.Fatalf("refresh against a mismatched document: %d", st)
	}
	resp, _ := s.MCP(tok3.Access).Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("an access token survived its client's client_id mismatch: %d", resp.StatusCode)
	}
	// a client never seen, whose host is down: 503 at the token endpoint
	other := cimdClient(s, ms.srv.URL+"/other.json")
	ms.with(func(m *metaServer) { m.status = 502 })
	if st, out := other.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"mwer_x"}}); st != 503 || out["error"] != "temporarily_unavailable" {
		t.Fatalf("unknown client during an outage: %d %v", st, out)
	}
}

// A CIMD client is public: credentials in a token request are refused
// (CIMD §5).
func TestCIMDPublicClientOnly(t *testing.T) {
	s, ms := startCIMD(t)
	b := s.Browser()
	b.SignIn()
	c := cimdClient(s, ms.clientID())
	tok := s.Authorize(b, c, "", "agent")
	st, out := c.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Refresh}, "client_secret": {"guess"}})
	if st != 401 || out["error"] != "invalid_client" {
		t.Fatalf("client_secret from a CIMD client: %d %v", st, out)
	}
	req, _ := http.NewRequest("POST", s.URL+"/oauth/token", strings.NewReader(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Refresh}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(ms.clientID()), "guess")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b2, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 401 || !strings.Contains(string(b2), "invalid_client") {
		t.Fatalf("Basic auth from a CIMD client: %d %s", resp.StatusCode, b2)
	}
	// the refresh token is still good: refusing the credentials spent nothing
	if st, out := c.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.Refresh}}); st != 200 {
		t.Fatalf("refresh after refused credentials: %d %v", st, out)
	}
}
