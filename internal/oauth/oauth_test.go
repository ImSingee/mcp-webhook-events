package oauth_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/ImSingee/mcp-webhook-events/internal/apptest"
)

func get(t *testing.T, u string) map[string]any {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d %s", u, resp.StatusCode, b)
	}
	return apptest.JSON(t, b)
}

func TestMetadata(t *testing.T) {
	s := apptest.Start(t)
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		m := get(t, s.URL+p)
		if m["resource"] != s.URL+"/mcp" || m["authorization_servers"].([]any)[0] != s.URL {
			t.Errorf("%s = %v", p, m)
		}
	}
	a, b := get(t, s.URL+"/.well-known/oauth-authorization-server"), get(t, s.URL+"/.well-known/openid-configuration")
	if a["issuer"] != s.URL || b["issuer"] != s.URL {
		t.Fatalf("issuer = %v / %v", a["issuer"], b["issuer"])
	}
	if a["authorization_response_iss_parameter_supported"] != true || a["code_challenge_methods_supported"].([]any)[0] != "S256" {
		t.Errorf("metadata = %v", a)
	}
	methods := a["token_endpoint_auth_methods_supported"].([]any)
	if len(methods) != 3 {
		t.Errorf("token auth methods = %v", methods)
	}
	// an MCP request without a token points at the resource metadata
	resp, _ := s.MCP("").Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, nil)
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `resource_metadata="`+s.URL+`/.well-known/oauth-protected-resource/mcp"`) {
		t.Errorf("no token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
	resp, _ = s.MCP("mwea_bogus").Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, nil)
	if resp.StatusCode != 401 || !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="invalid_token"`) {
		t.Errorf("bad token: %d %q", resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
	}
}

func register(t *testing.T, s *apptest.Server, body map[string]any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	resp, err := http.Post(s.URL+"/oauth/register", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, apptest.JSON(t, out)
}

func TestRegistrationRules(t *testing.T) {
	s := apptest.Start(t)
	for _, u := range []string{"http://example.com/cb", "ftp://x/cb", "https://x/cb#frag", "/relative", "cursor://cb"} {
		if st, out := register(t, s, map[string]any{"redirect_uris": []string{u}}); st != 400 || out["error"] != "invalid_redirect_uri" {
			t.Errorf("redirect %s: %d %v", u, st, out)
		}
	}
	if st, out := register(t, s, map[string]any{"redirect_uris": []string{"https://ok.example/cb"}, "grant_types": []string{"client_credentials"}}); st != 400 {
		t.Errorf("client_credentials: %d %v", st, out)
	}
	for _, u := range []string{"https://app.example/cb", "http://localhost:1234/cb", "http://127.0.0.1/cb", "http://[::1]:9/cb"} {
		if st, out := register(t, s, map[string]any{"redirect_uris": []string{u}, "token_endpoint_auth_method": "none"}); st != 201 || out["client_id"] == "" || out["client_secret"] != nil {
			t.Errorf("redirect %s: %d %v", u, st, out)
		}
	}
	// a confidential client gets a secret, by RFC 7591's default method
	st, out := register(t, s, map[string]any{"redirect_uris": []string{"https://app.example/cb"}, "client_name": "Web app"})
	if st != 201 || out["token_endpoint_auth_method"] != "client_secret_basic" || !strings.HasPrefix(out["client_secret"].(string), "mwecs_") {
		t.Fatalf("confidential: %d %v", st, out)
	}
}

// The whole flow: registration, authorization with consent, the code
// exchange, a token that works at /mcp, refresh rotation, and a second
// authorization for the same identity.
func TestFullFlow(t *testing.T) {
	s := apptest.Start(t)
	b := s.Browser()
	// signed out, the consent page sends the browser to sign in first
	c := s.Register("Claude Code")
	_, challenge := apptest.PKCE()
	resp, _ := b.Do("GET", c.AuthorizeURL(challenge, "", s.URL+"/mcp"), nil)
	consent := resp.Header.Get("Location")
	if !strings.HasPrefix(consent, "/consent?request=ar_") {
		t.Fatalf("authorize -> %q", consent)
	}
	resp, _ = b.Do("GET", consent, nil)
	if loc := resp.Header.Get("Location"); resp.StatusCode != 302 || loc != "/login?next="+url.QueryEscape(consent) {
		t.Fatalf("signed-out consent -> %d %q", resp.StatusCode, loc)
	}
	b.SignIn()
	resp, body := b.Do("GET", "/api/oauth/requests/"+strings.TrimPrefix(consent, "/consent?request="), nil)
	req := apptest.JSON(t, body)
	cl := req["client"].(map[string]any)
	if resp.StatusCode != 200 || cl["name"] != "Claude Code" || cl["redirect_host"] != "127.0.0.1" || req["resource"] != s.URL+"/mcp" {
		t.Fatalf("pending request = %d %v", resp.StatusCode, req)
	}

	verifier, challenge := apptest.PKCE()
	red := b.Consent(c.AuthorizeURL(challenge, "", s.URL+"/mcp"), "", "laptop")
	u, _ := url.Parse(red)
	q := u.Query()
	// the code comes back to the port the client asked for, with state and iss
	if u.Host != "127.0.0.1:54321" || q.Get("state") != "st-1" || q.Get("iss") != s.URL || q.Get("code") == "" {
		t.Fatalf("redirect = %s", red)
	}
	st, tok := c.Token(url.Values{"grant_type": {"authorization_code"}, "code": {q.Get("code")}, "code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1:54321/callback"}, "resource": {s.URL + "/mcp"}})
	if st != 200 || tok["token_type"] != "Bearer" || tok["expires_in"].(float64) != 3600 || tok["scope"] != "mcp" {
		t.Fatalf("token = %d %v", st, tok)
	}
	m := s.MCP(tok["access_token"].(string))
	who := m.Tool("whoami", nil)
	if who["identity"].(map[string]any)["name"] != "laptop" || who["client"].(map[string]any)["name"] != "Claude Code" {
		t.Fatalf("whoami = %v", who)
	}
	identity := who["identity"].(map[string]any)["id"].(string)

	// refresh: a new pair, the old refresh token spent
	st, next := c.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "resource": {s.URL + "/mcp"}})
	if st != 200 || next["refresh_token"] == tok["refresh_token"] || next["access_token"] == tok["access_token"] {
		t.Fatalf("refresh = %d %v", st, next)
	}
	s.MCP(next["access_token"].(string)).Tool("whoami", nil)

	// another client authorized for the same identity: two authorizations
	c2 := s.Register("Cursor")
	tok2 := s.Authorize(b, c2, identity, "")
	if tok2.IdentityID != identity {
		t.Fatalf("second authorization bound to %s, want %s", tok2.IdentityID, identity)
	}
	_, body = b.Do("GET", "/api/identities/"+identity+"/authorizations", nil)
	auths := apptest.JSON(t, body)["authorizations"].([]any)
	if len(auths) != 2 {
		t.Fatalf("authorizations = %v", auths)
	}
	// the same client authorized again is a third, separate grant
	s.Authorize(b, c, identity, "")
	_, body = b.Do("GET", "/api/identities/"+identity+"/authorizations", nil)
	if n := len(apptest.JSON(t, body)["authorizations"].([]any)); n != 3 {
		t.Fatalf("authorizations after a re-authorization = %d", n)
	}
}

func TestAuthorizeFailures(t *testing.T) {
	s := apptest.Start(t)
	b := s.Browser()
	b.SignIn()
	c := s.Register("x")
	_, challenge := apptest.PKCE()
	errPage := func(u string) {
		t.Helper()
		resp, body := b.Do("GET", u, nil)
		if resp.StatusCode != 400 || !strings.Contains(string(body), "授权请求无效") {
			t.Errorf("GET %s = %d %s, want the error page", u, resp.StatusCode, body)
		}
	}
	// no safe redirect: an error page, never a redirect
	errPage(s.URL + "/oauth/authorize?response_type=code&client_id=cli_nope&redirect_uri=http://127.0.0.1/cb&code_challenge=" + challenge + "&code_challenge_method=S256")
	errPage(c.AuthorizeURL(challenge, "http://127.0.0.1:1/other", ""))
	errPage(c.AuthorizeURL(challenge, "https://evil.example/callback", ""))
	errPage(c.AuthorizeURL(challenge, "http://localhost:54321/callback", ""))

	redirectErr := func(u, code string) {
		t.Helper()
		resp, _ := b.Do("GET", u, nil)
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != 302 || loc.Query().Get("error") != code || loc.Query().Get("iss") != s.URL || loc.Query().Get("state") != "st-1" {
			t.Errorf("GET %s -> %d %s, want error=%s with iss and state", u, resp.StatusCode, loc, code)
		}
	}
	redirectErr(strings.Replace(c.AuthorizeURL(challenge, "", ""), "code_challenge_method=S256", "code_challenge_method=plain", 1), "invalid_request")
	redirectErr(strings.Replace(c.AuthorizeURL(challenge, "", ""), "code_challenge="+challenge, "", 1), "invalid_request")
	redirectErr(strings.Replace(c.AuthorizeURL(challenge, "", ""), "response_type=code", "response_type=token", 1), "unsupported_response_type")
	redirectErr(c.AuthorizeURL(challenge, "", "https://other.example/mcp"), "invalid_target")

	// deny sends access_denied back, with iss
	resp, _ := b.Do("GET", c.AuthorizeURL(challenge, "", ""), nil)
	ar := strings.TrimPrefix(resp.Header.Get("Location"), "/consent?request=")
	resp, body := b.Do("POST", "/api/oauth/requests/"+ar+"/deny", nil)
	red, _ := url.Parse(apptest.JSON(t, body)["redirect_url"].(string))
	if resp.StatusCode != 200 || red.Query().Get("error") != "access_denied" || red.Query().Get("iss") != s.URL {
		t.Fatalf("deny = %d %s", resp.StatusCode, red)
	}
	// a request is answered once
	if resp, _ := b.Do("POST", "/api/oauth/requests/"+ar+"/approve", map[string]string{"new_identity_name": "x"}); resp.StatusCode != 404 {
		t.Errorf("approve after deny = %d, want 404", resp.StatusCode)
	}
}

func TestTokenFailures(t *testing.T) {
	s := apptest.Start(t)
	b := s.Browser()
	b.SignIn()
	c := s.Register("x")
	code := func() (string, string) {
		verifier, challenge := apptest.PKCE()
		u, _ := url.Parse(b.Consent(c.AuthorizeURL(challenge, "", s.URL+"/mcp"), "", "idn-"+challenge[:6]))
		return u.Query().Get("code"), verifier
	}
	form := func(code, verifier string) url.Values {
		return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {"http://127.0.0.1:54321/callback"}, "resource": {s.URL + "/mcp"}}
	}
	cases := []struct {
		name  string
		edit  func(url.Values)
		error string
	}{
		{"wrong PKCE verifier", func(f url.Values) { f.Set("code_verifier", strings.Repeat("x", 50)) }, "invalid_grant"},
		{"redirect mismatch", func(f url.Values) { f.Set("redirect_uri", "http://127.0.0.1:1/callback") }, "invalid_grant"},
		{"resource mismatch", func(f url.Values) { f.Set("resource", "https://other.example/mcp") }, "invalid_target"},
		{"another client", func(f url.Values) { f.Set("client_id", s.Register("y").ID) }, "invalid_grant"},
		{"unknown code", func(f url.Values) { f.Set("code", "mwec_nope") }, "invalid_grant"},
	}
	for _, tc := range cases {
		cd, v := code()
		f := form(cd, v)
		tc.edit(f)
		if st, out := c.Token(f); st != 400 || out["error"] != tc.error {
			t.Errorf("%s: %d %v, want 400 %s", tc.name, st, out, tc.error)
		}
	}
	if st, out := c.Token(url.Values{"grant_type": {"password"}}); st != 400 || out["error"] != "unsupported_grant_type" {
		t.Errorf("password grant: %d %v", st, out)
	}
	if st, out := c.Token(url.Values{"grant_type": {"authorization_code"}, "client_id": {"cli_nope"}}); st != 401 || out["error"] != "invalid_client" {
		t.Errorf("unknown client: %d %v", st, out)
	}

	// a code is used once; using it again revokes what it was exchanged for
	cd, v := code()
	st, tok := c.Token(form(cd, v))
	if st != 200 {
		t.Fatalf("first exchange: %d %v", st, tok)
	}
	if st, out := c.Token(form(cd, v)); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("code reuse: %d %v", st, out)
	}
	resp, _ := s.MCP(tok["access_token"].(string)).Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("token from a reused code still works: %d", resp.StatusCode)
	}
}

// A refresh token used twice revokes its whole family: the token the
// legitimate rotation produced stops working too.
func TestRefreshReplayRevokesFamily(t *testing.T) {
	s := apptest.Start(t)
	b := s.Browser()
	b.SignIn()
	c := s.Register("x")
	tok := s.Authorize(b, c, "", "agent")
	refresh := func(rt string) (int, map[string]any) {
		return c.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
	}
	st, next := refresh(tok.Refresh)
	if st != 200 {
		t.Fatalf("rotate: %d %v", st, next)
	}
	if st, out := refresh(tok.Refresh); st != 400 || out["error"] != "invalid_grant" || !strings.Contains(out["error_description"].(string), "revoked") {
		t.Fatalf("replay: %d %v", st, out)
	}
	if st, out := refresh(next["refresh_token"].(string)); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("the rotated refresh token survived the replay: %d %v", st, out)
	}
	resp, _ := s.MCP(next["access_token"].(string)).Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, nil)
	if resp.StatusCode != 401 {
		t.Fatalf("the rotated access token survived the replay: %d", resp.StatusCode)
	}
	// a refresh token belongs to its client
	tok2 := s.Authorize(b, c, tok.IdentityID, "")
	other := s.Register("y")
	if st, out := other.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok2.Refresh}}); st != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("another client's refresh: %d %v", st, out)
	}
	// and to its resource
	if st, out := c.Token(url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok2.Refresh}, "resource": {"https://elsewhere.example/mcp"}}); st != 400 || out["error"] != "invalid_target" {
		t.Fatalf("refresh for another resource: %d %v", st, out)
	}
}

func TestRevocationEndpoint(t *testing.T) {
	s := apptest.Start(t)
	b := s.Browser()
	b.SignIn()
	c := s.Register("x")
	tok := s.Authorize(b, c, "", "agent")
	resp, err := http.PostForm(s.URL+"/oauth/revoke", url.Values{"token": {tok.Refresh}, "client_id": {c.ID}})
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("revoke: %v %v", err, resp.Status)
	}
	resp.Body.Close()
	r, _ := s.MCP(tok.Access).Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, nil)
	if r.StatusCode != 401 {
		t.Fatalf("access token after revoking its refresh token: %d", r.StatusCode)
	}
	_, body := b.Do("GET", "/api/identities/"+tok.IdentityID+"/authorizations", nil)
	if n := len(apptest.JSON(t, body)["authorizations"].([]any)); n != 0 {
		t.Fatalf("authorizations after revocation = %d", n)
	}
}

// A token is bound to this server's MCP resource: one whose audience is
// another resource isn't accepted.
func TestAudienceBinding(t *testing.T) {
	s := apptest.Start(t)
	b := s.Browser()
	b.SignIn()
	tok := s.Authorize(b, s.Register("x"), "", "agent")
	if _, err := s.App.Store.DB().Exec(`UPDATE oauth_families SET resource = 'https://other.example/mcp'`); err != nil {
		t.Fatal(err)
	}
	r, _ := s.MCP(tok.Access).Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, nil)
	if r.StatusCode != 401 {
		t.Fatalf("a token for another resource got %d", r.StatusCode)
	}
}
