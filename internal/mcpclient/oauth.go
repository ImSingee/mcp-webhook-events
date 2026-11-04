package mcpclient

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"time"
)

// ASMetadata is the authorization server metadata the sign-in needs.
type ASMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	CodeChallengeMethods              []string `json:"code_challenge_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	AuthorizationResponseIssSupported bool     `json:"authorization_response_iss_parameter_supported"`
}

// Discovery is what the sign-in learns about a server before it starts.
type Discovery struct {
	Server   string
	MCPURL   string
	Resource string
	Scopes   []string
	AS       ASMetadata
}

// MCPURL is the MCP endpoint for what the user typed: a bare origin gets
// /mcp, a URL with a path is taken as the endpoint itself.
func MCPURL(server string) (string, error) {
	if !strings.Contains(server, "://") {
		server = "https://" + server
	}
	u, err := url.Parse(server)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("%q is not a server URL such as https://events.example.com", server)
	}
	u.RawQuery, u.Fragment = "", ""
	if u.Path == "" || u.Path == "/" {
		u.Path = "/mcp"
	}
	return u.String(), nil
}

func getJSON(ctx context.Context, hc *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(v)
}

// authParam is one parameter of a WWW-Authenticate Bearer challenge.
func authParam(h, name string) string {
	i := strings.Index(strings.ToLower(h), name+"=")
	if i < 0 {
		return ""
	}
	v := h[i+len(name)+1:]
	if strings.HasPrefix(v, `"`) {
		v = v[1:]
		if j := strings.IndexByte(v, '"'); j >= 0 {
			return v[:j]
		}
		return v
	}
	if j := strings.IndexAny(v, ", "); j >= 0 {
		return v[:j]
	}
	return v
}

// Discover finds a server's authorization server the way MCP's
// authorization spec lays out: the resource metadata named by the 401's
// WWW-Authenticate (or its well-known URLs), then the authorization
// server's metadata, whose issuer must be the one it was looked up by.
func Discover(ctx context.Context, hc *http.Client, server string) (Discovery, error) {
	mcpURL, err := MCPURL(server)
	if err != nil {
		return Discovery{}, err
	}
	d := Discovery{Server: server, MCPURL: mcpURL}
	body := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, mcpURL, strings.NewReader(body))
	if err != nil {
		return d, err
	}
	setHeaders(req.Header, "2026-07-28", "server/discover", "")
	resp, err := hc.Do(req)
	if err != nil {
		return d, fmt.Errorf("reach %s: %w", mcpURL, err)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	resp.Body.Close()
	var prmURLs []string
	if m := authParam(resp.Header.Get("WWW-Authenticate"), "resource_metadata"); m != "" {
		prmURLs = append(prmURLs, m)
	}
	u, _ := url.Parse(mcpURL)
	origin := u.Scheme + "://" + u.Host
	prmURLs = append(prmURLs, origin+"/.well-known/oauth-protected-resource"+strings.TrimSuffix(u.Path, "/"), origin+"/.well-known/oauth-protected-resource")
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	var lastErr error
	for _, p := range prmURLs {
		if lastErr = getJSON(ctx, hc, p, &prm); lastErr == nil && len(prm.AuthorizationServers) > 0 {
			break
		}
	}
	if len(prm.AuthorizationServers) == 0 {
		return d, fmt.Errorf("%s publishes no OAuth protected resource metadata (%v)", mcpURL, lastErr)
	}
	d.Resource, d.Scopes = prm.Resource, prm.ScopesSupported
	if d.Resource == "" {
		d.Resource = mcpURL
	}
	issuer := strings.TrimSuffix(prm.AuthorizationServers[0], "/")
	iu, err := url.Parse(issuer)
	if err != nil {
		return d, fmt.Errorf("authorization server %q is not a URL", issuer)
	}
	iorigin, ipath := iu.Scheme+"://"+iu.Host, strings.TrimSuffix(iu.Path, "/")
	candidates := []string{iorigin + "/.well-known/oauth-authorization-server" + ipath, iorigin + "/.well-known/openid-configuration" + ipath}
	if ipath != "" {
		candidates = append(candidates, issuer+"/.well-known/openid-configuration")
	}
	for _, c := range candidates {
		var m ASMetadata
		if err := getJSON(ctx, hc, c, &m); err != nil {
			lastErr = err
			continue
		}
		if m.Issuer != prm.AuthorizationServers[0] && m.Issuer != issuer {
			return d, fmt.Errorf("authorization server metadata at %s names issuer %q, not %q: refusing it", c, m.Issuer, issuer)
		}
		if !slices.Contains(m.CodeChallengeMethods, "S256") {
			return d, fmt.Errorf("authorization server %s doesn't support PKCE S256", issuer)
		}
		if m.RegistrationEndpoint == "" {
			return d, fmt.Errorf("authorization server %s offers no dynamic client registration", issuer)
		}
		d.AS = m
		return d, nil
	}
	return d, fmt.Errorf("no authorization server metadata for %s (%v)", issuer, lastErr)
}

// LoginOptions shape a sign-in.
type LoginOptions struct {
	ClientName string
	// OpenBrowser opens the authorization URL; nil prints it only.
	OpenBrowser func(string) error
	// Prompt is told the URL to open, before the browser is.
	Prompt  func(url string)
	Timeout time.Duration
}

// OpenBrowser opens u in the system's browser.
func OpenBrowser(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}

func randomURLSafe(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// TokenError is a refusal from the token endpoint.
type TokenError struct {
	Status int
	Code   string
	Desc   string
}

func (e *TokenError) Error() string {
	if e.Desc != "" {
		return e.Code + ": " + e.Desc
	}
	return fmt.Sprintf("token endpoint answered %d %s", e.Status, e.Code)
}

func postForm(ctx context.Context, hc *http.Client, endpoint string, form url.Values, clientID, secret string) (tokenResponse, error) {
	if secret == "" {
		form.Set("client_id", clientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if secret != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	}
	resp, err := hc.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()
	var t tokenResponse
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = json.Unmarshal(b, &t)
	if resp.StatusCode != http.StatusOK || t.AccessToken == "" {
		if t.Error == "" {
			t.Error = resp.Status
		}
		return t, &TokenError{Status: resp.StatusCode, Code: t.Error, Desc: t.ErrorDescription}
	}
	return t, nil
}

func (p *Profile) apply(t tokenResponse, now time.Time) {
	p.AccessToken = t.AccessToken
	if t.RefreshToken != "" {
		p.RefreshToken = t.RefreshToken
	}
	if t.ExpiresIn > 0 {
		p.ExpiresAt = now.Add(time.Duration(t.ExpiresIn) * time.Second)
	} else {
		p.ExpiresAt = now.Add(time.Hour)
	}
	if t.Scope != "" {
		p.Scope = t.Scope
	}
}

// Login signs in: it registers a client for a loopback redirect, sends the
// user's browser to the authorization endpoint with PKCE and the resource,
// waits for the callback (checking state and iss), and exchanges the code.
func Login(ctx context.Context, hc *http.Client, d Discovery, opt LoginOptions) (*Profile, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("open the loopback redirect: %w", err)
	}
	defer ln.Close()
	redirect := fmt.Sprintf("http://127.0.0.1:%d/callback", ln.Addr().(*net.TCPAddr).Port)
	name := opt.ClientName
	if name == "" {
		host, _ := os.Hostname()
		name = "mwe CLI (" + host + ")"
	}
	reg := map[string]any{
		"client_name": name, "redirect_uris": []string{redirect}, "grant_types": []string{"authorization_code", "refresh_token"},
		"response_types": []string{"code"}, "token_endpoint_auth_method": "none", "application_type": "native",
	}
	b, _ := json.Marshal(reg)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.AS.RegistrationEndpoint, strings.NewReader(string(b)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("register the client: %w", err)
	}
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	var client struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Error        string `json:"error"`
		Desc         string `json:"error_description"`
	}
	_ = json.Unmarshal(rb, &client)
	if resp.StatusCode/100 != 2 || client.ClientID == "" {
		return nil, fmt.Errorf("register the client: %s %s %s", resp.Status, client.Error, client.Desc)
	}
	verifier := randomURLSafe(48)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := randomURLSafe(24)
	q := url.Values{
		"response_type": {"code"}, "client_id": {client.ClientID}, "redirect_uri": {redirect},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {state}, "resource": {d.Resource},
	}
	if len(d.Scopes) > 0 {
		q.Set("scope", strings.Join(d.Scopes, " "))
	}
	authURL := d.AS.AuthorizationEndpoint + "?" + q.Encode()

	type result struct {
		code string
		err  error
	}
	done := make(chan result, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query()
		res := result{}
		switch {
		case v.Get("state") != state:
			res.err = errors.New("the callback's state doesn't match this sign-in")
		case v.Get("iss") != d.AS.Issuer && (v.Get("iss") != "" || d.AS.AuthorizationResponseIssSupported):
			// RFC 9207: a present iss must be the issuer; an absent one is
			// refused when the server says it sends iss
			res.err = fmt.Errorf("the callback's iss %q isn't the authorization server %q", v.Get("iss"), d.AS.Issuer)
		case v.Get("error") != "":
			res.err = fmt.Errorf("authorization refused: %s %s", v.Get("error"), v.Get("error_description"))
		case v.Get("code") == "":
			res.err = errors.New("the callback carries no code")
		default:
			res.code = v.Get("code")
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		msg := "已登录 mwe，可以关闭此页面。 / Signed in to mwe; you can close this page."
		if res.err != nil {
			msg = "登录失败 / Sign-in failed: " + html.EscapeString(res.err.Error())
		}
		fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><title>mwe</title><body style="font:16px system-ui;margin:4rem auto;max-width:36rem">%s</body>`, msg)
		select {
		case done <- res:
		default:
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go srv.Serve(ln)
	defer srv.Close()

	if opt.Prompt != nil {
		opt.Prompt(authURL)
	}
	if opt.OpenBrowser != nil {
		_ = opt.OpenBrowser(authURL)
	}
	timeout := opt.Timeout
	if timeout == 0 {
		timeout = 10 * time.Minute
	}
	var res result
	select {
	case res = <-done:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(timeout):
		return nil, errors.New("timed out waiting for the browser to come back")
	}
	if res.err != nil {
		return nil, res.err
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {res.code}, "redirect_uri": {redirect}, "code_verifier": {verifier}, "resource": {d.Resource}}
	t, err := postForm(ctx, hc, d.AS.TokenEndpoint, form, client.ClientID, client.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("exchange the code: %w", err)
	}
	p := &Profile{
		Server: d.Server, MCPURL: d.MCPURL, Resource: d.Resource, Issuer: d.AS.Issuer,
		TokenEndpoint: d.AS.TokenEndpoint, RevocationEndpoint: d.AS.RevocationEndpoint,
		ClientID: client.ClientID, ClientSecret: client.ClientSecret,
	}
	p.apply(t, time.Now())
	return p, nil
}

// Refresh renews a profile's tokens with its refresh token.
func Refresh(ctx context.Context, hc *http.Client, p *Profile) error {
	if p.RefreshToken == "" {
		return &TokenError{Code: "invalid_grant", Desc: "no refresh token saved"}
	}
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {p.RefreshToken}, "resource": {p.Resource}}
	t, err := postForm(ctx, hc, p.TokenEndpoint, form, p.ClientID, p.ClientSecret)
	if err != nil {
		return err
	}
	p.apply(t, time.Now())
	return nil
}

// Revoke revokes a profile's refresh token (and so its whole grant).
func Revoke(ctx context.Context, hc *http.Client, p *Profile) error {
	if p.RevocationEndpoint == "" {
		return nil
	}
	tok := p.RefreshToken
	if tok == "" {
		tok = p.AccessToken
	}
	form := url.Values{"token": {tok}}
	if p.ClientSecret == "" {
		form.Set("client_id", p.ClientID)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.RevocationEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if p.ClientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(p.ClientID), url.QueryEscape(p.ClientSecret))
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation endpoint answered %s", resp.Status)
	}
	return nil
}
