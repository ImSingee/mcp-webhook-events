package oauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ImSingee/mcp-webhook-events/internal/config"
	"github.com/ImSingee/mcp-webhook-events/internal/delivery"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
	"github.com/ImSingee/mcp-webhook-events/internal/version"
)

// Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document,
// "CIMD"; docs/spec has the -03 text this follows). A client whose
// client_id is an https URL publishes its metadata at that URL; the server
// fetches it (through the SSRF guard, no redirects, at most 5 KiB, JSON
// only), validates it, and keeps it as a snapshot that stays fresh for as
// long as its HTTP cache headers say, within MetadataMinTTL and
// MetadataMaxTTL. A failed fetch never replaces a good snapshot.

// MetadataMaxBytes is the most of a metadata document the server reads
// (CIMD §10.11 recommends 5 kilobytes).
const MetadataMaxBytes = 5 << 10

// MetadataTimeout bounds one metadata fetch.
const MetadataTimeout = 5 * time.Second

// MetadataError is why a client's metadata document couldn't be used.
type MetadataError struct {
	// Transient is a failure that may pass by itself (a network error, a
	// timeout, a 5xx): CIMD §6.1's transient class. Anything else is
	// terminal: the document was fetched but refused.
	Transient bool
	// Mismatch is a document whose client_id isn't the URL it was fetched
	// from (§4), which revokes what the client was granted (§6.1).
	Mismatch bool
	Msg      string
}

func (e *MetadataError) Error() string { return e.Msg }

func terminal(format string, a ...any) *MetadataError {
	return &MetadataError{Msg: fmt.Sprintf(format, a...)}
}

func transient(format string, a ...any) *MetadataError {
	return &MetadataError{Transient: true, Msg: fmt.Sprintf(format, a...)}
}

// IsClientIDURL reports whether a client_id is URL-shaped: such a
// client_id is a CIMD client (or an invalid one), never a dynamically
// registered client, whose ids this server makes as "cli_…" with no colon
// (CIMD §9.1).
func IsClientIDURL(clientID string) bool { return strings.Contains(clientID, ":") }

// CheckClientIDURL is a Client Identifier URL's rules (CIMD §3), plus
// §10.1's: it must not be this server's own issuer or resource identifier.
// The URL is taken as it is, never normalized.
func (s *Server) CheckClientIDURL(raw string) error {
	if len(raw) > 2048 {
		return errors.New("the client_id URL is longer than 2048 characters")
	}
	if !strings.HasPrefix(raw, "https://") {
		return errors.New("a client_id URL must use the https scheme")
	}
	if strings.Contains(raw, "#") {
		return errors.New("a client_id URL must not contain a fragment")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Opaque != "" {
		return errors.New("the client_id is not a valid https URL")
	}
	if u.User != nil {
		return errors.New("a client_id URL must not contain user information")
	}
	p := u.EscapedPath()
	if p == "" || p == "/" {
		return errors.New("a client_id URL must have a path other than /")
	}
	for _, seg := range strings.Split(p, "/") {
		if dec, err := url.PathUnescape(seg); err != nil || dec == "." || dec == ".." {
			return errors.New("a client_id URL must not contain . or .. path segments")
		}
	}
	if raw == s.Issuer() || raw == s.Cfg.MCPResource() {
		return errors.New("a client_id URL must not be this server's own issuer or resource identifier")
	}
	return nil
}

// MetadataHTTPClient is the client metadata fetches use: every connection
// through an SSRF guard that refuses non-public addresses (loopback ones
// too, unless allowLoopback), no redirects, no proxy, roots as given.
func MetadataHTTPClient(allowLoopback bool, roots *x509.CertPool, resolver delivery.Resolver) *http.Client {
	return (&delivery.Guard{AllowLoopback: allowLoopback, RootCAs: roots, Resolver: resolver}).Client(MetadataTimeout)
}

// fetchMetadata GETs a client's metadata document and returns it decoded,
// as fetched, and how long it may be cached.
func (s *Server) fetchMetadata(ctx context.Context, clientID string) (map[string]json.RawMessage, []byte, time.Duration, *MetadataError) {
	ctx, cancel := context.WithTimeout(ctx, MetadataTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil)
	if err != nil {
		return nil, nil, 0, terminal("the client_id URL can't be requested: %v", err)
	}
	// §6 and §10.7.1: say what we want; send nothing about the user
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mwe-server/"+version.Version)
	resp, err := s.MetadataClient.Do(req)
	if err != nil {
		return nil, nil, 0, classifyFetchError(err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return nil, nil, 0, terminal("the metadata document URL answered %d; redirects are not followed (CIMD §6)", resp.StatusCode)
	case resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests:
		return nil, nil, 0, transient("the metadata document URL answered %d", resp.StatusCode)
	default:
		return nil, nil, 0, terminal("the metadata document URL answered %d, not 200", resp.StatusCode)
	}
	mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || !(mt == "application/json" || (strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))) {
		return nil, nil, 0, terminal("the metadata document is served as %q, not JSON", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MetadataMaxBytes+1))
	if err != nil {
		return nil, nil, 0, transient("reading the metadata document failed: %v", err)
	}
	if len(body) > MetadataMaxBytes {
		return nil, nil, 0, terminal("the metadata document is larger than %d bytes", MetadataMaxBytes)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(body, &doc); err != nil || doc == nil {
		return nil, nil, 0, terminal("the metadata document is not a JSON object")
	}
	return doc, body, s.metadataTTL(resp.Header), nil
}

// classifyFetchError sorts a failed metadata request: refused by the SSRF
// guard or by TLS is terminal, a network failure or timeout transient.
func classifyFetchError(err error) *MetadataError {
	var (
		certErr *tls.CertificateVerificationError
		ue      x509.UnknownAuthorityError
		he      x509.HostnameError
		ne      net.Error
	)
	switch {
	case errors.Is(err, delivery.ErrBlocked):
		return terminal("the client_id URL resolves to an address that is not globally routable")
	case errors.As(err, &certErr), errors.As(err, &ue), errors.As(err, &he):
		return terminal("the client_id URL's TLS certificate is not trusted")
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return transient("fetching the metadata document timed out")
	}
	return transient("fetching the metadata document failed: %v", unwrapNetError(err))
}

func unwrapNetError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// Metadata cache bounds (CIMD §6.2): a document without cache directives
// stays fresh MetadataDefaultTTL; directives are honored within
// [MetadataMinTTL, MetadataMaxTTL], the floor being the fetch rate limit
// §6.2 allows.
const (
	DefaultMetadataMinTTL     = time.Minute
	DefaultMetadataDefaultTTL = 10 * time.Minute
	DefaultMetadataMaxTTL     = 24 * time.Hour
)

// metadataTTL is how long a document may be cached by its response's
// Cache-Control (s-maxage over max-age, since this server shares its cache
// among all its users; no-store and no-cache as zero) and Age; Expires is
// not honored (§6.2).
func (s *Server) metadataTTL(h http.Header) time.Duration {
	ttl, set := time.Duration(0), false
	maxAge, sMaxAge := -1, -1
	for _, part := range strings.Split(strings.Join(h.Values("Cache-Control"), ","), ",") {
		name, val, _ := strings.Cut(strings.TrimSpace(part), "=")
		val = strings.Trim(strings.TrimSpace(val), `"`)
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "no-store", "no-cache":
			set = true
		case "max-age":
			if n, err := strconv.Atoi(val); err == nil && n >= 0 {
				maxAge = n
			}
		case "s-maxage":
			if n, err := strconv.Atoi(val); err == nil && n >= 0 {
				sMaxAge = n
			}
		}
	}
	switch {
	case set:
		ttl = 0
	case sMaxAge >= 0:
		ttl, set = time.Duration(sMaxAge)*time.Second, true
	case maxAge >= 0:
		ttl, set = time.Duration(maxAge)*time.Second, true
	}
	if !set {
		return s.MetadataDefaultTTL
	}
	if age, err := strconv.Atoi(strings.TrimSpace(h.Get("Age"))); err == nil && age > 0 {
		ttl -= time.Duration(age) * time.Second
	}
	return min(max(ttl, s.MetadataMinTTL), s.MetadataMaxTTL)
}

// supportedGrants and supportedAuth are what this server offers a CIMD
// client: the code grant (with refresh), as a public client.
var supportedGrants = []string{"authorization_code", "refresh_token"}

func stringField(doc map[string]json.RawMessage, key string) (string, bool, error) {
	raw, ok := doc[key]
	if !ok || string(raw) == "null" {
		return "", false, nil
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", true, fmt.Errorf("%s must be a string", key)
	}
	return v, true, nil
}

func stringsField(doc map[string]json.RawMessage, key string) ([]string, bool, error) {
	raw, ok := doc[key]
	if !ok || string(raw) == "null" {
		return nil, false, nil
	}
	var v []string
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, true, fmt.Errorf("%s must be an array of strings", key)
	}
	return v, true, nil
}

// symmetric reports whether an auth method rests on a shared secret, which
// a public document can't carry (CIMD §4.1).
func symmetric(method string) bool { return strings.HasPrefix(method, "client_secret") }

// informativeURI keeps an informative URI (client_uri, logo_uri) only when
// it is an absolute https URL (CIMD §10.7: only known schemes).
func informativeURI(v string) string {
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return ""
	}
	return v
}

// ValidateMetadata checks a fetched document against its client_id
// (CIMD §4, §4.1, §5, §6; MCP's required client_id, client_name and
// redirect_uris) and returns the client it describes: a public client
// ("none"), with the grant types it and this server share.
func ValidateMetadata(clientID string, doc map[string]json.RawMessage) (store.Client, *MetadataError) {
	id, ok, err := stringField(doc, "client_id")
	if err != nil || !ok {
		return store.Client{}, terminal("the metadata document has no client_id string")
	}
	if id != clientID {
		e := terminal("the metadata document's client_id %q is not the URL it was fetched from", id)
		e.Mismatch = true
		return store.Client{}, e
	}
	for _, k := range []string{"client_secret", "client_secret_expires_at"} {
		if _, ok := doc[k]; ok {
			return store.Client{}, terminal("the metadata document must not contain %s (CIMD §4.1)", k)
		}
	}
	if _, a := doc["jwks"]; a {
		if _, b := doc["jwks_uri"]; b {
			return store.Client{}, terminal("the metadata document must not contain both jwks and jwks_uri (CIMD §4.1)")
		}
	}
	supported, hasSupported, err := stringsField(doc, "token_endpoint_auth_methods_supported")
	if err != nil {
		return store.Client{}, terminal("%v", err)
	}
	method, hasMethod, err := stringField(doc, "token_endpoint_auth_method")
	if err != nil {
		return store.Client{}, terminal("%v", err)
	}
	if slices.ContainsFunc(supported, symmetric) || symmetric(method) {
		return store.Client{}, terminal("the metadata document declares a shared-secret auth method, which a public document can't use (CIMD §4.1)")
	}
	if hasSupported && hasMethod && !slices.Contains(supported, method) {
		return store.Client{}, terminal("token_endpoint_auth_method %q is not among token_endpoint_auth_methods_supported (CIMD §5)", method)
	}
	// §5: the plural list wins, then the singular; neither means none (never
	// RFC 7591's client_secret_basic default)
	offered := []string{"none"}
	switch {
	case hasSupported:
		offered = supported
	case hasMethod:
		offered = []string{method}
	}
	if !slices.Contains(offered, "none") {
		return store.Client{}, terminal("the client authenticates only with %s; this server supports public clients (none) only", strings.Join(offered, ", "))
	}
	name, _, err := stringField(doc, "client_name")
	name = strings.TrimSpace(name)
	if err != nil || name == "" {
		return store.Client{}, terminal("the metadata document has no client_name")
	}
	if utf8.RuneCountInString(name) > 200 {
		name = string([]rune(name)[:200])
	}
	uris, _, err := stringsField(doc, "redirect_uris")
	if err != nil || len(uris) == 0 {
		return store.Client{}, terminal("the metadata document has no redirect_uris")
	}
	if len(uris) > 20 {
		return store.Client{}, terminal("the metadata document lists more than 20 redirect_uris")
	}
	for _, u := range uris {
		if err := checkRedirectURI(u); err != nil {
			return store.Client{}, terminal("%v", err)
		}
	}
	grants, hasGrants, err := stringsField(doc, "grant_types")
	if err != nil {
		return store.Client{}, terminal("%v", err)
	}
	if !hasGrants {
		grants = []string{"authorization_code"}
	}
	var shared []string
	for _, g := range supportedGrants {
		if slices.Contains(grants, g) {
			shared = append(shared, g)
		}
	}
	if !slices.Contains(shared, "authorization_code") {
		return store.Client{}, terminal("the client's grant_types don't include authorization_code, the only grant this server starts from (CIMD §6)")
	}
	responses, hasResponses, err := stringsField(doc, "response_types")
	if err != nil {
		return store.Client{}, terminal("%v", err)
	}
	if hasResponses && !slices.Contains(responses, "code") {
		return store.Client{}, terminal("the client's response_types don't include code (CIMD §6)")
	}
	clientURI, _, _ := stringField(doc, "client_uri")
	logoURI, _, _ := stringField(doc, "logo_uri")
	return store.Client{
		ID: clientID, Name: name, RedirectURIs: uris, TokenAuthMethod: "none", GrantTypes: shared, Kind: store.ClientCIMD,
		ClientURI: informativeURI(clientURI), LogoURI: informativeURI(logoURI),
	}, nil
}

// fetchCall is one metadata fetch others for the same URL wait on.
type fetchCall struct {
	done chan struct{}
	c    store.Client
	err  *MetadataError
}

// refreshMetadata fetches, validates and saves a client's document, once
// for all the requests that need it at the same time.
func (s *Server) refreshMetadata(ctx context.Context, clientID string) (store.Client, *MetadataError) {
	s.fetchMu.Lock()
	if call, ok := s.fetching[clientID]; ok {
		s.fetchMu.Unlock()
		select {
		case <-call.done:
			return call.c, call.err
		case <-ctx.Done():
			return store.Client{}, transient("fetching the metadata document was cancelled")
		}
	}
	call := &fetchCall{done: make(chan struct{})}
	s.fetching[clientID] = call
	s.fetchMu.Unlock()
	defer func() {
		s.fetchMu.Lock()
		delete(s.fetching, clientID)
		s.fetchMu.Unlock()
		close(call.done)
	}()
	ctx = context.WithoutCancel(ctx)
	doc, body, ttl, merr := s.fetchMetadata(ctx, clientID)
	if merr == nil {
		call.c, merr = ValidateMetadata(clientID, doc)
	}
	if merr != nil {
		call.err = merr
		return call.c, merr
	}
	now := s.Store.Now()
	fresh := now.Add(ttl)
	call.c.Metadata, call.c.MetadataFetchedAt, call.c.MetadataFreshUntil = json.RawMessage(body), &now, &fresh
	if err := s.Store.PutCIMDClient(ctx, call.c); err != nil {
		s.Log.Error("save client metadata", "client_id", clientID, "err", err)
		call.err = transient("saving the client's metadata failed")
		return call.c, call.err
	}
	saved, err := s.Store.GetClient(ctx, clientID)
	if err != nil {
		call.err = transient("reading the client's metadata back failed")
		return call.c, call.err
	}
	call.c = saved
	return saved, nil
}

// ResolveClient is the client a request names: a dynamically registered
// one from the database, or a CIMD client from its fresh snapshot or a new
// fetch of its document. allowStale lets a transient fetch failure fall
// back to the last good snapshot (CIMD §6.1), which the token endpoint
// does so outstanding grants survive an outage; the authorization
// endpoint doesn't.
func (s *Server) ResolveClient(ctx context.Context, clientID string, allowStale bool) (store.Client, error) {
	if !IsClientIDURL(clientID) {
		return s.Store.GetClient(ctx, clientID)
	}
	if err := s.CheckClientIDURL(clientID); err != nil {
		return store.Client{}, terminal("%v", err)
	}
	cur, err := s.Store.GetClient(ctx, clientID)
	have := err == nil && cur.Kind == store.ClientCIMD
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return store.Client{}, err
	}
	if have && cur.MetadataFreshUntil != nil && s.Store.Now().Before(*cur.MetadataFreshUntil) {
		return cur, nil
	}
	c, merr := s.refreshMetadata(ctx, clientID)
	if merr == nil {
		return c, nil
	}
	s.Log.Warn("client metadata document refused", "client_id", clientID, "transient", merr.Transient, "reason", merr.Msg)
	if merr.Mismatch && have {
		// §6.1: a client_id mismatch invalidates the client's outstanding
		// grants at once
		ids, err := s.Store.RevokeClientFamilies(ctx, clientID)
		if err != nil {
			s.Log.Error("revoke a mismatched client's grants", "client_id", clientID, "err", err)
		}
		for _, id := range ids {
			s.Core.FamilyRevoked(ctx, id)
		}
	}
	if merr.Transient && allowStale && have {
		return cur, nil
	}
	return store.Client{}, merr
}

// loopbackRedirectHosts are the hosts whose redirect URIs may name any
// port: the loopback IP literals of RFC 8252 §7.3 and the "localhost"
// RFC 9700 §4.1.3 extends that exception to.
var loopbackRedirectHosts = []string{"127.0.0.1", "::1", "localhost"}

// CIMDRedirectMatches reports whether a requested redirect URI matches one
// a CIMD document registers: by simple string comparison (CIMD §4.2,
// RFC 9700 §4.1.3), the one exception being the port of an http redirect
// to a loopback host, which the client picks at run time. Everything else
// about such a URI, the host included, must match exactly.
func CIMDRedirectMatches(registered, requested string) bool {
	if registered == requested {
		return true
	}
	a, err1 := url.Parse(registered)
	b, err2 := url.Parse(requested)
	if err1 != nil || err2 != nil || a.Scheme != "http" || b.Scheme != "http" || a.User != nil || b.User != nil ||
		strings.Contains(requested, "#") || a.Opaque != "" || b.Opaque != "" {
		return false
	}
	if a.Hostname() != b.Hostname() || !slices.Contains(loopbackRedirectHosts, a.Hostname()) {
		return false
	}
	return a.EscapedPath() == b.EscapedPath() && a.RawQuery == b.RawQuery && a.ForceQuery == b.ForceQuery
}

// redirectMatches is the redirect URI rule for a client's kind.
func redirectMatches(c store.Client, registered, requested string) bool {
	if c.Kind == store.ClientCIMD {
		return CIMDRedirectMatches(registered, requested)
	}
	return RedirectMatches(registered, requested)
}

// Warning is something the consent page should point out about a request.
type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ConsentWarnings are the warnings for a client sending the user back to
// redirectURI. A CIMD client redirecting to a local address gets
// localhost_redirect: the document can't stop another program on the
// user's machine from claiming to be that client (MCP authorization,
// "Localhost Redirect URI Risks").
func ConsentWarnings(c store.Client, redirectURI string) []Warning {
	out := []Warning{}
	u, err := url.Parse(redirectURI)
	if c.Kind == store.ClientCIMD && err == nil && u.Scheme == "http" && config.IsLoopbackHost(u.Hostname()) {
		out = append(out, Warning{
			Code:    "localhost_redirect",
			Message: "This client identifies itself by a URL but sends you back to a local address; any program on this computer could claim to be it.",
		})
	}
	return out
}

// MetadataHost is the host of a CIMD client's client_id URL, which the
// consent page shows beside the name the document asserts (CIMD §10.6);
// nil for a dynamically registered client.
func MetadataHost(c store.Client) any {
	if c.Kind != store.ClientCIMD {
		return nil
	}
	u, err := url.Parse(c.ID)
	if err != nil {
		return nil
	}
	return u.Host
}
