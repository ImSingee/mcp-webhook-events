// Package config reads the server's settings from its environment.
package config

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config is the server's settings, all from MWE_* environment variables.
type Config struct {
	Password string // MWE_PASSWORD, the platform's one password
	// PublicURL is MWE_PUBLIC_URL without a trailing slash: the OAuth
	// issuer, the origin admin requests must come from, and the base of
	// the MCP resource and webhook URLs.
	PublicURL string
	Addr      string // MWE_ADDR
	DataDir   string // MWE_DATA_DIR, which holds mwe.db
	// EventRetention is how long events are kept for replay and the UI.
	EventRetention time.Duration
	// MaxBodyBytes caps a received webhook's body.
	MaxBodyBytes int64
	// TrustProxy takes the client's address from X-Forwarded-For.
	TrustProxy bool
	// AllowPrivateNetwork (MWE_ALLOW_PRIVATE_NETWORK, formerly
	// MWE_ALLOW_PRIVATE_CALLBACKS) is for development and tests only. It
	// lets webhook-mode subscriptions deliver to http:// URLs and private
	// or loopback addresses, and, when the server itself runs on a
	// loopback public URL, lets client ID metadata documents be fetched
	// from loopback addresses (CIMD §10.7's development exception; their
	// URLs must still be https).
	AllowPrivateNetwork bool
	// ExtraCAFile (MWE_EXTRA_CA_FILE) is a PEM file of root certificates
	// trusted, besides the system's, by the server's outbound https
	// requests: client metadata fetches and webhook deliveries.
	ExtraCAFile string
	// CallbackAllowlist are callback origins (scheme://host[:port]) the
	// operator vouches for: webhook-mode subscriptions to them skip the
	// endpoint verification handshake (SEP-3415's "server-configured
	// allowlist"). The https rule and the SSRF check at every connection
	// still apply.
	CallbackAllowlist []string
	LogLevel          slog.Level // MWE_LOG_LEVEL: debug, info, warn or error
}

// CallbackAllowed reports whether a callback URL's origin is on the
// allowlist.
func (c Config) CallbackAllowed(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	o := strings.ToLower(u.Scheme + "://" + u.Host)
	for _, a := range c.CallbackAllowlist {
		if a == o {
			return true
		}
	}
	return false
}

// MCPResource is the MCP endpoint's URL, which is also the OAuth resource
// (RFC 8707) every access token is bound to.
func (c Config) MCPResource() string { return c.PublicURL + "/mcp" }

// Secure says whether the public URL is https, so cookies get Secure.
func (c Config) Secure() bool { return strings.HasPrefix(c.PublicURL, "https://") }

// DBPath is the SQLite database's file.
func (c Config) DBPath() string { return filepath.Join(c.DataDir, "mwe.db") }

// FromEnv reads the configuration from the process environment.
func FromEnv() (Config, error) { return Parse(os.Getenv) }

// Parse reads the configuration through getenv, so tests can pass a map.
func Parse(getenv func(string) string) (Config, error) {
	c := Config{
		Addr:           ":8080",
		DataDir:        "./data",
		EventRetention: 168 * time.Hour,
		MaxBodyBytes:   262144,
		LogLevel:       slog.LevelInfo,
	}
	var errs []error
	c.Password = getenv("MWE_PASSWORD")
	if c.Password == "" {
		errs = append(errs, errors.New("MWE_PASSWORD is required"))
	}
	pub, err := PublicURL(getenv("MWE_PUBLIC_URL"))
	if err != nil {
		errs = append(errs, err)
	}
	c.PublicURL = pub
	if v := getenv("MWE_ADDR"); v != "" {
		c.Addr = v
	}
	if v := getenv("MWE_DATA_DIR"); v != "" {
		c.DataDir = v
	}
	if v := getenv("MWE_EVENT_RETENTION"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute {
			errs = append(errs, fmt.Errorf("MWE_EVENT_RETENTION %q must be a duration of at least 1m, such as 168h", v))
		} else {
			c.EventRetention = d
		}
	}
	if v := getenv("MWE_MAX_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 || n > 16<<20 {
			errs = append(errs, fmt.Errorf("MWE_MAX_BODY_BYTES %q must be a byte count between 1 and %d", v, 16<<20))
		} else {
			c.MaxBodyBytes = n
		}
	}
	var oldPrivate, newPrivate *bool
	for _, b := range []struct {
		name string
		dst  **bool
	}{{"MWE_TRUST_PROXY", nil}, {"MWE_ALLOW_PRIVATE_CALLBACKS", &oldPrivate}, {"MWE_ALLOW_PRIVATE_NETWORK", &newPrivate}} {
		v := getenv(b.name)
		if v == "" {
			continue
		}
		on, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s %q must be true or false", b.name, v))
			continue
		}
		if b.dst == nil {
			c.TrustProxy = on
		} else {
			*b.dst = &on
		}
	}
	switch {
	case newPrivate != nil && oldPrivate != nil && *newPrivate != *oldPrivate:
		errs = append(errs, errors.New("MWE_ALLOW_PRIVATE_NETWORK and its old name MWE_ALLOW_PRIVATE_CALLBACKS disagree: set only MWE_ALLOW_PRIVATE_NETWORK"))
	case newPrivate != nil:
		c.AllowPrivateNetwork = *newPrivate
	case oldPrivate != nil:
		c.AllowPrivateNetwork = *oldPrivate
	}
	if v := getenv("MWE_EXTRA_CA_FILE"); v != "" {
		if _, err := os.Stat(v); err != nil {
			errs = append(errs, fmt.Errorf("MWE_EXTRA_CA_FILE %q: %v", v, err))
		}
		c.ExtraCAFile = v
	}
	for _, v := range strings.Split(getenv("MWE_CALLBACK_ALLOWLIST"), ",") {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
			errs = append(errs, fmt.Errorf("MWE_CALLBACK_ALLOWLIST entry %q must be an origin such as https://hooks.example.com", v))
			continue
		}
		c.CallbackAllowlist = append(c.CallbackAllowlist, strings.ToLower(u.Scheme+"://"+u.Host))
	}
	if v := getenv("MWE_LOG_LEVEL"); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil {
			errs = append(errs, fmt.Errorf("MWE_LOG_LEVEL %q must be debug, info, warn or error", v))
		}
	}
	return c, errors.Join(errs...)
}

// PublicURL checks a public URL and returns it without a trailing slash. It
// is an origin: http(s), a host, no path, query or fragment, since the
// OAuth metadata and the MCP endpoint live at fixed paths under its root.
// Plain http is allowed only for a loopback host.
func PublicURL(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("MWE_PUBLIC_URL is required, such as https://events.example.com")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("MWE_PUBLIC_URL %q must be an absolute http(s) URL, such as https://events.example.com", raw)
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("MWE_PUBLIC_URL %q must be an origin with no path, query or credentials; serve the platform at the root of its host", raw)
	}
	if u.Scheme == "http" && !IsLoopbackHost(u.Hostname()) {
		return "", fmt.Errorf("MWE_PUBLIC_URL %q must use https unless its host is localhost", raw)
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}

// MetadataLoopbackAllowed reports whether client ID metadata documents may
// be fetched from loopback addresses: only in development
// (MWE_ALLOW_PRIVATE_NETWORK) and only when the server's own public URL is
// on loopback, as CIMD §10.7 requires of that exception.
func (c Config) MetadataLoopbackAllowed() bool {
	u, err := url.Parse(c.PublicURL)
	return c.AllowPrivateNetwork && err == nil && IsLoopbackHost(u.Hostname())
}

// RootCAs are the roots the server's outbound https requests trust: the
// system's, plus MWE_EXTRA_CA_FILE's; nil (the system's) without it.
func (c Config) RootCAs() (*x509.CertPool, error) {
	if c.ExtraCAFile == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(c.ExtraCAFile)
	if err != nil {
		return nil, fmt.Errorf("MWE_EXTRA_CA_FILE: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("MWE_EXTRA_CA_FILE %s holds no PEM certificate", c.ExtraCAFile)
	}
	return pool, nil
}

// IsLoopbackHost reports whether host (without port) is localhost or a
// loopback IP.
func IsLoopbackHost(host string) bool {
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
