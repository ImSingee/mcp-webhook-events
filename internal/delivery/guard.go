package delivery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Resolver looks up a host's addresses; net.DefaultResolver is one.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Guard keeps webhook requests away from addresses that aren't globally
// routable. It checks every address at connection time, after its own DNS
// lookup, and connects to the address it checked, so a name that changes
// its answer between the check and the connection (DNS rebinding) can't
// reach an internal host. Its client never follows redirects.
type Guard struct {
	// AllowPrivate lets http:// and private, loopback and link-local
	// addresses through: MWE_ALLOW_PRIVATE_CALLBACKS, for development.
	AllowPrivate bool
	Resolver     Resolver
}

// ErrBlocked is a connection to an address the guard doesn't allow.
var ErrBlocked = errors.New("callback address is not globally routable")

// blocked are the IANA special-purpose ranges that are not globally
// reachable (IPv4 and IPv6 Special-Purpose Address Registries), plus
// multicast and the IPv4 "this network" and broadcast blocks.
var blocked = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
		"192.0.0.0/24", "192.0.2.0/24", "192.31.196.0/24", "192.52.193.0/24", "192.88.99.0/24", "192.168.0.0/16",
		"192.175.48.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"255.255.255.255/32",
		"::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/23",
		"2001:db8::/32", "2002::/16", "3fff::/20", "5f00::/16", "fc00::/7", "fe80::/10", "ff00::/8",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// Public reports whether ip is globally routable. An IPv4-mapped or
// NAT64 IPv6 address is judged by the IPv4 address inside it.
func Public(ip netip.Addr) bool {
	ip = ip.Unmap()
	if ip.Is6() && netip.MustParsePrefix("64:ff9b::/96").Contains(ip) {
		b := ip.As16()
		return Public(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	if ip.Zone() != "" {
		return false
	}
	for _, p := range blocked {
		if p.Contains(ip) {
			return false
		}
	}
	return ip.IsValid()
}

// CheckURL is a callback URL's static check, at subscribe time: absolute
// https (http too when private callbacks are allowed), with a host and no
// credentials or fragment.
func (g *Guard) CheckURL(raw string) (*url.URL, error) {
	if len(raw) > 2048 {
		return nil, errors.New("delivery.url is longer than 2048 characters")
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" || u.Opaque != "" {
		return nil, errors.New("delivery.url must be an absolute https URL")
	}
	if u.Scheme != "https" && !(g.AllowPrivate && u.Scheme == "http") {
		return nil, errors.New("delivery.url must use https")
	}
	if u.User != nil || u.Fragment != "" {
		return nil, errors.New("delivery.url must not carry credentials or a fragment")
	}
	return u, nil
}

// Resolvable checks, at subscribe time, that a callback host has at least
// one address the guard would connect to.
func (g *Guard) Resolvable(ctx context.Context, u *url.URL) error {
	if g.AllowPrivate {
		return nil
	}
	_, err := g.addrs(ctx, u.Hostname())
	return err
}

func (g *Guard) resolver() Resolver {
	if g.Resolver != nil {
		return g.Resolver
	}
	return net.DefaultResolver
}

// addrs is host's addresses the guard allows, in the resolver's order.
func (g *Guard) addrs(ctx context.Context, host string) ([]netip.Addr, error) {
	var ips []netip.Addr
	if ip, err := netip.ParseAddr(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")); err == nil {
		ips = []netip.Addr{ip}
	} else {
		ips, err = g.resolver().LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, fmt.Errorf("resolve %s: %w", host, err)
		}
	}
	var ok []netip.Addr
	for _, ip := range ips {
		if g.AllowPrivate || Public(ip) {
			ok = append(ok, ip.Unmap())
		}
	}
	if len(ok) == 0 {
		return nil, ErrBlocked
	}
	return ok, nil
}

func (g *Guard) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := g.addrs(ctx, host)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: 5 * time.Second}
	var last error
	for _, ip := range ips {
		c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

// Client is an HTTP client whose every connection goes through the guard:
// no proxy from the environment, no redirects, TLS SNI and Host from the
// URL's own host name.
func (g *Guard) Client(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:                 nil,
			DialContext:           g.dial,
			TLSHandshakeTimeout:   5 * time.Second,
			ResponseHeaderTimeout: timeout,
			MaxIdleConnsPerHost:   2,
			IdleConnTimeout:       60 * time.Second,
			ForceAttemptHTTP2:     true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}
