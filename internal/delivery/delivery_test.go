package delivery_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/apptest"
	"github.com/ImSingee/mcp-webhook-events/internal/config"
	"github.com/ImSingee/mcp-webhook-events/internal/delivery"
	"github.com/ImSingee/mcp-webhook-events/internal/events"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
)

// verify is a Standard Webhooks verifier written from the spec, not from
// the server's signing code: HMAC-SHA256 over "id.timestamp.body" with the
// base64-decoded secret after "whsec_", compared against each "v1,"
// signature in the header.
func verify(secret string, h http.Header, body []byte) bool {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, "whsec_"))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(h.Get("webhook-id") + "." + h.Get("webhook-timestamp") + "." + string(body)))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	for _, sig := range strings.Fields(h.Get("webhook-signature")) {
		if v, ok := strings.CutPrefix(sig, "v1,"); ok && hmac.Equal([]byte(v), []byte(want)) {
			return true
		}
	}
	return false
}

// The signature for Standard Webhooks' published example: secret
// whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw, id msg_p5jXN8AQM9LWM0D4loKWxJek,
// timestamp 1614265330, body {"test": 2432232314}.
func TestSignatureMatchesStandardWebhooksVector(t *testing.T) {
	got := delivery.Signature([]string{"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"}, "msg_p5jXN8AQM9LWM0D4loKWxJek", 1614265330, []byte(`{"test": 2432232314}`))
	if got != "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=" {
		t.Fatalf("signature = %s", got)
	}
	two := delivery.Signature([]string{"whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw", "whsec_" + base64.StdEncoding.EncodeToString(make([]byte, 32))}, "msg_x", 1, []byte("{}"))
	if len(strings.Fields(two)) != 2 {
		t.Fatalf("dual signature = %q", two)
	}
}

func TestParseSecret(t *testing.T) {
	ok := []string{"whsec_" + base64.StdEncoding.EncodeToString(make([]byte, 24)), "whsec_" + base64.StdEncoding.EncodeToString(make([]byte, 64)), "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"}
	bad := []string{"", "secret", "whsec_", "whsec_!!!", "whsec_" + base64.StdEncoding.EncodeToString(make([]byte, 23)), "whsec_" + base64.StdEncoding.EncodeToString(make([]byte, 65)), "WHSEC_" + base64.StdEncoding.EncodeToString(make([]byte, 32))}
	for _, s := range ok {
		if _, err := delivery.ParseSecret(s); err != nil {
			t.Errorf("ParseSecret(%q) = %v", s, err)
		}
	}
	for _, s := range bad {
		if _, err := delivery.ParseSecret(s); err == nil {
			t.Errorf("ParseSecret(%q) took it", s)
		}
	}
}

func TestPublic(t *testing.T) {
	public := []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "93.184.216.34"}
	private := []string{"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::a00:1", "224.0.0.1", "198.18.0.1", "2001:db8::1", "255.255.255.255"}
	for _, s := range public {
		if !delivery.Public(netip.MustParseAddr(s)) {
			t.Errorf("%s judged not public", s)
		}
	}
	for _, s := range private {
		if delivery.Public(netip.MustParseAddr(s)) {
			t.Errorf("%s judged public", s)
		}
	}
}

// receiver is a callback endpoint that answers the verification handshake
// and records every delivery.
type receiver struct {
	srv     *httptest.Server
	mu      sync.Mutex
	got     []delivered
	fail    atomic.Int32 // answer this many deliveries with 503 first
	status  atomic.Int32 // answer deliveries with this status when set
	badEcho atomic.Bool
}

type delivered struct {
	header http.Header
	body   []byte
	at     time.Time
}

func newReceiver(t *testing.T) *receiver {
	r := &receiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.got = append(r.got, delivered{req.Header.Clone(), b, time.Now()})
		r.mu.Unlock()
		var v map[string]any
		_ = json.Unmarshal(b, &v)
		if v["type"] == "verification" {
			c := v["challenge"]
			if r.badEcho.Load() {
				c = "not-the-nonce"
			}
			json.NewEncoder(w).Encode(map[string]any{"challenge": c})
			return
		}
		if r.fail.Load() > 0 {
			r.fail.Add(-1)
			w.WriteHeader(503)
			return
		}
		if s := r.status.Load(); s != 0 {
			w.WriteHeader(int(s))
			return
		}
		w.WriteHeader(204)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *receiver) all() []delivered {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]delivered(nil), r.got...)
}

// events are the deliveries that aren't control envelopes.
func (r *receiver) events() []delivered {
	var out []delivered
	for _, d := range r.all() {
		var v map[string]any
		_ = json.Unmarshal(d.body, &v)
		if v["type"] == nil {
			out = append(out, d)
		}
	}
	return out
}

func (r *receiver) waitFor(t *testing.T, what string, f func([]delivered) bool) []delivered {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := r.all(); f(got) {
			return got
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; got %d deliveries", what, len(r.all()))
	return nil
}

func secret() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return "whsec_" + base64.StdEncoding.EncodeToString(b)
}

func subscribe(m *apptest.MCP, url, secret string, extra map[string]any) (map[string]any, *apptest.RPCError) {
	p := map[string]any{"name": "webhook.received", "arguments": map[string]any{"channel": "ci"}, "delivery": map[string]any{"mode": "webhook", "url": url, "secret": secret}, "cursor": nil}
	for k, v := range extra {
		p[k] = v
	}
	return m.Try("events/subscribe", p)
}

// The webhook mode end to end: the endpoint is verified first, with the
// challenge signed and carrying the subscription id; events arrive in
// order, each signed by the Standard Webhooks scheme and verified here
// independently; a refresh keeps the id and reports delivery status.
func TestWebhookDelivery(t *testing.T) {
	s := apptest.Start(t, apptest.AllowPrivate())
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	rcv := newReceiver(t)
	cb := rcv.srv.URL + "/hooks/abc"
	sec := secret()
	res, err := subscribe(m, cb, sec, map[string]any{"ttlMs": 3600000})
	if err != nil {
		t.Fatal(err)
	}
	id := res["id"].(string)
	rb, _ := time.Parse(time.RFC3339, res["refreshBefore"].(string))
	if !strings.HasPrefix(id, "sub_") || res["resultType"] != "complete" || res["truncated"] != false || res["cursor"] == nil || time.Until(rb) > time.Hour+time.Minute || time.Until(rb) < 59*time.Minute {
		t.Fatalf("subscribe = %v", res)
	}
	all := rcv.all()
	if len(all) != 1 {
		t.Fatalf("before any event the endpoint got %d POSTs, want only the verification", len(all))
	}
	v := all[0]
	var vb map[string]any
	_ = json.Unmarshal(v.body, &vb)
	if vb["type"] != "verification" || vb["challenge"] == "" || v.header.Get("X-MCP-Subscription-Id") != id || !verify(sec, v.header, v.body) || !strings.HasPrefix(v.header.Get("webhook-id"), "msg_verification_") {
		t.Fatalf("verification POST: %v %s", v.header, v.body)
	}
	var sent []string
	for i := 0; i < 3; i++ {
		sent = append(sent, apptest.Send(t, url, key, `{"n":`+strconv.Itoa(i)+`}`))
	}
	got := rcv.waitFor(t, "3 events", func(d []delivered) bool { return len(d) >= 4 })
	ids := map[string]bool{}
	for i, d := range got[1:] {
		var o map[string]any
		_ = json.Unmarshal(d.body, &o)
		if o["eventId"] != sent[i] || o["name"] != "webhook.received" || o["cursor"] == nil || o["timestamp"] == nil {
			t.Errorf("delivery %d = %s", i, d.body)
		}
		if !verify(sec, d.header, d.body) {
			t.Errorf("delivery %d fails Standard Webhooks verification: %v", i, d.header)
		}
		if d.header.Get("Content-Type") != "application/json" || d.header.Get("X-MCP-Subscription-Id") != id {
			t.Errorf("delivery %d headers = %v", i, d.header)
		}
		ts, _ := strconv.ParseInt(d.header.Get("webhook-timestamp"), 10, 64)
		if time.Since(time.Unix(ts, 0)) > time.Minute {
			t.Errorf("stale webhook-timestamp %d", ts)
		}
		wid := d.header.Get("webhook-id")
		if ids[wid] || wid == o["eventId"] {
			t.Errorf("webhook-id %q is reused or is the eventId", wid)
		}
		ids[wid] = true
	}
	// a refresh with a new secret: same id, delivery status, dual signing
	sec2 := "whsec_" + base64.StdEncoding.EncodeToString([]byte("another-secret-of-32-bytes-long!"))
	res2, err := subscribe(m, cb, sec2, nil)
	if err != nil {
		t.Fatal(err)
	}
	ds, _ := res2["deliveryStatus"].(map[string]any)
	if res2["id"] != id || ds["active"] != true || ds["lastDeliveryAt"] == nil || ds["lastError"] != nil {
		t.Fatalf("refresh = %v", res2)
	}
	if len(rcv.all()) != 4 {
		t.Error("a refresh sent another verification")
	}
	apptest.Send(t, url, key, `{"after":"rotation"}`)
	got = rcv.waitFor(t, "the post-rotation event", func(d []delivered) bool { return len(d) >= 5 })
	last := got[4]
	if !verify(sec2, last.header, last.body) || !verify(sec, last.header, last.body) {
		t.Errorf("after rotation the delivery isn't signed with both secrets: %s", last.header.Get("webhook-signature"))
	}
	// unsubscribe stops deliveries and is then NotFound
	if _, err := m.Try("events/unsubscribe", map[string]any{"name": "webhook.received", "arguments": map[string]any{"channel": "ci"}, "delivery": map[string]any{"url": cb}}); err != nil {
		t.Fatal(err)
	}
	apptest.Send(t, url, key, `{"after":"unsubscribe"}`)
	time.Sleep(300 * time.Millisecond)
	if n := len(rcv.all()); n != 5 {
		t.Errorf("deliveries after unsubscribe: %d", n-5)
	}
	if _, err := m.Try("events/unsubscribe", map[string]any{"name": "webhook.received", "arguments": map[string]any{"channel": "ci"}, "delivery": map[string]any{"url": cb}}); err == nil || err.Code != -32023 {
		t.Errorf("second unsubscribe: %v", err)
	}
}

func TestSubscribeRejects(t *testing.T) {
	s := apptest.Start(t, apptest.AllowPrivate())
	m := s.NewAgent("agent")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	rcv := newReceiver(t)
	cases := []struct {
		name   string
		url    string
		secret string
		extra  map[string]any
		code   int
	}{
		{"short secret", rcv.srv.URL, "whsec_" + base64.StdEncoding.EncodeToString(make([]byte, 8)), nil, -32602},
		{"not a whsec secret", rcv.srv.URL, "not-a-standard-webhooks-secret", nil, -32602},
		{"no secret", rcv.srv.URL, "", nil, -32602},
		{"relative url", "/hooks", secret(), nil, -32602},
		{"other delivery mode", rcv.srv.URL, secret(), map[string]any{"delivery": map[string]any{"mode": "push", "url": rcv.srv.URL, "secret": secret()}}, -32026},
		{"bad ttl", rcv.srv.URL, secret(), map[string]any{"ttlMs": "soon"}, -32602},
	}
	for _, tc := range cases {
		if _, err := subscribe(m, tc.url, tc.secret, tc.extra); err == nil || err.Code != tc.code {
			t.Errorf("%s: %v, want %d", tc.name, err, tc.code)
		}
	}
	// an endpoint that doesn't echo the challenge: CallbackEndpointError,
	// with a category and nothing the endpoint said
	rcv.badEcho.Store(true)
	_, err := subscribe(m, rcv.srv.URL+"/x", secret(), nil)
	if err == nil || err.Code != -32027 || err.Data["reason"] != "challenge_failed" || strings.Contains(err.Message, "not-the-nonce") {
		t.Fatalf("bad echo: %v", err)
	}
	// TTL suggestions are clamped, never refused
	rcv.badEcho.Store(false)
	for _, ttl := range []any{1000, 30 * 24 * 3600 * 1000, nil} {
		res, err := subscribe(m, rcv.srv.URL+"/ttl", secret(), map[string]any{"ttlMs": ttl})
		if err != nil || res["refreshBefore"] == nil {
			t.Errorf("ttlMs %v: %v %v", ttl, res, err)
		}
	}
	// the key includes the URL: another URL is another subscription
	a, _ := subscribe(m, rcv.srv.URL+"/a", secret(), nil)
	b, _ := subscribe(m, rcv.srv.URL+"/b", secret(), nil)
	if a["id"] == b["id"] {
		t.Error("two URLs share a subscription id")
	}
	// and the principal: another identity subscribing the same URL gets
	// another subscription, and unsubscribing doesn't touch the first
	other := s.NewAgent("other")
	other.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	c, _ := subscribe(other, rcv.srv.URL+"/a", secret(), nil)
	if c["id"] == a["id"] {
		t.Error("two identities share a subscription id")
	}
	if _, err := other.Try("events/unsubscribe", map[string]any{"name": "webhook.received", "arguments": map[string]any{"channel": "ci"}, "delivery": map[string]any{"url": rcv.srv.URL + "/a"}}); err != nil {
		t.Fatal(err)
	}
	if sub, err := s.App.Store.GetSubscription(context.Background(), a["id"].(string)); err != nil || sub.Status != store.SubActive {
		t.Errorf("the first identity's subscription after the other's unsubscribe: %v %v", sub.Status, err)
	}
}

// Retries keep the webhook-id and sign afresh; 410 and 413 aren't retried
// and leave the subscription alone.
func TestRetriesAndNonRetryable(t *testing.T) {
	s := apptest.Start(t, apptest.AllowPrivate())
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	rcv := newReceiver(t)
	sec := secret()
	if _, err := subscribe(m, rcv.srv.URL, sec, nil); err != nil {
		t.Fatal(err)
	}
	rcv.fail.Store(2)
	apptest.Send(t, url, key, `{"flaky":1}`)
	got := rcv.waitFor(t, "a delivery after two failures", func(d []delivered) bool { return len(d) >= 4 })
	attempts := got[1:4]
	wid := attempts[0].header.Get("webhook-id")
	for i, a := range attempts {
		if a.header.Get("webhook-id") != wid || !verify(sec, a.header, a.body) {
			t.Errorf("attempt %d: webhook-id %q (want %q), verified %v", i, a.header.Get("webhook-id"), wid, verify(sec, a.header, a.body))
		}
	}
	if attempts[0].header.Get("webhook-signature") == attempts[2].header.Get("webhook-signature") && attempts[0].header.Get("webhook-timestamp") == attempts[2].header.Get("webhook-timestamp") && attempts[2].at.Sub(attempts[0].at) > 1100*time.Millisecond {
		t.Error("a retry reused its timestamp and signature")
	}
	// 410: one attempt, and the subscription goes on
	rcv.status.Store(410)
	apptest.Send(t, url, key, `{"gone":1}`)
	rcv.waitFor(t, "the 410 attempt", func(d []delivered) bool { return len(d) >= 5 })
	time.Sleep(500 * time.Millisecond)
	if n := len(rcv.all()); n != 5 {
		t.Fatalf("a 410 was retried: %d deliveries", n)
	}
	rcv.status.Store(0)
	apptest.Send(t, url, key, `{"after":"410"}`)
	rcv.waitFor(t, "a delivery after the 410", func(d []delivered) bool { return len(d) >= 6 })
	// a dead endpoint: retries end, the subscription reports it
	rcv.status.Store(500)
	apptest.Send(t, url, key, `{"dead":1}`)
	rcv.waitFor(t, "all attempts", func(d []delivered) bool { return len(d) >= 9 })
	time.Sleep(400 * time.Millisecond)
	if n := len(rcv.all()); n != 9 {
		t.Errorf("attempts for one event against a dead endpoint: %d, want 3", n-6)
	}
	res, err := subscribe(m, rcv.srv.URL, sec, nil)
	if err != nil {
		t.Fatal(err)
	}
	ds := res["deliveryStatus"].(map[string]any)
	if ds["lastError"] != "http_5xx" || ds["failedSince"] == nil {
		t.Errorf("deliveryStatus after failures = %v", ds)
	}
}

// Deleting the channel ends the subscription with a signed terminated
// envelope; the channel filter applies to deliveries, and broadcasts pass.
func TestTerminatedAndFilter(t *testing.T) {
	s := apptest.Start(t, apptest.AllowPrivate())
	m := s.NewAgent("agent")
	gh, ghKey := m.Webhook("gh")
	other, otherKey := m.Webhook("other")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "include", "identifiers": []any{"gh"}})
	rcv := newReceiver(t)
	sec := secret()
	res, err := subscribe(m, rcv.srv.URL, sec, nil)
	if err != nil {
		t.Fatal(err)
	}
	apptest.Send(t, other, otherKey, `{"filtered":1}`)
	want := apptest.Send(t, gh, ghKey, `{"kept":1}`)
	b := s.Browser()
	b.SignIn()
	b.Do("POST", "/api/broadcast", map[string]any{"message": "hello all"})
	got := rcv.waitFor(t, "two deliveries", func(d []delivered) bool { return len(d) >= 3 })
	var o1, o2 map[string]any
	_ = json.Unmarshal(got[1].body, &o1)
	_ = json.Unmarshal(got[2].body, &o2)
	if o1["eventId"] != want || o2["data"].(map[string]any)["identifier"] != ":system" {
		t.Fatalf("deliveries = %s / %s", got[1].body, got[2].body)
	}
	m.Tool("channel_delete", map[string]any{"name": "ci"})
	got = rcv.waitFor(t, "the terminated envelope", func(d []delivered) bool { return len(d) >= 4 })
	var env map[string]any
	_ = json.Unmarshal(got[3].body, &env)
	e := env["error"].(map[string]any)
	if env["type"] != "terminated" || e["code"] != float64(-32023) || !verify(sec, got[3].header, got[3].body) || got[3].header.Get("X-MCP-Subscription-Id") != res["id"] || !strings.HasPrefix(got[3].header.Get("webhook-id"), "msg_terminated_") {
		t.Fatalf("terminated envelope = %s %v", got[3].body, got[3].header)
	}
	sub, _ := s.App.Store.GetSubscription(context.Background(), res["id"].(string))
	if sub.Status != store.SubTerminated {
		t.Errorf("status after channel delete = %s", sub.Status)
	}
}

// staticResolver answers every lookup with fixed addresses.
type staticResolver struct {
	mu    sync.Mutex
	addrs []netip.Addr
	calls int
}

func (r *staticResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	return r.addrs, nil
}

func (r *staticResolver) set(a ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addrs = nil
	for _, s := range a {
		r.addrs = append(r.addrs, netip.MustParseAddr(s))
	}
}

// canary records whether anything connected to it.
func canary(t *testing.T) (port string, hits *atomic.Int32) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hits = &atomic.Int32{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			hits.Add(1)
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, hits
}

// Without MWE_ALLOW_PRIVATE_CALLBACKS, a callback that is http, or names or
// resolves to a non-public address, is refused before anything connects.
func TestSSRFAtSubscribe(t *testing.T) {
	res := &staticResolver{}
	s := apptest.Start(t, apptest.WithResolver(res))
	m := s.NewAgent("agent")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	port, hits := canary(t)
	res.set("10.0.0.7")
	for _, u := range []string{"https://127.0.0.1:" + port + "/x", "https://[::1]:" + port + "/x", "https://internal.example:" + port + "/x", "http://example.com/x", "https://169.254.169.254/latest"} {
		if _, err := subscribe(m, u, secret(), nil); err == nil || err.Code != -32602 {
			t.Errorf("subscribe %s: %v, want -32602", u, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("the server connected to the canary %d times", hits.Load())
	}
}

// DNS rebinding: a host that resolved to a public address when the
// subscription was made, and to a loopback one at delivery, is refused at
// connection time, and nothing reaches the loopback endpoint.
func TestSSRFAtDeliveryTime(t *testing.T) {
	res := &staticResolver{}
	s := apptest.Start(t, apptest.WithResolver(res))
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	port, hits := canary(t)
	ctx := context.Background()
	ch, err := s.App.Store.GetChannelByName(ctx, m.IdentityID, "ci")
	if err != nil {
		t.Fatal(err)
	}
	// a subscription made while rebind.example looked public (as if
	// verified then), stored directly
	head, _ := s.App.Store.Head(ctx)
	cb := "https://rebind.example:" + port + "/hook"
	id := delivery.SubscriptionID(m.IdentityID, cb, events.Name, `{"channel":"ci"}`)
	if err := s.App.Store.PutSubscription(ctx, store.Subscription{
		ID: id, IdentityID: m.IdentityID, EventName: events.Name, Arguments: `{"channel":"ci"}`, ChannelID: ch.ID, ChannelName: "ci",
		URL: cb, Secret: secret(), ExpiresAt: time.Now().Add(time.Hour), Delivery: store.Delivery{Cursor: head},
	}); err != nil {
		t.Fatal(err)
	}
	res.set("127.0.0.1")
	apptest.Send(t, url, key, `{"x":1}`)
	deadline := time.Now().Add(3 * time.Second)
	var sub store.Subscription
	for time.Now().Before(deadline) {
		sub, _ = s.App.Store.GetSubscription(ctx, id)
		if sub.LastError != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if sub.LastError != "connection_refused" || sub.Status != store.SubFailing {
		t.Fatalf("after a rebound delivery: status %s, last error %q", sub.Status, sub.LastError)
	}
	if hits.Load() != 0 {
		t.Fatalf("the delivery reached the loopback endpoint %d times", hits.Load())
	}
	// and the guard's own client never follows a redirect
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("the redirect was followed") }))
	defer target.Close()
	redir := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer redir.Close()
	resp, err := (&delivery.Guard{AllowPrivate: true}).Client(time.Second).Post(redir.URL, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("redirect answered %d", resp.StatusCode)
	}
}

// An origin on MWE_CALLBACK_ALLOWLIST is verified by configuration: the
// subscribe needs no handshake (nor a resolvable host at subscribe time),
// while one off the list still has to pass it; the SSRF check still
// guards every delivery connection.
func TestCallbackAllowlist(t *testing.T) {
	res := &staticResolver{}
	s := apptest.Start(t, apptest.WithResolver(res), apptest.WithConfig(func(c *config.Config) {
		c.CallbackAllowlist = []string{"https://trusted.example"}
	}))
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	res.set("127.0.0.1") // whatever it resolves to, the guard refuses at delivery
	sub, err := subscribe(m, "https://trusted.example/hook", secret(), nil)
	if err != nil {
		t.Fatalf("allowlisted subscribe: %v", err)
	}
	if calls := func() int { res.mu.Lock(); defer res.mu.Unlock(); return res.calls }(); calls != 0 {
		t.Errorf("the allowlisted subscribe resolved the host %d times", calls)
	}
	if _, err := subscribe(m, "https://untrusted.example/hook", secret(), nil); err == nil {
		t.Error("an origin off the allowlist skipped verification")
	}
	apptest.Send(t, url, key, `{}`)
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		got, _ := s.App.Store.GetSubscription(context.Background(), sub["id"].(string))
		if got.LastError == "connection_refused" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the delivery to an allowlisted host that resolves to loopback wasn't refused")
}
