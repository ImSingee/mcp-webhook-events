package delivery

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/events"
	"github.com/ImSingee/mcp-webhook-events/internal/idgen"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
)

// TTL limits for granted subscriptions. A suggestion below MinTTL is
// clamped up to it; one above MaxTTL, or a request for no expiry, gets
// MaxTTL: the server grants no unbounded subscriptions.
const (
	DefaultTTL = 24 * time.Hour
	MinTTL     = time.Minute
	MaxTTL     = 7 * 24 * time.Hour
	// MaxPerIdentity caps an identity's live subscriptions.
	MaxPerIdentity = 100
	// verifiedFor is how long a verified (identity, url) skips the
	// handshake on a fresh subscribe.
	verifiedFor = 24 * time.Hour
)

// Error is a subscribe failure with its SEP-3415 error code and data.
type Error struct {
	Code    int
	Message string
	Data    map[string]any
}

func (e *Error) Error() string { return e.Message }

// SubscribeRequest is one events/subscribe call, after its static checks.
type SubscribeRequest struct {
	IdentityID string
	FamilyID   string
	ClientID   string
	Channel    store.Channel
	Arguments  json.RawMessage // as the client sent them
	URL        string
	Secret     string
	Cursor     *string
	MaxAgeMs   *int64
	// TTL is the client's suggestion: nil for the server's default,
	// NoExpiry for ttlMs: null.
	TTL      *time.Duration
	NoExpiry bool
}

// SubscribeResult is events/subscribe's result fields.
type SubscribeResult struct {
	ID             string
	RefreshBefore  time.Time
	Cursor         int64
	Truncated      bool
	DeliveryStatus map[string]any // nil on a fresh subscription
}

// Canonical is arguments as canonical JSON (object keys sorted, no
// whitespace), how the subscription key compares them.
func Canonical(args json.RawMessage) (string, error) {
	if len(bytes.TrimSpace(args)) == 0 {
		return "{}", nil
	}
	d := json.NewDecoder(bytes.NewReader(args))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return "", err
	}
	b, err := json.Marshal(v)
	return string(b), err
}

// SubscriptionID derives a subscription's id from its key (identity,
// callback URL, event name, canonical arguments), stable across refreshes
// and restarts.
func SubscriptionID(identityID, callback, name, canonicalArgs string) string {
	h := sha256.New()
	for _, p := range []string{identityID, callback, name, canonicalArgs} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return "sub_" + hex.EncodeToString(h.Sum(nil))[:24]
}

// grant is the TTL granted for a request.
func grant(r SubscribeRequest) time.Duration {
	if r.NoExpiry {
		return MaxTTL
	}
	if r.TTL == nil {
		return DefaultTTL
	}
	d := *r.TTL
	if d < MinTTL {
		return MinTTL
	}
	if d > MaxTTL {
		return MaxTTL
	}
	return d
}

func live(s store.Subscription, now time.Time) bool {
	return (s.Status == store.SubActive || s.Status == store.SubFailing) && now.Before(s.ExpiresAt)
}

// Subscribe creates or refreshes a webhook-mode subscription. A fresh one
// (no live subscription under the key) has its endpoint verified first,
// unless the identity verified that URL recently, and starts from the
// client's cursor; a refresh renews the TTL and secret, resumes suspended
// delivery, and reports the delivery status, keeping its own position.
func (w *Worker) Subscribe(ctx context.Context, r SubscribeRequest) (SubscribeResult, error) {
	canon, err := Canonical(r.Arguments)
	if err != nil {
		return SubscribeResult{}, &Error{Code: -32602, Message: "arguments must be a JSON object"}
	}
	id := SubscriptionID(r.IdentityID, r.URL, events.Name, canon)
	now := w.Store.Now()
	expires := now.Add(grant(r))
	cur, err := w.Store.GetSubscription(ctx, id)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return SubscribeResult{}, err
	}
	if err == nil && live(cur, now) {
		status := map[string]any{
			"active":         !cur.Suspended,
			"lastDeliveryAt": stampOrNil(cur.LastDeliveryAt),
			"lastError":      strOrNil(cur.LastError),
		}
		if cur.FailedSince != nil {
			status["failedSince"] = events.Stamp(*cur.FailedSince)
		}
		if err := w.Store.RefreshSubscription(ctx, id, r.Secret, now.Add(w.RotationGrace), expires, r.FamilyID, r.ClientID); err != nil {
			return SubscribeResult{}, err
		}
		w.Kick()
		return SubscribeResult{ID: id, RefreshBefore: expires, Cursor: cur.Cursor, DeliveryStatus: status}, nil
	}
	n, err := w.liveCount(ctx, r.IdentityID)
	if err != nil {
		return SubscribeResult{}, err
	}
	if n >= MaxPerIdentity {
		return SubscribeResult{}, &Error{Code: events.CodeResourceExhausted, Message: "ResourceExhausted", Data: map[string]any{"limit": "subscriptions", "max": MaxPerIdentity}}
	}
	start, err := events.Resolve(ctx, w.Store, events.FilterOf(r.Channel), r.Cursor, r.MaxAgeMs)
	if errors.Is(err, events.ErrBadCursor) {
		return SubscribeResult{}, &Error{Code: -32602, Message: "Invalid params: " + err.Error()}
	}
	if err != nil {
		return SubscribeResult{}, err
	}
	ok, err := w.Store.Verified(ctx, r.IdentityID, r.URL, now.Add(-verifiedFor))
	if err != nil {
		return SubscribeResult{}, err
	}
	// an allowlisted URL is verified by configuration (SEP-3415's second
	// way to confirm an endpoint's intent): no handshake
	ok = ok || (w.Allowlisted != nil && w.Allowlisted(r.URL))
	if !ok {
		if reason, err := w.Verify(ctx, r.URL, id, r.Secret); err != nil {
			return SubscribeResult{}, err
		} else if reason != "" {
			return SubscribeResult{}, &Error{Code: events.CodeCallbackEndpointError, Message: "CallbackEndpointError", Data: map[string]any{"reason": reason}}
		}
		if err := w.Store.MarkVerified(ctx, r.IdentityID, r.URL); err != nil {
			return SubscribeResult{}, err
		}
	}
	sub := store.Subscription{
		ID: id, IdentityID: r.IdentityID, FamilyID: r.FamilyID, ClientID: r.ClientID, EventName: events.Name, Arguments: canon,
		ChannelID: r.Channel.ID, ChannelName: r.Channel.Name, URL: r.URL, Secret: r.Secret, ExpiresAt: expires,
		Delivery: store.Delivery{Cursor: start.Seq},
	}
	if err := w.Store.PutSubscription(ctx, sub); err != nil {
		return SubscribeResult{}, err
	}
	w.Kick()
	return SubscribeResult{ID: id, RefreshBefore: expires, Cursor: start.Seq, Truncated: start.Truncated}, nil
}

func (w *Worker) liveCount(ctx context.Context, identityID string) (int, error) {
	subs, err := w.Store.SubscriptionsWhere(ctx, "", identityID, "")
	if err != nil {
		return 0, err
	}
	now, n := w.Store.Now(), 0
	for _, s := range subs {
		if live(s, now) {
			n++
		}
	}
	return n, nil
}

// Unsubscribe deletes the live subscription under a key; ErrNotFound when
// there is none.
func (w *Worker) Unsubscribe(ctx context.Context, identityID, callback string, args json.RawMessage) error {
	canon, err := Canonical(args)
	if err != nil {
		return &Error{Code: -32602, Message: "arguments must be a JSON object"}
	}
	id := SubscriptionID(identityID, callback, events.Name, canon)
	cur, err := w.Store.GetSubscription(ctx, id)
	if err != nil {
		return err
	}
	if !live(cur, w.Store.Now()) {
		return store.ErrNotFound
	}
	return w.Store.DeleteSubscription(ctx, identityID, id)
}

// Verify runs the verification handshake: a signed verification envelope
// whose challenge the endpoint must echo in a 2xx JSON body. It returns
// the failure's lastError category, "" when the endpoint proved intent.
func (w *Worker) Verify(ctx context.Context, callback, subID, secret string) (string, error) {
	u, err := url.Parse(callback)
	if err != nil {
		return "", err
	}
	if !w.allowVerification(u.Hostname()) {
		return "", &Error{Code: events.CodeResourceExhausted, Message: "ResourceExhausted", Data: map[string]any{"limit": "verifications", "max": verificationsPerMinute}}
	}
	challenge := idgen.Secret("")
	body, _ := json.Marshal(map[string]any{"type": "verification", "challenge": challenge})
	var resp []byte
	status, err := w.send(ctx, callback, subID, []string{secret}, msgID("verification"), body, &resp)
	if err != nil || status < 200 || status >= 300 {
		return Category(status, err), nil
	}
	var echo struct {
		Challenge string `json:"challenge"`
	}
	if json.Unmarshal(resp, &echo) != nil || !idgen.Equal(echo.Challenge, challenge) {
		return "challenge_failed", nil
	}
	return "", nil
}

const verificationsPerMinute = 10

// allowVerification rate-limits verification POSTs per destination host.
func (w *Worker) allowVerification(host string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	recent := w.limiter[host][:0]
	for _, t := range w.limiter[host] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= verificationsPerMinute {
		w.limiter[host] = recent
		return false
	}
	w.limiter[host] = append(recent, now)
	return true
}

func stampOrNil(t *time.Time) any {
	if t == nil {
		return nil
	}
	return events.Stamp(*t)
}

func strOrNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}
