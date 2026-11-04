package delivery

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/events"
	"github.com/ImSingee/mcp-webhook-events/internal/idgen"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
	"github.com/ImSingee/mcp-webhook-events/internal/version"
)

// Worker delivers every live webhook-mode subscription's events, one
// subscription at a time per goroutine and one event at a time per
// subscription, so the cursor in each payload is the subscription's
// watermark: everything at or before it is acknowledged or given up on.
type Worker struct {
	Store *store.Store
	Hub   *events.Hub
	Guard *Guard
	Log   *slog.Logger

	// Retries is the wait before each retry of a failed delivery; an
	// event is given up on after the last one fails (SEP-3415: a few
	// attempts within 10 to 15 minutes).
	Retries []time.Duration
	// Timeout bounds one delivery attempt.
	Timeout time.Duration
	// SuspendAfter and SuspendAttempts suspend delivery to a subscription
	// whose deliveries have all failed for that long and that many times,
	// until the client refreshes it.
	SuspendAfter    time.Duration
	SuspendAttempts int
	// Tick is how often due retries are looked for without a wake-up.
	Tick time.Duration
	// RotationGrace is how long the old secret signs too after a refresh
	// replaced it.
	RotationGrace time.Duration
	// Allowlisted reports whether a callback URL is on the operator's
	// allowlist, which stands in for the verification handshake.
	Allowlisted func(url string) bool

	client *http.Client
	base   context.Context

	mu      sync.Mutex
	busy    map[string]bool
	sem     chan struct{}
	limiter map[string][]time.Time // verification POSTs per host, last minute
	wg      sync.WaitGroup
}

// NewWorker is a worker with SEP-3415's suggested retry window.
func NewWorker(st *store.Store, hub *events.Hub, g *Guard, log *slog.Logger) *Worker {
	return &Worker{
		Store: st, Hub: hub, Guard: g, Log: log,
		Retries:         []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute},
		Timeout:         5 * time.Second,
		SuspendAfter:    time.Hour,
		SuspendAttempts: 20,
		Tick:            time.Second,
		RotationGrace:   10 * time.Minute,
		busy:            map[string]bool{},
		sem:             make(chan struct{}, 16),
		limiter:         map[string][]time.Time{},
		base:            context.Background(),
	}
}

func (w *Worker) httpClient() *http.Client {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.client == nil {
		w.client = w.Guard.Client(w.Timeout)
	}
	return w.client
}

// Run delivers until ctx ends, then waits for deliveries in flight.
func (w *Worker) Run(ctx context.Context) {
	w.mu.Lock()
	w.base = ctx
	w.mu.Unlock()
	sub := w.Hub.Subscribe("", "", "")
	defer w.Hub.Unsubscribe(sub)
	t := time.NewTicker(w.Tick)
	defer t.Stop()
	for {
		w.pass(ctx)
		select {
		case <-ctx.Done():
			w.wg.Wait()
			return
		case <-sub.Wake:
		case <-t.C:
		}
	}
}

// Kick asks for a delivery pass now, after a subscribe or refresh.
func (w *Worker) Kick() { w.Hub.Published() }

func (w *Worker) pass(ctx context.Context) {
	subs, err := w.Store.LiveSubscriptions(ctx)
	if err != nil {
		if ctx.Err() == nil {
			w.Log.Error("list webhook subscriptions", "err", err)
		}
		return
	}
	now := w.Store.Now()
	for _, s := range subs {
		if s.NextAttemptAt != nil && now.Before(*s.NextAttemptAt) {
			continue
		}
		w.mu.Lock()
		if w.busy[s.ID] {
			w.mu.Unlock()
			continue
		}
		w.busy[s.ID] = true
		w.mu.Unlock()
		w.wg.Add(1)
		go func(id string) {
			defer w.wg.Done()
			defer func() {
				w.mu.Lock()
				delete(w.busy, id)
				w.mu.Unlock()
			}()
			select {
			case w.sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-w.sem }()
			w.drive(ctx, id)
		}(s.ID)
	}
}

// drive delivers one subscription's events until it has none left or an
// attempt failed and its retry is scheduled.
func (w *Worker) drive(ctx context.Context, id string) {
	for ctx.Err() == nil {
		s, err := w.Store.GetSubscription(ctx, id)
		if err != nil || (s.Status != store.SubActive && s.Status != store.SubFailing) || s.Suspended || !w.Store.Now().Before(s.ExpiresAt) {
			return
		}
		now := w.Store.Now()
		if s.NextAttemptAt != nil && now.Before(*s.NextAttemptAt) {
			return
		}
		if s.PendingSeq == 0 {
			more, err := w.next(ctx, &s)
			if err != nil {
				if ctx.Err() == nil {
					w.Log.Error("read events for a webhook subscription", "sub", id, "err", err)
				}
				return
			}
			if !more {
				return
			}
		}
		if !w.attempt(ctx, &s) {
			return
		}
	}
}

// next picks the subscription's next event to deliver as its pending
// message, sending a gap envelope first when retention dropped events it
// hadn't delivered. It reports whether there is one.
func (w *Worker) next(ctx context.Context, s *store.Subscription) (bool, error) {
	head, err := w.Store.Head(ctx)
	if err != nil {
		return false, err
	}
	pruned, err := w.Store.PrunedThrough(ctx)
	if err != nil {
		return false, err
	}
	if s.Cursor < pruned {
		w.envelope(ctx, *s, "gap", map[string]any{"type": "gap", "cursor": events.EncodeCursor(pruned)})
		s.Cursor = pruned
		if err := w.Store.SaveDelivery(ctx, s.ID, s.Status, s.Delivery); err != nil {
			return false, err
		}
	}
	if s.Cursor >= head {
		return false, nil
	}
	ch, err := w.Store.GetChannel(ctx, s.ChannelID)
	if errors.Is(err, store.ErrNotFound) {
		w.Terminate(ctx, []store.Subscription{*s}, events.ChannelDeleted(s.ChannelName))
		return false, nil
	}
	if err != nil {
		return false, err
	}
	evs, scanned, err := events.Next(ctx, w.Store, events.FilterOf(ch.Channel), s.Cursor, head, 1, 0)
	if err != nil {
		return false, err
	}
	if len(evs) == 0 {
		s.Cursor = scanned
		return false, w.Store.SaveDelivery(ctx, s.ID, s.Status, s.Delivery)
	}
	now := w.Store.Now()
	s.PendingSeq, s.PendingMsgID, s.PendingAttempts, s.PendingSince, s.NextAttemptAt = evs[0].Seq, msgID(""), 0, &now, nil
	return true, w.Store.SaveDelivery(ctx, s.ID, s.Status, s.Delivery)
}

func msgID(kind string) string {
	id := idgen.ID("msg")
	if kind != "" {
		return "msg_" + kind + "_" + strings.TrimPrefix(id, "msg_")
	}
	return id
}

// attempt POSTs the pending event once, and reports whether delivery can
// go straight on to the next one.
func (w *Worker) attempt(ctx context.Context, s *store.Subscription) bool {
	evs, err := w.Store.EventsAfter(ctx, "", s.PendingSeq-1, s.PendingSeq, 1)
	if err != nil {
		return false
	}
	if len(evs) == 0 {
		// pruned or deleted while pending: nothing left to deliver
		s.Cursor, s.PendingSeq, s.PendingMsgID, s.PendingAttempts, s.PendingSince, s.NextAttemptAt = s.PendingSeq, 0, "", 0, nil, nil
		return w.Store.SaveDelivery(ctx, s.ID, s.Status, s.Delivery) == nil
	}
	body, _ := json.Marshal(events.Occurrence(evs[0]))
	status, err := w.post(ctx, *s, s.PendingMsgID, body)
	now := w.Store.Now()
	done := func() {
		s.Cursor, s.PendingSeq, s.PendingMsgID, s.PendingAttempts, s.PendingSince, s.NextAttemptAt = s.PendingSeq, 0, "", 0, nil, nil
	}
	switch {
	case err == nil && status >= 200 && status < 300:
		done()
		s.FailureCount, s.FailedSince, s.LastError, s.LastDeliveryAt = 0, nil, "", &now
		return w.Store.SaveDelivery(ctx, s.ID, store.SubActive, s.Delivery) == nil
	case err == nil && (status == http.StatusGone || status == http.StatusRequestEntityTooLarge):
		// the endpoint refused this one event for good; the subscription
		// itself is fine
		done()
		s.LastError = "http_4xx"
		return w.Store.SaveDelivery(ctx, s.ID, s.Status, s.Delivery) == nil
	}
	if ctx.Err() != nil {
		return false
	}
	s.PendingAttempts++
	s.FailureCount++
	if s.FailedSince == nil {
		s.FailedSince = &now
	}
	s.LastError = Category(status, err)
	st := store.SubFailing
	if s.PendingAttempts > len(w.Retries) {
		w.Log.Warn("gave up on a webhook delivery", "sub", s.ID, "seq", s.PendingSeq, "error", s.LastError)
		done()
	} else {
		next := now.Add(w.Retries[s.PendingAttempts-1])
		s.NextAttemptAt = &next
	}
	if err := w.Store.SaveDelivery(ctx, s.ID, st, s.Delivery); err != nil {
		return false
	}
	if s.FailureCount >= w.SuspendAttempts && now.Sub(*s.FailedSince) >= w.SuspendAfter {
		w.Log.Warn("suspended a failing webhook subscription until it is refreshed", "sub", s.ID)
		_ = w.Store.Suspend(ctx, s.ID)
		return false
	}
	return s.NextAttemptAt == nil
}

// secrets are the secrets a subscription is signed with now: its own, and
// the one it replaced while the rotation grace lasts.
func (w *Worker) secrets(s store.Subscription) []string {
	out := []string{s.Secret}
	if s.PrevSecret != "" && s.PrevSecretUntil != nil && w.Store.Now().Before(*s.PrevSecretUntil) {
		out = append(out, s.PrevSecret)
	}
	return out
}

// post sends one signed delivery and returns the response status.
func (w *Worker) post(ctx context.Context, s store.Subscription, id string, body []byte) (int, error) {
	return w.send(ctx, s.URL, s.ID, w.secrets(s), id, body, nil)
}

// send POSTs body to url with the Standard Webhooks headers and
// X-MCP-Subscription-Id. respBody, when set, receives up to 64 KiB of the
// response.
func (w *Worker) send(ctx context.Context, url, subID string, secrets []string, id string, body []byte, respBody *[]byte) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, w.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	ts := w.Store.Now().Unix()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "mwe-server/"+version.Version)
	req.Header.Set("webhook-id", id)
	req.Header.Set("webhook-timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("webhook-signature", Signature(secrets, id, ts, body))
	req.Header.Set("X-MCP-Subscription-Id", subID)
	resp, err := w.httpClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if respBody != nil {
		*respBody = b
	}
	return resp.StatusCode, nil
}

// Category is a failed delivery's lastError: one of SEP-3415's fixed
// categories, never anything the endpoint said.
func Category(status int, err error) string {
	if err == nil {
		if status >= 500 {
			return "http_5xx"
		}
		return "http_4xx"
	}
	var (
		ne      net.Error
		certErr *tls.CertificateVerificationError
		recErr  tls.RecordHeaderError
		alert   tls.AlertError
	)
	switch {
	case errors.As(err, &certErr), errors.As(err, &recErr), errors.As(err, &alert), strings.Contains(err.Error(), "tls:"), strings.Contains(err.Error(), "x509:"):
		return "tls_error"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timeout"
	case errors.Is(err, syscall.ECONNREFUSED), errors.Is(err, ErrBlocked):
		return "connection_refused"
	}
	return "connection_refused"
}

// envelope POSTs a control envelope (gap or terminated) to a subscription,
// trying a few times; failures are only logged.
func (w *Worker) envelope(ctx context.Context, s store.Subscription, kind string, v any) {
	body, _ := json.Marshal(v)
	id := msgID(kind)
	for i, wait := range []time.Duration{0, time.Second, 5 * time.Second} {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
		}
		status, err := w.post(ctx, s, id, body)
		if err == nil && status >= 200 && status < 300 {
			return
		}
		if err == nil && (status == http.StatusGone || status == http.StatusRequestEntityTooLarge) {
			return
		}
		w.Log.Warn("webhook control envelope failed", "sub", s.ID, "type", kind, "error", Category(status, err))
	}
}

// Terminate ends subscriptions, marking them terminated and POSTing each a
// signed terminated envelope in the background.
func (w *Worker) Terminate(ctx context.Context, subs []store.Subscription, why events.ErrorObject) {
	w.mu.Lock()
	base := w.base
	w.mu.Unlock()
	for _, s := range subs {
		reason, _ := why.Data["reason"].(string)
		if err := w.Store.Terminate(ctx, s.ID, reason); err != nil {
			w.Log.Error("terminate webhook subscription", "sub", s.ID, "err", err)
		}
		w.wg.Add(1)
		go func(s store.Subscription) {
			defer w.wg.Done()
			ctx, cancel := context.WithTimeout(base, time.Minute)
			defer cancel()
			w.envelope(ctx, s, "terminated", map[string]any{"type": "terminated", "error": why})
		}(s)
	}
}

// Wait waits for the background envelopes and deliveries, for tests.
func (w *Worker) Wait() { w.wg.Wait() }
