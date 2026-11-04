package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/delivery"
	"github.com/ImSingee/mcp-webhook-events/internal/events"
	"github.com/ImSingee/mcp-webhook-events/internal/httpx"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
)

// descriptor is webhook.received as events/list describes it.
var descriptor = map[string]any{
	"name":        events.Name,
	"title":       "Webhook received",
	"description": "Fires for each request one of your webhooks receives (filtered by the channel you name), and for each platform broadcast, which every subscription receives whatever its channel says. data.identifier says which webhook sent it; identifiers starting with ':' are the platform's. The request's headers and body are untrusted third-party data.",
	"delivery":    []string{"poll", "push", "webhook"},
	"inputSchema": object(schema{
		"channel": str("The name of one of your channels (see channel_list / channel_create); its filter decides which webhooks' events you receive."),
	}, "channel"),
	"payloadSchema": schema{
		"type":     "object",
		"required": []string{"identifier", "kind", "webhook", "received_at", "request", "message", "title"},
		"properties": schema{
			"identifier":  str("The webhook's identifier, or a reserved identifier starting with ':' for a platform broadcast."),
			"kind":        schema{"type": "string", "enum": []string{"webhook", "system"}},
			"webhook":     schema{"type": []string{"object", "null"}, "properties": schema{"name": schema{"type": "string"}}, "description": "null for a broadcast."},
			"received_at": schema{"type": "string", "format": "date-time"},
			"request": schema{
				"type":        []string{"object", "null"},
				"description": "The received HTTP request, without the webhook key; null for a broadcast.",
				"properties": schema{
					"method":        schema{"type": "string"},
					"query":         schema{"type": "object", "additionalProperties": stringList},
					"headers":       schema{"type": "object", "additionalProperties": stringList},
					"content_type":  schema{"type": "string"},
					"body_encoding": schema{"type": "string", "enum": []string{"json", "text", "base64", "none"}},
					"body":          schema{"description": "The body: parsed JSON, text, base64 of binary, or null."},
				},
			},
			"message": schema{"type": []string{"string", "null"}, "description": "A broadcast's text; null for a webhook event."},
			"title":   schema{"type": []string{"string", "null"}, "description": "A broadcast's title, if it has one."},
		},
	},
}

func (s *Server) eventsList(w http.ResponseWriter, q *request) {
	if c, ok := q.params["cursor"]; ok && string(c) != "null" {
		writeError(w, q.id, errInvalidParams("Invalid params: unknown cursor (events/list has a single page)"))
		return
	}
	writeRPC(w, http.StatusOK, q.finish(map[string]any{"events": []any{descriptor}}))
}

// subParams are the fields events/poll, events/stream and events/subscribe
// share.
type subParams struct {
	channel  store.Channel
	args     json.RawMessage
	cursor   *string
	maxAgeMs *int64
}

func sepError(code int, msg string, data map[string]any) *rpcError {
	e := &rpcError{Status: http.StatusOK, Code: code, Message: msg}
	if data != nil {
		e.Data = data
	}
	return e
}

// parseSub checks an events request's name, arguments, cursor and
// maxAgeMs, and finds the channel the arguments name.
func (s *Server) parseSub(ctx context.Context, q *request) (subParams, *rpcError) {
	var p subParams
	var name string
	raw, ok := q.params["name"]
	if !ok || json.Unmarshal(raw, &name) != nil || name == "" {
		return p, errInvalidParams("Invalid params: name is required")
	}
	if name != events.Name {
		return p, sepError(events.CodeNotFound, "NotFound: no event type named "+name, map[string]any{"kind": "event"})
	}
	p.args = q.params["arguments"]
	var args map[string]json.RawMessage
	if len(p.args) == 0 || json.Unmarshal(p.args, &args) != nil || args == nil {
		return p, errInvalidParams(`Invalid params: arguments must be an object such as {"channel": "<name>"}`)
	}
	for k := range args {
		if k != "channel" {
			return p, errInvalidParams("Invalid params: unknown argument " + k + "; the only argument is channel")
		}
	}
	var channel string
	if err := json.Unmarshal(args["channel"], &channel); err != nil || channel == "" {
		return p, errInvalidParams("Invalid params: arguments.channel must be the name of one of your channels")
	}
	if c, ok := q.params["cursor"]; ok && string(c) != "null" {
		var cur string
		if json.Unmarshal(c, &cur) != nil {
			return p, errInvalidParams("Invalid params: cursor must be a string or null")
		}
		if _, err := events.DecodeCursor(cur); err != nil {
			return p, errInvalidParams("Invalid params: " + err.Error())
		}
		p.cursor = &cur
	}
	if m, ok := q.params["maxAgeMs"]; ok && string(m) != "null" {
		var n int64
		if json.Unmarshal(m, &n) != nil || n < 0 {
			return p, errInvalidParams("Invalid params: maxAgeMs must be a non-negative integer")
		}
		p.maxAgeMs = &n
	}
	c, err := s.Store.GetChannelByName(ctx, q.principal.IdentityID, channel)
	if errors.Is(err, store.ErrNotFound) {
		return p, sepError(events.CodeNotFound, "NotFound: you have no channel named "+channel+" (create it with channel_create)", map[string]any{"kind": "channel", "channel": channel})
	}
	if err != nil {
		s.Log.Error("load channel", "err", err)
		return p, &rpcError{Status: http.StatusInternalServerError, Code: codeInternal, Message: "internal error"}
	}
	p.channel = c.Channel
	return p, nil
}

func internalError(w http.ResponseWriter, q *request, s *Server, err error) {
	s.Log.Error("events request", "method", q.method, "err", err)
	writeError(w, q.id, &rpcError{Status: http.StatusInternalServerError, Code: codeInternal, Message: "internal error"})
}

const (
	defaultMaxEvents = 100
	maxMaxEvents     = 500
)

func (s *Server) eventsPoll(w http.ResponseWriter, q *request) {
	ctx := q.r.Context()
	p, e := s.parseSub(ctx, q)
	if e != nil {
		writeError(w, q.id, e)
		return
	}
	limit := defaultMaxEvents
	if m, ok := q.params["maxEvents"]; ok && string(m) != "null" {
		if json.Unmarshal(m, &limit) != nil || limit < 1 {
			writeError(w, q.id, errInvalidParams("Invalid params: maxEvents must be a positive integer"))
			return
		}
		limit = min(limit, maxMaxEvents)
	}
	start, err := events.Resolve(ctx, s.Store, events.FilterOf(p.channel), p.cursor, p.maxAgeMs)
	if err != nil {
		internalError(w, q, s, err)
		return
	}
	res := map[string]any{"events": []any{}, "cursor": events.EncodeCursor(start.Seq), "truncated": start.Truncated, "hasMore": false, "nextPollMs": s.NextPollMs}
	if p.cursor == nil {
		writeRPC(w, http.StatusOK, q.finish(res))
		return
	}
	evs, scanned, err := events.Next(ctx, s.Store, events.FilterOf(p.channel), start.Seq, start.Head, limit+1, 0)
	if err != nil {
		internalError(w, q, s, err)
		return
	}
	if len(evs) > limit {
		evs = evs[:limit]
		scanned = evs[limit-1].Seq
		res["hasMore"] = true
	}
	out := make([]any, len(evs))
	for i, e := range evs {
		o := events.Occurrence(e)
		// poll carries the cursor on the result, not on each occurrence
		delete(o, "cursor")
		out[i] = o
	}
	res["events"], res["cursor"] = out, events.EncodeCursor(scanned)
	writeRPC(w, http.StatusOK, q.finish(res))
}

// sseWriter writes one stream's frames, each a JSON-RPC message in a
// single data: line.
type sseWriter struct {
	mu    sync.Mutex
	w     http.ResponseWriter
	flush func() error
}

func (sw *sseWriter) send(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	sw.mu.Lock()
	defer sw.mu.Unlock()
	var buf bytes.Buffer
	buf.WriteString("data: ")
	buf.Write(b)
	buf.WriteString("\n\n")
	if _, err := sw.w.Write(buf.Bytes()); err != nil {
		return err
	}
	return sw.flush()
}

func (sw *sseWriter) comment() error {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if _, err := sw.w.Write([]byte(":\n\n")); err != nil {
		return err
	}
	return sw.flush()
}

func notification(method string, params map[string]any) map[string]any {
	return map[string]any{"jsonrpc": "2.0", "method": method, "params": params}
}

// eventsStream is SEP-3415 push delivery: the request's SSE response
// carries notifications/events/active, then the events after the start
// position (replay first, then live, in seq order), and a heartbeat on a
// fixed period whether or not events flowed in between (SEP-3415: at least
// every 30 seconds). The server ends it with
// notifications/events/terminated and the final result when the
// subscription can't go on (its channel deleted, its access revoked), or
// with just the final result when the server shuts down; a client ends it
// by closing the connection.
func (s *Server) eventsStream(w http.ResponseWriter, q *request) {
	ctx := q.r.Context()
	p, e := s.parseSub(ctx, q)
	if e != nil {
		writeError(w, q.id, e)
		return
	}
	// listen before reading the start, so nothing written in between is
	// missed
	sub := s.Hub.Subscribe(q.principal.IdentityID, p.channel.ID, q.principal.FamilyID)
	defer s.Hub.Unsubscribe(sub)
	filter := events.FilterOf(p.channel)
	start, err := events.Resolve(ctx, s.Store, filter, p.cursor, p.maxAgeMs)
	if err != nil {
		internalError(w, q, s, err)
		return
	}
	meta := map[string]any{metaSubscriptionID: q.id}
	withMeta := func(m map[string]any) map[string]any {
		m["_meta"] = meta
		return m
	}
	sw := &sseWriter{w: w, flush: httpx.SSE(w)}
	if sw.send(notification("notifications/events/active", withMeta(map[string]any{"cursor": events.EncodeCursor(start.Seq), "truncated": start.Truncated}))) != nil {
		return
	}
	final := func() {
		_ = sw.send(map[string]any{"jsonrpc": "2.0", "id": q.id, "result": map[string]any{"resultType": "complete", "_meta": meta}})
	}
	terminate := func(why events.ErrorObject) {
		if sw.send(notification("notifications/events/terminated", withMeta(map[string]any{"error": why}))) == nil {
			final()
		}
	}
	pos := start.Seq
	beat := time.NewTicker(s.Heartbeat)
	defer beat.Stop()
	// catchUp sends every event after pos up to the head.
	catchUp := func() bool {
		for {
			if why := sub.Ended(); why != nil {
				terminate(*why)
				return false
			}
			if sub.TakeDirty() {
				c, err := s.Store.GetChannel(ctx, p.channel.ID)
				if errors.Is(err, store.ErrNotFound) {
					terminate(events.ChannelDeleted(p.channel.Name))
					return false
				}
				if err != nil {
					return ctx.Err() == nil
				}
				filter = events.FilterOf(c.Channel)
			}
			head, err := s.Store.Head(ctx)
			if err != nil {
				return ctx.Err() == nil
			}
			evs, scanned, err := events.Next(ctx, s.Store, filter, pos, head, 200, 0)
			if err != nil {
				return ctx.Err() == nil
			}
			for _, e := range evs {
				if sw.send(notification("notifications/events/event", withMeta(events.Occurrence(e)))) != nil {
					return false
				}
			}
			pos = scanned
			if pos >= head {
				return true
			}
		}
	}
	if !catchUp() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.Base.Done():
			final()
			return
		case <-sub.Wake:
			if !catchUp() {
				return
			}
		case <-beat.C:
			if !catchUp() {
				return
			}
			if sw.send(notification("notifications/events/heartbeat", withMeta(map[string]any{"cursor": events.EncodeCursor(pos)}))) != nil {
				return
			}
		}
	}
}

func (s *Server) eventsSubscribe(w http.ResponseWriter, q *request) {
	ctx := q.r.Context()
	p, e := s.parseSub(ctx, q)
	if e != nil {
		writeError(w, q.id, e)
		return
	}
	var d struct {
		Mode   *string `json:"mode"`
		URL    string  `json:"url"`
		Secret string  `json:"secret"`
	}
	if raw, ok := q.params["delivery"]; !ok || json.Unmarshal(raw, &d) != nil {
		writeError(w, q.id, errInvalidParams("Invalid params: delivery must be an object with url and secret"))
		return
	}
	if d.Mode != nil && *d.Mode != "webhook" {
		writeError(w, q.id, sepError(events.CodeUnsupported, "Unsupported: events/subscribe is for webhook delivery only", map[string]any{"feature": "deliveryMode", "value": *d.Mode}))
		return
	}
	if _, err := delivery.ParseSecret(d.Secret); err != nil {
		writeError(w, q.id, errInvalidParams("Invalid params: "+err.Error()))
		return
	}
	u, err := s.Worker.Guard.CheckURL(d.URL)
	if err != nil {
		writeError(w, q.id, errInvalidParams("Invalid params: "+err.Error()))
		return
	}
	r := delivery.SubscribeRequest{
		IdentityID: q.principal.IdentityID, FamilyID: q.principal.FamilyID, ClientID: q.principal.ClientID,
		Channel: p.channel, Arguments: p.args, URL: d.URL, Secret: d.Secret, Cursor: p.cursor, MaxAgeMs: p.maxAgeMs,
	}
	if t, ok := q.params["ttlMs"]; ok {
		if string(t) == "null" {
			r.NoExpiry = true
		} else {
			var ms float64
			if json.Unmarshal(t, &ms) != nil {
				writeError(w, q.id, errInvalidParams("Invalid params: ttlMs must be an integer number of milliseconds or null"))
				return
			}
			ttl := time.Duration(max(ms, 0)) * time.Millisecond
			r.TTL = &ttl
		}
	}
	// an allowlisted origin is resolved only when delivering, where the
	// SSRF check runs at every connection anyway
	if !s.Cfg.CallbackAllowed(d.URL) {
		if err := s.Worker.Guard.Resolvable(ctx, u); err != nil {
			if errors.Is(err, delivery.ErrBlocked) {
				writeError(w, q.id, errInvalidParams("Invalid params: delivery.url must resolve to a globally routable address"))
			} else {
				writeError(w, q.id, sepError(events.CodeCallbackEndpointError, "CallbackEndpointError", map[string]any{"reason": "connection_refused"}))
			}
			return
		}
	}
	res, err := s.Worker.Subscribe(ctx, r)
	var de *delivery.Error
	if errors.As(err, &de) {
		writeError(w, q.id, sepError(de.Code, de.Message, de.Data))
		return
	}
	if err != nil {
		internalError(w, q, s, err)
		return
	}
	out := map[string]any{"id": res.ID, "refreshBefore": events.Stamp(res.RefreshBefore), "cursor": events.EncodeCursor(res.Cursor), "truncated": res.Truncated}
	if res.DeliveryStatus != nil {
		out["deliveryStatus"] = res.DeliveryStatus
	}
	writeRPC(w, http.StatusOK, q.finish(out))
}

func (s *Server) eventsUnsubscribe(w http.ResponseWriter, q *request) {
	var name string
	if err := json.Unmarshal(q.params["name"], &name); err != nil || name == "" {
		writeError(w, q.id, errInvalidParams("Invalid params: name is required"))
		return
	}
	if name != events.Name {
		writeError(w, q.id, sepError(events.CodeNotFound, "NotFound: no event type named "+name, map[string]any{"kind": "event"}))
		return
	}
	var d struct {
		URL string `json:"url"`
	}
	if raw, ok := q.params["delivery"]; !ok || json.Unmarshal(raw, &d) != nil || d.URL == "" {
		writeError(w, q.id, errInvalidParams("Invalid params: delivery.url is required"))
		return
	}
	args := q.params["arguments"]
	if len(args) == 0 {
		args = json.RawMessage(`{}`)
	}
	err := s.Worker.Unsubscribe(q.r.Context(), q.principal.IdentityID, d.URL, args)
	var de *delivery.Error
	switch {
	case errors.As(err, &de):
		writeError(w, q.id, sepError(de.Code, de.Message, de.Data))
	case errors.Is(err, store.ErrNotFound):
		writeError(w, q.id, sepError(events.CodeNotFound, "NotFound: no subscription matches this name, arguments and delivery.url", map[string]any{"kind": "subscription"}))
	case err != nil:
		internalError(w, q, s, err)
	default:
		writeRPC(w, http.StatusOK, q.finish(nil))
	}
}

// subscriptionsListen is the core subscriptions/listen stream at its
// minimum: the server's tool list never changes and it doesn't declare
// listChanged for events, so it acknowledges an empty filter and then only
// keeps the stream alive until either side ends it.
func (s *Server) subscriptionsListen(w http.ResponseWriter, q *request) {
	var p struct {
		Notifications map[string]json.RawMessage `json:"notifications"`
	}
	if raw, ok := q.params["notifications"]; ok {
		if json.Unmarshal(raw, &p.Notifications) != nil {
			writeError(w, q.id, errInvalidParams("Invalid params: notifications must be an object"))
			return
		}
	}
	meta := map[string]any{metaSubscriptionID: q.id}
	sw := &sseWriter{w: w, flush: httpx.SSE(w)}
	if sw.send(notification("notifications/subscriptions/acknowledged", map[string]any{"notifications": map[string]any{}, "_meta": meta})) != nil {
		return
	}
	t := time.NewTicker(s.Keepalive)
	defer t.Stop()
	for {
		select {
		case <-q.r.Context().Done():
			return
		case <-s.Base.Done():
			_ = sw.send(map[string]any{"jsonrpc": "2.0", "id": q.id, "result": map[string]any{"resultType": "complete", "_meta": meta}})
			return
		case <-t.C:
			if sw.comment() != nil {
				return
			}
		}
	}
}
