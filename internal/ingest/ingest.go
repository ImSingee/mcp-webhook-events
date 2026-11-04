// Package ingest is the webhook endpoint, ANY /hooks/{token}: it checks
// the webhook's key, keeps the request (without the key) as an event's
// data, and answers 202 with the event's id.
package ingest

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/textproto"
	"strings"
	"unicode/utf8"

	"github.com/ImSingee/mcp-webhook-events/internal/core"
	"github.com/ImSingee/mcp-webhook-events/internal/events"
	"github.com/ImSingee/mcp-webhook-events/internal/httpx"
	"github.com/ImSingee/mcp-webhook-events/internal/idgen"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
)

// Handler receives webhooks.
type Handler struct {
	Core    *core.Service
	MaxBody int64
	Log     *slog.Logger
}

// KeyHeader is the header a webhook's key may be sent in.
const KeyHeader = "X-Webhook-Key"

// dropped are the headers never kept with an event: the ones that can
// carry the webhook key, and other credentials.
var dropped = map[string]bool{
	KeyHeader:             true,
	"Authorization":       true,
	"Proxy-Authorization": true,
	"Cookie":              true,
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	httpx.WriteJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": msg}})
}

// key is the webhook key a request carries, from the header, a bearer
// Authorization, or the key query parameter, in that order.
func key(r *http.Request) string {
	if k := r.Header.Get(KeyHeader); k != "" {
		return k
	}
	if scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
		return strings.TrimSpace(tok)
	}
	return r.URL.Query().Get("key")
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wh, err := h.Core.Store.WebhookByToken(ctx, r.PathValue("token"))
	if errors.Is(err, store.ErrNotFound) {
		fail(w, http.StatusNotFound, "not_found", "no webhook at this URL")
		return
	}
	if err != nil {
		h.Log.Error("look up webhook", "err", err)
		fail(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	k := key(r)
	if k == "" || !idgen.HashEqual(k, wh.KeyHash) {
		fail(w, http.StatusUnauthorized, "unauthorized", "missing or wrong webhook key: send it as the X-Webhook-Key header, an Authorization: Bearer header, or the key query parameter")
		return
	}
	body, err := httpx.ReadBody(r, h.MaxBody)
	if errors.Is(err, httpx.ErrTooLarge) {
		fail(w, http.StatusRequestEntityTooLarge, "too_large", "the body is larger than this server accepts")
		return
	}
	if err != nil {
		fail(w, http.StatusBadRequest, "invalid_argument", "could not read the body")
		return
	}
	now := h.Core.Store.Now()
	req := &core.RequestData{
		Method:      r.Method,
		Query:       map[string][]string{},
		Headers:     map[string][]string{},
		ContentType: r.Header.Get("Content-Type"),
	}
	for k, vs := range r.URL.Query() {
		if k != "key" {
			req.Query[k] = vs
		}
	}
	for k, vs := range r.Header {
		if !dropped[textproto.CanonicalMIMEHeaderKey(k)] {
			req.Headers[k] = vs
		}
	}
	switch {
	case len(body) == 0:
		req.BodyEncoding, req.Body = "none", nil
	case json.Valid(body):
		req.BodyEncoding, req.Body = "json", json.RawMessage(body)
	case utf8.Valid(body):
		req.BodyEncoding, req.Body = "text", string(body)
	default:
		req.BodyEncoding, req.Body = "base64", base64.StdEncoding.EncodeToString(body)
	}
	data, err := events.MarshalData(core.EventData{
		Identifier: wh.Identifier, Kind: "webhook", Webhook: &core.WebhookRef{Name: wh.Name},
		ReceivedAt: events.Stamp(now), Request: req,
	})
	if err != nil {
		fail(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	e, err := h.Core.AppendEvent(ctx, store.Event{
		ID: idgen.ID("evt"), IdentityID: wh.IdentityID, Identifier: wh.Identifier, Kind: "webhook",
		WebhookID: wh.ID, ReceivedAt: now, Data: data,
	})
	if err != nil {
		h.Log.Error("store event", "err", err)
		fail(w, http.StatusInternalServerError, "internal", "internal error")
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"event_id": e.ID})
}
