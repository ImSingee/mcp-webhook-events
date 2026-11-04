package admin

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/ImSingee/mcp-webhook-events/internal/core"
	"github.com/ImSingee/mcp-webhook-events/internal/events"
	"github.com/ImSingee/mcp-webhook-events/internal/httpx"
	"github.com/ImSingee/mcp-webhook-events/internal/oauth"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
)

func identityView(i store.IdentityInfo) map[string]any {
	var last any
	if i.LastEventAt != nil {
		last = events.Stamp(*i.LastEventAt)
	}
	return map[string]any{
		"id": i.ID, "name": i.Name, "created_at": events.Stamp(i.CreatedAt),
		"webhook_count": i.WebhookCount, "channel_count": i.ChannelCount, "authorization_count": i.AuthorizationCount,
		"last_event_at": last,
	}
}

func (s *Server) listIdentities(w http.ResponseWriter, r *http.Request) {
	ids, err := s.Store.ListIdentities(r.Context())
	if err != nil {
		s.fail(w, err, "identities")
		return
	}
	out := make([]any, len(ids))
	for i, v := range ids {
		out[i] = identityView(v)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"identities": out})
}

func (s *Server) createIdentity(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	v, err := s.Core.CreateIdentity(r.Context(), body.Name)
	if err != nil {
		s.fail(w, err, "identity")
		return
	}
	info, err := s.Store.GetIdentity(r.Context(), v.ID)
	if err != nil {
		s.fail(w, err, "identity")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, identityView(info))
}

func (s *Server) getIdentity(w http.ResponseWriter, r *http.Request) {
	info, err := s.Store.GetIdentity(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err, "identity")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, identityView(info))
}

func (s *Server) renameIdentity(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &body) {
		return
	}
	id := r.PathValue("id")
	if err := s.Core.RenameIdentity(r.Context(), id, body.Name); err != nil {
		s.fail(w, err, "identity")
		return
	}
	s.getIdentity(w, r)
}

func (s *Server) deleteIdentity(w http.ResponseWriter, r *http.Request) {
	if err := s.Core.DeleteIdentity(r.Context(), r.PathValue("id")); err != nil {
		s.fail(w, err, "identity")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// identity is the {iid} of a nested route, checked to exist.
func (s *Server) identity(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("iid")
	if _, err := s.Store.GetIdentity(r.Context(), id); err != nil {
		s.fail(w, err, "identity")
		return "", false
	}
	return id, true
}

func (s *Server) listWebhooks(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	ws, err := s.Store.ListWebhooks(r.Context(), iid)
	if err != nil {
		s.fail(w, err, "webhooks")
		return
	}
	out := make([]any, len(ws))
	for i, v := range ws {
		out[i] = s.Core.WebhookView(v)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"webhooks": out})
}

func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	var body struct {
		Identifier  string `json:"identifier"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !decode(w, r, &body) {
		return
	}
	wh, key, err := s.Core.CreateWebhook(r.Context(), iid, body.Identifier, body.Name, body.Description)
	if err != nil {
		s.fail(w, err, "webhook")
		return
	}
	info, err := s.Store.GetWebhook(r.Context(), iid, wh.ID)
	if err != nil {
		s.fail(w, err, "webhook")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"webhook": s.Core.WebhookView(info), "key": key})
}

func (s *Server) updateWebhook(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	var body struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if !decode(w, r, &body) {
		return
	}
	wid := r.PathValue("wid")
	if err := s.Core.UpdateWebhook(r.Context(), iid, wid, body.Name, body.Description); err != nil {
		s.fail(w, err, "webhook")
		return
	}
	info, err := s.Store.GetWebhook(r.Context(), iid, wid)
	if err != nil {
		s.fail(w, err, "webhook")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.Core.WebhookView(info))
}

func (s *Server) rotateWebhook(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	wid := r.PathValue("wid")
	key, err := s.Core.RotateWebhookKey(r.Context(), iid, wid)
	if err != nil {
		s.fail(w, err, "webhook")
		return
	}
	info, err := s.Store.GetWebhook(r.Context(), iid, wid)
	if err != nil {
		s.fail(w, err, "webhook")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"webhook": s.Core.WebhookView(info), "key": key})
}

func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteWebhook(r.Context(), iid, r.PathValue("wid")); err != nil {
		s.fail(w, err, "webhook")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listChannels(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	cs, err := s.Store.ListChannels(r.Context(), iid)
	if err != nil {
		s.fail(w, err, "channels")
		return
	}
	out := make([]any, len(cs))
	for i, v := range cs {
		out[i] = s.Core.ChannelView(v)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"channels": out})
}

func (s *Server) createChannel(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	var body struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Mode        string   `json:"mode"`
		Identifiers []string `json:"identifiers"`
	}
	if !decode(w, r, &body) {
		return
	}
	c, err := s.Core.CreateChannel(r.Context(), store.Channel{IdentityID: iid, Name: body.Name, Description: body.Description, Mode: body.Mode, Identifiers: body.Identifiers})
	if err != nil {
		s.fail(w, err, "channel")
		return
	}
	info, err := s.Store.GetChannel(r.Context(), c.ID)
	if err != nil {
		s.fail(w, err, "channel")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, s.Core.ChannelView(info))
}

func (s *Server) updateChannel(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	var body struct {
		Description *string   `json:"description"`
		Mode        *string   `json:"mode"`
		Identifiers *[]string `json:"identifiers"`
	}
	if !decode(w, r, &body) {
		return
	}
	info, err := s.Core.UpdateChannel(r.Context(), iid, r.PathValue("cid"), core.ChannelPatch{Description: body.Description, Mode: body.Mode, Identifiers: body.Identifiers})
	if err != nil {
		s.fail(w, err, "channel")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.Core.ChannelView(info))
}

func (s *Server) deleteChannel(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	if err := s.Core.DeleteChannel(r.Context(), iid, r.PathValue("cid")); err != nil {
		s.fail(w, err, "channel")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listAuthorizations(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	as, err := s.Store.ListAuthorizations(r.Context(), iid)
	if err != nil {
		s.fail(w, err, "authorizations")
		return
	}
	out := make([]any, len(as))
	for i, a := range as {
		var used any
		if a.LastUsedAt != nil {
			used = events.Stamp(*a.LastUsedAt)
		}
		out[i] = map[string]any{
			"id": a.ID, "client_id": a.ClientID, "client_name": a.ClientName, "redirect_host": oauth.RedirectHost(a.RedirectURI),
			"created_at": events.Stamp(a.CreatedAt), "last_used_at": used,
			"registration":  a.ClientKind,
			"metadata_host": oauth.MetadataHost(store.Client{ID: a.ClientID, Kind: a.ClientKind}),
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"authorizations": out})
}

func (s *Server) revokeAuthorization(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	if err := s.Core.RevokeAuthorization(r.Context(), iid, r.PathValue("aid")); err != nil {
		s.fail(w, err, "authorization")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listSubscriptions(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	subs, err := s.Store.ListSubscriptions(r.Context(), iid)
	if err != nil {
		s.fail(w, err, "subscriptions")
		return
	}
	now := s.Store.Now()
	out := make([]any, len(subs))
	for i, sub := range subs {
		status := sub.Status
		if (status == store.SubActive || status == store.SubFailing) && !now.Before(sub.ExpiresAt) {
			status = store.SubExpired
		}
		var last, lastErr any
		if sub.LastDeliveryAt != nil {
			last = events.Stamp(*sub.LastDeliveryAt)
		}
		if sub.LastError != "" {
			lastErr = sub.LastError
		}
		out[i] = map[string]any{
			"id": sub.ID, "channel": sub.ChannelName, "url": sub.URL, "status": status,
			"expires_at": events.Stamp(sub.ExpiresAt), "failure_count": sub.FailureCount,
			"last_delivery_at": last, "last_error": lastErr, "created_at": events.Stamp(sub.CreatedAt),
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"subscriptions": out})
}

func (s *Server) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	iid, ok := s.identity(w, r)
	if !ok {
		return
	}
	sid := r.PathValue("sid")
	sub, err := s.Store.GetSubscription(r.Context(), sid)
	if err != nil || sub.IdentityID != iid {
		s.fail(w, store.ErrNotFound, "subscription")
		return
	}
	// a live subscription's endpoint is told it ended
	if (sub.Status == store.SubActive || sub.Status == store.SubFailing) && s.Core.Subs != nil {
		s.Core.Subs.Terminate(r.Context(), []store.Subscription{sub}, events.AccessRevoked("The subscription was removed by the platform's administrator"))
	}
	if err := s.Store.DeleteSubscription(r.Context(), iid, sid); err != nil {
		s.fail(w, err, "subscription")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// EventView is an event as the admin API returns it.
func EventView(e store.Event) map[string]any {
	var idn, name any
	if e.IdentityID != "" {
		idn, name = e.IdentityID, e.IdentityName
	}
	return map[string]any{
		"id": e.ID, "seq": e.Seq, "identity_id": idn, "identity_name": name, "identifier": e.Identifier,
		"kind": e.Kind, "received_at": events.Stamp(e.ReceivedAt), "data": e.Data,
	}
}

func (s *Server) listEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.EventFilter{IdentityID: q.Get("identity_id"), Identifier: q.Get("identifier"), Limit: 50}
	if v := q.Get("before"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			apiError(w, http.StatusBadRequest, "invalid_argument", "before must be an event seq")
			return
		}
		f.Before = n
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			apiError(w, http.StatusBadRequest, "invalid_argument", "limit must be a positive integer")
			return
		}
		f.Limit = min(n, 200)
	}
	evs, err := s.Store.ListEvents(r.Context(), f)
	if err != nil {
		s.fail(w, err, "events")
		return
	}
	out := make([]any, len(evs))
	for i, e := range evs {
		out[i] = EventView(e)
	}
	var next any
	if len(evs) == f.Limit {
		next = evs[len(evs)-1].Seq
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"events": out, "next_before": next})
}

func (s *Server) broadcast(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Identifier string `json:"identifier"`
		Title      string `json:"title"`
		Message    string `json:"message"`
	}
	if !decode(w, r, &body) {
		return
	}
	e, err := s.Core.Broadcast(r.Context(), body.Identifier, body.Title, body.Message)
	if err != nil {
		s.fail(w, err, "broadcast")
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"event_id": e.ID})
}

func (s *Server) getRequest(w http.ResponseWriter, r *http.Request) {
	p, err := s.OAuth.PendingRequest(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err, "authorization request")
		return
	}
	ids, err := s.Store.ListIdentities(r.Context())
	if err != nil {
		s.fail(w, err, "identities")
		return
	}
	idents := make([]any, len(ids))
	for i, v := range ids {
		idents[i] = map[string]any{"id": v.ID, "name": v.Name, "authorization_count": v.AuthorizationCount}
	}
	host := oauth.RedirectHost(p.Request.RedirectURI)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"id": p.Request.ID,
		"client": map[string]any{
			"id": p.Client.ID, "name": p.Client.Name, "redirect_uri": p.Request.RedirectURI, "redirect_host": host,
			"registration":  p.Client.Kind,
			"metadata_host": oauth.MetadataHost(p.Client),
			"warnings":      oauth.ConsentWarnings(p.Client, p.Request.RedirectURI),
		},
		"scope": p.Request.Scope, "resource": p.Request.Resource, "expires_at": events.Stamp(p.Request.ExpiresAt),
		"identities": idents,
	})
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body struct {
		IdentityID      string `json:"identity_id"`
		NewIdentityName string `json:"new_identity_name"`
	}
	if !decode(w, r, &body) {
		return
	}
	if (body.IdentityID == "") == (body.NewIdentityName == "") {
		apiError(w, http.StatusBadRequest, "invalid_argument", "send exactly one of identity_id and new_identity_name")
		return
	}
	if _, err := s.OAuth.PendingRequest(r.Context(), id); err != nil {
		s.fail(w, err, "authorization request")
		return
	}
	identityID := body.IdentityID
	if identityID != "" {
		if _, err := s.Store.GetIdentity(r.Context(), identityID); errors.Is(err, store.ErrNotFound) {
			apiError(w, http.StatusBadRequest, "invalid_argument", "identity_id names no identity")
			return
		} else if err != nil {
			s.fail(w, err, "identity")
			return
		}
	} else {
		v, err := s.Core.CreateIdentity(r.Context(), body.NewIdentityName)
		if err != nil {
			s.fail(w, err, "identity")
			return
		}
		identityID = v.ID
	}
	u, err := s.OAuth.Approve(r.Context(), id, identityID)
	if err != nil {
		s.fail(w, err, "authorization request")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"redirect_url": u})
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request) {
	u, err := s.OAuth.Deny(r.Context(), r.PathValue("id"))
	if err != nil {
		s.fail(w, err, "authorization request")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"redirect_url": u})
}
