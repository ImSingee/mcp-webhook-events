package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/ImSingee/mcp-webhook-events/internal/core"
	"github.com/ImSingee/mcp-webhook-events/internal/events"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
)

type schema = map[string]any

func object(props schema, required ...string) schema {
	s := schema{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func str(desc string) schema { return schema{"type": "string", "description": desc} }

var (
	nullableString = schema{"type": []string{"string", "null"}}
	stringList     = schema{"type": "array", "items": schema{"type": "string"}}

	webhookSchema = object(schema{
		"id": schema{"type": "string"}, "identifier": schema{"type": "string"}, "name": schema{"type": "string"},
		"description": schema{"type": "string"}, "url": schema{"type": "string"}, "created_at": schema{"type": "string"},
		"updated_at": schema{"type": "string"}, "last_event_at": nullableString, "event_count": schema{"type": "integer"},
	}, "id", "identifier", "name", "description", "url", "created_at", "updated_at", "last_event_at", "event_count")

	channelSchema = object(schema{
		"id": schema{"type": "string"}, "name": schema{"type": "string"}, "description": schema{"type": "string"},
		"mode":        schema{"type": "string", "enum": []string{"all", "include", "exclude"}},
		"identifiers": stringList, "created_at": schema{"type": "string"}, "updated_at": schema{"type": "string"},
		"active_streams": schema{"type": "integer"}, "subscription_count": schema{"type": "integer"},
	}, "id", "name", "description", "mode", "identifiers", "created_at", "updated_at", "active_streams", "subscription_count")

	keySchema = object(schema{
		"id": schema{"type": "string"}, "identifier": schema{"type": "string"}, "name": schema{"type": "string"},
		"url": schema{"type": "string"}, "key": schema{"type": "string"}, "usage": schema{"type": "string"},
	}, "id", "identifier", "name", "url", "key", "usage")

	identifierArg  = str("The webhook's identifier, as given to webhook_create.")
	modeArg        = schema{"type": "string", "enum": []string{"all", "include", "exclude"}, "description": "all: every event of your webhooks; include: only the listed identifiers; exclude: all but the listed identifiers. Platform broadcasts always pass."}
	identifiersArg = schema{"type": "array", "items": schema{"type": "string"}, "description": "Webhook identifiers (or reserved ones starting with ':') for include/exclude. Must be empty for mode all."}
)

// tool is one MCP tool and what runs it.
type tool struct {
	def map[string]any
	run func(ctx context.Context, s *Server, q *request, args json.RawMessage) (map[string]any, error)
}

func def(name, title, desc string, in, out schema, readOnly, destructive bool) map[string]any {
	return map[string]any{
		"name": name, "title": title, "description": desc, "inputSchema": in, "outputSchema": out,
		"annotations": map[string]any{"title": title, "readOnlyHint": readOnly, "destructiveHint": destructive, "idempotentHint": readOnly, "openWorldHint": false},
	}
}

var tools = []tool{
	{def("whoami", "Who am I", "The identity this token is bound to, the client it was issued to, and the MCP URL.",
		object(schema{}), object(schema{
			"identity": object(schema{"id": schema{"type": "string"}, "name": schema{"type": "string"}}, "id", "name"),
			"client":   object(schema{"id": schema{"type": "string"}, "name": schema{"type": "string"}}, "id", "name"),
			"mcp_url":  schema{"type": "string"}, "event_name": schema{"type": "string"},
		}, "identity", "client", "mcp_url", "event_name"), true, false), toolWhoami},
	{def("webhook_create", "Create webhook", "Create a webhook: a public URL that turns every request into a webhook.received event for your identity. Returns the URL and its key, which is shown only once.",
		object(schema{
			"identifier":  str("Unique within your identity: lowercase words joined by single hyphens (^[a-z0-9]+(-[a-z0-9]+)*$), at most 64 characters, e.g. github-push. Events carry it as data.identifier."),
			"name":        str("Display name; defaults to the identifier."),
			"description": str("What sends to this webhook."),
		}, "identifier"), keySchema, false, false), toolWebhookCreate},
	{def("webhook_list", "List webhooks", "List your webhooks with their URLs and activity (keys are never shown again).",
		object(schema{}), object(schema{"webhooks": schema{"type": "array", "items": webhookSchema}}, "webhooks"), true, false), toolWebhookList},
	{def("webhook_update", "Update webhook", "Change a webhook's name or description. The identifier can't change.",
		object(schema{"identifier": identifierArg, "name": str("New display name."), "description": str("New description.")}, "identifier"),
		object(schema{"webhook": webhookSchema}, "webhook"), false, false), toolWebhookUpdate},
	{def("webhook_rotate_key", "Rotate webhook key", "Give a webhook a new key. The old key stops working at once.",
		object(schema{"identifier": identifierArg}, "identifier"), keySchema, false, true), toolWebhookRotate},
	{def("webhook_delete", "Delete webhook", "Delete a webhook. Its URL stops accepting requests; past events stay.",
		object(schema{"identifier": identifierArg}, "identifier"),
		object(schema{"deleted": schema{"type": "string"}}, "deleted"), false, true), toolWebhookDelete},
	{def("channel_create", "Create channel", "Create a channel: a saved filter over your webhooks' identifiers that event subscriptions name in their arguments ({\"channel\": \"<name>\"}).",
		object(schema{
			"name":        str("Unique within your identity, same rule as webhook identifiers."),
			"description": str("What the channel is for."),
			"mode":        modeArg,
			"identifiers": identifiersArg,
		}, "name", "mode"), object(schema{"channel": channelSchema}, "channel"), false, false), toolChannelCreate},
	{def("channel_update", "Update channel", "Change a channel's description, mode or identifiers. Live subscriptions on it apply the new rule to their next event.",
		object(schema{"name": str("The channel's name."), "description": str("New description."), "mode": modeArg, "identifiers": identifiersArg}, "name"),
		object(schema{"channel": channelSchema}, "channel"), false, false), toolChannelUpdate},
	{def("channel_list", "List channels", "List your channels and their filters.",
		object(schema{}), object(schema{"channels": schema{"type": "array", "items": channelSchema}}, "channels"), true, false), toolChannelList},
	{def("channel_delete", "Delete channel", "Delete a channel. Live subscriptions on it end with a terminated signal.",
		object(schema{"name": str("The channel's name.")}, "name"),
		object(schema{"deleted": schema{"type": "string"}}, "deleted"), false, true), toolChannelDelete},
}

func (s *Server) toolsList(w http.ResponseWriter, q *request) {
	defs := make([]any, len(tools))
	for i, t := range tools {
		defs[i] = t.def
	}
	res := map[string]any{"tools": defs}
	if q.modern {
		res["ttlMs"] = 3600000
		res["cacheScope"] = "public"
	}
	writeRPC(w, http.StatusOK, q.finish(res))
}

// toolResult is a tool's answer: structured content and the same as text.
func toolResult(v map[string]any) map[string]any {
	b, _ := json.MarshalIndent(v, "", "  ")
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": string(b)}}, "structuredContent": v}
}

func toolError(msg string) map[string]any {
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": msg}}, "isError": true}
}

func (s *Server) toolsCall(w http.ResponseWriter, q *request) {
	var name string
	if err := json.Unmarshal(q.params["name"], &name); err != nil || name == "" {
		writeError(w, q.id, errInvalidParams("Invalid params: name is required"))
		return
	}
	for _, t := range tools {
		if t.def["name"] != name {
			continue
		}
		out, err := t.run(q.r.Context(), s, q, q.params["arguments"])
		switch {
		case err == nil:
			writeRPC(w, http.StatusOK, q.finish(toolResult(out)))
		case core.IsInvalid(err) || errors.Is(err, errArgs):
			writeRPC(w, http.StatusOK, q.finish(toolError(err.Error())))
		case errors.Is(err, store.ErrNotFound):
			writeRPC(w, http.StatusOK, q.finish(toolError(notFoundMessage(err))))
		case errors.Is(err, store.ErrConflict):
			writeRPC(w, http.StatusOK, q.finish(toolError(conflictMessage(err))))
		default:
			s.Log.Error("tool failed", "tool", name, "err", err)
			writeRPC(w, http.StatusOK, q.finish(toolError("internal error running "+name)))
		}
		return
	}
	writeError(w, q.id, errInvalidParams("Unknown tool: "+name))
}

var errArgs = errors.New("invalid arguments")

// what names the thing an ErrNotFound or ErrConflict is about.
type what struct {
	error
	msg string
}

func (w what) Error() string { return w.msg }
func (w what) Unwrap() error { return w.error }

func notFoundMessage(err error) string {
	var w what
	if errors.As(err, &w) {
		return w.msg
	}
	return "not found"
}

func conflictMessage(err error) string { return notFoundMessage(err) }

// decodeArgs reads a tool's arguments into v, refusing unknown fields.
func decodeArgs(args json.RawMessage, v any) error {
	if len(bytes.TrimSpace(args)) == 0 || string(bytes.TrimSpace(args)) == "null" {
		args = json.RawMessage(`{}`)
	}
	d := json.NewDecoder(bytes.NewReader(args))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", errArgs, err)
	}
	return nil
}

func toolWhoami(ctx context.Context, s *Server, q *request, args json.RawMessage) (map[string]any, error) {
	if err := decodeArgs(args, &struct{}{}); err != nil {
		return nil, err
	}
	p := q.principal
	return map[string]any{
		"identity":   map[string]any{"id": p.IdentityID, "name": p.IdentityName},
		"client":     map[string]any{"id": p.ClientID, "name": p.ClientName},
		"mcp_url":    s.Cfg.MCPResource(),
		"event_name": events.Name,
	}, nil
}

func (s *Server) webhookByIdentifier(ctx context.Context, q *request, identifier string) (store.WebhookInfo, error) {
	if identifier == "" {
		return store.WebhookInfo{}, fmt.Errorf("%w: identifier is required", errArgs)
	}
	w, err := s.Store.GetWebhookByIdentifier(ctx, q.principal.IdentityID, identifier)
	if errors.Is(err, store.ErrNotFound) {
		return w, what{err, "no webhook with identifier " + identifier + "; webhook_list shows yours"}
	}
	return w, err
}

func keyResult(s *Server, w store.Webhook, key string) map[string]any {
	url := s.Core.WebhookURL(w.PathToken)
	return map[string]any{"id": w.ID, "identifier": w.Identifier, "name": w.Name, "url": url, "key": key, "usage": core.KeyUsage(url, key)}
}

func toolWebhookCreate(ctx context.Context, s *Server, q *request, args json.RawMessage) (map[string]any, error) {
	var a struct{ Identifier, Name, Description string }
	if err := decodeArgs(args, &a); err != nil {
		return nil, err
	}
	w, key, err := s.Core.CreateWebhook(ctx, q.principal.IdentityID, a.Identifier, a.Name, a.Description)
	if errors.Is(err, store.ErrConflict) {
		return nil, what{err, "you already have a webhook with identifier " + a.Identifier}
	}
	if err != nil {
		return nil, err
	}
	return keyResult(s, w, key), nil
}

func toolWebhookList(ctx context.Context, s *Server, q *request, args json.RawMessage) (map[string]any, error) {
	if err := decodeArgs(args, &struct{}{}); err != nil {
		return nil, err
	}
	ws, err := s.Store.ListWebhooks(ctx, q.principal.IdentityID)
	if err != nil {
		return nil, err
	}
	out := make([]any, len(ws))
	for i, w := range ws {
		out[i] = s.Core.WebhookView(w)
	}
	return map[string]any{"webhooks": out}, nil
}

func toolWebhookUpdate(ctx context.Context, s *Server, q *request, args json.RawMessage) (map[string]any, error) {
	var a struct {
		Identifier  string
		Name        *string
		Description *string
	}
	if err := decodeArgs(args, &a); err != nil {
		return nil, err
	}
	w, err := s.webhookByIdentifier(ctx, q, a.Identifier)
	if err != nil {
		return nil, err
	}
	if err := s.Core.UpdateWebhook(ctx, q.principal.IdentityID, w.ID, a.Name, a.Description); err != nil {
		return nil, err
	}
	w, err = s.Store.GetWebhook(ctx, q.principal.IdentityID, w.ID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"webhook": s.Core.WebhookView(w)}, nil
}

func toolWebhookRotate(ctx context.Context, s *Server, q *request, args json.RawMessage) (map[string]any, error) {
	var a struct{ Identifier string }
	if err := decodeArgs(args, &a); err != nil {
		return nil, err
	}
	w, err := s.webhookByIdentifier(ctx, q, a.Identifier)
	if err != nil {
		return nil, err
	}
	key, err := s.Core.RotateWebhookKey(ctx, q.principal.IdentityID, w.ID)
	if err != nil {
		return nil, err
	}
	return keyResult(s, w.Webhook, key), nil
}

func toolWebhookDelete(ctx context.Context, s *Server, q *request, args json.RawMessage) (map[string]any, error) {
	var a struct{ Identifier string }
	if err := decodeArgs(args, &a); err != nil {
		return nil, err
	}
	w, err := s.webhookByIdentifier(ctx, q, a.Identifier)
	if err != nil {
		return nil, err
	}
	if err := s.Store.DeleteWebhook(ctx, q.principal.IdentityID, w.ID); err != nil {
		return nil, err
	}
	return map[string]any{"deleted": w.Identifier}, nil
}

func (s *Server) channelByName(ctx context.Context, q *request, name string) (store.ChannelInfo, error) {
	if name == "" {
		return store.ChannelInfo{}, fmt.Errorf("%w: name is required", errArgs)
	}
	c, err := s.Store.GetChannelByName(ctx, q.principal.IdentityID, name)
	if errors.Is(err, store.ErrNotFound) {
		return c, what{err, "no channel named " + name + "; channel_list shows yours"}
	}
	return c, err
}

func toolChannelCreate(ctx context.Context, s *Server, q *request, args json.RawMessage) (map[string]any, error) {
	var a struct {
		Name, Description, Mode string
		Identifiers             []string
	}
	if err := decodeArgs(args, &a); err != nil {
		return nil, err
	}
	c, err := s.Core.CreateChannel(ctx, store.Channel{IdentityID: q.principal.IdentityID, Name: a.Name, Description: a.Description, Mode: a.Mode, Identifiers: a.Identifiers})
	if errors.Is(err, store.ErrConflict) {
		return nil, what{err, "you already have a channel named " + a.Name}
	}
	if err != nil {
		return nil, err
	}
	info, err := s.Store.GetChannel(ctx, c.ID)
	if err != nil {
		return nil, err
	}
	return map[string]any{"channel": s.Core.ChannelView(info)}, nil
}

func toolChannelUpdate(ctx context.Context, s *Server, q *request, args json.RawMessage) (map[string]any, error) {
	var a struct {
		Name        string
		Description *string
		Mode        *string
		Identifiers *[]string
	}
	if err := decodeArgs(args, &a); err != nil {
		return nil, err
	}
	c, err := s.channelByName(ctx, q, a.Name)
	if err != nil {
		return nil, err
	}
	info, err := s.Core.UpdateChannel(ctx, q.principal.IdentityID, c.ID, core.ChannelPatch{Description: a.Description, Mode: a.Mode, Identifiers: a.Identifiers})
	if err != nil {
		return nil, err
	}
	return map[string]any{"channel": s.Core.ChannelView(info)}, nil
}

func toolChannelList(ctx context.Context, s *Server, q *request, args json.RawMessage) (map[string]any, error) {
	if err := decodeArgs(args, &struct{}{}); err != nil {
		return nil, err
	}
	cs, err := s.Store.ListChannels(ctx, q.principal.IdentityID)
	if err != nil {
		return nil, err
	}
	out := make([]any, len(cs))
	for i, c := range cs {
		out[i] = s.Core.ChannelView(c)
	}
	return map[string]any{"channels": out}, nil
}

func toolChannelDelete(ctx context.Context, s *Server, q *request, args json.RawMessage) (map[string]any, error) {
	var a struct{ Name string }
	if err := decodeArgs(args, &a); err != nil {
		return nil, err
	}
	c, err := s.channelByName(ctx, q, a.Name)
	if err != nil {
		return nil, err
	}
	if err := s.Core.DeleteChannel(ctx, q.principal.IdentityID, c.ID); err != nil {
		return nil, err
	}
	return map[string]any{"deleted": c.Name}, nil
}
