package core

import (
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/events"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
)

// The JSON shapes the admin API (docs/admin-api.md) and the MCP tools both
// return, snake_case with RFC 3339 UTC times.

func stampPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return events.Stamp(*t)
}

// WebhookView is a webhook as the API returns it.
func (s *Service) WebhookView(w store.WebhookInfo) map[string]any {
	return map[string]any{
		"id":            w.ID,
		"identifier":    w.Identifier,
		"name":          w.Name,
		"description":   w.Description,
		"url":           s.WebhookURL(w.PathToken),
		"created_at":    events.Stamp(w.CreatedAt),
		"updated_at":    events.Stamp(w.UpdatedAt),
		"last_event_at": stampPtr(w.LastEventAt),
		"event_count":   w.EventCount,
	}
}

// ChannelView is a channel as the API returns it.
func (s *Service) ChannelView(c store.ChannelInfo) map[string]any {
	ids := c.Identifiers
	if ids == nil {
		ids = []string{}
	}
	return map[string]any{
		"id":                 c.ID,
		"name":               c.Name,
		"description":        c.Description,
		"mode":               c.Mode,
		"identifiers":        ids,
		"created_at":         events.Stamp(c.CreatedAt),
		"updated_at":         events.Stamp(c.UpdatedAt),
		"active_streams":     s.Hub.OnChannel(c.ID),
		"subscription_count": c.SubscriptionCount,
	}
}

// KeyUsage tells how to send a webhook's key, for the agent that just got
// it.
func KeyUsage(url, key string) string {
	return "POST anything to " + url + " with the key in one of: header \"X-Webhook-Key: " + key + "\", header \"Authorization: Bearer " + key + "\", or query \"?key=" + key + "\". " +
		"Example: curl -X POST '" + url + "' -H 'X-Webhook-Key: " + key + "' -H 'Content-Type: application/json' -d '{\"hello\":\"world\"}'. " +
		"The key is shown only now; rotate it with webhook_rotate_key if it is lost."
}
