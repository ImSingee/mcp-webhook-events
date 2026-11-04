package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// Webhook is an inbound URL that turns each request into an event.
type Webhook struct {
	ID          string
	IdentityID  string
	Identifier  string
	Name        string
	Description string
	PathToken   string // the URL is <public>/hooks/<PathToken>
	KeyHash     string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// WebhookInfo is a webhook with the activity the UI shows.
type WebhookInfo struct {
	Webhook
	EventCount  int
	LastEventAt *time.Time
}

const webhookCols = `w.id, w.identity_id, w.identifier, w.name, w.description, w.path_token, w.key_hash, w.created_at, w.updated_at`

func scanWebhook(sc interface{ Scan(...any) error }, extra ...any) (Webhook, error) {
	var (
		w                Webhook
		created, updated int64
	)
	dst := append([]any{&w.ID, &w.IdentityID, &w.Identifier, &w.Name, &w.Description, &w.PathToken, &w.KeyHash, &created, &updated}, extra...)
	err := sc.Scan(dst...)
	w.CreatedAt, w.UpdatedAt = at(created), at(updated)
	return w, err
}

// CreateWebhook adds a webhook; ErrConflict if the identity already has
// one with that identifier.
func (s *Store) CreateWebhook(ctx context.Context, w Webhook) (Webhook, error) {
	now := s.nowMS()
	w.CreatedAt, w.UpdatedAt = at(now), at(now)
	_, err := s.db.ExecContext(ctx, `INSERT INTO webhooks (id, identity_id, identifier, name, description, path_token, key_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		w.ID, w.IdentityID, w.Identifier, w.Name, w.Description, w.PathToken, w.KeyHash, now, now)
	if isUnique(err) {
		return Webhook{}, ErrConflict
	}
	return w, err
}

const webhookInfoSelect = `SELECT ` + webhookCols + `,
  (SELECT COUNT(*) FROM events e WHERE e.webhook_id = w.id),
  (SELECT MAX(e.received_at) FROM events e WHERE e.webhook_id = w.id)
FROM webhooks w`

func scanWebhookInfo(sc interface{ Scan(...any) error }) (WebhookInfo, error) {
	var (
		v    WebhookInfo
		last sql.NullInt64
	)
	w, err := scanWebhook(sc, &v.EventCount, &last)
	v.Webhook, v.LastEventAt = w, ms(last)
	return v, err
}

// ListWebhooks is an identity's webhooks, oldest first.
func (s *Store) ListWebhooks(ctx context.Context, identityID string) ([]WebhookInfo, error) {
	rows, err := s.db.QueryContext(ctx, webhookInfoSelect+` WHERE w.identity_id = ? ORDER BY w.created_at, w.id`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WebhookInfo{}
	for rows.Next() {
		v, err := scanWebhookInfo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetWebhook is one of an identity's webhooks by id.
func (s *Store) GetWebhook(ctx context.Context, identityID, id string) (WebhookInfo, error) {
	v, err := scanWebhookInfo(s.db.QueryRowContext(ctx, webhookInfoSelect+` WHERE w.identity_id = ? AND w.id = ?`, identityID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return WebhookInfo{}, ErrNotFound
	}
	return v, err
}

// GetWebhookByIdentifier is one of an identity's webhooks by identifier.
func (s *Store) GetWebhookByIdentifier(ctx context.Context, identityID, identifier string) (WebhookInfo, error) {
	v, err := scanWebhookInfo(s.db.QueryRowContext(ctx, webhookInfoSelect+` WHERE w.identity_id = ? AND w.identifier = ?`, identityID, identifier))
	if errors.Is(err, sql.ErrNoRows) {
		return WebhookInfo{}, ErrNotFound
	}
	return v, err
}

// WebhookByToken is the webhook served at /hooks/<token>.
func (s *Store) WebhookByToken(ctx context.Context, token string) (Webhook, error) {
	w, err := scanWebhook(s.db.QueryRowContext(ctx, `SELECT `+webhookCols+` FROM webhooks w WHERE w.path_token = ?`, token))
	if errors.Is(err, sql.ErrNoRows) {
		return Webhook{}, ErrNotFound
	}
	return w, err
}

// UpdateWebhook changes a webhook's name and description where given.
func (s *Store) UpdateWebhook(ctx context.Context, identityID, id string, name, description *string) error {
	return affected(s.db.ExecContext(ctx, `UPDATE webhooks SET name = COALESCE(?, name), description = COALESCE(?, description), updated_at = ? WHERE identity_id = ? AND id = ?`,
		nullable(name), nullable(description), s.nowMS(), identityID, id))
}

// RotateWebhookKey replaces a webhook's key; the old one stops working.
func (s *Store) RotateWebhookKey(ctx context.Context, identityID, id, keyHash string) error {
	return affected(s.db.ExecContext(ctx, `UPDATE webhooks SET key_hash = ?, updated_at = ? WHERE identity_id = ? AND id = ?`, keyHash, s.nowMS(), identityID, id))
}

// DeleteWebhook deletes a webhook; its events stay, unlinked from it.
func (s *Store) DeleteWebhook(ctx context.Context, identityID, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM webhooks WHERE identity_id = ? AND id = ?`, identityID, id))
}

func nullable(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

// Channel is a named, persisted event filter an identity subscribes by.
type Channel struct {
	ID          string
	IdentityID  string
	Name        string
	Description string
	Mode        string // all, include or exclude
	Identifiers []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ChannelInfo is a channel with its webhook-mode subscription count.
type ChannelInfo struct {
	Channel
	SubscriptionCount int
}

const channelSelect = `SELECT c.id, c.identity_id, c.name, c.description, c.mode, c.identifiers, c.created_at, c.updated_at,
  (SELECT COUNT(*) FROM event_subscriptions s WHERE s.channel_id = c.id AND s.status IN ('active', 'failing'))
FROM channels c`

func scanChannel(sc interface{ Scan(...any) error }) (ChannelInfo, error) {
	var (
		c                ChannelInfo
		ids              string
		created, updated int64
	)
	err := sc.Scan(&c.ID, &c.IdentityID, &c.Name, &c.Description, &c.Mode, &ids, &created, &updated, &c.SubscriptionCount)
	c.CreatedAt, c.UpdatedAt = at(created), at(updated)
	c.Identifiers = []string{}
	if ids != "" {
		_ = json.Unmarshal([]byte(ids), &c.Identifiers)
	}
	return c, err
}

func idsJSON(ids []string) string {
	if ids == nil {
		ids = []string{}
	}
	b, _ := json.Marshal(ids)
	return string(b)
}

// CreateChannel adds a channel; ErrConflict if the identity already has
// one by that name.
func (s *Store) CreateChannel(ctx context.Context, c Channel) (Channel, error) {
	now := s.nowMS()
	c.CreatedAt, c.UpdatedAt = at(now), at(now)
	if c.Identifiers == nil {
		c.Identifiers = []string{}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO channels (id, identity_id, name, description, mode, identifiers, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.IdentityID, c.Name, c.Description, c.Mode, idsJSON(c.Identifiers), now, now)
	if isUnique(err) {
		return Channel{}, ErrConflict
	}
	return c, err
}

// ListChannels is an identity's channels, oldest first.
func (s *Store) ListChannels(ctx context.Context, identityID string) ([]ChannelInfo, error) {
	rows, err := s.db.QueryContext(ctx, channelSelect+` WHERE c.identity_id = ? ORDER BY c.created_at, c.id`, identityID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ChannelInfo{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// GetChannel is a channel by id.
func (s *Store) GetChannel(ctx context.Context, id string) (ChannelInfo, error) {
	c, err := scanChannel(s.db.QueryRowContext(ctx, channelSelect+` WHERE c.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ChannelInfo{}, ErrNotFound
	}
	return c, err
}

// GetChannelByName is one of an identity's channels by name.
func (s *Store) GetChannelByName(ctx context.Context, identityID, name string) (ChannelInfo, error) {
	c, err := scanChannel(s.db.QueryRowContext(ctx, channelSelect+` WHERE c.identity_id = ? AND c.name = ?`, identityID, name))
	if errors.Is(err, sql.ErrNoRows) {
		return ChannelInfo{}, ErrNotFound
	}
	return c, err
}

// UpdateChannel replaces a channel's description, mode and identifiers.
func (s *Store) UpdateChannel(ctx context.Context, c Channel) error {
	return affected(s.db.ExecContext(ctx, `UPDATE channels SET description = ?, mode = ?, identifiers = ?, updated_at = ? WHERE identity_id = ? AND id = ?`,
		c.Description, c.Mode, idsJSON(c.Identifiers), s.nowMS(), c.IdentityID, c.ID))
}

// DeleteChannel deletes a channel.
func (s *Store) DeleteChannel(ctx context.Context, identityID, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM channels WHERE identity_id = ? AND id = ?`, identityID, id))
}
