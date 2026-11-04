package store

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// Subscription statuses. Active and failing subscriptions are live; an
// expired one lapsed without a refresh; a terminated one was ended by the
// server (its channel or identity deleted, its authorization revoked).
const (
	SubActive     = "active"
	SubFailing    = "failing"
	SubExpired    = "expired"
	SubTerminated = "terminated"
)

// Subscription is a webhook-mode event subscription (SEP-3415
// events/subscribe), keyed by (identity, url, event name, arguments) and
// identified by an id derived from that key.
type Subscription struct {
	ID              string
	IdentityID      string
	FamilyID        string // the authorization that last subscribed or refreshed
	ClientID        string
	EventName       string
	Arguments       string // canonical JSON
	ChannelID       string // "" once the channel is deleted
	ChannelName     string
	URL             string
	Secret          string
	PrevSecret      string // signed with too until PrevSecretUntil, after a rotation
	PrevSecretUntil *time.Time
	ExpiresAt       time.Time
	Status          string
	Suspended       bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
	Delivery
}

// Delivery is the part of a subscription its delivery worker owns.
type Delivery struct {
	// Cursor is the watermark: every event at or before it has been
	// acknowledged by the endpoint or given up on.
	Cursor          int64
	FailureCount    int
	FailedSince     *time.Time
	LastDeliveryAt  *time.Time
	LastError       string
	PendingSeq      int64 // the event being delivered, 0 for none
	PendingMsgID    string
	PendingAttempts int
	PendingSince    *time.Time
	NextAttemptAt   *time.Time
}

const subCols = `id, identity_id, COALESCE(family_id, ''), COALESCE(client_id, ''), event_name, arguments, COALESCE(channel_id, ''), channel_name, url, secret, COALESCE(prev_secret, ''), prev_secret_until, cursor, expires_at, status, suspended, failure_count, failed_since, last_delivery_at, COALESCE(last_error, ''), COALESCE(pending_seq, 0), COALESCE(pending_msg_id, ''), pending_attempts, pending_since, next_attempt_at, created_at, updated_at`

func scanSub(sc interface{ Scan(...any) error }) (Subscription, error) {
	var (
		s                                                       Subscription
		prevUntil, failedSince, lastDelivery, pendSince, nextAt sql.NullInt64
		expires, created, updated                               int64
	)
	err := sc.Scan(&s.ID, &s.IdentityID, &s.FamilyID, &s.ClientID, &s.EventName, &s.Arguments, &s.ChannelID, &s.ChannelName, &s.URL, &s.Secret, &s.PrevSecret, &prevUntil,
		&s.Cursor, &expires, &s.Status, &s.Suspended, &s.FailureCount, &failedSince, &lastDelivery, &s.LastError, &s.PendingSeq, &s.PendingMsgID, &s.PendingAttempts, &pendSince, &nextAt, &created, &updated)
	s.PrevSecretUntil, s.FailedSince, s.LastDeliveryAt, s.PendingSince, s.NextAttemptAt = ms(prevUntil), ms(failedSince), ms(lastDelivery), ms(pendSince), ms(nextAt)
	s.ExpiresAt, s.CreatedAt, s.UpdatedAt = at(expires), at(created), at(updated)
	return s, err
}

func scanSubs(rows *sql.Rows, err error) ([]Subscription, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Subscription{}
	for rows.Next() {
		s, err := scanSub(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func msPtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return t.UnixMilli()
}

func strOrNull(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// GetSubscription is a subscription by id.
func (s *Store) GetSubscription(ctx context.Context, id string) (Subscription, error) {
	sub, err := scanSub(s.db.QueryRowContext(ctx, `SELECT `+subCols+` FROM event_subscriptions WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Subscription{}, ErrNotFound
	}
	return sub, err
}

// PutSubscription writes a fresh subscription, replacing any lapsed one
// with the same id.
func (s *Store) PutSubscription(ctx context.Context, sub Subscription) error {
	now := s.nowMS()
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO event_subscriptions (id, identity_id, family_id, client_id, event_name, arguments, channel_id, channel_name, url, secret, prev_secret, prev_secret_until, cursor, expires_at, status, suspended, failure_count, failed_since, last_delivery_at, last_error, pending_seq, pending_msg_id, pending_attempts, pending_since, next_attempt_at, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, 0, 0, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, ?, ?)`,
		sub.ID, sub.IdentityID, strOrNull(sub.FamilyID), strOrNull(sub.ClientID), sub.EventName, sub.Arguments, strOrNull(sub.ChannelID), sub.ChannelName, sub.URL, sub.Secret,
		sub.Cursor, sub.ExpiresAt.UnixMilli(), SubActive, now, now)
	return err
}

// RefreshSubscription renews a live subscription in place: a new TTL, the
// latest secret (keeping the old one for dual signing until prevUntil when
// it changed), the refreshing authorization, and delivery resumed.
func (s *Store) RefreshSubscription(ctx context.Context, id, secret string, prevUntil time.Time, expires time.Time, familyID, clientID string) error {
	return affected(s.db.ExecContext(ctx, `UPDATE event_subscriptions SET
  prev_secret = CASE WHEN secret != ? THEN secret ELSE prev_secret END,
  prev_secret_until = CASE WHEN secret != ? THEN ? ELSE prev_secret_until END,
  secret = ?, expires_at = ?, suspended = 0, family_id = ?, client_id = ?, updated_at = ?
WHERE id = ? AND status IN ('active', 'failing')`,
		secret, secret, prevUntil.UnixMilli(), secret, expires.UnixMilli(), strOrNull(familyID), strOrNull(clientID), s.nowMS(), id))
}

// SaveDelivery writes the worker's state of a live subscription.
func (s *Store) SaveDelivery(ctx context.Context, id string, status string, d Delivery) error {
	var pending any
	if d.PendingSeq > 0 {
		pending = d.PendingSeq
	}
	_, err := s.db.ExecContext(ctx, `UPDATE event_subscriptions SET cursor = ?, status = ?, failure_count = ?, failed_since = ?, last_delivery_at = ?, last_error = ?, pending_seq = ?, pending_msg_id = ?, pending_attempts = ?, pending_since = ?, next_attempt_at = ?, updated_at = ?
WHERE id = ? AND status IN ('active', 'failing')`,
		d.Cursor, status, d.FailureCount, msPtr(d.FailedSince), msPtr(d.LastDeliveryAt), strOrNull(d.LastError), pending, strOrNull(d.PendingMsgID), d.PendingAttempts, msPtr(d.PendingSince), msPtr(d.NextAttemptAt), s.nowMS(), id)
	return err
}

// Suspend stops delivery to a subscription until its next refresh.
func (s *Store) Suspend(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE event_subscriptions SET suspended = 1, updated_at = ? WHERE id = ?`, s.nowMS(), id)
	return err
}

// LiveSubscriptions is every subscription the worker should deliver to:
// active or failing, not suspended, not past its TTL.
func (s *Store) LiveSubscriptions(ctx context.Context) ([]Subscription, error) {
	return scanSubs(s.db.QueryContext(ctx, `SELECT `+subCols+` FROM event_subscriptions WHERE status IN ('active', 'failing') AND suspended = 0 AND expires_at > ? ORDER BY created_at`, s.nowMS()))
}

// ListSubscriptions is an identity's subscriptions, newest first.
func (s *Store) ListSubscriptions(ctx context.Context, identityID string) ([]Subscription, error) {
	return scanSubs(s.db.QueryContext(ctx, `SELECT `+subCols+` FROM event_subscriptions WHERE identity_id = ? ORDER BY created_at DESC, id`, identityID))
}

// SubscriptionsWhere is the live subscriptions of a channel, identity or
// authorization (exactly one of them non-empty).
func (s *Store) SubscriptionsWhere(ctx context.Context, channelID, identityID, familyID string) ([]Subscription, error) {
	q := `SELECT ` + subCols + ` FROM event_subscriptions WHERE status IN ('active', 'failing') AND `
	switch {
	case channelID != "":
		return scanSubs(s.db.QueryContext(ctx, q+`channel_id = ?`, channelID))
	case identityID != "":
		return scanSubs(s.db.QueryContext(ctx, q+`identity_id = ?`, identityID))
	default:
		return scanSubs(s.db.QueryContext(ctx, q+`family_id = ?`, familyID))
	}
}

// Terminate marks a subscription ended by the server.
func (s *Store) Terminate(ctx context.Context, id, reason string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE event_subscriptions SET status = 'terminated', last_error = COALESCE(?, last_error), pending_seq = NULL, next_attempt_at = NULL, updated_at = ? WHERE id = ?`, strOrNull(reason), s.nowMS(), id)
	return err
}

// DeleteSubscription deletes one of an identity's subscriptions.
func (s *Store) DeleteSubscription(ctx context.Context, identityID, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM event_subscriptions WHERE identity_id = ? AND id = ?`, identityID, id))
}

// ExpireSubscriptions marks the live subscriptions past their TTL expired,
// and deletes ended ones a week after they ended.
func (s *Store) ExpireSubscriptions(ctx context.Context) (int64, error) {
	now := s.nowMS()
	res, err := s.db.ExecContext(ctx, `UPDATE event_subscriptions SET status = 'expired', pending_seq = NULL, next_attempt_at = NULL, updated_at = ? WHERE status IN ('active', 'failing') AND expires_at <= ?`, now, now)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	week := int64(7 * 24 * time.Hour / time.Millisecond)
	if _, err := s.db.ExecContext(ctx, `DELETE FROM event_subscriptions WHERE status IN ('expired', 'terminated') AND updated_at <= ?`, now-week); err != nil {
		return n, err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM webhook_verifications WHERE verified_at <= ?`, now-week); err != nil {
		return n, err
	}
	return n, nil
}

// Verified reports whether an identity's intent to receive at url was
// confirmed since after.
func (s *Store) Verified(ctx context.Context, identityID, url string, after time.Time) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM webhook_verifications WHERE identity_id = ? AND url = ? AND verified_at > ?`, identityID, url, after.UnixMilli()).Scan(&n)
	return n > 0, err
}

// MarkVerified records a successful verification of (identity, url).
func (s *Store) MarkVerified(ctx context.Context, identityID, url string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO webhook_verifications (identity_id, url, verified_at) VALUES (?, ?, ?) ON CONFLICT(identity_id, url) DO UPDATE SET verified_at = excluded.verified_at`, identityID, url, s.nowMS())
	return err
}
