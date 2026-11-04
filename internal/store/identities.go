package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/idgen"
)

// Identity is an agent identity: the owner of webhooks, channels, OAuth
// grants and subscriptions. Every MCP token is bound to one.
type Identity struct {
	ID        string
	Name      string
	CreatedAt time.Time
}

// IdentityInfo is an identity with the counts the admin UI shows.
type IdentityInfo struct {
	Identity
	WebhookCount       int
	ChannelCount       int
	AuthorizationCount int
	LastEventAt        *time.Time
}

const identityInfoSelect = `
SELECT i.id, i.name, i.created_at,
  (SELECT COUNT(*) FROM webhooks w WHERE w.identity_id = i.id),
  (SELECT COUNT(*) FROM channels c WHERE c.identity_id = i.id),
  (SELECT COUNT(*) FROM oauth_families f WHERE f.identity_id = i.id AND f.revoked_at IS NULL),
  (SELECT MAX(e.received_at) FROM events e WHERE e.identity_id = i.id)
FROM identities i`

func scanIdentityInfo(sc interface{ Scan(...any) error }) (IdentityInfo, error) {
	var (
		v       IdentityInfo
		created int64
		last    sql.NullInt64
	)
	err := sc.Scan(&v.ID, &v.Name, &created, &v.WebhookCount, &v.ChannelCount, &v.AuthorizationCount, &last)
	v.CreatedAt = at(created)
	v.LastEventAt = ms(last)
	return v, err
}

// CreateIdentity adds an identity; ErrConflict if the name is taken.
func (s *Store) CreateIdentity(ctx context.Context, name string) (Identity, error) {
	v := Identity{ID: idgen.ID("idn"), Name: name, CreatedAt: at(s.nowMS())}
	_, err := s.db.ExecContext(ctx, `INSERT INTO identities (id, name, created_at) VALUES (?, ?, ?)`, v.ID, v.Name, v.CreatedAt.UnixMilli())
	if isUnique(err) {
		return Identity{}, ErrConflict
	}
	return v, err
}

// ListIdentities is every identity, oldest first.
func (s *Store) ListIdentities(ctx context.Context) ([]IdentityInfo, error) {
	rows, err := s.db.QueryContext(ctx, identityInfoSelect+` ORDER BY i.created_at, i.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IdentityInfo{}
	for rows.Next() {
		v, err := scanIdentityInfo(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetIdentity is the identity with that id.
func (s *Store) GetIdentity(ctx context.Context, id string) (IdentityInfo, error) {
	v, err := scanIdentityInfo(s.db.QueryRowContext(ctx, identityInfoSelect+` WHERE i.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return IdentityInfo{}, ErrNotFound
	}
	return v, err
}

// RenameIdentity renames an identity; ErrConflict if the name is taken.
func (s *Store) RenameIdentity(ctx context.Context, id, name string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE identities SET name = ? WHERE id = ?`, name, id)
	if isUnique(err) {
		return ErrConflict
	}
	return affected(res, err)
}

// DeleteIdentity deletes an identity and, by cascade, its webhooks,
// channels, grants, subscriptions and events.
func (s *Store) DeleteIdentity(ctx context.Context, id string) error {
	return affected(s.db.ExecContext(ctx, `DELETE FROM identities WHERE id = ?`, id))
}

// affected turns "no row changed" into ErrNotFound.
func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}
