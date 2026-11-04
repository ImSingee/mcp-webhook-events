// Package store keeps the server's state in SQLite: identities, OAuth
// clients and grants, admin sessions, webhooks, channels, events and
// webhook-mode event subscriptions.
//
// Times are stored as Unix milliseconds. Secrets (tokens, webhook keys,
// session ids, authorization codes) are stored only as hashes.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/sqlitedb"
)

var (
	// ErrNotFound is a row that doesn't exist (or isn't the caller's).
	ErrNotFound = errors.New("not found")
	// ErrConflict is a write that would break a uniqueness rule.
	ErrConflict = errors.New("conflict")
)

// Store is the database and the clock its rows are stamped by.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens (creating if needed) the database at path and migrates it.
func Open(ctx context.Context, path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
	}
	// the database holds webhook-mode signing secrets: readable by the
	// server's user only (SQLite would create it 0644)
	if f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600); err == nil {
		f.Close()
	}
	db, err := sqlitedb.Open(ctx, path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// SetClock replaces the store's clock, for tests.
func (s *Store) SetClock(now func() time.Time) { s.now = now }

// Now is the store's clock.
func (s *Store) Now() time.Time { return s.now() }

func (s *Store) nowMS() int64 { return s.now().UnixMilli() }

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// DB is the underlying database, for tests.
func (s *Store) DB() *sql.DB { return s.db }

// migrations are applied in order, each once; the meta table remembers
// how many have run.
var migrations = []string{
	`
CREATE TABLE identities (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL
);

CREATE TABLE oauth_clients (
  client_id TEXT PRIMARY KEY,
  client_secret_hash TEXT,
  client_name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  token_endpoint_auth_method TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE oauth_requests (
  id TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  state TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE oauth_families (
  id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);
CREATE INDEX oauth_families_identity ON oauth_families(identity_id);

CREATE TABLE oauth_codes (
  code_hash TEXT PRIMARY KEY,
  client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  scope TEXT NOT NULL,
  resource TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  family_id TEXT
);

CREATE TABLE oauth_tokens (
  token_hash TEXT PRIMARY KEY,
  kind TEXT NOT NULL CHECK (kind IN ('access', 'refresh')),
  family_id TEXT NOT NULL REFERENCES oauth_families(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  revoked_at INTEGER
);
CREATE INDEX oauth_tokens_family ON oauth_tokens(family_id);

CREATE TABLE admin_sessions (
  id_hash TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE webhooks (
  id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  identifier TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  path_token TEXT NOT NULL UNIQUE,
  key_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (identity_id, identifier)
);

CREATE TABLE channels (
  id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  mode TEXT NOT NULL CHECK (mode IN ('all', 'include', 'exclude')),
  identifiers TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE (identity_id, name)
);

CREATE TABLE events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  id TEXT NOT NULL UNIQUE,
  identity_id TEXT REFERENCES identities(id) ON DELETE CASCADE,
  identifier TEXT NOT NULL,
  kind TEXT NOT NULL,
  webhook_id TEXT REFERENCES webhooks(id) ON DELETE SET NULL,
  received_at INTEGER NOT NULL,
  data TEXT NOT NULL
);
CREATE INDEX events_identity ON events(identity_id, seq);
CREATE INDEX events_webhook ON events(webhook_id, seq);
CREATE INDEX events_received ON events(received_at);

CREATE TABLE event_subscriptions (
  id TEXT PRIMARY KEY,
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  family_id TEXT,
  client_id TEXT,
  event_name TEXT NOT NULL,
  arguments TEXT NOT NULL,
  channel_id TEXT REFERENCES channels(id) ON DELETE SET NULL,
  channel_name TEXT NOT NULL,
  url TEXT NOT NULL,
  secret TEXT NOT NULL,
  prev_secret TEXT,
  prev_secret_until INTEGER,
  cursor INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  status TEXT NOT NULL,
  suspended INTEGER NOT NULL DEFAULT 0,
  failure_count INTEGER NOT NULL DEFAULT 0,
  failed_since INTEGER,
  last_delivery_at INTEGER,
  last_error TEXT,
  pending_seq INTEGER,
  pending_msg_id TEXT,
  pending_attempts INTEGER NOT NULL DEFAULT 0,
  pending_since INTEGER,
  next_attempt_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX event_subscriptions_identity ON event_subscriptions(identity_id);
CREATE INDEX event_subscriptions_channel ON event_subscriptions(channel_id);

CREATE TABLE webhook_verifications (
  identity_id TEXT NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
  url TEXT NOT NULL,
  verified_at INTEGER NOT NULL,
  PRIMARY KEY (identity_id, url)
);
`,
	// CIMD (Client ID Metadata Document) clients: identified by their
	// https URL, with the last document fetched and validated kept as a
	// snapshot, and how long it stays fresh by its HTTP cache headers.
	`
ALTER TABLE oauth_clients ADD COLUMN kind TEXT NOT NULL DEFAULT 'dcr';
ALTER TABLE oauth_clients ADD COLUMN client_uri TEXT;
ALTER TABLE oauth_clients ADD COLUMN logo_uri TEXT;
ALTER TABLE oauth_clients ADD COLUMN metadata TEXT;
ALTER TABLE oauth_clients ADD COLUMN metadata_fetched_at INTEGER;
ALTER TABLE oauth_clients ADD COLUMN metadata_fresh_until INTEGER;
`,
}

func (s *Store) migrate(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		return err
	}
	var applied int
	err := s.db.QueryRowContext(ctx, `SELECT CAST(value AS INTEGER) FROM meta WHERE key = 'schema_version'`).Scan(&applied)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if applied > len(migrations) {
		return fmt.Errorf("database schema version %d is newer than this build knows (%d): upgrade mwe-server", applied, len(migrations))
	}
	for i := applied; i < len(migrations); i++ {
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES ('schema_version', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, fmt.Sprint(i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// isUnique reports whether err is a UNIQUE or PRIMARY KEY violation.
func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// inTx runs f in a transaction, committing when it returns nil.
func (s *Store) inTx(ctx context.Context, f func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := f(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// ms converts a nullable millisecond column to a time pointer.
func ms(v sql.NullInt64) *time.Time {
	if !v.Valid {
		return nil
	}
	t := time.UnixMilli(v.Int64).UTC()
	return &t
}

// at converts milliseconds to a UTC time.
func at(v int64) time.Time { return time.UnixMilli(v).UTC() }

func metaGet(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, key string) (string, error) {
	var v string
	err := q.QueryRowContext(ctx, `SELECT value FROM meta WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}
