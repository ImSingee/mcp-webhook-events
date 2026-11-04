package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

// Event is one received webhook request or platform broadcast. Seq is the
// global, ever-increasing position every cursor is built on.
type Event struct {
	Seq          int64
	ID           string
	IdentityID   string // "" for a platform broadcast
	IdentityName string // filled by reads that join it
	Identifier   string
	Kind         string // webhook or system
	WebhookID    string
	ReceivedAt   time.Time
	Data         json.RawMessage
}

const eventCols = `e.seq, e.id, COALESCE(e.identity_id, ''), COALESCE(i.name, ''), e.identifier, e.kind, COALESCE(e.webhook_id, ''), e.received_at, e.data`

const eventFrom = ` FROM events e LEFT JOIN identities i ON i.id = e.identity_id`

func scanEvent(sc interface{ Scan(...any) error }) (Event, error) {
	var (
		e    Event
		recv int64
		data string
	)
	err := sc.Scan(&e.Seq, &e.ID, &e.IdentityID, &e.IdentityName, &e.Identifier, &e.Kind, &e.WebhookID, &recv, &data)
	e.ReceivedAt = at(recv)
	e.Data = json.RawMessage(data)
	return e, err
}

func scanEvents(rows *sql.Rows, err error) ([]Event, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// InsertEvent stores an event and returns it with its Seq.
func (s *Store) InsertEvent(ctx context.Context, e Event) (Event, error) {
	var identity, webhook any
	if e.IdentityID != "" {
		identity = e.IdentityID
	}
	if e.WebhookID != "" {
		webhook = e.WebhookID
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO events (id, identity_id, identifier, kind, webhook_id, received_at, data) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.ID, identity, e.Identifier, e.Kind, webhook, e.ReceivedAt.UnixMilli(), string(e.Data))
	if err != nil {
		return Event{}, err
	}
	e.Seq, err = res.LastInsertId()
	return e, err
}

// Head is the highest seq ever assigned, 0 before the first event. A
// deleted event's seq is never handed out again (AUTOINCREMENT), so the
// head never moves back.
func (s *Store) Head(ctx context.Context) (int64, error) {
	var n sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT seq FROM sqlite_sequence WHERE name = 'events'`).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return n.Int64, err
}

// PrunedThrough is the highest seq retention has deleted: a cursor below
// it may have missed events.
func (s *Store) PrunedThrough(ctx context.Context) (int64, error) {
	v, err := metaGet(ctx, s.db, "events_pruned_through")
	if err != nil || v == "" {
		return 0, err
	}
	return strconv.ParseInt(v, 10, 64)
}

// EventsFor is up to limit events with after < seq <= upTo that an
// identity can see: its own and the platform's broadcasts, in seq order.
func (s *Store) EventsFor(ctx context.Context, identityID string, after, upTo int64, limit int) ([]Event, error) {
	return scanEvents(s.db.QueryContext(ctx, `SELECT `+eventCols+eventFrom+` WHERE e.seq > ? AND e.seq <= ? AND (e.identity_id = ? OR e.identity_id IS NULL) ORDER BY e.seq LIMIT ?`,
		after, upTo, identityID, limit))
}

// EventsAfter is up to limit events of any identity with after < seq <=
// upTo, in seq order: what the admin UI's live view follows. identityID
// narrows it to one identity ("_broadcast" for broadcasts only).
func (s *Store) EventsAfter(ctx context.Context, identityID string, after, upTo int64, limit int) ([]Event, error) {
	q := `SELECT ` + eventCols + eventFrom + ` WHERE e.seq > ? AND e.seq <= ?`
	args := []any{after, upTo}
	switch identityID {
	case "":
	case "_broadcast":
		q += ` AND e.identity_id IS NULL`
	default:
		q += ` AND e.identity_id = ?`
		args = append(args, identityID)
	}
	q += ` ORDER BY e.seq LIMIT ?`
	return scanEvents(s.db.QueryContext(ctx, q, append(args, limit)...))
}

// SeqBefore is the highest seq of an event received before t (0 if none):
// the position a replay bounded by maxAgeMs starts after.
func (s *Store) SeqBefore(ctx context.Context, t time.Time) (int64, error) {
	var n sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MAX(seq) FROM events WHERE received_at < ?`, t.UnixMilli()).Scan(&n)
	return n.Int64, err
}

// EventFilter narrows the admin event list.
type EventFilter struct {
	IdentityID string // "" for all, "_broadcast" for broadcasts only
	Identifier string
	Before     int64 // only seq < Before when > 0
	Limit      int
}

// ListEvents is events newest first, for the admin UI.
func (s *Store) ListEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	var (
		where []string
		args  []any
	)
	switch f.IdentityID {
	case "":
	case "_broadcast":
		where = append(where, `e.identity_id IS NULL`)
	default:
		where = append(where, `e.identity_id = ?`)
		args = append(args, f.IdentityID)
	}
	if f.Identifier != "" {
		where = append(where, `e.identifier = ?`)
		args = append(args, f.Identifier)
	}
	if f.Before > 0 {
		where = append(where, `e.seq < ?`)
		args = append(args, f.Before)
	}
	q := `SELECT ` + eventCols + eventFrom
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, ` AND `)
	}
	q += ` ORDER BY e.seq DESC LIMIT ?`
	return scanEvents(s.db.QueryContext(ctx, q, append(args, f.Limit)...))
}

// GetEvent is an event by id.
func (s *Store) GetEvent(ctx context.Context, id string) (Event, error) {
	e, err := scanEvent(s.db.QueryRowContext(ctx, `SELECT `+eventCols+eventFrom+` WHERE e.id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Event{}, ErrNotFound
	}
	return e, err
}

// PruneEvents deletes the events received before cutoff, as a prefix of
// seq so that PrunedThrough tells exactly which positions are gone. It
// returns how many were deleted.
func (s *Store) PruneEvents(ctx context.Context, cutoff time.Time) (int64, error) {
	var deleted int64
	err := s.inTx(ctx, func(tx *sql.Tx) error {
		var through sql.NullInt64
		if err := tx.QueryRowContext(ctx, `SELECT MAX(seq) FROM events WHERE received_at < ?`, cutoff.UnixMilli()).Scan(&through); err != nil {
			return err
		}
		if !through.Valid {
			return nil
		}
		res, err := tx.ExecContext(ctx, `DELETE FROM events WHERE seq <= ?`, through.Int64)
		if err != nil {
			return err
		}
		deleted, _ = res.RowsAffected()
		prev, err := metaGet(ctx, tx, "events_pruned_through")
		if err != nil {
			return err
		}
		if p, _ := strconv.ParseInt(prev, 10, 64); p >= through.Int64 {
			return nil
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO meta (key, value) VALUES ('events_pruned_through', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, strconv.FormatInt(through.Int64, 10))
		return err
	})
	return deleted, err
}
