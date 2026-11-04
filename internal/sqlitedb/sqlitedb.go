// Package sqlitedb is the one way this module reaches SQLite: it opens a
// database with the pragmas the server relies on, and imports modernc's
// driver only after handing modernc's libc a clean environment.
//
// modernc's SQLite runs on modernc's libc, which keeps its own copy of the
// environment, taken from os.Environ at the first getenv. On macOS and the
// BSDs that libc's getenv ends the whole process when it meets an entry with
// no "=" in it (it prints "TODOTODO" and calls os.Exit(1)), where every real
// libc skips the entry. SQLite's first open reads SQLITE_TMPDIR, so the copy
// is cleaned here, before anything can open a database.
package sqlitedb

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"

	"modernc.org/libc"
	_ "modernc.org/sqlite"
)

// init runs before any of the module's own code opens a database, and before
// any goroutine of it, so libc's copy is taken once, here: modernc's
// SetEnviron isn't safe to race with a first getenv.
func init() {
	libc.SetEnviron(nil, wellFormed(os.Environ()))
}

// wellFormed is env without the entries that aren't NAME=value.
func wellFormed(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.Contains(kv, "=") {
			out = append(out, kv)
		}
	}
	return out
}

// Open opens the database file at path in WAL mode with foreign keys on.
// SQLite allows one writer at a time, so the pool holds a single connection
// for writes to queue on rather than fail with SQLITE_BUSY.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	q := url.Values{}
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Set("_txlock", "immediate")
	dsn := "file:" + path + "?" + q.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	return db, nil
}
