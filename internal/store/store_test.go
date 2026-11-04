package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/sqlitedb"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "mwe.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrateTwice(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "mwe.db")
	for i := 0; i < 2; i++ {
		s, err := Open(context.Background(), p)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		s.Close()
	}
}

func TestIdentityLifecycle(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	a, err := s.CreateIdentity(ctx, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateIdentity(ctx, "laptop"); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name: %v, want ErrConflict", err)
	}
	if err := s.RenameIdentity(ctx, a.ID, "desk"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetIdentity(ctx, a.ID)
	if err != nil || got.Name != "desk" {
		t.Fatalf("get = %+v, %v", got, err)
	}
	if err := s.DeleteIdentity(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetIdentity(ctx, a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete: %v", err)
	}
}

func TestEventsHeadAndPrune(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	s.SetClock(func() time.Time { return now })
	idn, _ := s.CreateIdentity(ctx, "a")
	for i := 0; i < 5; i++ {
		_, err := s.InsertEvent(ctx, Event{ID: "evt_" + string(rune('a'+i)), IdentityID: idn.ID, Identifier: "x", Kind: "webhook", ReceivedAt: now.Add(time.Duration(i) * time.Hour), Data: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
	}
	if h, _ := s.Head(ctx); h != 5 {
		t.Fatalf("head = %d", h)
	}
	n, err := s.PruneEvents(ctx, now.Add(2*time.Hour+time.Minute))
	if err != nil || n != 3 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	if p, _ := s.PrunedThrough(ctx); p != 3 {
		t.Fatalf("pruned through = %d", p)
	}
	if h, _ := s.Head(ctx); h != 5 {
		t.Fatalf("head after prune = %d", h)
	}
	// a deleted top event's seq isn't reused
	if _, err := s.DB().Exec(`DELETE FROM events WHERE seq = 5`); err != nil {
		t.Fatal(err)
	}
	e, _ := s.InsertEvent(ctx, Event{ID: "evt_z", Identifier: ":system", Kind: "system", ReceivedAt: now, Data: json.RawMessage(`{}`)})
	if e.Seq != 6 {
		t.Fatalf("seq after deleting the top = %d, want 6", e.Seq)
	}
	evs, err := s.EventsFor(ctx, "idn_other", 0, 10, 10)
	if err != nil || len(evs) != 1 || evs[0].ID != "evt_z" {
		t.Fatalf("another identity sees %+v, %v; want only the broadcast", evs, err)
	}
}

// A database made before CIMD (schema 1) upgrades in place: its clients
// become dcr clients and keep working.
func TestMigrateFromSchema1(t *testing.T) {
	ctx := context.Background()
	p := filepath.Join(t.TempDir(), "old.db")
	db, err := sqlitedb.Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`,
		migrations[0],
		`INSERT INTO meta (key, value) VALUES ('schema_version', '1')`,
		`INSERT INTO oauth_clients (client_id, client_name, redirect_uris, token_endpoint_auth_method, grant_types, created_at) VALUES ('cli_old', 'Old', '["http://127.0.0.1/cb"]', 'none', '["authorization_code"]', 1)`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	s, err := Open(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	c, err := s.GetClient(ctx, "cli_old")
	if err != nil || c.Kind != ClientDCR || c.Name != "Old" || c.MetadataFetchedAt != nil {
		t.Fatalf("old client after the upgrade = %+v, %v", c, err)
	}
}

func TestPutCIMDClient(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	fresh := now.Add(time.Hour)
	c := Client{ID: "https://app.example/client.json", Name: "App", RedirectURIs: []string{"http://127.0.0.1/cb"}, TokenAuthMethod: "none",
		GrantTypes: []string{"authorization_code"}, ClientURI: "https://app.example", Metadata: json.RawMessage(`{"client_id":"x"}`), MetadataFetchedAt: &now, MetadataFreshUntil: &fresh}
	if err := s.PutCIMDClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.Name = "App 2"
	if err := s.PutCIMDClient(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetClient(ctx, c.ID)
	if err != nil || got.Kind != ClientCIMD || got.Name != "App 2" || !got.MetadataFreshUntil.Equal(fresh) || got.ClientURI != "https://app.example" || string(got.Metadata) != `{"client_id":"x"}` {
		t.Fatalf("CIMD client = %+v, %v", got, err)
	}
	// a dynamically registered client is never overwritten
	if err := s.CreateClient(ctx, Client{ID: "cli_x", Name: "DCR", RedirectURIs: []string{"https://a/cb"}, TokenAuthMethod: "none", GrantTypes: []string{"authorization_code"}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCIMDClient(ctx, Client{ID: "cli_x", Name: "Hijack", RedirectURIs: []string{"https://evil/cb"}, TokenAuthMethod: "none"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.GetClient(ctx, "cli_x"); got.Name != "DCR" || got.Kind != ClientDCR {
		t.Fatalf("PutCIMDClient overwrote a DCR client: %+v", got)
	}
}
