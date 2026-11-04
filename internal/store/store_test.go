package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
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
