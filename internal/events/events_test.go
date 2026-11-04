package events

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/store"
)

func TestFilterMatch(t *testing.T) {
	ev := func(identity, identifier string) store.Event {
		return store.Event{IdentityID: identity, Identifier: identifier}
	}
	all := Filter{IdentityID: "a", Mode: "all"}
	inc := Filter{IdentityID: "a", Mode: "include", Identifiers: []string{"gh", ":ops"}}
	exc := Filter{IdentityID: "a", Mode: "exclude", Identifiers: []string{"gh"}}
	cases := []struct {
		f    Filter
		e    store.Event
		want bool
	}{
		{all, ev("a", "gh"), true},
		{all, ev("b", "gh"), false},
		{inc, ev("a", "gh"), true},
		{inc, ev("a", "ci"), false},
		{inc, ev("a", ":ops"), true},
		{exc, ev("a", "gh"), false},
		{exc, ev("a", "ci"), true},
		{exc, ev("b", "ci"), false},
		// a broadcast passes every rule
		{all, ev("", ":system"), true},
		{inc, ev("", ":system"), true},
		{exc, ev("", ":system"), true},
		{Filter{IdentityID: "a", Mode: "exclude", Identifiers: []string{":system"}}, ev("", ":system"), true},
		{Filter{IdentityID: "a", Mode: "bogus"}, ev("a", "gh"), false},
	}
	for _, tc := range cases {
		if got := tc.f.Match(tc.e); got != tc.want {
			t.Errorf("%+v.Match(%+v) = %v, want %v", tc.f, tc.e, got, tc.want)
		}
	}
}

func TestCursor(t *testing.T) {
	for _, n := range []int64{0, 1, 1 << 40} {
		got, err := DecodeCursor(EncodeCursor(n))
		if err != nil || got != n {
			t.Errorf("round trip %d = %d, %v", n, got, err)
		}
	}
	for _, c := range []string{"", "abc", "bXdlMTp4", "bXdlMTotMQ", "!!"} {
		if _, err := DecodeCursor(c); err == nil {
			t.Errorf("DecodeCursor(%q) took it", c)
		}
	}
}

func TestResolve(t *testing.T) {
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	st.SetClock(func() time.Time { return now })
	idn, _ := st.CreateIdentity(ctx, "a")
	f := Filter{IdentityID: idn.ID, Mode: "all"}
	add := func(at time.Time, identity string) {
		_, err := st.InsertEvent(ctx, store.Event{ID: "evt_" + at.Format("150405.000") + identity, IdentityID: identity, Identifier: "gh", Kind: "webhook", ReceivedAt: at, Data: json.RawMessage(`{}`)})
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		add(now.Add(time.Duration(i-10)*time.Minute), idn.ID) // seq 1..4, 10..7 minutes ago
	}
	s, _ := Resolve(ctx, st, f, nil, nil)
	if s.Seq != 4 || s.Truncated {
		t.Errorf("null cursor = %+v", s)
	}
	c := EncodeCursor(1)
	s, _ = Resolve(ctx, st, f, &c, nil)
	if s.Seq != 1 || s.Truncated {
		t.Errorf("cursor 1 = %+v", s)
	}
	// maxAgeMs of 8 minutes skips seq 2 (9 minutes ago): truncated
	age := int64(8 * time.Minute / time.Millisecond)
	s, _ = Resolve(ctx, st, f, &c, &age)
	if s.Seq != 2 || !s.Truncated {
		t.Errorf("maxAge 8m = %+v", s)
	}
	// a future cursor resets to the head
	fut := EncodeCursor(99)
	if s, _ = Resolve(ctx, st, f, &fut, nil); s.Seq != 4 || !s.Truncated {
		t.Errorf("future cursor = %+v", s)
	}
	// below retention
	if _, err := st.PruneEvents(ctx, now.Add(-8*time.Minute-time.Second)); err != nil {
		t.Fatal(err)
	}
	if s, _ = Resolve(ctx, st, f, &c, nil); s.Seq != 2 || !s.Truncated {
		t.Errorf("pruned cursor = %+v", s)
	}
	// Next reads past events of others and reports how far it read
	other, _ := st.CreateIdentity(ctx, "b")
	add(now, other.ID)
	add(now, idn.ID)
	evs, scanned, err := Next(ctx, st, f, 4, 6, 0, 0)
	if err != nil || len(evs) != 1 || evs[0].Seq != 6 || scanned != 6 {
		t.Errorf("Next = %v %d %v", evs, scanned, err)
	}
	evs, scanned, _ = Next(ctx, st, f, 2, 6, 1, 0)
	if len(evs) != 1 || evs[0].Seq != 3 || scanned != 3 {
		t.Errorf("Next limit 1 = %v %d", evs, scanned)
	}
}

func TestHub(t *testing.T) {
	h := NewHub()
	a := h.Subscribe("i1", "c1", "f1")
	b := h.Subscribe("i2", "c2", "f2")
	h.Published()
	h.Published()
	for _, s := range []*Sub{a, b} {
		select {
		case <-s.Wake:
		default:
			t.Fatal("not woken")
		}
		select {
		case <-s.Wake:
			t.Fatal("two wakes were not coalesced")
		default:
		}
	}
	h.ChannelChanged("c1")
	if !a.TakeDirty() || a.TakeDirty() || b.TakeDirty() {
		t.Error("ChannelChanged")
	}
	h.End(func(s *Sub) bool { return s.FamilyID == "f2" }, AccessRevoked("x"))
	if a.Ended() != nil || b.Ended() == nil || b.Ended().Code != CodeForbidden {
		t.Error("End")
	}
	if h.OnChannel("c1") != 1 {
		t.Error("OnChannel")
	}
	h.Unsubscribe(a)
	if h.OnChannel("c1") != 0 {
		t.Error("Unsubscribe")
	}
}
