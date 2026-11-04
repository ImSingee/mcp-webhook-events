package events

import (
	"sync"
	"sync/atomic"
)

// Hub tells the readers of the feed (push streams, the admin UI's live
// view, the webhook delivery worker) that something they read has
// changed: a new event, an edited channel, or a subscription that has
// to end.
type Hub struct {
	mu   sync.Mutex
	subs map[*Sub]struct{}
}

// NewHub is an empty hub.
func NewHub() *Hub { return &Hub{subs: map[*Sub]struct{}{}} }

// Sub is one reader. Wake receives (coalesced) whenever the reader should
// look again; Dirty and Ended say why beyond "new events".
type Sub struct {
	// Wake has room for one signal, so a burst of changes wakes the
	// reader once and a slow reader never blocks the hub.
	Wake <-chan struct{}
	wake chan struct{}

	IdentityID string // "" for a reader of every identity's events
	ChannelID  string // "" for a reader not bound to a channel
	FamilyID   string // the authorization the reader came with, if any

	dirty atomic.Bool
	ended atomic.Pointer[ErrorObject]
}

// Subscribe adds a reader.
func (h *Hub) Subscribe(identityID, channelID, familyID string) *Sub {
	w := make(chan struct{}, 1)
	s := &Sub{Wake: w, wake: w, IdentityID: identityID, ChannelID: channelID, FamilyID: familyID}
	h.mu.Lock()
	h.subs[s] = struct{}{}
	h.mu.Unlock()
	return s
}

// Unsubscribe removes a reader.
func (h *Hub) Unsubscribe(s *Sub) {
	h.mu.Lock()
	delete(h.subs, s)
	h.mu.Unlock()
}

func (s *Sub) poke() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// TakeDirty reports whether the reader's channel changed since it last
// asked, and clears it.
func (s *Sub) TakeDirty() bool { return s.dirty.Swap(false) }

// Ended is why the reader's subscription has to end, nil while it may go
// on.
func (s *Sub) Ended() *ErrorObject { return s.ended.Load() }

func (h *Hub) each(f func(*Sub)) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.subs {
		f(s)
	}
}

// Published wakes every reader: there are new events.
func (h *Hub) Published() { h.each((*Sub).poke) }

// ChannelChanged tells the readers of a channel to read its rule again.
func (h *Hub) ChannelChanged(channelID string) {
	h.each(func(s *Sub) {
		if s.ChannelID == channelID {
			s.dirty.Store(true)
			s.poke()
		}
	})
}

// End ends the subscriptions of the readers match picks, with why.
func (h *Hub) End(match func(*Sub) bool, why ErrorObject) {
	h.each(func(s *Sub) {
		if match(s) {
			w := why
			s.ended.CompareAndSwap(nil, &w)
			s.poke()
		}
	})
}

// OnChannel counts the readers bound to a channel: its live push streams.
func (h *Hub) OnChannel(channelID string) int {
	n := 0
	h.each(func(s *Sub) {
		if s.ChannelID == channelID {
			n++
		}
	})
	return n
}
