package admin

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/httpx"
)

// eventStream is the admin UI's live event view: an SSE stream with an
// "event" frame per new event (optionally of one identity, or
// "_broadcast"), and a ": ping" comment every 20 seconds.
func (s *Server) eventStream(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	identity := r.URL.Query().Get("identity_id")
	sub := s.Core.Hub.Subscribe("", "", "")
	defer s.Core.Hub.Unsubscribe(sub)
	pos, err := s.Store.Head(ctx)
	if err != nil {
		s.fail(w, err, "events")
		return
	}
	flush := httpx.SSE(w)
	var mu sync.Mutex
	write := func(b []byte) bool {
		mu.Lock()
		defer mu.Unlock()
		if _, err := w.Write(b); err != nil {
			return false
		}
		return flush() == nil
	}
	if !write([]byte(": connected\n\n")) {
		return
	}
	ping := time.NewTicker(s.Ping)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.Base.Done():
			return
		case <-ping.C:
			if !write([]byte(": ping\n\n")) {
				return
			}
		case <-sub.Wake:
			for {
				head, err := s.Store.Head(ctx)
				if err != nil {
					return
				}
				evs, err := s.Store.EventsAfter(ctx, identity, pos, head, 200)
				if err != nil {
					return
				}
				for _, e := range evs {
					b, _ := json.Marshal(EventView(e))
					if !write(append(append([]byte("event: event\ndata: "), b...), '\n', '\n')) {
						return
					}
				}
				if len(evs) < 200 {
					pos = head
					break
				}
				pos = evs[len(evs)-1].Seq
			}
		}
	}
}
