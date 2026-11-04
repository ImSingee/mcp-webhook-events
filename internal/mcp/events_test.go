package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/apptest"
)

var jsonMarshal = json.Marshal

const ev = "webhook.received"

func sub(channel string, cursor any) map[string]any {
	return map[string]any{"name": ev, "arguments": map[string]any{"channel": channel}, "cursor": cursor}
}

func TestEventsList(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	res := m.Call("events/list", nil)
	evs := res["events"].([]any)
	d := evs[0].(map[string]any)
	if len(evs) != 1 || d["name"] != ev || res["resultType"] != "complete" || res["nextCursor"] != nil {
		t.Fatalf("events/list = %v", res)
	}
	if len(d["delivery"].([]any)) != 3 || d["inputSchema"].(map[string]any)["type"] != "object" || d["payloadSchema"].(map[string]any)["type"] != "object" {
		t.Errorf("descriptor = %v", d)
	}
}

func TestEventErrors(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	cases := []struct {
		name   string
		method string
		params map[string]any
		code   int
	}{
		{"unknown event", "events/poll", map[string]any{"name": "nope.event", "arguments": map[string]any{}, "cursor": nil}, -32023},
		{"unknown channel", "events/poll", sub("nope", nil), -32023},
		{"channel of the wrong type", "events/poll", map[string]any{"name": ev, "arguments": map[string]any{"channel": 12345}}, -32602},
		{"unknown argument", "events/poll", map[string]any{"name": ev, "arguments": map[string]any{"channel": "ci", "x": 1}}, -32602},
		{"no arguments", "events/poll", map[string]any{"name": ev}, -32602},
		{"bad cursor", "events/poll", sub("ci", "not-ours"), -32602},
		{"negative maxAgeMs", "events/poll", map[string]any{"name": ev, "arguments": map[string]any{"channel": "ci"}, "maxAgeMs": -1}, -32602},
		{"maxEvents zero", "events/poll", map[string]any{"name": ev, "arguments": map[string]any{"channel": "ci"}, "maxEvents": 0}, -32602},
		{"stream unknown event", "events/stream", map[string]any{"name": "nope.event", "arguments": map[string]any{}}, -32023},
	}
	for _, tc := range cases {
		_, err := m.Try(tc.method, tc.params)
		if err == nil || err.Code != tc.code {
			t.Errorf("%s: %v, want %d", tc.name, err, tc.code)
		}
	}
	// a stream that can't open is a JSON error, not an SSE stream
	st := m.Open("events/stream", sub("nope", nil))
	if ct := st.Resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("failed stream Content-Type = %q", ct)
	}
	if f := st.Next(time.Second); f["error"] == nil {
		t.Errorf("failed stream = %v", f)
	}
}

// Poll: a null cursor starts from now; later polls page through the
// backlog with hasMore; an absent cursor is a null one.
func TestPollPagination(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	apptest.Send(t, url, key, `{"before":true}`)
	first := m.Call("events/poll", sub("ci", nil))
	if len(first["events"].([]any)) != 0 || first["hasMore"] != false || first["truncated"] != false || first["nextPollMs"] == nil || first["cursor"] == nil {
		t.Fatalf("bootstrap poll = %v", first)
	}
	absent := m.Call("events/poll", map[string]any{"name": ev, "arguments": map[string]any{"channel": "ci"}})
	if len(absent["events"].([]any)) != 0 {
		t.Errorf("an absent cursor replayed: %v", absent)
	}
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, apptest.Send(t, url, key, fmt.Sprintf(`{"n":%d}`, i)))
	}
	cursor := first["cursor"]
	var got []string
	for page := 0; ; page++ {
		p := map[string]any{"name": ev, "arguments": map[string]any{"channel": "ci"}, "cursor": cursor, "maxEvents": 2}
		r := m.Call("events/poll", p)
		for _, e := range r["events"].([]any) {
			o := e.(map[string]any)
			if o["cursor"] != nil || o["name"] != ev || o["timestamp"] == nil {
				t.Errorf("poll occurrence = %v", o)
			}
			got = append(got, o["eventId"].(string))
		}
		cursor = r["cursor"]
		if r["hasMore"] == false {
			if page != 2 {
				t.Errorf("drained in %d pages, want 3", page+1)
			}
			break
		}
		if len(r["events"].([]any)) != 2 {
			t.Fatalf("a hasMore page with %d events", len(r["events"].([]any)))
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(ids) {
		t.Fatalf("polled %v, want %v", got, ids)
	}
	// nothing new: an empty page whose cursor is still good
	r := m.Call("events/poll", sub("ci", cursor))
	if len(r["events"].([]any)) != 0 || r["cursor"] != cursor {
		t.Errorf("quiet poll = %v", r)
	}
}

// Push: active first, then the replay after the cursor, then live events,
// with heartbeats carrying the cursor between them, every frame tagged with
// the request id.
func TestStreamFrameOrder(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	start := m.Call("events/poll", sub("ci", nil))["cursor"]
	a := apptest.Send(t, url, key, `{"replay":1}`)
	b := apptest.Send(t, url, key, `{"replay":2}`)
	st := m.Open("events/stream", sub("ci", start))
	if ct := st.Resp.Header.Get("Content-Type"); ct != "text/event-stream" || st.Resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("stream headers: %v", st.Resp.Header)
	}
	f := st.Next(2 * time.Second)
	if f["method"] != "notifications/events/active" || apptest.Params(f)["cursor"] != start || apptest.Params(f)["truncated"] != false {
		t.Fatalf("first frame = %v", f)
	}
	id := apptest.Params(f)["_meta"].(map[string]any)["io.modelcontextprotocol/subscriptionId"]
	for _, want := range []string{a, b} {
		e := st.NextMethod("notifications/events/event", 2*time.Second)
		if apptest.Params(e)["eventId"] != want {
			t.Fatalf("replay got %v, want %s", apptest.Params(e)["eventId"], want)
		}
	}
	c := apptest.Send(t, url, key, `{"live":1}`)
	e := st.NextMethod("notifications/events/event", 2*time.Second)
	p := apptest.Params(e)
	if p["eventId"] != c || p["name"] != ev || p["cursor"] == nil || apptest.EventData(e)["identifier"] != "gh" {
		t.Fatalf("live event = %v", e)
	}
	hb := st.NextMethod("notifications/events/heartbeat", 2*time.Second)
	if apptest.Params(hb)["cursor"] != p["cursor"] {
		t.Errorf("heartbeat cursor %v, want the last event's %v", apptest.Params(hb)["cursor"], p["cursor"])
	}
	if id == nil || apptest.Params(hb)["_meta"].(map[string]any)["io.modelcontextprotocol/subscriptionId"] != id {
		t.Errorf("heartbeat _meta = %v", apptest.Params(hb)["_meta"])
	}
	// no SSE comments on an events stream: the heartbeat is the keepalive
	st.Close()
	for f := range st.Frames {
		if f["comment"] != nil {
			t.Errorf("SSE comment on an events stream: %v", f)
		}
	}
	// a heartbeat advances the cursor even when nothing matches
	m.Tool("channel_update", map[string]any{"name": "ci", "mode": "exclude", "identifiers": []any{"gh"}})
	st2 := m.Open("events/stream", sub("ci", nil))
	st2.NextMethod("notifications/events/active", time.Second)
	apptest.Send(t, url, key, `{}`)
	hb = st2.NextMethod("notifications/events/heartbeat", 2*time.Second)
	if hb2 := apptest.Params(hb)["cursor"]; hb2 == p["cursor"] {
		t.Errorf("heartbeat cursor didn't advance past a filtered-out event")
	}
}

// A channel edited while a stream is open filters the stream's next event
// by the new rule; a platform broadcast passes any rule.
func TestChannelUpdateTakesEffectAndBroadcastBypasses(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	gh, ghKey := m.Webhook("gh")
	ci, ciKey := m.Webhook("ci-builds")
	m.Tool("channel_create", map[string]any{"name": "main", "mode": "all"})
	st := m.Open("events/stream", sub("main", nil))
	st.NextMethod("notifications/events/active", time.Second)
	apptest.Send(t, gh, ghKey, `{"a":1}`)
	if e := st.NextMethod("notifications/events/event", 2*time.Second); apptest.EventData(e)["identifier"] != "gh" {
		t.Fatalf("all: %v", e)
	}
	m.Tool("channel_update", map[string]any{"name": "main", "mode": "exclude", "identifiers": []any{"gh"}})
	apptest.Send(t, gh, ghKey, `{"excluded":true}`)
	ciID := apptest.Send(t, ci, ciKey, `{"b":1}`)
	if e := st.NextMethod("notifications/events/event", 2*time.Second); apptest.Params(e)["eventId"] != ciID {
		t.Fatalf("after exclude gh, got %v, want the ci-builds event", apptest.EventData(e))
	}
	b := s.Browser()
	b.SignIn()
	resp, body := b.Do("POST", "/api/broadcast", map[string]any{"title": "Maintenance", "message": "at 10:00"})
	if resp.StatusCode != 201 {
		t.Fatalf("broadcast: %d %s", resp.StatusCode, body)
	}
	e := st.NextMethod("notifications/events/event", 2*time.Second)
	d := apptest.EventData(e)
	if d["identifier"] != ":system" || d["kind"] != "system" || d["message"] != "at 10:00" || d["webhook"] != nil || d["request"] != nil {
		t.Fatalf("broadcast event = %v", d)
	}
	// include a list without :system: broadcasts still pass
	m.Tool("channel_update", map[string]any{"name": "main", "mode": "include", "identifiers": []any{"nothing-here"}})
	apptest.Send(t, ci, ciKey, `{"c":1}`)
	b.Do("POST", "/api/broadcast", map[string]any{"message": "second"})
	e = st.NextMethod("notifications/events/event", 2*time.Second)
	if apptest.EventData(e)["message"] != "second" {
		t.Fatalf("include list: got %v", apptest.EventData(e))
	}
	// another identity's events never pass
	other := s.NewAgent("other")
	ou, ok := other.Webhook("gh")
	m.Tool("channel_update", map[string]any{"name": "main", "mode": "all"})
	apptest.Send(t, ou, ok, `{}`)
	if f, quiet := st.Quiet(500 * time.Millisecond); !quiet {
		t.Fatalf("another identity's event reached the stream: %v", f)
	}
}

// Deleting a channel ends its streams with terminated and the final result.
func TestChannelDeleteTerminates(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	st := m.Open("events/stream", sub("ci", nil))
	f := st.NextMethod("notifications/events/active", time.Second)
	id := apptest.Params(f)["_meta"].(map[string]any)["io.modelcontextprotocol/subscriptionId"]
	m.Tool("channel_delete", map[string]any{"name": "ci"})
	term := st.NextMethod("notifications/events/terminated", 2*time.Second)
	e := apptest.Params(term)["error"].(map[string]any)
	if e["code"] != float64(-32023) || e["message"] != "NotFound" {
		t.Fatalf("terminated = %v", term)
	}
	final := st.Next(time.Second)
	res := final["result"].(map[string]any)
	if final["id"] != id || res["resultType"] != "complete" || len(res) != 2 || res["_meta"].(map[string]any)["io.modelcontextprotocol/subscriptionId"] != id {
		t.Fatalf("final frame = %v", final)
	}
	if _, ok := <-st.Frames; ok {
		t.Fatal("the stream stayed open after the final frame")
	}
	// revoking the authorization ends a stream with Forbidden
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	st = m.Open("events/stream", sub("ci", nil))
	st.NextMethod("notifications/events/active", time.Second)
	b := s.Browser()
	b.SignIn()
	_, body := b.Do("GET", "/api/identities/"+m.IdentityID+"/authorizations", nil)
	aid := apptest.JSON(t, body)["authorizations"].([]any)[0].(map[string]any)["id"].(string)
	if resp, _ := b.Do("DELETE", "/api/identities/"+m.IdentityID+"/authorizations/"+aid, nil); resp.StatusCode != 204 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	term = st.NextMethod("notifications/events/terminated", 2*time.Second)
	if apptest.Params(term)["error"].(map[string]any)["code"] != float64(-32024) {
		t.Fatalf("revoked: %v", term)
	}
}

// A stream resumed with its last cursor gets exactly what it missed.
func TestStreamResumeByCursor(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	st := m.Open("events/stream", sub("ci", nil))
	st.NextMethod("notifications/events/active", time.Second)
	apptest.Send(t, url, key, `{"n":1}`)
	last := apptest.Params(st.NextMethod("notifications/events/event", 2*time.Second))["cursor"]
	st.Close()
	missed := []string{apptest.Send(t, url, key, `{"n":2}`), apptest.Send(t, url, key, `{"n":3}`)}
	st = m.Open("events/stream", sub("ci", last))
	if a := apptest.Params(st.NextMethod("notifications/events/active", time.Second)); a["cursor"] != last || a["truncated"] != false {
		t.Fatalf("resumed active = %v", a)
	}
	for _, want := range missed {
		if got := apptest.Params(st.NextMethod("notifications/events/event", 2*time.Second))["eventId"]; got != want {
			t.Fatalf("resume got %v, want %s", got, want)
		}
	}
	if f, quiet := st.Quiet(300 * time.Millisecond); !quiet {
		t.Fatalf("resume sent more: %v", f)
	}
}

// A cursor older than the retained events is truncated: the stream starts
// at the oldest position it can serve and says so. maxAgeMs does the same
// when its floor skips events.
func TestTruncated(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	old := m.Call("events/poll", sub("ci", nil))["cursor"]
	apptest.Send(t, url, key, `{"old":1}`)
	apptest.Send(t, url, key, `{"old":2}`)
	// those two fall out of retention
	if _, err := s.App.Store.PruneEvents(context.Background(), time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	kept := apptest.Send(t, url, key, `{"kept":1}`)
	st := m.Open("events/stream", sub("ci", old))
	a := apptest.Params(st.NextMethod("notifications/events/active", time.Second))
	if a["truncated"] != true || a["cursor"] == old {
		t.Fatalf("active after retention = %v", a)
	}
	if got := apptest.Params(st.NextMethod("notifications/events/event", 2*time.Second))["eventId"]; got != kept {
		t.Fatalf("after the gap got %v, want %s", got, kept)
	}
	st.Close()
	p := m.Call("events/poll", sub("ci", old))
	if p["truncated"] != true || len(p["events"].([]any)) != 1 {
		t.Fatalf("poll after retention = %v", p)
	}
	// maxAgeMs: events older than the floor are skipped, and that is truncated
	recent := m.Call("events/poll", sub("ci", nil))["cursor"]
	apptest.Send(t, url, key, `{"stale":1}`)
	time.Sleep(300 * time.Millisecond)
	fresh := apptest.Send(t, url, key, `{"fresh":1}`)
	p = m.Call("events/poll", map[string]any{"name": ev, "arguments": map[string]any{"channel": "ci"}, "cursor": recent, "maxAgeMs": 150})
	evs := p["events"].([]any)
	if p["truncated"] != true || len(evs) != 1 || evs[0].(map[string]any)["eventId"] != fresh {
		t.Fatalf("maxAgeMs poll = %v", p)
	}
	// a floor that skips nothing this channel would get isn't truncated
	m.Tool("channel_update", map[string]any{"name": "ci", "mode": "exclude", "identifiers": []any{"gh"}})
	recent = m.Call("events/poll", sub("ci", nil))["cursor"]
	apptest.Send(t, url, key, `{"filtered":1}`)
	time.Sleep(300 * time.Millisecond)
	p = m.Call("events/poll", map[string]any{"name": ev, "arguments": map[string]any{"channel": "ci"}, "cursor": recent, "maxAgeMs": 150})
	if p["truncated"] != false {
		t.Errorf("maxAgeMs over filtered-out events = %v", p)
	}
	// maxAgeMs is ignored with a null cursor
	p = m.Call("events/poll", map[string]any{"name": ev, "arguments": map[string]any{"channel": "ci"}, "cursor": nil, "maxAgeMs": 1})
	if p["truncated"] != false || len(p["events"].([]any)) != 0 {
		t.Errorf("maxAgeMs with null cursor = %v", p)
	}
}

// Server shutdown closes open streams with the final result.
func TestShutdownSendsFinalResult(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	st := m.Open("events/stream", sub("ci", nil))
	st.NextMethod("notifications/events/active", time.Second)
	listen := m.Open("subscriptions/listen", map[string]any{"notifications": map[string]any{"toolsListChanged": true, "eventsListChanged": true}})
	ack := listen.Next(time.Second)
	if ack["method"] != "notifications/subscriptions/acknowledged" || len(apptest.Params(ack)["notifications"].(map[string]any)) != 0 {
		t.Fatalf("listen ack = %v", ack)
	}
	s.App.Stop()
	for _, x := range []*apptest.Stream{st, listen} {
		for {
			f := x.Next(2 * time.Second)
			if f["result"] != nil {
				if f["result"].(map[string]any)["resultType"] != "complete" {
					t.Errorf("final = %v", f)
				}
				break
			}
		}
	}
}

// Heartbeats keep their period while events flow: a busy stream still
// gets one at least every interval (SEP-3415's "at least every 30
// seconds"), not only when it goes quiet.
func TestHeartbeatWhileBusy(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	st := m.Open("events/stream", sub("ci", nil))
	st.NextMethod("notifications/events/active", time.Second)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			case <-time.After(50 * time.Millisecond):
				apptest.Send(t, url, key, `{}`)
			}
		}
	}()
	defer close(stop)
	beats, deadline := 0, time.After(1100*time.Millisecond) // the test server beats every 200ms
	for beats < 3 {
		select {
		case f := <-st.Frames:
			if f["method"] == "notifications/events/heartbeat" {
				beats++
			}
		case <-deadline:
			t.Fatalf("%d heartbeats in 1.1s of steady events, want at least 3", beats)
		}
	}
}
