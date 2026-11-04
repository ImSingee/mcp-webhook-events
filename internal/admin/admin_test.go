package admin_test

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/apptest"
)

func TestSignInAndCSRF(t *testing.T) {
	s := apptest.Start(t)
	b := s.Browser()
	// signed out: pages go to /login with next, the API is 401
	resp, _ := b.Do("GET", "/", nil)
	if resp.StatusCode != 302 || resp.Header.Get("Location") != "/login?next=%2F" {
		t.Errorf("GET / signed out: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := b.Do("GET", "/login", nil); resp.StatusCode != 200 {
		t.Errorf("GET /login: %d", resp.StatusCode)
	}
	if resp, _ := b.Do("GET", "/api/identities", nil); resp.StatusCode != 401 {
		t.Errorf("API signed out: %d", resp.StatusCode)
	}
	resp, body := b.Do("GET", "/api/meta", nil)
	meta := apptest.JSON(t, body)
	if resp.StatusCode != 200 || meta["mcp_url"] != s.URL+"/mcp" || meta["public_url"] != s.URL || meta["version"] == "" {
		t.Errorf("meta: %d %v", resp.StatusCode, meta)
	}
	resp, body = b.Do("POST", "/api/login", map[string]string{"password": "wrong"})
	if resp.StatusCode != 401 || apptest.JSON(t, body)["error"].(map[string]any)["code"] != "unauthorized" {
		t.Errorf("wrong password: %d %s", resp.StatusCode, body)
	}
	b.SignIn()
	resp, _ = b.Do("GET", "/", nil)
	if resp.StatusCode != 200 {
		t.Errorf("GET / signed in: %d", resp.StatusCode)
	}
	// non-GET API calls need the header and the same origin
	req, _ := http.NewRequest("POST", s.URL+"/api/identities", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	r, err := b.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Errorf("POST without X-MWE-Request: %d", r.StatusCode)
	}
	req, _ = http.NewRequest("POST", s.URL+"/api/identities", strings.NewReader(`{"name":"x"}`))
	req.Header.Set("X-MWE-Request", "1")
	req.Header.Set("Origin", "https://evil.example")
	r, _ = b.Client.Do(req)
	r.Body.Close()
	if r.StatusCode != 403 {
		t.Errorf("POST from another origin: %d", r.StatusCode)
	}
	// logout ends the session
	if resp, _ := b.Do("POST", "/api/logout", nil); resp.StatusCode != 204 {
		t.Errorf("logout: %d", resp.StatusCode)
	}
	if resp, _ := b.Do("GET", "/api/identities", nil); resp.StatusCode != 401 {
		t.Errorf("after logout: %d", resp.StatusCode)
	}
}

func TestLoginBackoff(t *testing.T) {
	s := apptest.Start(t)
	b := s.Browser()
	for i := 0; i < 5; i++ {
		b.Do("POST", "/api/login", map[string]string{"password": "nope"})
	}
	resp, body := b.Do("POST", "/api/login", map[string]string{"password": apptest.Password})
	e := apptest.JSON(t, body)["error"].(map[string]any)
	if resp.StatusCode != 429 || e["code"] != "rate_limited" || e["retry_after_seconds"].(float64) < 1 {
		t.Fatalf("after 5 failures: %d %s", resp.StatusCode, body)
	}
}

func TestIdentitiesWebhooksChannels(t *testing.T) {
	s := apptest.Start(t)
	b := s.Browser()
	b.SignIn()
	resp, body := b.Do("POST", "/api/identities", map[string]string{"name": "  laptop  "})
	idn := apptest.JSON(t, body)
	if resp.StatusCode != 201 || idn["name"] != "laptop" || !strings.HasPrefix(idn["id"].(string), "idn_") || idn["last_event_at"] != nil {
		t.Fatalf("create identity: %d %v", resp.StatusCode, idn)
	}
	id := idn["id"].(string)
	if resp, body := b.Do("POST", "/api/identities", map[string]string{"name": "laptop"}); resp.StatusCode != 409 || apptest.JSON(t, body)["error"].(map[string]any)["code"] != "conflict" {
		t.Errorf("duplicate name: %d %s", resp.StatusCode, body)
	}
	if resp, _ := b.Do("POST", "/api/identities", map[string]string{"name": "   "}); resp.StatusCode != 400 {
		t.Errorf("blank name: %d", resp.StatusCode)
	}
	resp, body = b.Do("PATCH", "/api/identities/"+id, map[string]string{"name": "desk"})
	if resp.StatusCode != 200 || apptest.JSON(t, body)["name"] != "desk" {
		t.Errorf("rename: %d %s", resp.StatusCode, body)
	}
	resp, body = b.Do("POST", "/api/identities/"+id+"/webhooks", map[string]string{"identifier": "github-push", "name": "GitHub", "description": "d"})
	wh := apptest.JSON(t, body)
	w := wh["webhook"].(map[string]any)
	if resp.StatusCode != 201 || !strings.HasPrefix(wh["key"].(string), "mwek_") || !strings.HasPrefix(w["url"].(string), s.URL+"/hooks/") || w["event_count"].(float64) != 0 {
		t.Fatalf("create webhook: %d %s", resp.StatusCode, body)
	}
	for _, bad := range []string{"Bad", "a--b", "", strings.Repeat("a", 65)} {
		if resp, _ := b.Do("POST", "/api/identities/"+id+"/webhooks", map[string]string{"identifier": bad}); resp.StatusCode != 400 {
			t.Errorf("identifier %q: %d", bad, resp.StatusCode)
		}
	}
	if resp, _ := b.Do("POST", "/api/identities/"+id+"/webhooks", map[string]string{"identifier": "github-push"}); resp.StatusCode != 409 {
		t.Errorf("duplicate identifier: %d", resp.StatusCode)
	}
	apptest.Send(t, w["url"].(string), wh["key"].(string), `{"a":1}`)
	_, body = b.Do("GET", "/api/identities/"+id+"/webhooks", nil)
	list := apptest.JSON(t, body)["webhooks"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["event_count"].(float64) != 1 || list[0].(map[string]any)["last_event_at"] == nil {
		t.Errorf("webhook list = %v", list)
	}
	wid := w["id"].(string)
	resp, body = b.Do("PATCH", "/api/identities/"+id+"/webhooks/"+wid, map[string]string{"description": "new"})
	if resp.StatusCode != 200 || apptest.JSON(t, body)["description"] != "new" || apptest.JSON(t, body)["name"] != "GitHub" {
		t.Errorf("patch webhook: %d %s", resp.StatusCode, body)
	}
	resp, body = b.Do("POST", "/api/identities/"+id+"/webhooks/"+wid+"/rotate-key", nil)
	if resp.StatusCode != 200 || apptest.JSON(t, body)["key"] == wh["key"] {
		t.Errorf("rotate: %d %s", resp.StatusCode, body)
	}
	resp, body = b.Do("POST", "/api/identities/"+id+"/channels", map[string]any{"name": "ci", "mode": "include", "identifiers": []string{"github-push", ":system"}})
	ch := apptest.JSON(t, body)
	if resp.StatusCode != 201 || ch["mode"] != "include" || ch["active_streams"].(float64) != 0 || ch["subscription_count"].(float64) != 0 {
		t.Fatalf("create channel: %d %s", resp.StatusCode, body)
	}
	if resp, _ := b.Do("POST", "/api/identities/"+id+"/channels", map[string]any{"name": "x", "mode": "all", "identifiers": []string{"a"}}); resp.StatusCode != 400 {
		t.Errorf("all with identifiers: %d", resp.StatusCode)
	}
	if resp, _ := b.Do("POST", "/api/identities/"+id+"/channels", map[string]any{"name": "x", "mode": "include", "identifiers": []string{"Bad"}}); resp.StatusCode != 400 {
		t.Errorf("bad identifier in list: %d", resp.StatusCode)
	}
	resp, body = b.Do("PATCH", "/api/identities/"+id+"/channels/"+ch["id"].(string), map[string]any{"mode": "exclude"})
	if resp.StatusCode != 200 || apptest.JSON(t, body)["mode"] != "exclude" || len(apptest.JSON(t, body)["identifiers"].([]any)) != 2 {
		t.Errorf("patch channel: %d %s", resp.StatusCode, body)
	}
	_, body = b.Do("GET", "/api/identities", nil)
	got := apptest.JSON(t, body)["identities"].([]any)[0].(map[string]any)
	if got["webhook_count"].(float64) != 1 || got["channel_count"].(float64) != 1 || got["last_event_at"] == nil {
		t.Errorf("identity counts = %v", got)
	}
	if resp, _ := b.Do("DELETE", "/api/identities/"+id+"/channels/"+ch["id"].(string), nil); resp.StatusCode != 204 {
		t.Errorf("delete channel: %d", resp.StatusCode)
	}
	if resp, _ := b.Do("DELETE", "/api/identities/"+id+"/webhooks/"+wid, nil); resp.StatusCode != 204 {
		t.Errorf("delete webhook: %d", resp.StatusCode)
	}
	if resp, _ := b.Do("GET", "/api/identities/idn_nope/webhooks", nil); resp.StatusCode != 404 {
		t.Errorf("unknown identity: %d", resp.StatusCode)
	}
	if resp, _ := b.Do("GET", "/api/nope", nil); resp.StatusCode != 404 {
		t.Errorf("unknown API: %d", resp.StatusCode)
	}
}

// Deleting an identity deletes what it owns and ends its streams; its
// tokens stop working.
func TestDeleteIdentityCascades(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	apptest.Send(t, url, key, `{}`)
	st := m.Open("events/stream", map[string]any{"name": "webhook.received", "arguments": map[string]any{"channel": "ci"}})
	st.NextMethod("notifications/events/active", time.Second)
	b := s.Browser()
	b.SignIn()
	if resp, _ := b.Do("DELETE", "/api/identities/"+m.IdentityID, nil); resp.StatusCode != 204 {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	term := st.NextMethod("notifications/events/terminated", 2*time.Second)
	if apptest.Params(term)["error"].(map[string]any)["code"] != float64(-32024) {
		t.Errorf("terminated = %v", term)
	}
	r, _ := m.Raw(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "server/discover"}, nil)
	if r.StatusCode != 401 {
		t.Errorf("token after identity delete: %d", r.StatusCode)
	}
	for _, table := range []string{"webhooks", "channels", "oauth_families", "events"} {
		var n int
		s.App.Store.DB().QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n)
		if n != 0 {
			t.Errorf("%s left: %d", table, n)
		}
	}
	if resp, _ := b.Do("POST", url+"?key="+key, map[string]any{}); resp.StatusCode != 404 {
		t.Errorf("the deleted identity's webhook URL answers %d", resp.StatusCode)
	}
}

func TestEventsAPIAndStream(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	b := s.Browser()
	b.SignIn()
	// the live view
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", s.URL+"/api/events/stream", nil)
	resp, err := b.Client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("stream content type %q", resp.Header.Get("Content-Type"))
	}
	frames := make(chan string, 10)
	go func() {
		r := bufio.NewReader(resp.Body)
		var ev string
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, "event: ") {
				ev = strings.TrimSpace(strings.TrimPrefix(line, "event: "))
			}
			if strings.HasPrefix(line, "data: ") && ev == "event" {
				frames <- strings.TrimPrefix(strings.TrimSpace(line), "data: ")
			}
		}
	}()
	var ids []string
	for i := 0; i < 5; i++ {
		ids = append(ids, apptest.Send(t, url, key, `{}`))
	}
	b.Do("POST", "/api/broadcast", map[string]any{"message": "hi"})
	select {
	case f := <-frames:
		var e map[string]any
		json.Unmarshal([]byte(f), &e)
		if e["id"] != ids[0] || e["identity_name"] != "agent" || e["kind"] != "webhook" || e["data"].(map[string]any)["identifier"] != "gh" {
			t.Errorf("live event = %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no live event")
	}
	// the list, newest first, paged by before
	_, body := b.Do("GET", "/api/events?limit=2", nil)
	page := apptest.JSON(t, body)
	evs := page["events"].([]any)
	first := evs[0].(map[string]any)
	if len(evs) != 2 || first["identity_id"] != nil || first["kind"] != "system" || first["data"].(map[string]any)["message"] != "hi" {
		t.Fatalf("page 1 = %v", page)
	}
	next := page["next_before"].(float64)
	_, body = b.Do("GET", "/api/events?limit=10&before="+strconv.FormatInt(int64(next), 10), nil)
	if n := len(apptest.JSON(t, body)["events"].([]any)); n != 4 {
		t.Errorf("page 2 has %d events, want 4", n)
	}
	_, body = b.Do("GET", "/api/events?identity_id=_broadcast", nil)
	if n := len(apptest.JSON(t, body)["events"].([]any)); n != 1 {
		t.Errorf("broadcast filter: %d", n)
	}
	_, body = b.Do("GET", "/api/events?identity_id="+m.IdentityID+"&identifier=gh", nil)
	if n := len(apptest.JSON(t, body)["events"].([]any)); n != 5 {
		t.Errorf("identity filter: %d", n)
	}
	if resp, _ := b.Do("POST", "/api/broadcast", map[string]any{"identifier": "system", "message": "x"}); resp.StatusCode != 400 {
		t.Errorf("non-reserved broadcast identifier: %d", resp.StatusCode)
	}
	if resp, _ := b.Do("POST", "/api/broadcast", map[string]any{"message": ""}); resp.StatusCode != 400 {
		t.Errorf("empty broadcast: %d", resp.StatusCode)
	}
}

func TestConsentAPIRules(t *testing.T) {
	s := apptest.Start(t)
	b := s.Browser()
	b.SignIn()
	c := s.Register("x")
	_, challenge := apptest.PKCE()
	resp, _ := b.Do("GET", c.AuthorizeURL(challenge, "", ""), nil)
	ar := strings.TrimPrefix(resp.Header.Get("Location"), "/consent?request=")
	if resp, _ := b.Do("POST", "/api/oauth/requests/"+ar+"/approve", map[string]string{}); resp.StatusCode != 400 {
		t.Errorf("approve with neither: %d", resp.StatusCode)
	}
	if resp, _ := b.Do("POST", "/api/oauth/requests/"+ar+"/approve", map[string]string{"identity_id": "idn_x", "new_identity_name": "y"}); resp.StatusCode != 400 {
		t.Errorf("approve with both: %d", resp.StatusCode)
	}
	if resp, _ := b.Do("POST", "/api/oauth/requests/"+ar+"/approve", map[string]string{"identity_id": "idn_nope"}); resp.StatusCode != 400 {
		t.Errorf("approve unknown identity: %d", resp.StatusCode)
	}
	b.Do("POST", "/api/identities", map[string]string{"name": "taken"})
	if resp, _ := b.Do("POST", "/api/oauth/requests/"+ar+"/approve", map[string]string{"new_identity_name": "taken"}); resp.StatusCode != 409 {
		t.Errorf("approve with a taken name: %d", resp.StatusCode)
	}
	// none of the refusals spent the request
	if resp, _ := b.Do("GET", "/api/oauth/requests/"+ar, nil); resp.StatusCode != 200 {
		t.Errorf("request after refusals: %d", resp.StatusCode)
	}
	if resp, _ := b.Do("GET", "/api/oauth/requests/ar_nope", nil); resp.StatusCode != 404 {
		t.Errorf("unknown request: %d", resp.StatusCode)
	}
	// the request expires
	s.App.Store.DB().Exec(`UPDATE oauth_requests SET expires_at = 0`)
	if resp, _ := b.Do("GET", "/api/oauth/requests/"+ar, nil); resp.StatusCode != 404 {
		t.Errorf("expired request: %d", resp.StatusCode)
	}
}

func TestSubscriptionsAPI(t *testing.T) {
	s := apptest.Start(t, apptest.AllowPrivate())
	m := s.NewAgent("agent")
	m.Tool("channel_create", map[string]any{"name": "ci", "mode": "all"})
	rcv := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v map[string]any
		json.NewDecoder(r.Body).Decode(&v)
		json.NewEncoder(w).Encode(map[string]any{"challenge": v["challenge"]})
	})
	srv := newServer(t, rcv)
	secret := "whsec_" + strings.Repeat("A", 43) + "="
	res, err := m.Try("events/subscribe", map[string]any{"name": "webhook.received", "arguments": map[string]any{"channel": "ci"}, "delivery": map[string]any{"url": srv + "/cb", "secret": secret}})
	if err != nil {
		t.Fatal(err)
	}
	b := s.Browser()
	b.SignIn()
	_, body := b.Do("GET", "/api/identities/"+m.IdentityID+"/subscriptions", nil)
	subs := apptest.JSON(t, body)["subscriptions"].([]any)
	sub := subs[0].(map[string]any)
	if len(subs) != 1 || sub["id"] != res["id"] || sub["channel"] != "ci" || sub["status"] != "active" || sub["url"] != srv+"/cb" {
		t.Fatalf("subscriptions = %v", subs)
	}
	_, body = b.Do("GET", "/api/identities/"+m.IdentityID+"/channels", nil)
	if n := apptest.JSON(t, body)["channels"].([]any)[0].(map[string]any)["subscription_count"].(float64); n != 1 {
		t.Errorf("subscription_count = %v", n)
	}
	if resp, _ := b.Do("DELETE", "/api/identities/"+m.IdentityID+"/subscriptions/"+res["id"].(string), nil); resp.StatusCode != 204 {
		t.Errorf("delete subscription: %d", resp.StatusCode)
	}
	s.App.Worker.Wait()
}
