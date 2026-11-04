package ingest_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/ImSingee/mcp-webhook-events/internal/apptest"
)

func post(t *testing.T, url string, body []byte, headers map[string]string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var v map[string]any
	_ = json.Unmarshal(b, &v)
	return resp.StatusCode, v
}

// stored is the data of the event with that id.
func stored(t *testing.T, s *apptest.Server, id string) map[string]any {
	t.Helper()
	e, err := s.App.Store.GetEvent(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if err := json.Unmarshal(e.Data, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

func TestKeyThreeWays(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	cases := []struct {
		name    string
		url     string
		headers map[string]string
	}{
		{"header", url, map[string]string{"X-Webhook-Key": key}},
		{"bearer", url, map[string]string{"Authorization": "Bearer " + key}},
		{"query", url + "?key=" + key + "&ref=main", nil},
	}
	for _, tc := range cases {
		h := map[string]string{"Content-Type": "application/json", "Cookie": "session=secret", "X-Custom": "kept"}
		for k, v := range tc.headers {
			h[k] = v
		}
		st, out := post(t, tc.url, []byte(`{"via":"`+tc.name+`"}`), h)
		if st != http.StatusAccepted || !strings.HasPrefix(out["event_id"].(string), "evt_") {
			t.Fatalf("%s: %d %v", tc.name, st, out)
		}
		d := stored(t, s, out["event_id"].(string))
		req := d["request"].(map[string]any)
		raw, _ := json.Marshal(d)
		if strings.Contains(string(raw), key) {
			t.Errorf("%s: the key was stored: %s", tc.name, raw)
		}
		hdrs := req["headers"].(map[string]any)
		for _, k := range []string{"X-Webhook-Key", "Authorization", "Cookie"} {
			if hdrs[k] != nil {
				t.Errorf("%s: header %s was stored", tc.name, k)
			}
		}
		if hdrs["X-Custom"] == nil || req["query"].(map[string]any)["key"] != nil {
			t.Errorf("%s: request = %v", tc.name, req)
		}
		if tc.name == "query" && req["query"].(map[string]any)["ref"].([]any)[0] != "main" {
			t.Errorf("query lost ref: %v", req["query"])
		}
		if d["identifier"] != "gh" || d["kind"] != "webhook" || req["body_encoding"] != "json" || req["body"].(map[string]any)["via"] != tc.name || req["method"] != "POST" || d["message"] != nil {
			t.Errorf("%s: data = %v", tc.name, d)
		}
	}
}

func TestRefusals(t *testing.T) {
	s := apptest.Start(t) // MaxBodyBytes is 4096 in tests
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	if st, out := post(t, url, []byte("{}"), nil); st != 401 || out["error"].(map[string]any)["code"] != "unauthorized" {
		t.Errorf("no key: %d %v", st, out)
	}
	if st, _ := post(t, url, []byte("{}"), map[string]string{"X-Webhook-Key": "mwek_wrong"}); st != 401 {
		t.Errorf("wrong key: %d", st)
	}
	if st, _ := post(t, url+"?key=mwek_wrong", []byte("{}"), nil); st != 401 {
		t.Errorf("wrong query key: %d", st)
	}
	if st, _ := post(t, s.URL+"/hooks/nope", []byte("{}"), map[string]string{"X-Webhook-Key": key}); st != 404 {
		t.Errorf("unknown token: %d", st)
	}
	if st, _ := post(t, url, bytes.Repeat([]byte("a"), 4097), map[string]string{"X-Webhook-Key": key}); st != 413 {
		t.Errorf("body over the limit: %d", st)
	}
	if st, _ := post(t, url, bytes.Repeat([]byte("a"), 4096), map[string]string{"X-Webhook-Key": key}); st != 202 {
		t.Errorf("body at the limit: %d", st)
	}
	// a rotated key: the old one stops working at once
	nk := m.Tool("webhook_rotate_key", map[string]any{"identifier": "gh"})["key"].(string)
	if st, _ := post(t, url, []byte("{}"), map[string]string{"X-Webhook-Key": key}); st != 401 {
		t.Errorf("old key after rotation: %d", st)
	}
	if st, _ := post(t, url, []byte("{}"), map[string]string{"X-Webhook-Key": nk}); st != 202 {
		t.Errorf("new key: %d", st)
	}
	// a deleted webhook's URL is gone
	m.Tool("webhook_delete", map[string]any{"identifier": "gh"})
	if st, _ := post(t, url, []byte("{}"), map[string]string{"X-Webhook-Key": nk}); st != 404 {
		t.Errorf("deleted webhook: %d", st)
	}
}

func TestBodyEncodings(t *testing.T) {
	s := apptest.Start(t)
	m := s.NewAgent("agent")
	url, key := m.Webhook("gh")
	h := map[string]string{"X-Webhook-Key": key}
	bin := []byte{0xff, 0x00, 0xfe, 0x01}
	cases := []struct {
		body     []byte
		encoding string
		want     any
	}{
		{[]byte(`[1,2]`), "json", []any{float64(1), float64(2)}},
		{[]byte("plain text ✓"), "text", "plain text ✓"},
		{bin, "base64", base64.StdEncoding.EncodeToString(bin)},
		{nil, "none", nil},
	}
	for _, tc := range cases {
		_, out := post(t, url, tc.body, h)
		req := stored(t, s, out["event_id"].(string))["request"].(map[string]any)
		got, _ := json.Marshal(req["body"])
		want, _ := json.Marshal(tc.want)
		if req["body_encoding"] != tc.encoding || string(got) != string(want) {
			t.Errorf("%q: %v %s, want %s %s", tc.body, req["body_encoding"], got, tc.encoding, want)
		}
	}
	// any method is a webhook
	req, _ := http.NewRequest(http.MethodPut, url+"?key="+key, strings.NewReader("x"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != 202 {
		t.Fatalf("PUT: %v %v", err, resp.Status)
	}
	resp.Body.Close()
}
