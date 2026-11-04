package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/mcpclient"
)

// EventName is the server's one event type.
const EventName = "webhook.received"

func eventsCmd(ctx context.Context, env Env, args []string) error {
	if len(args) == 0 {
		return usagef("usage: mwe events tail|poll --channel <name>")
	}
	switch args[0] {
	case "tail":
		return tail(ctx, env, args[1:])
	case "poll":
		return poll(ctx, env, args[1:])
	}
	return usagef("unknown events command %q: use tail or poll", args[0])
}

type occurrence struct {
	EventID   string          `json:"eventId"`
	Name      string          `json:"name"`
	Timestamp string          `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
	Cursor    *string         `json:"cursor,omitempty"`
}

// line is an event as one human-readable line.
func line(o occurrence) string {
	var d struct {
		Identifier string  `json:"identifier"`
		Kind       string  `json:"kind"`
		Message    *string `json:"message"`
		Title      *string `json:"title"`
		Request    *struct {
			Method       string          `json:"method"`
			BodyEncoding string          `json:"body_encoding"`
			Body         json.RawMessage `json:"body"`
		} `json:"request"`
	}
	_ = json.Unmarshal(o.Data, &d)
	var what string
	switch {
	case d.Request != nil:
		body := string(d.Request.Body)
		if d.Request.BodyEncoding == "base64" {
			body = "(binary, base64) " + body
		}
		if len(body) > 300 {
			body = body[:300] + "…"
		}
		what = d.Request.Method + " " + body
	case d.Message != nil:
		what = "broadcast: "
		if d.Title != nil {
			what += *d.Title + " — "
		}
		what += *d.Message
	}
	return fmt.Sprintf("%s  %-20s %s  %s", o.Timestamp, d.Identifier, o.EventID, strings.ReplaceAll(what, "\n", " "))
}

func printEvent(env Env, o occurrence, asJSON bool) {
	if asJSON {
		b, _ := json.Marshal(o)
		fmt.Fprintln(env.Stdout, string(b))
		return
	}
	fmt.Fprintln(env.Stdout, line(o))
}

// errTerminated is a subscription the server ended.
type errTerminated struct{ msg string }

func (e errTerminated) Error() string { return "the server ended the subscription: " + e.msg }

// tail follows a channel with events/stream, reconnecting from its last
// cursor when the connection drops, until interrupted or the server ends
// the subscription.
func tail(ctx context.Context, env Env, args []string) error {
	f := newFlags(env, "events tail")
	channel := f.String("channel", "", "the channel to follow")
	cursor := f.String("cursor", "", "resume after this cursor (default: from now)")
	maxAge := f.Duration("max-age", 0, "when resuming, skip events older than this (e.g. 10m)")
	asJSON := f.Bool("json", false, "print each event as a JSON line")
	if _, err := f.parse(args); err != nil {
		return err
	}
	if *channel == "" {
		return usagef("usage: mwe events tail --channel <name> [--cursor c] [--max-age d] [--json]")
	}
	c, err := client(env, *f.profile)
	if err != nil {
		return err
	}
	var cur *string
	if *cursor != "" {
		cur = cursor
	}
	defer func() {
		if cur != nil {
			fmt.Fprintf(env.Stderr, "last cursor: %s\n", *cur)
		}
	}()
	backoff := time.Second
	for first := true; ; first = false {
		params := map[string]any{"name": EventName, "arguments": map[string]any{"channel": *channel}, "cursor": nil}
		if cur != nil {
			params["cursor"] = *cur
			if *maxAge > 0 {
				params["maxAgeMs"] = maxAge.Milliseconds()
			}
		}
		opened := false
		err := c.Stream(ctx, "events/stream", EventName, params, func(m mcpclient.Message) error {
			if m.Error != nil {
				return m.Error
			}
			if m.Result != nil {
				return errors.New("server closed the stream")
			}
			var p struct {
				occurrence
				Truncated bool                `json:"truncated"`
				Error     *mcpclient.RPCError `json:"error"`
			}
			_ = json.Unmarshal(m.Params, &p)
			switch m.Method {
			case "notifications/events/active":
				opened = true
				backoff = time.Second
				if p.Cursor != nil {
					cur = p.Cursor
				}
				if first || p.Truncated {
					msg := "following channel " + *channel
					if p.Truncated {
						msg += " (truncated: some events after your cursor were skipped)"
					}
					fmt.Fprintln(env.Stderr, msg)
				}
			case "notifications/events/event":
				printEvent(env, p.occurrence, *asJSON)
				if p.Cursor != nil {
					cur = p.Cursor
				}
			case "notifications/events/heartbeat":
				if p.Cursor != nil {
					cur = p.Cursor
				}
			case "notifications/events/error":
				fmt.Fprintf(env.Stderr, "mwe: event error: %v\n", p.Error)
			case "notifications/events/terminated":
				msg := "terminated"
				if p.Error != nil {
					msg = p.Error.Error()
				}
				return errTerminated{msg}
			}
			return nil
		})
		if ctx.Err() != nil {
			return nil
		}
		var te errTerminated
		var re *mcpclient.RPCError
		switch {
		case errors.As(err, &te):
			return err
		case errors.As(err, &re):
			return err
		case errors.Is(err, mcpclient.ErrNotSignedIn):
			return err
		}
		if !opened && err != nil && first {
			return err
		}
		why := "the stream ended"
		if err != nil {
			why = err.Error()
		}
		fmt.Fprintf(env.Stderr, "mwe: %s; reconnecting in %s\n", why, backoff)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, 30*time.Second)
	}
}

// poll reads a channel with events/poll: once, or repeatedly at the
// server's pace with --follow.
func poll(ctx context.Context, env Env, args []string) error {
	f := newFlags(env, "events poll")
	channel := f.String("channel", "", "the channel to read")
	cursor := f.String("cursor", "", "read after this cursor (default: start from now)")
	maxEvents := f.Int("max-events", 0, "at most this many events per poll")
	maxAge := f.Duration("max-age", 0, "skip events older than this")
	follow := f.Bool("follow", false, "keep polling")
	asJSON := f.Bool("json", false, "print each event as a JSON line")
	if _, err := f.parse(args); err != nil {
		return err
	}
	if *channel == "" {
		return usagef("usage: mwe events poll --channel <name> [--cursor c] [--max-events n] [--follow] [--json]")
	}
	c, err := client(env, *f.profile)
	if err != nil {
		return err
	}
	var cur any
	if *cursor != "" {
		cur = *cursor
	}
	for {
		params := map[string]any{"name": EventName, "arguments": map[string]any{"channel": *channel}, "cursor": cur}
		if *maxEvents > 0 {
			params["maxEvents"] = *maxEvents
		}
		if *maxAge > 0 {
			params["maxAgeMs"] = maxAge.Milliseconds()
		}
		raw, err := c.Call(ctx, "events/poll", EventName, params)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		var r struct {
			Events     []occurrence `json:"events"`
			Cursor     *string      `json:"cursor"`
			Truncated  bool         `json:"truncated"`
			HasMore    bool         `json:"hasMore"`
			NextPollMs int          `json:"nextPollMs"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return err
		}
		if r.Truncated {
			fmt.Fprintln(env.Stderr, "mwe: truncated: some events after the cursor were skipped")
		}
		for _, o := range r.Events {
			printEvent(env, o, *asJSON)
		}
		if r.Cursor != nil {
			cur = *r.Cursor
		} else {
			cur = nil
		}
		if !*follow {
			if r.Cursor != nil {
				fmt.Fprintf(env.Stderr, "cursor: %s%s\n", *r.Cursor, map[bool]string{true: " (more available)"}[r.HasMore])
			}
			return nil
		}
		wait := time.Duration(max(r.NextPollMs, 1000)) * time.Millisecond
		if r.HasMore {
			wait = 0
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(wait):
		}
	}
}
