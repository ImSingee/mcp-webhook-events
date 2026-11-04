// Package events is the event feed every delivery path reads: the channel
// filter, the opaque cursor over the global event sequence, the start
// position a resumed subscription replays from, and the hub that wakes
// readers when something changes.
//
// Readers never get events pushed through the hub. The hub only says
// "something changed"; each reader then reads the store for events after
// its own position. Events are written one at a time in seq order (see
// core.Service.AppendEvent), so a reader that has read up to the head has
// seen everything before it, and a slow reader never loses events to a
// full buffer.
package events

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/store"
)

// Name is the one event type the server offers.
const Name = "webhook.received"

// TimeFormat is how every timestamp is written: RFC 3339 in UTC with
// milliseconds.
const TimeFormat = "2006-01-02T15:04:05.000Z07:00"

// Stamp formats t with TimeFormat in UTC.
func Stamp(t time.Time) string { return t.UTC().Format(TimeFormat) }

// Filter is a channel's rule, bound to its identity.
type Filter struct {
	IdentityID  string
	Mode        string // all, include or exclude
	Identifiers []string
}

// FilterOf is a channel's filter.
func FilterOf(c store.Channel) Filter {
	return Filter{IdentityID: c.IdentityID, Mode: c.Mode, Identifiers: c.Identifiers}
}

// Match reports whether the filter lets e through. A platform broadcast
// (no identity) always passes: it is meant for every subscriber, whatever
// their channel says.
func (f Filter) Match(e store.Event) bool {
	if e.IdentityID == "" {
		return true
	}
	if e.IdentityID != f.IdentityID {
		return false
	}
	switch f.Mode {
	case "all":
		return true
	case "include":
		return slices.Contains(f.Identifiers, e.Identifier)
	case "exclude":
		return !slices.Contains(f.Identifiers, e.Identifier)
	}
	return false
}

const cursorPrefix = "mwe1:"

// EncodeCursor is the opaque cursor for the position after seq.
func EncodeCursor(seq int64) string {
	return base64.RawURLEncoding.EncodeToString([]byte(cursorPrefix + strconv.FormatInt(seq, 10)))
}

// ErrBadCursor is a cursor this server didn't make.
var ErrBadCursor = errors.New("cursor is not one this server issued")

// DecodeCursor is the position a cursor stands for.
func DecodeCursor(c string) (int64, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return 0, ErrBadCursor
	}
	s, ok := strings.CutPrefix(string(b), cursorPrefix)
	if !ok {
		return 0, ErrBadCursor
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, ErrBadCursor
	}
	return n, nil
}

// Occurrence is an event as SEP-3415 delivers it (EventOccurrence), with
// the cursor of the position after it.
func Occurrence(e store.Event) map[string]any {
	return map[string]any{
		"eventId":   e.ID,
		"name":      Name,
		"timestamp": Stamp(e.ReceivedAt),
		"data":      e.Data,
		"cursor":    EncodeCursor(e.Seq),
	}
}

// Start is where a subscription's delivery begins.
type Start struct {
	Seq       int64 // deliver events with seq > Seq
	Head      int64 // the head when the start was taken
	Truncated bool  // events after the client's cursor were skipped
}

// scanCap bounds how many events Resolve reads to tell whether a maxAgeMs
// floor skipped any the subscription would have received; past it, it
// assumes it did.
const scanCap = 5000

// Resolve is the start for a client's cursor (nil for "from now") and
// optional maxAgeMs, under SEP-3415's cursor lifecycle: a cursor older
// than the retained events, or one this database never reached, starts at
// the nearest position it can serve and is truncated; a maxAgeMs floor
// past the cursor moves the start up to it, truncated when that skips an
// event the filter would let through.
func Resolve(ctx context.Context, st *store.Store, f Filter, cursor *string, maxAgeMs *int64) (Start, error) {
	head, err := st.Head(ctx)
	if err != nil {
		return Start{}, err
	}
	if cursor == nil {
		return Start{Seq: head, Head: head}, nil
	}
	c, err := DecodeCursor(*cursor)
	if err != nil {
		return Start{}, err
	}
	s := Start{Seq: c, Head: head}
	if c > head {
		s.Seq, s.Truncated = head, true
		return s, nil
	}
	pruned, err := st.PrunedThrough(ctx)
	if err != nil {
		return Start{}, err
	}
	if c < pruned {
		s.Seq, s.Truncated = pruned, true
	}
	if maxAgeMs != nil {
		floor, err := st.SeqBefore(ctx, st.Now().Add(-time.Duration(*maxAgeMs)*time.Millisecond))
		if err != nil {
			return Start{}, err
		}
		if floor > s.Seq {
			if !s.Truncated {
				skipped, scanned, err := Next(ctx, st, f, s.Seq, floor, 1, scanCap)
				if err != nil {
					return Start{}, err
				}
				s.Truncated = len(skipped) > 0 || scanned < floor
			}
			s.Seq = floor
		}
	}
	return s, nil
}

const batch = 500

// Next is up to limit (0 for no limit) events in (after, upTo] the filter lets through, in
// seq order, and the position read through: the seq of the last event
// returned when limit was reached, else upTo. maxScan > 0 stops after that
// many events are read, returning the position reached.
func Next(ctx context.Context, st *store.Store, f Filter, after, upTo int64, limit, maxScan int) ([]store.Event, int64, error) {
	out := []store.Event{}
	pos, read := after, 0
	for pos < upTo {
		evs, err := st.EventsFor(ctx, f.IdentityID, pos, upTo, batch)
		if err != nil {
			return nil, pos, err
		}
		for _, e := range evs {
			pos = e.Seq
			read++
			if f.Match(e) {
				out = append(out, e)
				if limit > 0 && len(out) == limit {
					return out, pos, nil
				}
			}
			if maxScan > 0 && read >= maxScan {
				return out, pos, nil
			}
		}
		if len(evs) < batch {
			return out, upTo, nil
		}
	}
	return out, upTo, nil
}

// ErrorObject is the nested JSON-RPC error SEP-3415 carries in a
// terminated or error signal.
type ErrorObject struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

// SEP-3415 error codes (provisional in the draft).
const (
	CodeNotFound              = -32023
	CodeForbidden             = -32024
	CodeResourceExhausted     = -32025
	CodeUnsupported           = -32026
	CodeCallbackEndpointError = -32027
)

// ChannelDeleted is the termination for a subscription whose channel was
// deleted.
func ChannelDeleted(name string) ErrorObject {
	return ErrorObject{Code: CodeNotFound, Message: "NotFound", Data: map[string]any{"kind": "channel", "channel": name, "reason": "The channel was deleted"}}
}

// AccessRevoked is the termination for a subscription whose identity or
// authorization is gone.
func AccessRevoked(reason string) ErrorObject {
	return ErrorObject{Code: CodeForbidden, Message: "Forbidden", Data: map[string]any{"reason": reason}}
}

// MarshalData is v as the raw JSON an event's data is stored as.
func MarshalData(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	return json.RawMessage(b), err
}
