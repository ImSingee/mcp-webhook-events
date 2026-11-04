// Package core is the platform's operations as the admin UI, the MCP
// tools and the webhook endpoint share them: each one checks its input,
// writes the store, and tells the readers of the event feed what changed,
// so a channel edited in the UI or by an agent reaches open streams the
// same way.
package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/ImSingee/mcp-webhook-events/internal/config"
	"github.com/ImSingee/mcp-webhook-events/internal/events"
	"github.com/ImSingee/mcp-webhook-events/internal/ident"
	"github.com/ImSingee/mcp-webhook-events/internal/idgen"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
)

// InvalidError is input that breaks a rule; its message says which.
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &InvalidError{Msg: fmt.Sprintf(format, a...)} }

// IsInvalid reports whether err is an InvalidError.
func IsInvalid(err error) bool {
	var ie *InvalidError
	return errors.As(err, &ie)
}

// Terminator ends webhook-mode subscriptions, telling their endpoints.
type Terminator interface {
	Terminate(ctx context.Context, subs []store.Subscription, why events.ErrorObject)
}

// Service is the platform's operations.
type Service struct {
	Store *store.Store
	Hub   *events.Hub
	Cfg   config.Config
	Log   *slog.Logger
	// Subs ends webhook-mode subscriptions; set once delivery is running.
	Subs Terminator

	// appendMu makes event writes and their wake-ups happen one at a time,
	// in seq order, which the feed's readers rely on.
	appendMu sync.Mutex
}

// New is a service over st.
func New(cfg config.Config, st *store.Store, hub *events.Hub, log *slog.Logger) *Service {
	return &Service{Store: st, Hub: hub, Cfg: cfg, Log: log}
}

// AppendEvent stores an event and wakes the feed's readers.
func (s *Service) AppendEvent(ctx context.Context, e store.Event) (store.Event, error) {
	s.appendMu.Lock()
	defer s.appendMu.Unlock()
	e, err := s.Store.InsertEvent(ctx, e)
	if err != nil {
		return e, err
	}
	s.Hub.Published()
	return e, nil
}

// EventData is an event's data as agents receive it (the payload of
// webhook.received) and the admin UI shows it.
type EventData struct {
	Identifier string       `json:"identifier"`
	Kind       string       `json:"kind"`
	Webhook    *WebhookRef  `json:"webhook"`
	ReceivedAt string       `json:"received_at"`
	Request    *RequestData `json:"request"`
	Message    *string      `json:"message"`
	Title      *string      `json:"title"`
}

// WebhookRef names the webhook an event came in on.
type WebhookRef struct {
	Name string `json:"name"`
}

// RequestData is the received HTTP request, without the webhook key.
type RequestData struct {
	Method       string              `json:"method"`
	Query        map[string][]string `json:"query"`
	Headers      map[string][]string `json:"headers"`
	ContentType  string              `json:"content_type"`
	BodyEncoding string              `json:"body_encoding"` // json, text, base64 or none
	Body         any                 `json:"body"`
}

// Broadcast posts a platform event to every identity. identifier must be
// reserved (":system" when empty).
func (s *Service) Broadcast(ctx context.Context, identifier, title, message string) (store.Event, error) {
	if identifier == "" {
		identifier = ident.System
	}
	if !ident.ValidReserved(identifier) {
		return store.Event{}, invalid("identifier %q must be a reserved identifier: ':' then lowercase letters, digits, ':' or '-' (^:[a-z0-9][a-z0-9:-]*$), at most %d characters", identifier, ident.MaxLen)
	}
	message = strings.TrimSpace(message)
	if message == "" {
		return store.Event{}, invalid("message is required")
	}
	if len(message) > 16<<10 || len(title) > 512 {
		return store.Event{}, invalid("the title is limited to 512 bytes and the message to 16 KiB")
	}
	now := s.Store.Now()
	d := EventData{Identifier: identifier, Kind: "system", ReceivedAt: events.Stamp(now), Message: &message}
	if t := strings.TrimSpace(title); t != "" {
		d.Title = &t
	}
	data, err := events.MarshalData(d)
	if err != nil {
		return store.Event{}, err
	}
	return s.AppendEvent(ctx, store.Event{ID: idgen.ID("evt"), Identifier: identifier, Kind: "system", ReceivedAt: now, Data: data})
}

// Identity names: any text, 1 to 64 characters once trimmed.
func checkIdentityName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || utf8.RuneCountInString(name) > 64 {
		return "", invalid("name must be 1 to 64 characters")
	}
	return name, nil
}

// CreateIdentity adds an identity.
func (s *Service) CreateIdentity(ctx context.Context, name string) (store.Identity, error) {
	name, err := checkIdentityName(name)
	if err != nil {
		return store.Identity{}, err
	}
	return s.Store.CreateIdentity(ctx, name)
}

// RenameIdentity renames an identity.
func (s *Service) RenameIdentity(ctx context.Context, id, name string) error {
	name, err := checkIdentityName(name)
	if err != nil {
		return err
	}
	return s.Store.RenameIdentity(ctx, id, name)
}

// DeleteIdentity deletes an identity with everything it owns, ending its
// open streams and webhook-mode subscriptions first.
func (s *Service) DeleteIdentity(ctx context.Context, id string) error {
	if _, err := s.Store.GetIdentity(ctx, id); err != nil {
		return err
	}
	subs, err := s.Store.SubscriptionsWhere(ctx, "", id, "")
	if err != nil {
		return err
	}
	why := events.AccessRevoked("The identity was deleted")
	if s.Subs != nil && len(subs) > 0 {
		s.Subs.Terminate(ctx, subs, why)
	}
	if err := s.Store.DeleteIdentity(ctx, id); err != nil {
		return err
	}
	s.Hub.End(func(sub *events.Sub) bool { return sub.IdentityID == id }, why)
	return nil
}

// RevokeAuthorization revokes one of an identity's authorizations.
func (s *Service) RevokeAuthorization(ctx context.Context, identityID, familyID string) error {
	if err := s.Store.RevokeAuthorization(ctx, identityID, familyID); err != nil {
		return err
	}
	s.FamilyRevoked(ctx, familyID)
	return nil
}

// FamilyRevoked ends what an authorization had open once it is revoked:
// its push streams and the webhook-mode subscriptions it last refreshed.
func (s *Service) FamilyRevoked(ctx context.Context, familyID string) {
	why := events.AccessRevoked("Access revoked")
	s.Hub.End(func(sub *events.Sub) bool { return sub.FamilyID == familyID }, why)
	subs, err := s.Store.SubscriptionsWhere(ctx, "", "", familyID)
	if err != nil {
		s.Log.Error("list subscriptions of a revoked authorization", "family", familyID, "err", err)
		return
	}
	if s.Subs != nil && len(subs) > 0 {
		s.Subs.Terminate(ctx, subs, why)
	}
}

// WebhookURL is the public URL of a webhook's path token.
func (s *Service) WebhookURL(token string) string { return s.Cfg.PublicURL + "/hooks/" + token }

func checkText(field string, v string, max int) error {
	if utf8.RuneCountInString(v) > max {
		return invalid("%s is limited to %d characters", field, max)
	}
	return nil
}

// CreateWebhook adds a webhook and returns it with its key, which is shown
// only this once.
func (s *Service) CreateWebhook(ctx context.Context, identityID, identifier, name, description string) (store.Webhook, string, error) {
	if err := ident.CheckUser("identifier", identifier); err != nil {
		return store.Webhook{}, "", &InvalidError{Msg: err.Error()}
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = identifier
	}
	if err := errors.Join(checkText("name", name, 200), checkText("description", description, 2000)); err != nil {
		return store.Webhook{}, "", err
	}
	key := idgen.Secret("mwek_")
	w, err := s.Store.CreateWebhook(ctx, store.Webhook{
		ID: idgen.ID("whk"), IdentityID: identityID, Identifier: identifier, Name: name, Description: description,
		PathToken: idgen.Secret(""), KeyHash: idgen.Hash(key),
	})
	return w, key, err
}

// UpdateWebhook changes a webhook's name or description.
func (s *Service) UpdateWebhook(ctx context.Context, identityID, id string, name, description *string) error {
	if name != nil {
		n := strings.TrimSpace(*name)
		if n == "" {
			return invalid("name can't be empty")
		}
		name = &n
		if err := checkText("name", n, 200); err != nil {
			return err
		}
	}
	if description != nil {
		if err := checkText("description", *description, 2000); err != nil {
			return err
		}
	}
	return s.Store.UpdateWebhook(ctx, identityID, id, name, description)
}

// RotateWebhookKey gives a webhook a new key and returns it; the old one
// stops working at once.
func (s *Service) RotateWebhookKey(ctx context.Context, identityID, id string) (string, error) {
	key := idgen.Secret("mwek_")
	return key, s.Store.RotateWebhookKey(ctx, identityID, id, idgen.Hash(key))
}

// ChannelPatch is a partial channel update: nil fields stay as they are.
type ChannelPatch struct {
	Description *string
	Mode        *string
	Identifiers *[]string
}

func checkChannel(c *store.Channel) error {
	if err := ident.CheckUser("name", c.Name); err != nil {
		return &InvalidError{Msg: err.Error()}
	}
	if err := checkText("description", c.Description, 1000); err != nil {
		return err
	}
	switch c.Mode {
	case "all":
		if len(c.Identifiers) > 0 {
			return invalid("identifiers must be empty when mode is all")
		}
	case "include", "exclude":
	default:
		return invalid("mode %q must be all, include or exclude", c.Mode)
	}
	if len(c.Identifiers) > 200 {
		return invalid("a channel lists at most 200 identifiers")
	}
	seen := make([]string, 0, len(c.Identifiers))
	for _, id := range c.Identifiers {
		if err := ident.CheckFilter(id); err != nil {
			return &InvalidError{Msg: err.Error()}
		}
		if !slices.Contains(seen, id) {
			seen = append(seen, id)
		}
	}
	c.Identifiers = seen
	return nil
}

// CreateChannel adds a channel.
func (s *Service) CreateChannel(ctx context.Context, c store.Channel) (store.Channel, error) {
	if c.Mode == "" {
		c.Mode = "all"
	}
	if c.Identifiers == nil {
		c.Identifiers = []string{}
	}
	if err := checkChannel(&c); err != nil {
		return store.Channel{}, err
	}
	c.ID = idgen.ID("chn")
	return s.Store.CreateChannel(ctx, c)
}

// UpdateChannel applies p to a channel; open streams on it filter their
// next event by the new rule.
func (s *Service) UpdateChannel(ctx context.Context, identityID, id string, p ChannelPatch) (store.ChannelInfo, error) {
	cur, err := s.Store.GetChannel(ctx, id)
	if err != nil {
		return store.ChannelInfo{}, err
	}
	if cur.IdentityID != identityID {
		return store.ChannelInfo{}, store.ErrNotFound
	}
	c := cur.Channel
	if p.Description != nil {
		c.Description = *p.Description
	}
	if p.Mode != nil {
		c.Mode = *p.Mode
		// switching to all drops a list that no longer applies
		if c.Mode == "all" && p.Identifiers == nil {
			c.Identifiers = []string{}
		}
	}
	if p.Identifiers != nil {
		c.Identifiers = *p.Identifiers
		if c.Identifiers == nil {
			c.Identifiers = []string{}
		}
	}
	if err := checkChannel(&c); err != nil {
		return store.ChannelInfo{}, err
	}
	if err := s.Store.UpdateChannel(ctx, c); err != nil {
		return store.ChannelInfo{}, err
	}
	s.Hub.ChannelChanged(id)
	return s.Store.GetChannel(ctx, id)
}

// DeleteChannel deletes a channel, ending its open streams and webhook-mode
// subscriptions with a terminated signal.
func (s *Service) DeleteChannel(ctx context.Context, identityID, id string) error {
	cur, err := s.Store.GetChannel(ctx, id)
	if err != nil {
		return err
	}
	if cur.IdentityID != identityID {
		return store.ErrNotFound
	}
	subs, err := s.Store.SubscriptionsWhere(ctx, id, "", "")
	if err != nil {
		return err
	}
	why := events.ChannelDeleted(cur.Name)
	if s.Subs != nil && len(subs) > 0 {
		s.Subs.Terminate(ctx, subs, why)
	}
	if err := s.Store.DeleteChannel(ctx, identityID, id); err != nil {
		return err
	}
	s.Hub.End(func(sub *events.Sub) bool { return sub.ChannelID == id }, why)
	return nil
}

// Maintain runs the periodic cleanup until ctx ends: event retention,
// expired OAuth state and lapsed subscriptions.
func (s *Service) Maintain(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		s.MaintainOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// MaintainOnce is one round of Maintain.
func (s *Service) MaintainOnce(ctx context.Context) {
	if n, err := s.Store.PruneEvents(ctx, s.Store.Now().Add(-s.Cfg.EventRetention)); err != nil {
		s.Log.Error("prune events", "err", err)
	} else if n > 0 {
		s.Log.Info("pruned events past retention", "count", n)
	}
	if err := s.Store.CleanupOAuth(ctx); err != nil {
		s.Log.Error("clean up oauth state", "err", err)
	}
	if n, err := s.Store.ExpireSubscriptions(ctx); err != nil {
		s.Log.Error("expire subscriptions", "err", err)
	} else if n > 0 {
		s.Log.Info("webhook subscriptions expired", "count", n)
	}
}
