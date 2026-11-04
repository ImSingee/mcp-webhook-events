// Package app assembles the server: the store, the event feed, the OAuth
// authorization server, the MCP endpoint, the webhook endpoint, the
// webhook delivery worker and the admin UI, behind one http.Handler.
package app

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/admin"
	"github.com/ImSingee/mcp-webhook-events/internal/config"
	"github.com/ImSingee/mcp-webhook-events/internal/core"
	"github.com/ImSingee/mcp-webhook-events/internal/delivery"
	"github.com/ImSingee/mcp-webhook-events/internal/events"
	"github.com/ImSingee/mcp-webhook-events/internal/ingest"
	"github.com/ImSingee/mcp-webhook-events/internal/mcp"
	"github.com/ImSingee/mcp-webhook-events/internal/oauth"
	"github.com/ImSingee/mcp-webhook-events/internal/store"
	"github.com/ImSingee/mcp-webhook-events/internal/web"
)

// App is the assembled server.
type App struct {
	Cfg    config.Config
	Log    *slog.Logger
	Store  *store.Store
	Hub    *events.Hub
	Core   *core.Service
	OAuth  *oauth.Server
	Worker *delivery.Worker
	MCP    *mcp.Server
	Admin  *admin.Server
	// Handler serves every route.
	Handler http.Handler

	cancel context.CancelFunc
	done   chan struct{}
}

// Options adjust an App, for tests.
type Options struct {
	// Assets replaces the UI's files.
	Assets fs.FS
	// Resolver replaces the delivery guard's DNS.
	Resolver delivery.Resolver
}

// New opens the database and assembles the server.
func New(ctx context.Context, cfg config.Config, log *slog.Logger, opt Options) (*App, error) {
	st, err := store.Open(ctx, cfg.DBPath())
	if err != nil {
		return nil, err
	}
	hub := events.NewHub()
	svc := core.New(cfg, st, hub, log)
	guard := &delivery.Guard{AllowPrivate: cfg.AllowPrivateCallbacks, Resolver: opt.Resolver}
	worker := delivery.NewWorker(st, hub, guard, log.With("component", "delivery"))
	worker.Allowlisted = cfg.CallbackAllowed
	svc.Subs = worker
	auth := oauth.New(cfg, st, svc, log.With("component", "oauth"))
	assets := opt.Assets
	if assets == nil {
		assets = web.Assets()
	}
	a := &App{
		Cfg: cfg, Log: log, Store: st, Hub: hub, Core: svc, OAuth: auth, Worker: worker,
		MCP:   mcp.New(cfg, svc, auth, worker, log.With("component", "mcp")),
		Admin: admin.New(cfg, svc, auth, web.New(assets), log.With("component", "admin")),
	}
	mux := http.NewServeMux()
	auth.Routes(mux)
	mux.Handle("/mcp", a.MCP)
	mux.Handle("/hooks/{token}", &ingest.Handler{Core: svc, MaxBody: cfg.MaxBodyBytes, Log: log.With("component", "ingest")})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	a.Admin.Routes(mux)
	a.Handler = logged(log, mux)
	return a, nil
}

// Start runs the background work (delivery, retention) until Stop. Open
// streams end gracefully, with their final result, when Stop is called.
func (a *App) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancel = cancel
	a.done = make(chan struct{})
	a.MCP.Base, a.Admin.Base = ctx, ctx
	go func() {
		defer close(a.done)
		go a.Core.Maintain(ctx, 10*time.Minute)
		a.Worker.Run(ctx)
	}()
}

// Stop ends the background work and the open streams.
func (a *App) Stop() {
	if a.cancel != nil {
		a.cancel()
		<-a.done
	}
}

// Close stops the app and closes the database.
func (a *App) Close() error {
	a.Stop()
	return a.Store.Close()
}

// recorder keeps a response's status for the request log, and unwraps to
// the real writer so streams can still flush.
type recorder struct {
	http.ResponseWriter
	status int
}

func (r *recorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.ResponseWriter.Write(b)
}

func (r *recorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func logged(log *slog.Logger, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w}
		h.ServeHTTP(rec, r)
		level := slog.LevelDebug
		if rec.status >= 500 {
			level = slog.LevelError
		} else if rec.status >= 400 {
			level = slog.LevelInfo
		}
		log.Log(r.Context(), level, "http", "method", r.Method, "path", r.URL.Path, "status", rec.status, "dur", time.Since(start).Round(time.Millisecond).String(), "mcp_method", r.Header.Get("Mcp-Method"))
	})
}
