// Command mwe-server is the mcp-webhook-events platform: it receives
// webhooks and delivers them to AI agents as MCP events (SEP-3415), with
// its own OAuth authorization server and admin UI. It is configured
// entirely by MWE_* environment variables (see README.md).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/app"
	"github.com/ImSingee/mcp-webhook-events/internal/config"
	"github.com/ImSingee/mcp-webhook-events/internal/version"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-version", "--version":
			fmt.Println("mwe-server", version.Version)
			return
		case "healthcheck":
			os.Exit(healthcheck())
		case "-h", "-help", "--help", "help":
			fmt.Println("usage: mwe-server              run the server (configured by MWE_* environment variables; see README.md)\n       mwe-server version\n       mwe-server healthcheck  exit 0 when the local server answers /healthz")
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mwe-server:", err)
		os.Exit(1)
	}
}

// healthcheck asks the server on MWE_ADDR for /healthz, for the container's
// health check.
func healthcheck() int {
	addr := os.Getenv("MWE_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort(host, port) + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck:", resp.Status)
		return 1
	}
	return 0
}

func run() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a, err := app.New(ctx, cfg, log, app.Options{})
	if err != nil {
		return err
	}
	defer a.Close()
	a.Start()
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: a.Handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	log.Info("mwe-server listening", "addr", ln.Addr().String(), "public_url", cfg.PublicURL, "mcp", cfg.MCPResource(), "version", version.Version, "data", cfg.DBPath())
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	// end the background work and the open streams first, which write their
	// final frames, then let the in-flight requests finish
	a.Stop()
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}
