// Command mwe is the mcp-webhook-events CLI: sign in to a server, manage
// webhooks and channels, follow events, and bridge a stdio MCP client to
// the server (mwe mcp).
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/ImSingee/mcp-webhook-events/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Run(ctx, cli.Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}, os.Args[1:])
	stop()
	os.Exit(code)
}
