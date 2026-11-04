// Package cli is the mwe command: signing in to a server, managing
// webhooks and channels through its MCP tools, following events, and the
// stdio bridge that lets a stdio-only MCP client use the server.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ImSingee/mcp-webhook-events/internal/mcpclient"
	"github.com/ImSingee/mcp-webhook-events/internal/version"
)

// Env is what a command runs with, so tests can give their own.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// ConfigDir holds the credentials ("" for mcpclient.ConfigDir()).
	ConfigDir string
	// HTTP is the client for everything; it must have no overall
	// timeout, since streams stay open.
	HTTP *http.Client
	// OpenBrowser opens the sign-in page (nil for the system browser).
	OpenBrowser func(string) error
}

const usage = `mwe — the mcp-webhook-events CLI

Usage:
  mwe login <server-url> [--profile p] [--no-browser]   sign in (OAuth, in the browser)
  mwe logout [--profile p]                              revoke and forget the sign-in
  mwe status [--profile p] [--json]                     show the sign-in and its identity
  mwe webhooks list|create|update|rotate-key|delete      manage webhooks
  mwe channels list|create|update|delete                manage channels
  mwe events tail --channel c [--cursor x] [--max-age d] [--json]   follow events (events/stream)
  mwe events poll --channel c [--cursor x] [--max-events n] [--follow] [--json]
  mwe mcp [--profile p]                                 stdio MCP bridge to the server
  mwe version

Every command takes --profile (default "default", or $MWE_PROFILE).
Run "mwe <command> -h" for a command's flags.
`

// Run runs mwe with args (without the program name) and returns its exit
// code.
func Run(ctx context.Context, env Env, args []string) int {
	if env.HTTP == nil {
		env.HTTP = &http.Client{}
	}
	if env.ConfigDir == "" {
		d, err := mcpclient.ConfigDir()
		if err != nil {
			fmt.Fprintln(env.Stderr, "mwe:", err)
			return 1
		}
		env.ConfigDir = d
	}
	if len(args) == 0 {
		fmt.Fprint(env.Stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "login":
		err = login(ctx, env, args[1:])
	case "logout":
		err = logout(ctx, env, args[1:])
	case "status":
		err = status(ctx, env, args[1:])
	case "webhooks", "webhook":
		err = webhooks(ctx, env, args[1:])
	case "channels", "channel":
		err = channels(ctx, env, args[1:])
	case "events":
		err = eventsCmd(ctx, env, args[1:])
	case "mcp":
		err = bridgeCmd(ctx, env, args[1:])
	case "version", "--version", "-version":
		fmt.Fprintln(env.Stdout, "mwe", version.Version)
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, usage)
	default:
		fmt.Fprintf(env.Stderr, "mwe: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	if err == nil {
		return 0
	}
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	var ue usageError
	if errors.As(err, &ue) {
		fmt.Fprintln(env.Stderr, "mwe:", err)
		return 2
	}
	fmt.Fprintln(env.Stderr, "mwe:", err)
	return 1
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func usagef(format string, a ...any) error { return usageError{fmt.Sprintf(format, a...)} }

// flags is a command's flag set with the shared --profile.
type flags struct {
	*flag.FlagSet
	profile *string
}

func newFlags(env Env, name string) flags {
	fs := flag.NewFlagSet("mwe "+name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	def := os.Getenv("MWE_PROFILE")
	if def == "" {
		def = mcpclient.DefaultProfile
	}
	return flags{FlagSet: fs, profile: fs.String("profile", def, "the sign-in to use")}
}

// parse parses flags anywhere among the positional arguments and returns
// the positionals.
func (f flags) parse(args []string) ([]string, error) {
	var pos []string
	for {
		if err := f.Parse(args); err != nil {
			return nil, err
		}
		rest := f.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func client(env Env, profile string) (*mcpclient.Client, error) {
	s, err := mcpclient.OpenSession(env.ConfigDir, profile, env.HTTP)
	if err != nil {
		return nil, err
	}
	return mcpclient.NewClient(s, env.HTTP), nil
}

func printJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func login(ctx context.Context, env Env, args []string) error {
	f := newFlags(env, "login")
	noBrowser := f.Bool("no-browser", false, "print the sign-in URL instead of opening a browser")
	name := f.String("client-name", "", "the name the server's consent page shows for this CLI")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return usagef("usage: mwe login <server-url> [--profile p] [--no-browser]")
	}
	d, err := mcpclient.Discover(ctx, env.HTTP, pos[0])
	if err != nil {
		return err
	}
	open := env.OpenBrowser
	if open == nil {
		open = mcpclient.OpenBrowser
	}
	if *noBrowser {
		open = nil
	}
	p, err := mcpclient.Login(ctx, env.HTTP, d, mcpclient.LoginOptions{
		ClientName:  *name,
		OpenBrowser: open,
		Prompt: func(u string) {
			fmt.Fprintf(env.Stderr, "Open this URL to sign in and choose the identity to bind:\n\n  %s\n\nWaiting for the browser...\n", u)
		},
	})
	if err != nil {
		return err
	}
	if err := mcpclient.Update(env.ConfigDir, func(file *mcpclient.File) (bool, error) {
		file.Profiles[*f.profile] = p
		return true, nil
	}); err != nil {
		return err
	}
	c, err := client(env, *f.profile)
	if err != nil {
		return err
	}
	who, err := whoami(ctx, c)
	if err != nil {
		return fmt.Errorf("signed in, but whoami failed: %w", err)
	}
	_ = mcpclient.Update(env.ConfigDir, func(file *mcpclient.File) (bool, error) {
		if q, ok := file.Profiles[*f.profile]; ok {
			q.IdentityID, q.IdentityName = who.Identity.ID, who.Identity.Name
			return true, nil
		}
		return false, nil
	})
	fmt.Fprintf(env.Stdout, "Signed in to %s as identity %q (%s); profile %q.\n", d.MCPURL, who.Identity.Name, who.Identity.ID, *f.profile)
	return nil
}

type whoamiResult struct {
	Identity struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"identity"`
	Client struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"client"`
	MCPURL    string `json:"mcp_url"`
	EventName string `json:"event_name"`
}

func whoami(ctx context.Context, c *mcpclient.Client) (whoamiResult, error) {
	var w whoamiResult
	raw, err := c.CallTool(ctx, "whoami", nil)
	if err != nil {
		return w, err
	}
	return w, json.Unmarshal(raw, &w)
}

func logout(ctx context.Context, env Env, args []string) error {
	f := newFlags(env, "logout")
	if _, err := f.parse(args); err != nil {
		return err
	}
	var p *mcpclient.Profile
	err := mcpclient.Update(env.ConfigDir, func(file *mcpclient.File) (bool, error) {
		p = file.Profiles[*f.profile]
		if p == nil {
			return false, nil
		}
		delete(file.Profiles, *f.profile)
		return true, nil
	})
	if err != nil {
		return err
	}
	if p == nil {
		fmt.Fprintf(env.Stdout, "Profile %q has no sign-in.\n", *f.profile)
		return nil
	}
	if err := mcpclient.Revoke(ctx, env.HTTP, p); err != nil {
		fmt.Fprintf(env.Stderr, "mwe: couldn't revoke the sign-in at the server (%v); it was forgotten here\n", err)
	}
	fmt.Fprintf(env.Stdout, "Signed out of %s (profile %q).\n", p.MCPURL, *f.profile)
	return nil
}

func status(ctx context.Context, env Env, args []string) error {
	f := newFlags(env, "status")
	asJSON := f.Bool("json", false, "print JSON")
	if _, err := f.parse(args); err != nil {
		return err
	}
	c, err := client(env, *f.profile)
	if err != nil {
		return err
	}
	who, err := whoami(ctx, c)
	if err != nil {
		return err
	}
	p := c.Session.Profile()
	if *asJSON {
		printJSON(env.Stdout, map[string]any{"profile": *f.profile, "mcp_url": p.MCPURL, "issuer": p.Issuer, "client_id": p.ClientID, "access_token_expires_at": p.ExpiresAt, "whoami": who})
		return nil
	}
	tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "Profile:\t%s\n", *f.profile)
	fmt.Fprintf(tw, "Server:\t%s\n", p.MCPURL)
	fmt.Fprintf(tw, "Identity:\t%s (%s)\n", who.Identity.Name, who.Identity.ID)
	fmt.Fprintf(tw, "Client:\t%s (%s)\n", who.Client.Name, who.Client.ID)
	fmt.Fprintf(tw, "Token expires:\t%s\n", p.ExpiresAt.Local().Format(time.RFC3339))
	return tw.Flush()
}

func splitList(s string) []string {
	out := []string{}
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

func orDash(v any) string {
	if v == nil {
		return "-"
	}
	if s, ok := v.(string); ok && s == "" {
		return "-"
	}
	return fmt.Sprint(v)
}

// tool runs one tool for a management command and prints its result:
// JSON with --json, else through human.
func tool(ctx context.Context, env Env, profile, name string, args map[string]any, asJSON bool, human func(map[string]any)) error {
	c, err := client(env, profile)
	if err != nil {
		return err
	}
	raw, err := c.CallTool(ctx, name, args)
	if err != nil {
		return err
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return err
	}
	if asJSON {
		printJSON(env.Stdout, v)
		return nil
	}
	human(v)
	return nil
}

func webhooks(ctx context.Context, env Env, args []string) error {
	if len(args) == 0 {
		return usagef("usage: mwe webhooks list|create|update|rotate-key|delete")
	}
	sub, args := args[0], args[1:]
	f := newFlags(env, "webhooks "+sub)
	asJSON := f.Bool("json", false, "print JSON")
	name := f.String("name", "", "display name")
	desc := f.String("description", "", "description")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	set := map[string]bool{}
	f.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	need := func(n int, u string) error {
		if len(pos) != n {
			return usagef("usage: mwe webhooks %s", u)
		}
		return nil
	}
	printKey := func(v map[string]any) {
		fmt.Fprintf(env.Stdout, "Identifier: %v\nURL:        %v\nKey:        %v   (shown only now)\n\n%v\n", v["identifier"], v["url"], v["key"], v["usage"])
	}
	switch sub {
	case "list", "ls":
		if err := need(0, "list [--json]"); err != nil {
			return err
		}
		return tool(ctx, env, *f.profile, "webhook_list", nil, *asJSON, func(v map[string]any) {
			tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "IDENTIFIER\tNAME\tEVENTS\tLAST EVENT\tURL")
			for _, x := range v["webhooks"].([]any) {
				w := x.(map[string]any)
				fmt.Fprintf(tw, "%v\t%v\t%v\t%s\t%v\n", w["identifier"], w["name"], w["event_count"], orDash(w["last_event_at"]), w["url"])
			}
			tw.Flush()
		})
	case "create":
		if err := need(1, "create <identifier> [--name n] [--description d] [--json]"); err != nil {
			return err
		}
		return tool(ctx, env, *f.profile, "webhook_create", map[string]any{"identifier": pos[0], "name": *name, "description": *desc}, *asJSON, printKey)
	case "update":
		if err := need(1, "update <identifier> [--name n] [--description d]"); err != nil {
			return err
		}
		a := map[string]any{"identifier": pos[0]}
		if set["name"] {
			a["name"] = *name
		}
		if set["description"] {
			a["description"] = *desc
		}
		return tool(ctx, env, *f.profile, "webhook_update", a, *asJSON, func(v map[string]any) {
			w := v["webhook"].(map[string]any)
			fmt.Fprintf(env.Stdout, "Updated %v: name %q, description %q\n", w["identifier"], w["name"], w["description"])
		})
	case "rotate-key":
		if err := need(1, "rotate-key <identifier> [--json]"); err != nil {
			return err
		}
		return tool(ctx, env, *f.profile, "webhook_rotate_key", map[string]any{"identifier": pos[0]}, *asJSON, printKey)
	case "delete", "rm":
		if err := need(1, "delete <identifier>"); err != nil {
			return err
		}
		return tool(ctx, env, *f.profile, "webhook_delete", map[string]any{"identifier": pos[0]}, *asJSON, func(v map[string]any) {
			fmt.Fprintf(env.Stdout, "Deleted webhook %v\n", v["deleted"])
		})
	}
	return usagef("unknown webhooks command %q: use list, create, update, rotate-key or delete", sub)
}

func channels(ctx context.Context, env Env, args []string) error {
	if len(args) == 0 {
		return usagef("usage: mwe channels list|create|update|delete")
	}
	sub, args := args[0], args[1:]
	f := newFlags(env, "channels "+sub)
	asJSON := f.Bool("json", false, "print JSON")
	mode := f.String("mode", "", "all, include or exclude")
	ids := f.String("identifiers", "", "comma-separated identifiers for include/exclude")
	desc := f.String("description", "", "description")
	pos, err := f.parse(args)
	if err != nil {
		return err
	}
	set := map[string]bool{}
	f.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	need := func(n int, u string) error {
		if len(pos) != n {
			return usagef("usage: mwe channels %s", u)
		}
		return nil
	}
	printChannel := func(v map[string]any) {
		c := v["channel"].(map[string]any)
		fmt.Fprintf(env.Stdout, "Channel %v: mode %v, identifiers %v\n", c["name"], c["mode"], c["identifiers"])
	}
	switch sub {
	case "list", "ls":
		if err := need(0, "list [--json]"); err != nil {
			return err
		}
		return tool(ctx, env, *f.profile, "channel_list", nil, *asJSON, func(v map[string]any) {
			tw := tabwriter.NewWriter(env.Stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tMODE\tIDENTIFIERS\tSTREAMS\tSUBSCRIPTIONS\tDESCRIPTION")
			for _, x := range v["channels"].([]any) {
				c := x.(map[string]any)
				var list []string
				for _, i := range c["identifiers"].([]any) {
					list = append(list, fmt.Sprint(i))
				}
				fmt.Fprintf(tw, "%v\t%v\t%s\t%v\t%v\t%s\n", c["name"], c["mode"], orDash(strings.Join(list, ",")), c["active_streams"], c["subscription_count"], orDash(c["description"]))
			}
			tw.Flush()
		})
	case "create":
		if err := need(1, "create <name> [--mode all|include|exclude] [--identifiers a,b] [--description d]"); err != nil {
			return err
		}
		m := *mode
		if m == "" {
			m = "all"
		}
		return tool(ctx, env, *f.profile, "channel_create", map[string]any{"name": pos[0], "mode": m, "identifiers": splitList(*ids), "description": *desc}, *asJSON, printChannel)
	case "update":
		if err := need(1, "update <name> [--mode m] [--identifiers a,b] [--description d]"); err != nil {
			return err
		}
		a := map[string]any{"name": pos[0]}
		if set["mode"] {
			a["mode"] = *mode
		}
		if set["identifiers"] {
			a["identifiers"] = splitList(*ids)
		}
		if set["description"] {
			a["description"] = *desc
		}
		return tool(ctx, env, *f.profile, "channel_update", a, *asJSON, printChannel)
	case "delete", "rm":
		if err := need(1, "delete <name>"); err != nil {
			return err
		}
		return tool(ctx, env, *f.profile, "channel_delete", map[string]any{"name": pos[0]}, *asJSON, func(v map[string]any) {
			fmt.Fprintf(env.Stdout, "Deleted channel %v\n", v["deleted"])
		})
	}
	return usagef("unknown channels command %q: use list, create, update or delete", sub)
}
