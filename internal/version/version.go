// Package version holds the build's version, set at link time:
//
//	go build -ldflags "-X github.com/ImSingee/mcp-webhook-events/internal/version.Version=v1.2.3"
package version

// Version is the build's version string; "dev" for a build without ldflags.
var Version = "dev"
