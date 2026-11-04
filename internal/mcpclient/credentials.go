// Package mcpclient is the CLI's side of the platform: its saved sign-ins,
// the OAuth client that makes them (RFC 9728 and 8414 discovery, RFC 7591
// registration, PKCE with a loopback redirect), and a 2026-07-28 MCP
// client over Streamable HTTP that renews its token as it goes.
package mcpclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Profile is one saved sign-in.
type Profile struct {
	Server             string    `json:"server"`
	MCPURL             string    `json:"mcp_url"`
	Resource           string    `json:"resource"`
	Issuer             string    `json:"issuer"`
	TokenEndpoint      string    `json:"token_endpoint"`
	RevocationEndpoint string    `json:"revocation_endpoint,omitempty"`
	ClientID           string    `json:"client_id"`
	ClientSecret       string    `json:"client_secret,omitempty"`
	AccessToken        string    `json:"access_token"`
	RefreshToken       string    `json:"refresh_token,omitempty"`
	ExpiresAt          time.Time `json:"expires_at"`
	Scope              string    `json:"scope,omitempty"`
	IdentityID         string    `json:"identity_id,omitempty"`
	IdentityName       string    `json:"identity_name,omitempty"`
}

// File is the credentials file: profiles by name.
type File struct {
	Profiles map[string]*Profile `json:"profiles"`
}

// DefaultProfile is the profile used when none is named.
const DefaultProfile = "default"

// ConfigDir is where the CLI keeps its files: $MWE_CONFIG_DIR, else
// $XDG_CONFIG_HOME/mwe, else ~/.config/mwe.
func ConfigDir() (string, error) {
	if d := os.Getenv("MWE_CONFIG_DIR"); d != "" {
		return d, nil
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" && filepath.IsAbs(d) {
		return filepath.Join(d, "mwe"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "mwe"), nil
}

func credPath(dir string) string { return filepath.Join(dir, "credentials.json") }

// Load reads the credentials file; a missing file is an empty one. A file
// that doesn't parse is an error, never "no sign-ins", so a save can't
// write over it.
func Load(dir string) (*File, error) {
	b, err := os.ReadFile(credPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return &File{Profiles: map[string]*Profile{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var f File
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s doesn't parse (%v); fix or remove it", credPath(dir), err)
	}
	if f.Profiles == nil {
		f.Profiles = map[string]*Profile{}
	}
	return &f, nil
}

// Save writes the credentials file atomically, readable by the user only.
func Save(dir string, f *File) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".credentials-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), credPath(dir))
}

// Update loads the file under the lock, lets f change it, and saves it when
// f reports a change.
func Update(dir string, f func(*File) (bool, error)) error {
	unlock, err := Lock(dir)
	if err != nil {
		return err
	}
	defer unlock()
	file, err := Load(dir)
	if err != nil {
		return err
	}
	changed, err := f(file)
	if err != nil || !changed {
		return err
	}
	return Save(dir, file)
}
