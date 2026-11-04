//go:build !unix

package mcpclient

import (
	"os"
	"path/filepath"
	"time"
)

// Lock takes the credentials lock by creating a lock file exclusively,
// waiting for another process to remove it (and taking over one older than
// a minute, left by a process that died).
func Lock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "credentials.lock")
	for {
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err == nil {
			f.Close()
			return func() { os.Remove(p) }, nil
		}
		if st, serr := os.Stat(p); serr == nil && time.Since(st.ModTime()) > time.Minute {
			os.Remove(p)
			continue
		}
		time.Sleep(50 * time.Millisecond)
	}
}
