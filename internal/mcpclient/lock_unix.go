//go:build unix

package mcpclient

import (
	"os"
	"path/filepath"
	"syscall"
)

// Lock takes the credentials lock, an exclusive flock on a file beside
// them, so two mwe processes never rotate the same refresh token at once:
// the server revokes a sign-in whose refresh token is used twice.
func Lock(dir string) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "credentials.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
