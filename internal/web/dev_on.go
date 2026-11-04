//go:build dev

package web

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

// Development build (make dev): the UI is read from internal/web/assets on
// every request and nothing is cached, so an edit shows on reload.
const devBuild = true

func assetsDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "assets")
}

func assets() fs.FS { return os.DirFS(assetsDir()) }
