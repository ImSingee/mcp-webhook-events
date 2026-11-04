//go:build !dev

package web

import "io/fs"

const devBuild = false

// The shipped server serves the UI from the binary.
func assets() fs.FS {
	f, err := fs.Sub(embedded, "assets")
	if err != nil {
		panic(err)
	}
	return f
}
