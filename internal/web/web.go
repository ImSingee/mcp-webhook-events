// Package web serves the admin UI's files: the pages (index.html,
// login.html, consent.html) and the scripts, styles and images they name.
//
// The files are embedded in the binary; a build with -tags dev reads them
// from internal/web/assets on every request instead, so a change shows on
// reload. Every file goes out with an ETag of its content, to be asked for
// again each time (an unchanged file is a 304), and a page names each of
// its own scripts and styles with its content's hash (/app.js?v=…): a
// browser or proxy that kept an older app.js never serves it under a newer
// page, and a file asked for by its current hash is cached for good.
package web

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strings"
	"time"
)

//go:embed assets
var embedded embed.FS

// Pages are the HTML files the server routes to; the rest are served by
// name.
const (
	IndexPage   = "index.html"
	LoginPage   = "login.html"
	ConsentPage = "consent.html"
)

// Assets is the UI's files: embedded, or read from disk under -tags dev.
func Assets() fs.FS { return assets() }

// Handler serves files from an fs.FS.
type Handler struct {
	fsys fs.FS
	// noStore turns caching off (dev builds).
	noStore bool
}

// New serves fsys; tests pass an fstest.MapFS.
func New(fsys fs.FS) *Handler { return &Handler{fsys: fsys, noStore: devBuild} }

// pageRef is a script, stylesheet or image of the UI's own that a page
// names by a root-relative or relative path.
var pageRef = regexp.MustCompile(`(src|href)="(/?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.(?:js|mjs|css|svg|png|ico|webmanifest|json))"`)

func shortHash(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:6])
}

// versioned is page with each of its own files named by its content's
// hash; a name that isn't among the files keeps its name.
func (h *Handler) versioned(page []byte) []byte {
	return pageRef.ReplaceAllFunc(page, func(m []byte) []byte {
		g := pageRef.FindSubmatch(m)
		ref := string(g[2])
		b, err := fs.ReadFile(h.fsys, strings.TrimPrefix(ref, "/"))
		if err != nil {
			return m
		}
		return []byte(fmt.Sprintf(`%s="%s?v=%s"`, g[1], ref, shortHash(b)))
	})
}

// serve writes one file with its ETag and cache rule.
func (h *Handler) serve(w http.ResponseWriter, r *http.Request, name string) {
	b, err := fs.ReadFile(h.fsys, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(name, ".html") {
		b = h.versioned(b)
	}
	sum := sha256.Sum256(b)
	w.Header().Set("ETag", `"`+hex.EncodeToString(sum[:12])+`"`)
	switch {
	case h.noStore:
		w.Header().Set("Cache-Control", "no-store")
	case r.URL.Query().Get("v") != "" && r.URL.Query().Get("v") == hex.EncodeToString(sum[:6]):
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	default:
		w.Header().Set("Cache-Control", "no-cache")
	}
	ct := mime.TypeByExtension(path.Ext(name))
	if strings.HasSuffix(name, ".html") {
		ct = "text/html; charset=utf-8"
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
	}
	if ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(b))
}

// Page serves one of the pages, whatever the request's path.
func (h *Handler) Page(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.serve(w, r, name) })
}

// Has reports whether the UI has a file by that name.
func (h *Handler) Has(name string) bool {
	_, err := fs.Stat(h.fsys, name)
	return err == nil
}

// Static serves the file the request's path names. Directories and the
// root aren't served.
func (h *Handler) Static() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if name == "" || strings.HasPrefix(name, ".") || strings.Contains(name, "/.") {
			http.NotFound(w, r)
			return
		}
		if st, err := fs.Stat(h.fsys, name); err != nil || st.IsDir() {
			http.NotFound(w, r)
			return
		}
		h.serve(w, r, name)
	})
}
