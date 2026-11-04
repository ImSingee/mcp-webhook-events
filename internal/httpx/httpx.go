// Package httpx holds the small HTTP helpers the server's handlers share.
package httpx

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// WriteJSON writes v as a JSON response with status.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// ErrTooLarge is a body over the reader's limit.
var ErrTooLarge = errors.New("request body too large")

// ReadBody reads up to limit bytes of r's body; ErrTooLarge past it.
func ReadBody(r *http.Request, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, ErrTooLarge
	}
	return b, nil
}

// DecodeJSON reads a JSON body of at most limit bytes into v, refusing
// fields v doesn't have.
func DecodeJSON(r *http.Request, limit int64, v any) error {
	b, err := ReadBody(r, limit)
	if err != nil {
		return err
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("unexpected data after the JSON body")
	}
	return nil
}

// ClientIP is the address a request came from: the first X-Forwarded-For
// entry when the server sits behind a trusted proxy, else the peer.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if ip := strings.TrimSpace(first); ip != "" {
				return ip
			}
		}
		if ip := strings.TrimSpace(r.Header.Get("X-Real-Ip")); ip != "" {
			return ip
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// SSE prepares w for a Server-Sent Events stream and sends its headers. The
// returned flush pushes what was written so far to the client.
func SSE(w http.ResponseWriter) (flush func() error) {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache, no-store")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Time{})
	_ = rc.Flush()
	return rc.Flush
}
