// Package delivery is SEP-3415's webhook delivery mode: events/subscribe's
// subscriptions, the endpoint verification handshake, and the worker that
// POSTs each subscription's events in order, signed by the Standard
// Webhooks scheme, to callback URLs it checks against SSRF at every
// connection.
package delivery

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
)

// ErrBadSecret is a delivery.secret that isn't a Standard Webhooks
// symmetric secret: "whsec_" and the base64 of 24 to 64 random bytes.
var ErrBadSecret = errors.New(`delivery.secret must be "whsec_" followed by the base64 encoding of 24 to 64 random bytes`)

// ParseSecret is the key bytes of a whsec_ secret.
func ParseSecret(s string) ([]byte, error) {
	b64, ok := strings.CutPrefix(s, "whsec_")
	if !ok {
		return nil, ErrBadSecret
	}
	var (
		key []byte
		err error
	)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err = enc.Strict().DecodeString(b64); err == nil {
			break
		}
	}
	if err != nil || len(key) < 24 || len(key) > 64 {
		return nil, ErrBadSecret
	}
	return key, nil
}

// Signature is the webhook-signature header for body: "v1,<base64 HMAC>"
// for each secret, space-separated, over "<id>.<timestamp>.<body>".
// Secrets that don't parse are skipped.
func Signature(secrets []string, msgID string, timestamp int64, body []byte) string {
	var sigs []string
	for _, s := range secrets {
		key, err := ParseSecret(s)
		if err != nil {
			continue
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(msgID + "." + strconv.FormatInt(timestamp, 10) + "."))
		mac.Write(body)
		sigs = append(sigs, "v1,"+base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	}
	return strings.Join(sigs, " ")
}
