// Package idgen makes the random identifiers and secrets the server hands
// out, and the hashes it stores in their place.
package idgen

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ID is prefix + "_" + 16 random bytes in lowercase base32, such as
// "evt_…": unguessable and safe in URLs, headers and file names.
func ID(prefix string) string {
	return prefix + "_" + strings.ToLower(b32.EncodeToString(Bytes(16)))
}

// Secret is prefix + 32 random bytes in base64url, for bearer secrets
// (tokens, webhook keys, cookies) that are stored only as a Hash.
func Secret(prefix string) string {
	return prefix + base64.RawURLEncoding.EncodeToString(Bytes(32))
}

// Bytes is n bytes from the system's CSPRNG.
func Bytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("idgen: crypto/rand failed: " + err.Error())
	}
	return b
}

// Hash is the hex SHA-256 of a high-entropy secret. A secret made by Secret
// has 256 bits of entropy, so a fast hash is enough to keep the stored
// value from being usable.
func Hash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// Equal compares two strings in constant time with respect to their content.
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// HashEqual reports whether secret hashes to hash, in constant time.
func HashEqual(secret, hash string) bool { return Equal(Hash(secret), hash) }
