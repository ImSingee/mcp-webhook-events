// Package ident holds the naming rules for the identifiers webhooks and
// channels are known by.
//
// A user's identifier is lowercase words joined by single hyphens, at most
// 64 characters: "github-push". A reserved identifier starts with ":" and
// names an event the platform itself emits, such as ":system" for a
// broadcast; users can list reserved identifiers in a channel's filter but
// never create one.
package ident

import (
	"fmt"
	"regexp"
)

// MaxLen is the longest identifier, user or reserved.
const MaxLen = 64

var (
	userRe     = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	reservedRe = regexp.MustCompile(`^:[a-z0-9][a-z0-9:-]*$`)
)

// System is the reserved identifier of a platform broadcast.
const System = ":system"

// ValidUser reports whether s is a valid user identifier.
func ValidUser(s string) bool { return len(s) <= MaxLen && userRe.MatchString(s) }

// ValidReserved reports whether s is a valid reserved identifier.
func ValidReserved(s string) bool { return len(s) <= MaxLen && reservedRe.MatchString(s) }

// ValidFilter reports whether s may appear in a channel's identifier list:
// a user identifier or a reserved one.
func ValidFilter(s string) bool { return ValidUser(s) || ValidReserved(s) }

// CheckUser is ValidUser as an error that says what the rule is.
func CheckUser(field, s string) error {
	if ValidUser(s) {
		return nil
	}
	if s == "" {
		return fmt.Errorf("%s is required", field)
	}
	return fmt.Errorf("%s %q is invalid: use lowercase letters and digits in words joined by single hyphens (^[a-z0-9]+(-[a-z0-9]+)*$), at most %d characters", field, s, MaxLen)
}

// CheckFilter is ValidFilter as an error that says what the rule is.
func CheckFilter(s string) error {
	if ValidFilter(s) {
		return nil
	}
	return fmt.Errorf("identifier %q is invalid: use a webhook identifier (^[a-z0-9]+(-[a-z0-9]+)*$) or a reserved one starting with ':' (^:[a-z0-9][a-z0-9:-]*$), at most %d characters", s, MaxLen)
}
