package ident

import (
	"strings"
	"testing"
)

func TestValidUser(t *testing.T) {
	good := []string{"a", "github-push", "ci2", "a-b-c", "0", strings.Repeat("a", 64)}
	bad := []string{"", "-a", "a-", "a--b", "A", "a_b", "a.b", ":system", "a b", strings.Repeat("a", 65), "é"}
	for _, s := range good {
		if !ValidUser(s) {
			t.Errorf("ValidUser(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if ValidUser(s) {
			t.Errorf("ValidUser(%q) = true, want false", s)
		}
	}
}

func TestValidReserved(t *testing.T) {
	good := []string{":system", ":a", ":ops:deploy", ":x-y", ":0"}
	bad := []string{"system", ":", "::a", ":-a", ":A", ":a b", ":" + strings.Repeat("a", 64)}
	for _, s := range good {
		if !ValidReserved(s) {
			t.Errorf("ValidReserved(%q) = false, want true", s)
		}
	}
	for _, s := range bad {
		if ValidReserved(s) {
			t.Errorf("ValidReserved(%q) = true, want false", s)
		}
	}
}

func TestValidFilterTakesBoth(t *testing.T) {
	for _, s := range []string{"github-push", ":system"} {
		if !ValidFilter(s) {
			t.Errorf("ValidFilter(%q) = false", s)
		}
	}
	if ValidFilter("Bad") || CheckFilter("Bad") == nil {
		t.Error("ValidFilter took an uppercase identifier")
	}
	if err := CheckUser("identifier", ""); err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("CheckUser(\"\") = %v, want a required error", err)
	}
}
