package config

import (
	"strings"
	"testing"
)

func TestValidName(t *testing.T) {
	for _, ok := range []string{"a", "hq-laptop", "p3000", "a1-b2-c3", strings.Repeat("x", 63)} {
		if !ValidName(ok) {
			t.Errorf("ValidName(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{"", "-lead", "trail-", "UPPER", "under_score", "has space", "dot.name", strings.Repeat("x", 64), "é"} {
		if ValidName(bad) {
			t.Errorf("ValidName(%q) = true, want false", bad)
		}
	}
}

func TestAutoName(t *testing.T) {
	for in, want := range map[string]string{
		"Kabir-ThinkPad": "kabir-thinkpad",
		"  spaced out  ": "spaced-out",
		"a__b..c":        "a-b-c",
		"---":            "device",
		"":               "device",
	} {
		if got := AutoName(in); got != want {
			t.Errorf("AutoName(%q) = %q, want %q", in, got, want)
		}
	}
	if got := AutoName(strings.Repeat("z", 100)); len(got) > 48 || !ValidName(got) {
		t.Errorf("long name not stemmed validly: %q", got)
	}
	// Multibyte truncation must stay valid (no split runes).
	if got := AutoName(strings.Repeat("é", 100)); !ValidName(got) {
		t.Errorf("multibyte stem invalid: %q", got)
	}
}

func TestValidHost(t *testing.T) {
	for _, ok := range []string{
		"t3.oci.pujan.space", "a.b", "localhost", "x123.y-z9.example",
	} {
		if !ValidHost(ok) {
			t.Errorf("ValidHost(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"", "UPPER.com", "has space.com", "trail-.com", "-lead.com",
		"a..b", "http://x.com", "x.com:443", "x.com/path", "under_score.com",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 130) + "com",
	} {
		if ValidHost(bad) {
			t.Errorf("ValidHost(%q) = true, want false", bad)
		}
	}
}
