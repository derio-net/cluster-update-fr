package scrub

import (
	"strings"
	"testing"
)

func TestTranscriptStripsEscapesBeforeScrubbing(t *testing.T) {
	secret := "session-" + strings.Repeat("Tk8", 6)
	half := len(secret) / 2
	coloured := "$ echo \x1b[31m" + secret[:half] + "\x1b[0m" + secret[half:] + "\r\n\x1b]0;title\x07done"
	set := NewSet(nil)
	set.Add("omni-sa-key", secret)
	out := Transcript(set, coloured)
	if strings.Contains(out, secret[:half]) || strings.Contains(out, secret[half:]) {
		t.Fatalf("token split by a colour code leaked: %q", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("escape sequences must be stripped: %q", out)
	}
	if !strings.Contains(out, "done") {
		t.Errorf("text after an OSC sequence lost: %q", out)
	}
}
