package scrub

import (
	"strings"
	"testing"
	"time"
)

// p5-relay-3b: acceptance runs against ALL accepted spans. A token T, a
// key/value glued to it (its key has no boundary: the byte before is T's),
// and a bearer token glued to that value (its boundary byte is inside the
// key/value's secret): each acceptance depends on the one before, so a
// decision taken before the glued hits existed leaked the bearer value.
func TestGluedChainNextToARejectedCandidate(t *testing.T) {
	r := strings.Repeat
	gh := "gh" + "p_" + r("Z9", 18)
	bearerValue := r("b4", 8) + "TAILBEARER"
	text := "x " + gh + "pass" + "word=" + r("p8", 4) + "Bear" + "er " + bearerValue + " end"
	got := String(text)
	for _, leak := range []string{gh[len(gh)-8:], "p8p8p8p8", "TAILBEARER"} {
		if strings.Contains(got, leak) {
			t.Errorf("%q survived in %q", leak, got)
		}
	}
	// The rejected candidate on its own (a bearer glued to plain text) still
	// does not redact ordinary prose.
	if got := String("theBearer of good news"); got != "theBearer of good news" {
		t.Errorf("benign glued word redacted: %q", got)
	}
}

func withLimits(t *testing.T, rounds int, d time.Duration, budget func(int) int) {
	t.Helper()
	or, od, ob := maxRounds, timeLimit, workBudget
	maxRounds, timeLimit, workBudget = rounds, d, budget
	t.Cleanup(func() { maxRounds, timeLimit, workBudget = or, od, ob })
}

func secretsText() (string, []string) {
	r := strings.Repeat
	gh := "gh" + "p_" + r("Q7", 18)
	sk := "s" + "k-" + r("k3", 12)
	kv := "to" + "ken: " + r("v5", 6)
	return "log line " + gh + " and " + sk + "\n" + kv + "\nend", []string{gh[len(gh)-8:], sk[len(sk)-8:], "v5v5v5v5"}
}

func assertClosed(t *testing.T, name string) {
	t.Helper()
	text, tails := secretsText()
	got := String(text)
	for _, leak := range tails {
		if strings.Contains(got, leak) {
			t.Errorf("%s: %q survived in %q", name, leak, got)
		}
	}
	found := strings.Join(Find(text), ",")
	if !strings.Contains(found, limitKind) {
		t.Errorf("%s: the limit was not reported (Find = %s)", name, found)
	}
}

// Every cap fails closed: the remaining candidate regions are redacted as
// «redacted:scrub-limit» and the limit is reported, never a silent return
// with secrets left.
func TestRoundCapFailsClosed(t *testing.T) {
	withLimits(t, 0, timeLimit, workBudget) // no round may run: the cap is hit at once
	assertClosed(t, "round cap")
}

func TestWorkBudgetFailsClosed(t *testing.T) {
	withLimits(t, maxRounds, timeLimit, func(int) int { return 0 })
	assertClosed(t, "work budget")
}

func TestTimeLimitFailsClosed(t *testing.T) {
	withLimits(t, maxRounds, 0, workBudget)
	assertClosed(t, "time limit")
}

// The fail-closed region still leaves text that holds no start alone.
func TestFailClosedLeavesCleanTextAlone(t *testing.T) {
	withLimits(t, maxRounds, timeLimit, func(int) int { return 0 })
	if got := String("nothing to see here\n"); got != "nothing to see here\n" {
		t.Errorf("clean text changed: %q", got)
	}
}
