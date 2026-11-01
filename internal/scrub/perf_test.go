package scrub

import (
	"strings"
	"testing"
	"time"
)

// adversarial builds n bytes of input designed to make a naive matcher
// quadratic: many near-miss prefixes, long runs of token characters,
// unclosed quotes, PEM headers with no END, digit runs before colons — and
// one real token in the middle, which must still be redacted.
func adversarial(n int) (string, string) {
	r := strings.Repeat
	real := "gh" + "p_" + r("R7", 18) // a real-shaped token
	chunks := []string{
		r("s"+"k-", 300),                       // sk- inside sk- runs
		"gh" + "p_" + r("A", 30) + "gh" + "p_", // near-miss: too short
		r("e"+"yJ", 200),                       // JWT prefixes, no body
		"to" + `ken: "` + r("q", 500) + "\n",   // unclosed quote
		r("12345678:", 100),                    // telegram near-misses
		r("Bear"+"er ", 50) + "\n",             // scheme words
		"-----BEGIN RSA PRIVATE " + "KEY-----\n" + r("M", 200) + "\n", // no END
		r("pass"+"word=", 100) + "\n",
		r("x", 3000), // a long plain run
		"\n",
	}
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		if b.Len() > n/2 && !strings.Contains(b.String()[n/2-1:], real) && i%len(chunks) == 0 {
			b.WriteString(" " + real + " ")
		}
		b.WriteString(chunks[i%len(chunks)])
	}
	return b.String()[:n], real
}

// p5-relay-3b: scrubbing adversarial input is linear-ish and well inside the
// 10 s transcript limit, and still fails closed (the real token is gone).
func TestAdversarialInputIsLinear(t *testing.T) {
	timeOf := func(n int) (time.Duration, string, string) {
		in, real := adversarial(n)
		t0 := time.Now()
		out := String(in)
		return time.Since(t0), out, real
	}
	small, _, _ := timeOf(256 << 10)
	big, out, real := timeOf(1 << 20)
	t.Logf("256 KiB: %v, 1 MiB: %v", small, big)
	if strings.Contains(out, real[len(real)-12:]) {
		t.Error("the real token survived adversarial input")
	}
	limit := 5 * time.Second
	if raceEnabled {
		limit = 30 * time.Second // the race detector slows everything ~10x
	}
	if big > limit {
		t.Errorf("1 MiB of adversarial input took %v (limit %v)", big, limit)
	}
	floor := 20 * time.Millisecond
	if small < floor {
		small = floor
	}
	if big > 10*small { // 4x the input; linear is ~4x, quadratic ~16x
		t.Errorf("not linear: 256 KiB %v, 1 MiB %v", small, big)
	}
}

// Plain prose and code at 1 MiB stay fast and untouched by any limit.
func TestLargeBenignInputHitsNoLimit(t *testing.T) {
	line := "func (c *Client) Token() string { return c.tok } // token, key and secret handling\n"
	in := strings.Repeat(line, (1<<20)/len(line))
	if f := Find(in); len(f) != 0 {
		t.Fatalf("benign input reported %v", f)
	}
}
