package scrub

import (
	"strings"
	"testing"
)

// sample builds one secret per pattern from parts (this public repo never
// carries a literal token). tag makes each instance distinct, so a leaked
// fragment can be named.
func samples(tag string) map[string]string {
	r := func(s string, n int) string { return strings.Repeat(s, n) }
	t8 := r(tag, 8) // tag is one alnum char
	return map[string]string{
		"pem":      "-----BEGIN RSA PRIVATE " + "KEY-----\nMII" + t8 + "\n-----END RSA PRIVATE " + "KEY-----",
		"jwt":      "ey" + "J" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "." + "ey" + "JzdWIiOi" + t8 + "." + "c2ln" + t8 + t8,
		"ghpat":    "github" + "_pat_" + r("A1", 11) + "_" + t8 + r("b2", 25) + t8,
		"ghp":      "gh" + "p_" + r("Z9", 14) + t8,
		"ghs":      "gh" + "s_" + r("Q7", 14) + t8,
		"openai":   "s" + "k-" + r("k3", 8) + t8,
		"telegram": "1234567" + "89:" + r("T5", 13) + r(tag, 9), // exactly 35
		"bearer":   "Bear" + "er " + r("b4", 6) + t8,
		"gitea":    "tok" + "en " + r("a1", 16) + strings.Repeat(map[string]string{"x": "c", "y": "d"}[tag], 8),
		"yamlq":    "to" + `ken: "` + r("q6", 4) + t8 + `"`,
		"yamlp":    "pass" + "word: " + r("p8", 4) + t8,
	}
}

// tailOf is the distinctive end of a secret: what must never survive.
func tailOf(kind, s string) string {
	switch kind {
	case "pem":
		i := strings.Index(s, "MII")
		return s[i : i+11]
	case "yamlq":
		return s[len(s)-9 : len(s)-1]
	}
	return s[len(s)-8:]
}

// p5-relay-3: two secrets placed directly after one another — of the same
// pattern and of every other — both stay redacted. A greedy value class that
// swallows the next token's prefix, or a left-boundary rule that rejects a
// token glued to the previous one, must never leak the second.
func TestAdjacentSecretsAreBothRedacted(t *testing.T) {
	a, b := samples("x"), samples("y")
	for ka, sa := range a {
		for kb, sb := range b {
			for _, glue := range []string{"", " ", "\n"} {
				text := "start " + sa + glue + sb + " end"
				got := String(text)
				for _, leak := range []string{tailOf(ka, sa), tailOf(kb, sb)} {
					if strings.Contains(got, leak) {
						t.Errorf("%s+%q+%s: %q survived in %q", ka, glue, kb, leak, got)
					}
				}
				if String(got) != got {
					t.Errorf("%s+%s: not idempotent", ka, kb)
				}
			}
		}
	}
}

// Each sample on its own is a secret (the pairs above test something).
func TestEverySampleIsRedactedAlone(t *testing.T) {
	for k, s := range samples("x") {
		if got := String("a " + s + " b"); strings.Contains(got, tailOf(k, s)) {
			t.Errorf("%s alone survived: %q", k, got)
		}
	}
}

// Three and more back to back (the old fix-point loop handled one per round).
func TestLongRunsOfAdjacentTokens(t *testing.T) {
	var parts []string
	for _, c := range "abcdefghijklmnopqrst" {
		parts = append(parts, samples(string(c))["ghp"])
	}
	got := String(strings.Join(parts, ""))
	for i, p := range parts {
		if strings.Contains(got, p[len(p)-8:]) {
			t.Fatalf("token %d of %d survived: %q", i+1, len(parts), got)
		}
	}
}
