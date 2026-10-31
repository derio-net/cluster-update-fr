// Package scrub redacts credentials from any text the console stores, logs,
// renders or sends (R25): logs, session transcripts, PR bodies, Telegram
// messages and console pages all pass through String.
//
// The fixtures in testdata/scrub/cases.json are shared with derio-net/frank's
// scripts/life_scrub.py; keep the two pattern sets in step.
//
// Two rules keep the table free of bypasses (RE2 has no lookaround):
//   - no pattern CONSUMES a boundary character — boundaries are checked in
//     code against the bytes around the match, so a match never eats the
//     separator its neighbour needs;
//   - no pattern is anchored to end of line — a value ends at whitespace, a
//     quote, a comma or a closing brace, so trailing comments, JSON and
//     inline maps are covered.
//
// String also repeats until stable, so a token whose left boundary was the
// tail of an adjacent token is caught on the next pass.
package scrub

import (
	"encoding/base64"
	"io"
	"regexp"
	"strings"
)

type pattern struct {
	kind string
	// re's capture group 1 is the secret; text outside it (a key name, a
	// scheme word) is kept so redacted output stays readable.
	re *regexp.Regexp
	// notBefore rejects a match whose preceding byte is in this set.
	notBefore string
	// classify refines the kind from the secret (optional).
	classify func(secret string) string
}

const (
	alnum      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	wordChars  = alnum + "_"
	tokenChars = alnum + "_-"
	b64Chars   = alnum + "_+/-"
)

var patterns = []pattern{
	{kind: "private-key", re: regexp.MustCompile(`(-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----)`)},
	{kind: "jwt", re: regexp.MustCompile(`(eyJ[A-Za-z0-9_+/=-]{20,}(?:\.[A-Za-z0-9_+/=-]+)*)`), notBefore: b64Chars, classify: classifyEyJ},
	{kind: "github-pat", re: regexp.MustCompile(`(github_pat_[A-Za-z0-9_]{22,})`), notBefore: wordChars},
	{kind: "github-token", re: regexp.MustCompile(`((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})`), notBefore: wordChars},
	{kind: "api-key", re: regexp.MustCompile(`(sk-[A-Za-z0-9_-]{20,})`), notBefore: tokenChars},
	// Exactly 35 secret characters: a longer run is redacted at its first 35,
	// which over-redacts harmlessly instead of leaking an adjacent token.
	{kind: "telegram-bot-token", re: regexp.MustCompile(`([0-9]{6,12}:[A-Za-z0-9_-]{35})`), notBefore: "0123456789"},
	{kind: "bearer", re: regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})`)},
	{kind: "gitea-token", re: regexp.MustCompile(`(?i)\btoken\s+([0-9a-f]{40})`)},
	// The value class also stops at a backtick, so Markdown prose such as
	// "`token:`/`client-key-data:`" is not read as a key/value pair.
	{kind: "yaml-secret", re: regexp.MustCompile(`(?i)\b(?:token|access_token|refresh_token|client-key-data|client-certificate-data|key|crt|ca|password|passwd|secret|private_key|api_key|apikey)["']?\s*[:=]\s*["']?([^\s"'` + "`" + `,}«#]{16,})`)},
}

// classifyEyJ tells an Omni service-account key (base64 JSON carrying a PGP
// private key) from a JWT; both are redacted.
func classifyEyJ(secret string) string {
	first := strings.SplitN(secret, ".", 2)[0]
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(first); err == nil {
			if strings.Contains(string(b), `"pgp_key"`) {
				return "omni-sa-key"
			}
			return "jwt"
		}
	}
	return "jwt"
}

func marker(kind string) string { return "«redacted:" + kind + "»" }

type hit struct {
	start, end int
	kind       string
}

// matches returns every accepted secret span of p in text. A rejected match
// (bad left boundary) resumes scanning one byte after its start, so an
// overlapping valid match is not skipped.
func (p pattern) matches(text string) []hit {
	var hits []hit
	pos := 0
	for pos <= len(text) {
		m := p.re.FindStringSubmatchIndex(text[pos:])
		if m == nil || m[2] < 0 {
			break
		}
		start, end := pos+m[2], pos+m[3]
		if p.notBefore != "" && start > 0 && strings.IndexByte(p.notBefore, text[start-1]) >= 0 {
			pos = pos + m[0] + 1
			continue
		}
		kind := p.kind
		if p.classify != nil {
			kind = p.classify(text[start:end])
		}
		hits = append(hits, hit{start, end, kind})
		next := pos + m[1]
		if next <= pos {
			next = pos + 1
		}
		pos = next
	}
	return hits
}

// apply redacts until stable, calling seen for every redacted hit.
func apply(text string, seen func(kind string)) string {
	for i := 0; i < 8; i++ {
		changed := false
		for _, p := range patterns {
			hits := p.matches(text)
			if hits == nil {
				continue
			}
			changed = true
			var b strings.Builder
			last := 0
			for _, h := range hits {
				seen(h.kind)
				b.WriteString(text[last:h.start])
				b.WriteString(marker(h.kind))
				last = h.end
			}
			b.WriteString(text[last:])
			text = b.String()
		}
		if !changed {
			break
		}
	}
	return text
}

// String returns text with every credential replaced by «redacted:<kind>».
// It is idempotent.
func String(text string) string { return apply(text, func(string) {}) }

// Find returns the kinds of credential present in text, without duplicates,
// in the order String would redact them. nil means clean.
func Find(text string) []string {
	var kinds []string
	seen := map[string]bool{}
	apply(text, func(k string) {
		if !seen[k] {
			seen[k] = true
			kinds = append(kinds, k)
		}
	})
	return kinds
}

type writer struct{ w io.Writer }

// Writer wraps w so that everything written through it is scrubbed first.
// The log package writes one complete line per call, so per-Write scrubbing
// sees whole tokens.
func Writer(w io.Writer) io.Writer { return writer{w} }

func (s writer) Write(p []byte) (int, error) {
	if _, err := io.WriteString(s.w, String(string(p))); err != nil {
		return 0, err
	}
	return len(p), nil
}
