// Package scrub redacts credentials from any text the console stores, logs,
// renders or sends (R25): logs, session transcripts, PR bodies, Telegram
// messages and console pages all pass through String.
//
// The pattern list mirrors derio-net/frank's scripts/life_scrub.py fixture
// set; keep the two in step when a credential kind is added.
package scrub

import (
	"encoding/base64"
	"io"
	"regexp"
	"strings"
)

// Every pattern has exactly ONE capture group: the secret. Text around it
// (a key name, a separator) is kept, so redacted output stays readable.
type pattern struct {
	kind     string
	re       *regexp.Regexp
	classify func(secret string) string // optional: refine the kind
}

var patterns = []pattern{
	{kind: "private-key", re: regexp.MustCompile(`(-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----)`)},
	{kind: "jwt", re: regexp.MustCompile(`(?:^|[^A-Za-z0-9_+/-])(eyJ[A-Za-z0-9_+/=-]{20,}(?:\.[A-Za-z0-9_+/=-]+)*)`), classify: classifyEyJ},
	{kind: "github-pat", re: regexp.MustCompile(`(github_pat_[A-Za-z0-9_]{22,})`)},
	{kind: "github-token", re: regexp.MustCompile(`(?:^|[^A-Za-z0-9_])((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})`)},
	{kind: "api-key", re: regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(sk-[A-Za-z0-9_-]{20,})`)},
	{kind: "telegram-bot-token", re: regexp.MustCompile(`(?:^|[^0-9])([0-9]{6,12}:[A-Za-z0-9_-]{35})(?:[^A-Za-z0-9_-]|$)`)},
	{kind: "bearer", re: regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})`)},
	{kind: "gitea-token", re: regexp.MustCompile(`(?i)\btoken\s+([0-9a-f]{40})\b`)},
	{kind: "yaml-secret", re: regexp.MustCompile(`(?mi)^\s*-?\s*(?:token|client-key-data|client-certificate-data|key|crt|ca|password|secret|private_key)\s*:\s*["']?([^\s"'«]{16,})["']?\s*$`)},
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

// String returns text with every credential replaced by «redacted:<kind>».
// It is idempotent.
func String(text string) string {
	for _, p := range patterns {
		text = replace(text, p)
	}
	return text
}

func replace(text string, p pattern) string {
	idx := p.re.FindAllStringSubmatchIndex(text, -1)
	if idx == nil {
		return text
	}
	var b strings.Builder
	last := 0
	for _, m := range idx {
		start, end := m[2], m[3]
		if start < 0 {
			continue
		}
		kind := p.kind
		if p.classify != nil {
			kind = p.classify(text[start:end])
		}
		b.WriteString(text[last:start])
		b.WriteString(marker(kind))
		last = end
	}
	b.WriteString(text[last:])
	return b.String()
}

// Find returns the kinds of credential present in text, in pattern order,
// without duplicates. nil means clean.
func Find(text string) []string {
	var kinds []string
	seen := map[string]bool{}
	for _, p := range patterns {
		for _, m := range p.re.FindAllStringSubmatchIndex(text, -1) {
			if m[2] < 0 {
				continue
			}
			kind := p.kind
			if p.classify != nil {
				kind = p.classify(text[m[2]:m[3]])
			}
			if !seen[kind] {
				seen[kind] = true
				kinds = append(kinds, kind)
			}
		}
	}
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
