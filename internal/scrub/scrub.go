// Package scrub redacts credentials from any text the console stores, logs,
// renders or sends (R25): logs, session transcripts, PR bodies, Telegram
// messages and console pages all pass through it.
//
// Two layers, in this order:
//
//  1. Literal set (literal.go) — the FIRST line of defence. Every credential
//     the console holds or injects (GitHub App token, Gitea token, Telegram
//     bot token, each session's Omni SA key, talosconfig and kubeconfig
//     material) is registered with its exact value plus derived forms: each
//     line of a multi-line value, URL query/path escapes, JSON string
//     escaping, lower/upper hex, and base64 (standard and URL alphabets) at
//     all three byte alignments. Base64 runs — including runs wrapped across
//     lines at any width, CRLF or LF, indented with spaces or tabs — are also
//     decoded and searched for any registered form (one level of double
//     encoding included); a hit redacts the whole run. Matches from a set and
//     all its ancestors are merged on the original text and redacted once.
//     Process-wide credentials go through Register; each session gets its
//     own Set whose parent is the process-wide one.
//  2. Patterns (this file) — the SECOND line, for secrets the console never
//     saw (a token an agent pasted, a key printed by a tool).
//
// Transcripts go through Transcript, which first strips terminal escape
// sequences (a colour code inside a token would otherwise split it).
//
// Gaps left consciously (audited 2026-10-31; prefer adding a literal form or
// a pattern over widening a floor):
//   - values shorter than 8 characters are not registered (they would redact
//     ordinary words); pattern floors are also 8;
//   - a raw (non-base64) secret hard-wrapped mid-value by a terminal or
//     editor is not rejoined; only base64 runs are;
//   - encodings beyond the listed forms: base32, compressed-then-encoded,
//     two levels of base64, double URL-encoding, JSON producers that escape
//     differently from Go (e.g. "\/"), Unicode escapes of ordinary letters;
//   - a wrapped base64 run followed by a line that is itself pure base64
//     (a lone word such as "value") absorbs that line — over-redaction;
//   - the pattern layer cannot recognise an unknown credential format that
//     carries no key name (bare hex/base64 with no context) — only the
//     literal layer catches those, and only for secrets the console knows.
//
// The pattern fixtures in testdata/scrub/cases.json are shared with
// derio-net/frank's scripts/life_scrub.py; keep the two pattern sets in step.
//
// Rules that keep the pattern table free of bypasses (RE2 has no lookaround):
//   - no pattern CONSUMES a boundary character — boundaries are checked in
//     code against the bytes around the match, so a match never eats the
//     separator its neighbour needs;
//   - no pattern is anchored to end of line — a value ends at whitespace, a
//     quote or (trimmed in code) a trailing comma or brace;
//   - over-redaction is preferred to under-redaction: floors are low.
//
// Redaction repeats until stable, so a token whose left boundary was the
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
	// trimRight strips these trailing bytes from the secret span (a
	// separator the value class could not exclude without leaking).
	trimRight string
}

const secretKeys = `(?:token|access_token|refresh_token|client-key-data|client-certificate-data|key|crt|ca|password|passwd|pass|secret|client_secret|private_key|api_key|apikey)`

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
	{kind: "bearer", re: regexp.MustCompile(`(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{8,})`)},
	{kind: "gitea-token", re: regexp.MustCompile(`(?i)\btoken\s+([0-9a-f]{40})`)},
	// key/value secrets (YAML, JSON, env). Quoted values run to the matching
	// quote, so '#', ',' and '}' inside a secret are redacted with it.
	// Unquoted values run to whitespace (so " #" starts a comment but "a#b"
	// does not) or a quote/backtick (Markdown prose such as
	// "`token:`/`client-key-data:`" is not a pair); a trailing ',' or '}'
	// is trimmed in code. Floors are low on purpose: over-redaction is the
	// safe failure here.
	//
	// A value may sit on the NEXT, indented line (YAML block style), hence
	// sep. An opening quote with no closing quote on its line redacts to end
	// of line (the unclosed-quote fallbacks run after the closed forms, and an
	// already-redacted value is skipped by isMarker).
	{kind: "yaml-secret", re: regexp.MustCompile(`(?i)\b` + secretKeys + `["']?` + sep + `"([^"\n]{8,})"`)},
	{kind: "yaml-secret", re: regexp.MustCompile(`(?i)\b` + secretKeys + `["']?` + sep + `'([^'\n]{8,})'`)},
	{kind: "yaml-secret", re: regexp.MustCompile(`(?i)\b` + secretKeys + `["']?` + sep + `"([^"\n]{8,})`)},
	{kind: "yaml-secret", re: regexp.MustCompile(`(?i)\b` + secretKeys + `["']?` + sep + `'([^'\n]{8,})`)},
	{kind: "yaml-secret", re: regexp.MustCompile(`(?i)\b` + secretKeys + `["']?` + sep + `([^\s"'` + "`" + `]{8,})`), trimRight: ",}"},
}

// sep is the key/value separator: ':' or '=', optionally followed by a line
// break and the indentation of a block-style value.
const sep = `[ \t]*[:=][ \t]*(?:\r?\n[ \t]+)?`

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

// isMarker reports whether s is exactly one redaction marker, so a redacted
// value is never redacted again (keeps String idempotent and Find clean).
func isMarker(s string) bool {
	return strings.HasPrefix(s, "«redacted:") && strings.HasSuffix(s, "»") && strings.Count(s, "«") == 1
}

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
		if p.trimRight != "" {
			for end > start && strings.IndexByte(p.trimRight, text[end-1]) >= 0 {
				end--
			}
		}
		if isMarker(text[start:end]) {
			pos = pos + m[1]
			continue
		}
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

// String returns text with every credential replaced by «redacted:<kind>»:
// first the process-wide literal set (Register), then every pattern. It is
// idempotent.
func String(text string) string { return global.String(text) }

// Find returns the kinds of credential present in text, without duplicates,
// in the order String would redact them. nil means clean.
func Find(text string) []string { return global.Find(text) }

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
