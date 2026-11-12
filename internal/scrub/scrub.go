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
//  2. Patterns (this file, matched by engine.go) — the SECOND line, for
//     secrets the console never saw (a token an agent pasted, a key printed
//     by a tool).
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
//   - no pattern CONSUMES a boundary character, and no pattern carries a \b:
//     the left boundary is checked in code against the byte before the match
//     (notBefore), so a match never eats the separator its neighbour needs,
//     and a byte that belongs to another secret never rejects a match;
//   - no pattern is anchored to end of line — a value ends at whitespace, a
//     quote or (trimmed in code) a trailing comma or brace;
//   - over-redaction is preferred to under-redaction: floors are low, and
//     every limit (work, rounds, time) fails closed by redacting.
package scrub

import (
	"encoding/base64"
	"io"
	"regexp"
	"strings"
)

// pattern is one credential shape. Every match starts where begins says; re is
// the whole pattern anchored at that start, its capture group 1 the secret
// (text outside it — a key name, a scheme word — stays readable).
type pattern struct {
	kind string
	// begins reports, by plain byte comparison (no regexp — the start index
	// is one linear byte scan), whether a match can begin at text[p].
	begins func(text string, p int) bool
	re     *regexp.Regexp // ^whole pattern
	// notBefore rejects a match whose preceding byte is in this set — unless
	// that byte belongs to another accepted secret (adjacent tokens).
	notBefore string
	// reach bounds how far a match beginning at s can extend; re only ever
	// sees that window (linear work), and a capture that fills a window cut
	// by the cap is extended to the end of its run (fail closed).
	reach func(text string, s int) (end int, capped bool)
	// classify refines the kind from the secret (optional).
	classify func(secret string) string
	// trimRight strips these trailing bytes from the secret span (a
	// separator the value class could not exclude without leaking).
	trimRight string
	// codeNoise marks the unquoted key/value variant, which also matches Go
	// expressions (`secret := f(...)`). Redaction always applies it; only the
	// repository guard skips it for Go source, where a hard-coded secret
	// would be a quoted literal (still checked).
	codeNoise bool
}

// keyNames are the key/value keys that name a secret (case-insensitive).
var keyNames = []string{"token", "access_token", "refresh_token", "client-key-data", "client-certificate-data", "key", "crt", "ca",
	"password", "passwd", "pass", "secret", "client_secret", "private_key", "api_key", "apikey"}

var secretKeys = `(?:` + strings.Join(keyNames, "|") + `)`

const (
	alnum      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	wordChars  = alnum + "_"
	tokenChars = alnum + "_-"
	b64Chars   = alnum + "_+/-"
)

// sep is the key/value separator: ':' or '=', optionally followed by a line
// break and the indentation of a block-style value.
const sep = `[ \t]*[:=][ \t]*(?:\r?\n[ \t]+)?`

func mk(kind string, begins func(string, int) bool, body, notBefore string, reach func(string, int) (int, bool)) pattern {
	return pattern{kind: kind, begins: begins, notBefore: notBefore, reach: reach, re: regexp.MustCompile(`^(?:` + body + `)`)}
}

// pemHeaderRe is the private-key pattern's header part — the ONE definition
// both the pattern and its fail-closed path (a header with no END in reach)
// use, so no header form the pattern recognises can skip failing closed.
const pemHeaderRe = `-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----`

var patterns = []pattern{
	mk("private-key", lit("-----BEGIN "),
		`(`+pemHeaderRe+`[\s\S]*?-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----)`, "", reachFar),
	withClassify(mk("jwt", lit("eyJ"), `(eyJ[A-Za-z0-9_+/=-]{20,}(?:\.[A-Za-z0-9_+/=-]+)*)`, b64Chars, reachRun), classifyEyJ),
	mk("github-pat", lit("github_pat_"), `(github_pat_[A-Za-z0-9_]{22,})`, wordChars, reachRun),
	mk("github-token", ghToken, `((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,})`, wordChars, reachRun),
	mk("api-key", lit("sk-"), `(sk-[A-Za-z0-9_-]{20,})`, tokenChars, reachRun),
	// Exactly 35 secret characters: a longer run is redacted at its first 35,
	// which over-redacts harmlessly instead of leaking an adjacent token.
	mk("telegram-bot-token", telegramID, `([0-9]{6,12}:[A-Za-z0-9_-]{35})`, "0123456789", reachRun),
	mk("bearer", wordThenSpace("bearer"), `(?i)bearer\s+([A-Za-z0-9._~+/=-]{8,})`, wordChars, reachWord),
	mk("gitea-token", wordThenSpace("token"), `(?i)token\s+([0-9a-f]{40})`, wordChars, reachWord),
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
	// of line (the unclosed-quote forms; overlaps with the closed form merge,
	// and an already-redacted value is skipped by isMarker).
	keyValue(`"([^"\n]{8,})"`, "", false),
	keyValue(`'([^'\n]{8,})'`, "", false),
	keyValue(`"([^"\n]{8,})`, "", false),
	keyValue(`'([^'\n]{8,})`, "", false),
	keyValue(`([^\s"'`+"`"+`]{8,})`, ",}", true),
}

func withClassify(p pattern, f func(string) string) pattern { p.classify = f; return p }

func keyValue(value, trimRight string, codeNoise bool) pattern {
	p := mk("yaml-secret", keyThenSep, `(?i)`+secretKeys+`["']?`+sep+value, wordChars, reachKV)
	p.trimRight, p.codeNoise = trimRight, codeNoise
	return p
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

// isMarker reports whether s is exactly one redaction marker, so a redacted
// value is never redacted again (keeps String idempotent and Find clean).
func isMarker(s string) bool {
	return strings.HasPrefix(s, "«redacted:") && strings.HasSuffix(s, "»") && strings.Count(s, "«") == 1
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
