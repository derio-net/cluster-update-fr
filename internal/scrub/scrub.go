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
// Every pattern is matched against the SAME text, overlapping matches
// included, and the accepted spans are unioned: a pattern whose value class
// swallows the start of an adjacent token can never hide that token from its
// own pattern, and a token whose left boundary is the tail of an adjacent
// secret is accepted (p5-relay-3). Redaction then repeats until stable.
package scrub

import (
	"encoding/base64"
	"io"
	"regexp"
	"sort"
	"strings"
)

type pattern struct {
	kind string
	// re's capture group 1 is the secret; text outside it (a key name, a
	// scheme word) is kept so redacted output stays readable.
	re *regexp.Regexp
	// notBefore rejects a match whose preceding byte is in this set — unless
	// that byte belongs to another accepted secret (adjacent tokens).
	notBefore string
	// glued (key/value patterns) is re matched at an exact position, without
	// the \b an adjacent secret's tail defeats; tried only inside accepted
	// secret spans.
	glued *regexp.Regexp
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
	// The scheme word starts at \b — or, glued to a previous secret
	// ("…xyzBearer abc…"), inside its span (p5-relay-3).
	bounded("bearer", `bearer\s+([A-Za-z0-9._~+/=-]{8,})`),
	bounded("gitea-token", `token\s+([0-9a-f]{40})`),
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
	keyValue(`"([^"\n]{8,})"`, "", false),
	keyValue(`'([^'\n]{8,})'`, "", false),
	keyValue(`"([^"\n]{8,})`, "", false),
	keyValue(`'([^'\n]{8,})`, "", false),
	keyValue(`([^\s"'`+"`"+`]{8,})`, ",}", true),
}

// keyValue builds a key/value pattern. Its key must start at a word
// boundary (\b, cheap to scan with) — except right after another secret:
// "…<token>password: v" has no boundary before "password", so glued, the
// same pattern anchored and without \b, is re-tried inside every accepted
// secret span (p5-relay-3).
func keyValue(value, trimRight string, codeNoise bool) pattern {
	p := bounded("yaml-secret", secretKeys+`["']?`+sep+value)
	p.trimRight, p.codeNoise = trimRight, codeNoise
	return p
}

// bounded: a case-insensitive pattern starting at a word boundary, with its
// glued form for a start inside another secret.
func bounded(kind, body string) pattern {
	return pattern{kind: kind, re: regexp.MustCompile(`(?i)\b` + body), glued: regexp.MustCompile(`(?i)^(?:` + body + `)`)}
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

// candidate is one regex match of a pattern; boundaryOK says whether its
// left boundary (notBefore) holds on its own.
type candidate struct {
	hit
	from       int // where the left boundary is checked
	boundaryOK bool
}

// candidates returns every match of p in text, overlapping ones included:
// scanning resumes one byte after each match's START, never at its end. A
// greedy value class can swallow the prefix of an ADJACENT token (ghp_…
// eating the next "ghp", sk-… the next "sk") and resuming at the end would
// then never see that token, leaking its tail — the adjacent-token boundary
// bug, first found in the Telegram pattern. Overlaps are merged later.
func (p pattern) candidates(text string) []candidate {
	var out []candidate
	pos := 0
	for pos < len(text) {
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
		if end > start && !isMarker(text[start:end]) {
			kind := p.kind
			if p.classify != nil {
				kind = p.classify(text[start:end])
			}
			ok := p.notBefore == "" || start == 0 || strings.IndexByte(p.notBefore, text[start-1]) < 0
			out = append(out, candidate{hit{start, end, kind}, start, ok})
		}
		pos += m[0] + 1
	}
	return out
}

// gluedAt tries p's glued form at exactly position k (a key that starts
// inside another secret).
func (p pattern) gluedAt(text string, k int) (hit, bool) {
	m := p.glued.FindStringSubmatchIndex(text[k:])
	if m == nil || m[2] < 0 {
		return hit{}, false
	}
	start, end := k+m[2], k+m[3]
	for p.trimRight != "" && end > start && strings.IndexByte(p.trimRight, text[end-1]) >= 0 {
		end--
	}
	if end <= start || isMarker(text[start:end]) {
		return hit{}, false
	}
	return hit{start, end, p.kind}, true
}

// spans matches EVERY pattern against the same text and accepts a
// candidate whose left boundary holds, or whose start touches or lies
// inside an accepted span (the byte before it is part of another secret,
// so the boundary rule must not reject it — e.g. two tokens back to back).
// Accepted spans are merged where they overlap.
func spans(text string, skipCodeNoise bool) []hit {
	var all []candidate
	for _, p := range patterns {
		if skipCodeNoise && p.codeNoise {
			continue
		}
		all = append(all, p.candidates(text)...)
	}
	if len(all) == 0 {
		return nil
	}
	// In boundary order: whether a candidate's boundary byte lies in (or right
	// after) an accepted secret depends only on candidates checked earlier.
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].from != all[j].from {
			return all[i].from < all[j].from
		}
		return all[i].end > all[j].end
	})
	var acc []hit
	maxEnd := -1 // furthest end of an accepted span whose boundary precedes the current group
	for i := 0; i < len(all); {
		j, groupEnd := i, maxEnd
		for ; j < len(all) && all[j].from == all[i].from; j++ {
			c := all[j]
			if c.boundaryOK || (c.from > 0 && maxEnd >= c.from) {
				acc = append(acc, c.hit)
				if c.end > groupEnd {
					groupEnd = c.end
				}
			}
		}
		maxEnd, i = groupEnd, j
	}
	if len(acc) == 0 {
		return nil
	}
	// A key/value pair whose key starts inside (or right after) an accepted
	// secret has no \b before it: try the glued forms at each such position.
	// New hits are scanned in turn, so a chain of glued pairs is followed.
	tried := map[int]bool{}
	for q := 0; q < len(acc); q++ {
		h := acc[q]
		for k := h.start + 1; k <= h.end && k < len(text); k++ {
			if tried[k] || strings.IndexByte(wordChars, text[k-1]) < 0 {
				continue // already tried, or a \b is there and the main scan saw it
			}
			tried[k] = true
			for _, p := range patterns {
				if p.glued == nil || (skipCodeNoise && p.codeNoise) {
					continue
				}
				if g, ok := p.gluedAt(text, k); ok {
					acc = append(acc, g)
				}
			}
		}
	}
	sort.SliceStable(acc, func(i, j int) bool {
		if acc[i].start != acc[j].start {
			return acc[i].start < acc[j].start
		}
		return acc[i].end > acc[j].end
	})
	merged := []hit{acc[0]}
	for _, h := range acc[1:] {
		last := &merged[len(merged)-1]
		if h.start < last.end {
			if h.end > last.end {
				last.end = h.end
			}
			continue
		}
		merged = append(merged, h)
	}
	return merged
}

// apply redacts until stable, calling seen for every redacted hit.
func apply(text string, seen func(kind string)) string {
	return applyPatterns(text, seen, false)
}

func applyPatterns(text string, seen func(kind string), skipCodeNoise bool) string {
	for i := 0; i < 8; i++ {
		hits := spans(text, skipCodeNoise)
		if hits == nil {
			break
		}
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
