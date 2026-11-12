package scrub

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// minLiteral is the shortest registered form that is replaced. Shorter
// fragments (a short line of a multi-line value) would redact ordinary words.
const minLiteral = 8

// Set is a set of exact secret values, the FIRST line of defence: every
// credential the console itself holds or injects is registered here, and its
// literal occurrences are replaced before the pattern pass runs, so a known
// secret is redacted whatever shape it appears in (inside a sentence, split
// across a YAML block, base64- or URL-encoded, or inside a larger base64
// blob such as a base64-encoded kubeconfig).
//
// Matching is done on the ORIGINAL text against the forms of this set and
// every ancestor at once; overlapping and adjacent matches are merged and each
// merged span is redacted once, so neither registration order nor set level
// can make one replacement break another and leak a remainder.
//
// The zero value is not usable; call NewSet.
type Set struct {
	parent *Set
	mu     sync.RWMutex
	forms  map[string]form
	cached []entry // this set's forms, rebuilt lazily
}

type form struct {
	kind string
	raw  bool // a plain value or line (searched for inside decoded base64)
}

type entry struct {
	form string
	kind string
	raw  bool
}

// NewSet returns an empty set whose String also applies parent's literals
// (nil for none). A session set has the process-wide set as its parent.
func NewSet(parent *Set) *Set { return &Set{parent: parent, forms: map[string]form{}} }

// global holds the console's own credentials (GitHub App token, Gitea token,
// Telegram bot token, …); package-level String applies it.
var global = NewSet(nil)

// Register adds a credential to the process-wide set.
func Register(kind, value string) { global.Add(kind, value) }

// Add registers value and its derived forms: the trimmed value, every line of
// a multi-line value (PEM blocks, talosconfig keys), and for each of those its
// URL escapes and its base64 encodings (standard and URL alphabets) at all
// three byte alignments, so the secret is found inside a larger base64 blob.
func (s *Set) Add(kind, value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	candidates := []string{value}
	if strings.ContainsAny(value, "\r\n") {
		for _, line := range strings.FieldsFunc(value, func(r rune) bool { return r == '\n' || r == '\r' }) {
			candidates = append(candidates, strings.TrimSpace(line))
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	changed := false
	put := func(f string, raw bool) {
		if len(f) < minLiteral {
			return
		}
		if old, ok := s.forms[f]; ok && old.kind == kind && (old.raw || !raw) {
			return
		}
		s.forms[f] = form{kind: kind, raw: raw}
		changed = true
	}
	for _, c := range candidates {
		put(c, true)
		for _, f := range derivedForms(c) {
			put(f, false)
		}
	}
	if changed { // re-registering a known value (every token read) is free
		s.cached = nil
	}
}

// derivedForms returns the encoded forms of v that are stable whatever bytes
// surround it.
func derivedForms(v string) []string {
	b := []byte(v)
	out := []string{
		url.QueryEscape(v), url.PathEscape(v),
		hex.EncodeToString(b), strings.ToUpper(hex.EncodeToString(b)),
		jsonEscaped(v),
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
		// Offset 0 with padding: the common "the whole value was encoded".
		out = append(out, enc.EncodeToString(b))
		for k := 0; k < 3; k++ {
			out = append(out, alignedBase64(enc.WithPadding(base64.NoPadding), b, k))
		}
	}
	return out
}

// alignedBase64 encodes b as it appears when preceded by k bytes inside a
// larger blob, keeping only the characters determined by b alone: base64
// character i covers bits [6i, 6i+6), so it depends only on b when that range
// lies within [8k, 8(k+len(b))).
func alignedBase64(enc *base64.Encoding, b []byte, k int) string {
	padded := append(make([]byte, k), b...)
	s := enc.EncodeToString(padded)
	start := (8*k + 5) / 6
	end := 8 * (k + len(b)) / 6
	if end > len(s) {
		end = len(s)
	}
	if start >= end {
		return ""
	}
	return s[start:end]
}

func (s *Set) own() []entry {
	s.mu.RLock()
	c := s.cached
	s.mu.RUnlock()
	if c != nil {
		return c
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil {
		return s.cached
	}
	out := make([]entry, 0, len(s.forms))
	for f, m := range s.forms {
		out = append(out, entry{f, m.kind, m.raw})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].form < out[j].form })
	s.cached = out
	return out
}

// all returns the forms of s and every ancestor.
func (s *Set) all() []entry {
	var out []entry
	for p := s; p != nil; p = p.parent {
		out = append(out, p.own()...)
	}
	return out
}

type span struct {
	start, end int
	kind       string
	weight     int // length of the form that produced it
}

// base64Token is a base64 run inside one line.
var base64Token = regexp.MustCompile(`[A-Za-z0-9+/_-]{4,}={0,2}`)

// base64Line is a line that is nothing but base64 (and indentation).
var base64Line = regexp.MustCompile(`^[ \t]*[A-Za-z0-9+/_-]{4,}={0,2}[ \t]*$`)

// minBase64Run is the shortest stripped run worth decoding.
const minBase64Run = 24

var wrapSpace = strings.NewReplacer("\r", "", "\n", "", " ", "", "\t", "")

// base64Runs returns [start, end) spans of base64 runs, including runs
// WRAPPED across lines (PEM bodies, `base64` output at 64/76 columns,
// indented YAML block scalars): a run that reaches the end of its line
// continues through every following line that is nothing but base64. A
// following line that is not pure base64 ("next: value") ends the run, so
// surrounding text is not swallowed.
func base64Runs(text string) [][2]int {
	type line struct{ start, end int } // end excludes the line break
	var lines []line
	for st := 0; st <= len(text); {
		i := strings.IndexByte(text[st:], '\n')
		if i < 0 {
			lines = append(lines, line{st, len(text)})
			break
		}
		end := st + i
		if end > st && text[end-1] == '\r' {
			end--
		}
		lines = append(lines, line{st, end})
		st += i + 1
	}
	var runs [][2]int
	for li := 0; li < len(lines); li++ {
		l := lines[li]
		toks := base64Token.FindAllStringIndex(text[l.start:l.end], -1)
		for ti, t := range toks {
			start, end := l.start+t[0], l.start+t[1]
			last := ti == len(toks)-1 && strings.TrimRight(text[end:l.end], " \t") == ""
			next := li
			if last && !strings.HasSuffix(text[start:end], "=") {
				for next+1 < len(lines) && base64Line.MatchString(text[lines[next+1].start:lines[next+1].end]) {
					next++
					end = lines[next].start + len(strings.TrimRight(text[lines[next].start:lines[next].end], " \t"))
					if strings.HasSuffix(text[lines[next].start:end], "=") {
						break // padding ends a blob
					}
				}
			}
			runs = append(runs, [2]int{start, end})
			if next != li {
				li = next
				break
			}
		}
	}
	return runs
}

// literals redacts every registered form found in text.
func (s *Set) literals(text string, seen func(string)) string {
	if s == nil {
		return text
	}
	entries := s.all()
	if len(entries) == 0 {
		return text
	}
	var spans []span
	for _, e := range entries {
		for idx := 0; idx < len(text); {
			i := strings.Index(text[idx:], e.form)
			if i < 0 {
				break
			}
			st := idx + i
			spans = append(spans, span{st, st + len(e.form), e.kind, len(e.form)})
			idx = st + 1 // overlapping occurrences too
		}
	}
	// Decode base64-looking runs (wrapped ones joined first) and look for any
	// registered form inside: catches what the aligned forms cannot — a
	// document wrapped at 64/76 columns, a value split across lines before
	// encoding, one level of double encoding. The WHOLE run is redacted.
	for _, m := range base64Runs(text) {
		joined := wrapSpace.Replace(text[m[0]:m[1]])
		if len(joined) < minBase64Run {
			continue
		}
		decoded := decodeLoose(joined)
		if decoded == nil {
			continue
		}
		for _, e := range entries {
			if bytes.Contains(decoded, []byte(e.form)) {
				spans = append(spans, span{m[0], m[1], e.kind, len(e.form)})
				break
			}
		}
	}
	if len(spans) == 0 {
		return text
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end
	})
	merged := []span{spans[0]}
	for _, sp := range spans[1:] {
		cur := &merged[len(merged)-1]
		if sp.start <= cur.end { // overlapping or adjacent
			if sp.end > cur.end {
				cur.end = sp.end
			}
			if sp.weight > cur.weight {
				cur.kind, cur.weight = sp.kind, sp.weight
			}
			continue
		}
		merged = append(merged, sp)
	}
	var b strings.Builder
	last := 0
	for _, sp := range merged {
		seen(sp.kind)
		b.WriteString(text[last:sp.start])
		b.WriteString(marker(sp.kind))
		last = sp.end
	}
	b.WriteString(text[last:])
	return b.String()
}

// jsonEscaped is v as it appears inside a JSON string (quotes, backslashes,
// control characters and HTML-sensitive characters escaped).
func jsonEscaped(v string) string {
	b, err := json.Marshal(v)
	if err != nil || len(b) < 2 {
		return v
	}
	return string(b[1 : len(b)-1])
}

func decodeLoose(run string) []byte {
	run = strings.TrimRight(run, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(run); err == nil {
			return b
		}
		// A run cut mid-quantum: drop the dangling characters.
		if cut := len(run) - len(run)%4; cut > 0 && cut != len(run) {
			if b, err := enc.DecodeString(run[:cut]); err == nil {
				return b
			}
		}
	}
	return nil
}

// String redacts the set's literals first, then every pattern.
func (s *Set) String(text string) string {
	return apply(s.literals(text, func(string) {}), func(string) {})
}

// Find reports the kinds present, literal hits included.
func (s *Set) Find(text string) []string {
	var kinds []string
	seen := map[string]bool{}
	add := func(k string) {
		if !seen[k] {
			seen[k] = true
			kinds = append(kinds, k)
		}
	}
	apply(s.literals(text, add), add)
	return kinds
}

// Global returns the process-wide literal set (parent of every session set).
func Global() *Set { return global }
