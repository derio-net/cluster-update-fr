package scrub

import (
	"encoding/base64"
	"net/url"
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
// across a YAML block, base64- or URL-encoded).
//
// The zero value is not usable; call NewSet.
type Set struct {
	parent *Set
	mu     sync.RWMutex
	forms  map[string]string // form -> kind
	sorted []entry           // forms, longest first (rebuilt lazily)
}

// NewSet returns an empty set whose String also applies parent's literals
// (nil for none). A session set has the process-wide set as its parent.
func NewSet(parent *Set) *Set { return &Set{parent: parent, forms: map[string]string{}} }

// global holds the console's own credentials (GitHub App token, Gitea token,
// Telegram bot token, …); package-level String applies it.
var global = NewSet(nil)

// Register adds a credential to the process-wide set.
func Register(kind, value string) { global.Add(kind, value) }

// Add registers value and its derived forms: the trimmed value, its standard,
// URL-safe and unpadded base64 encodings, its URL query/path escapes, and
// every line of a multi-line value (PEM blocks, talosconfig keys) together
// with each line's base64 form.
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
	for _, c := range candidates {
		for _, f := range forms(c) {
			if len(f) >= minLiteral && s.forms[f] != kind {
				s.forms[f] = kind
				changed = true
			}
		}
	}
	if changed { // re-registering a known value (every token read) is free
		s.sorted = nil
	}
}

func forms(v string) []string {
	b := []byte(v)
	out := []string{
		v,
		base64.StdEncoding.EncodeToString(b),
		base64.RawStdEncoding.EncodeToString(b),
		base64.URLEncoding.EncodeToString(b),
		base64.RawURLEncoding.EncodeToString(b),
		url.QueryEscape(v),
		url.PathEscape(v),
	}
	return out
}

type entry struct{ form, kind string }

// ordered returns the registered forms, longest first, so a whole value is
// replaced before any of its lines. The slice is immutable once built.
func (s *Set) ordered() []entry {
	s.mu.RLock()
	cached := s.sorted
	s.mu.RUnlock()
	if cached != nil {
		return cached
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sorted != nil {
		return s.sorted
	}
	out := make([]entry, 0, len(s.forms))
	for f, k := range s.forms {
		out = append(out, entry{f, k})
	}
	sort.Slice(out, func(i, j int) bool {
		if len(out[i].form) != len(out[j].form) {
			return len(out[i].form) > len(out[j].form)
		}
		return out[i].form < out[j].form
	})
	s.sorted = out
	return out
}

// literals replaces every registered form (this set's, then its parent's).
func (s *Set) literals(text string, seen func(string)) string {
	if s == nil {
		return text
	}
	for _, e := range s.ordered() {
		if strings.Contains(text, e.form) {
			seen(e.kind)
			text = strings.ReplaceAll(text, e.form, marker(e.kind))
		}
	}
	return s.parent.literals(text, seen)
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
