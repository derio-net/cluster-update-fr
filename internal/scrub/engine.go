package scrub

import (
	"container/heap"
	"sort"
	"strings"
	"time"
)

// The pattern engine (p5-relay-3b). Linear, and fail closed:
//
//  1. ONE linear byte scan finds every position a match can begin at, and
//     which patterns can begin there (plain byte comparisons of each
//     pattern's prefix — overlapping prefixes included, since every byte is
//     checked). Nothing is ever matched unanchored.
//  2. At each start, each pattern whose prefix is there is matched anchored,
//     on a window its reach function bounds (a token: its run; a key/value:
//     its line or the next; a PEM block: 64 KiB). A secret that fills a
//     window cut by the cap is extended to the end of its line.
//  3. Every candidate — of every pattern, overlapping ones included — is
//     accepted if its left boundary holds, or if the byte before it belongs
//     to an accepted secret (a token glued to the previous one). Candidates
//     are decided in start order against ALL spans accepted so far, which is
//     the fixed point (a span can only start at or after its candidate's
//     start); a verification pass re-checks every rejected candidate
//     against the final set.
//  4. Accepted spans are merged and redacted; the whole repeats until stable.
//
// Every limit — the work budget (bytes handed to anchored matches), the
// round cap, the time limit — fails CLOSED: each start not yet decided has
// the region a match could have covered from it redacted as
// «redacted:scrub-limit». Over-redaction is acceptable; a leak is not.

const (
	windowCap = 8192     // most a non-PEM match spans before fail-closed extension
	pemCap    = 64 << 10 // a PEM block
	limitKind = "scrub-limit"
)

// Limits; variables so tests can force each fail-closed path.
var (
	maxRounds = 4
	timeLimit = 5 * time.Second
	// work budget per pass: bytes handed to anchored matches.
	workBudget = func(n int) int { return 64*n + 4<<20 }
)

// --- begins: plain byte comparisons, one call per byte and pattern ---

func lit(prefix string) func(string, int) bool {
	return func(text string, p int) bool { return strings.HasPrefix(text[p:], prefix) }
}

func ghToken(text string, p int) bool {
	return p+4 <= len(text) && text[p] == 'g' && text[p+1] == 'h' && strings.IndexByte("opusr", text[p+2]) >= 0 && text[p+3] == '_'
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// telegramID: 6 to 12 digits from p, then ':'.
func telegramID(text string, p int) bool {
	i := p
	for i < len(text) && i-p <= 12 && isDigit(text[i]) {
		i++
	}
	return i-p >= 6 && i-p <= 12 && i < len(text) && text[i] == ':'
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// wordThenSpace: the word (any case) followed by whitespace.
func wordThenSpace(word string) func(string, int) bool {
	return func(text string, p int) bool {
		return hasPrefixFold(text[p:], word) && p+len(word) < len(text) && isSpace(text[p+len(word)])
	}
}

// keyThenSep: a secret key name (any case), an optional quote, blanks, then
// ':' or '='.
func keyThenSep(text string, p int) bool {
	for _, k := range keyNames {
		if !hasPrefixFold(text[p:], k) {
			continue
		}
		i := p + len(k)
		if i < len(text) && (text[i] == '"' || text[i] == '\'') {
			i++
		}
		for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
			i++
		}
		if i < len(text) && (text[i] == ':' || text[i] == '=') {
			return true
		}
	}
	return false
}

// firstBytes: every byte a match can begin with — the scan skips the rest.
var firstBytes = func() (t [256]bool) {
	for _, s := range []string{"-", "e", "g", "s", "0123456789", "bB", "tT"} {
		for i := 0; i < len(s); i++ {
			t[s[i]] = true
		}
	}
	for _, k := range keyNames {
		t[strings.ToLower(k)[0]], t[strings.ToUpper(k)[0]] = true, true
	}
	return t
}()

func isSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

func isWord(b byte) bool { return strings.IndexByte(wordChars, b) >= 0 }

func capAt(s, c, n int) int {
	if s+c < n {
		return s + c
	}
	return n
}

// lineEnd is the index of the next '\n' at or after i (or len(text)).
func lineEnd(text string, i int) int {
	if j := strings.IndexByte(text[i:], '\n'); j >= 0 {
		return i + j
	}
	return len(text)
}

// reachRun: a token is one run of non-space bytes.
func reachRun(text string, s int) (int, bool) {
	lim := capAt(s, windowCap, len(text))
	e := s
	for e < lim && !isSpace(text[e]) {
		e++
	}
	return e, e == lim && lim < len(text) && !isSpace(text[lim])
}

// reachWord: a scheme word, whitespace, then one run ("Bearer abc").
func reachWord(text string, s int) (int, bool) {
	lim := capAt(s, windowCap, len(text))
	e := s
	for e < lim && !isSpace(text[e]) {
		e++
	}
	for e < lim && isSpace(text[e]) {
		e++
	}
	for e < lim && !isSpace(text[e]) {
		e++
	}
	return e, e == lim && lim < len(text) && !isSpace(text[lim])
}

// reachKV: key, optional quote, separator (possibly a line break and
// indentation), then a quoted value to its quote or line end, or an
// unquoted run.
func reachKV(text string, s int) (int, bool) {
	n := len(text)
	lim := capAt(s, windowCap, n)
	i := s
	blank := func() {
		for i < lim && (text[i] == ' ' || text[i] == '\t') {
			i++
		}
	}
	for i < lim && (isWord(text[i]) || text[i] == '-') {
		i++
	}
	for i < lim && (text[i] == '"' || text[i] == '\'') {
		i++
	}
	blank()
	if i >= lim || (text[i] != ':' && text[i] != '=') {
		return i, false
	}
	i++
	blank()
	if i < lim && text[i] == '\r' {
		i++
	}
	if i < lim && text[i] == '\n' {
		i++
		blank()
	}
	if i < lim && (text[i] == '"' || text[i] == '\'') {
		q := text[i]
		i++
		for i < lim && text[i] != q && text[i] != '\n' {
			i++
		}
		if i < lim {
			return i + 1, false
		}
		return i, lim < n && text[lim] != '\n'
	}
	for i < lim && !isSpace(text[i]) && text[i] != '"' && text[i] != '\'' && text[i] != '`' {
		i++
	}
	return i, i == lim && lim < n && !isSpace(text[lim])
}

// reachFar: a PEM block spans lines.
func reachFar(text string, s int) (int, bool) { return capAt(s, pemCap, len(text)), false }

type candidate struct {
	hit
	from int // the match start, where the left boundary is checked
	ok   bool
}

// startAt is a position some patterns (bit i = patterns[i]) can begin at.
type startAt struct {
	pos  int
	pats uint32
}

// startPositions: ONE linear byte scan; every position a match of any
// pattern can begin at, ascending, with the patterns that can begin there.
func startPositions(text string) []startAt {
	var out []startAt
	for p := 0; p < len(text); p++ {
		if !firstBytes[text[p]] {
			continue
		}
		var m uint32
		for i, pt := range patterns {
			if pt.begins(text, p) {
				m |= 1 << i
			}
		}
		if m != 0 {
			out = append(out, startAt{p, m})
		}
	}
	return out
}

func positions(ss []startAt) []int {
	out := make([]int, len(ss))
	for i, s := range ss {
		out[i] = s.pos
	}
	return out
}

// spanHeap orders accepted spans by start.
type spanHeap []hit

func (h spanHeap) Len() int           { return len(h) }
func (h spanHeap) Less(i, j int) bool { return h[i].start < h[j].start }
func (h spanHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *spanHeap) Push(x any)        { *h = append(*h, x.(hit)) }
func (h *spanHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// spans returns the merged secret spans of text. limited reports that a
// limit was hit; the undecided starts' regions are then included, as
// limitKind.
func spans(text string, skipCodeNoise bool, deadline time.Time) (out []hit, limited bool) {
	starts := startPositions(text)
	if len(starts) == 0 {
		return nil, false
	}
	n := len(text)
	budget := workBudget(n)
	var cands []candidate
	undecided := -1
	for i, st := range starts {
		s := st.pos
		if i%256 == 0 && time.Now().After(deadline) {
			undecided = i
			break
		}
		for pi, p := range patterns {
			if (skipCodeNoise && p.codeNoise) || st.pats&(1<<pi) == 0 {
				continue
			}
			w, capped := p.reach(text, s)
			budget -= w - s + 1
			if budget < 0 {
				undecided = i
				break
			}
			m := p.re.FindStringSubmatchIndex(text[s:w])
			if m == nil || m[2] < 0 {
				continue
			}
			cs, ce := s+m[2], s+m[3]
			if capped && ce == w {
				ce = lineEnd(text, w) // filled a capped window: fail closed to the line end
			}
			for p.trimRight != "" && ce > cs && strings.IndexByte(p.trimRight, text[ce-1]) >= 0 {
				ce--
			}
			if ce <= cs || isMarker(text[cs:ce]) {
				continue
			}
			kind := p.kind
			if p.classify != nil {
				kind = p.classify(text[cs:ce])
			}
			ok := p.notBefore == "" || s == 0 || strings.IndexByte(p.notBefore, text[s-1]) < 0
			cands = append(cands, candidate{hit{cs, ce, kind}, s, ok})
		}
		if undecided >= 0 {
			break
		}
	}
	acc := accept(cands)
	if undecided >= 0 {
		acc = append(acc, closedRegions(text, positions(starts[undecided:]))...)
		limited = true
	}
	return merge(acc), limited
}

// accept decides candidates in start order against every span accepted so
// far (the fixed point), then verifies every rejected candidate against the
// final set; a disagreement accepts it and verifies again (bounded).
func accept(cands []candidate) []hit {
	if len(cands) == 0 {
		return nil
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].from < cands[j].from })
	accepted := make([]bool, len(cands))
	pending := &spanHeap{}
	maxEnd := -1 // furthest end of an accepted span starting before the current candidate
	for i := 0; i < len(cands); {
		f := cands[i].from
		for pending.Len() > 0 && (*pending)[0].start < f {
			if h := heap.Pop(pending).(hit); h.end > maxEnd {
				maxEnd = h.end
			}
		}
		j := i
		for ; j < len(cands) && cands[j].from == f; j++ {
			if cands[j].ok || (f > 0 && maxEnd >= f) {
				accepted[j] = true
			}
		}
		for k := i; k < j; k++ {
			if accepted[k] {
				heap.Push(pending, cands[k].hit)
			}
		}
		i = j
	}
	for round := 0; round < 4; round++ {
		var hs []hit
		for k, c := range cands {
			if accepted[k] {
				hs = append(hs, c.hit)
			}
		}
		sort.Slice(hs, func(a, b int) bool { return hs[a].start < hs[b].start })
		prefMax := make([]int, len(hs))
		for k, h := range hs {
			prefMax[k] = h.end
			if k > 0 && prefMax[k-1] > prefMax[k] {
				prefMax[k] = prefMax[k-1]
			}
		}
		changed := false
		for k, c := range cands {
			if accepted[k] || c.from == 0 {
				continue
			}
			// accepted spans starting before c.from: does one reach it?
			idx := sort.Search(len(hs), func(x int) bool { return hs[x].start >= c.from }) - 1
			if idx >= 0 && prefMax[idx] >= c.from {
				accepted[k], changed = true, true
			}
		}
		if !changed {
			break
		}
	}
	var out []hit
	for k, c := range cands {
		if accepted[k] {
			out = append(out, c.hit)
		}
	}
	return out
}

// closedRegions: for every undecided start, the region a match from it could
// cover (its window cap, extended to the line end) — linear, merged.
func closedRegions(text string, starts []int) []hit {
	n := len(text)
	var out []hit
	end := -1
	for _, s := range starts {
		c := windowCap
		if strings.HasPrefix(text[s:], "-----BEGIN") {
			c = pemCap
		}
		e := lineEnd(text, capAt(s, c, n))
		if e <= end {
			continue
		}
		if s < end {
			s = end // contiguous with the previous region
		}
		out = append(out, hit{s, e, limitKind})
		end = e
	}
	return out
}

func merge(acc []hit) []hit {
	if len(acc) == 0 {
		return nil
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
			if h.kind == limitKind {
				last.kind = limitKind // a fail-closed region is reported as such
			}
			continue
		}
		merged = append(merged, h)
	}
	return merged
}

type hit struct {
	start, end int
	kind       string
}

// apply redacts until stable, calling seen for every redacted hit.
func apply(text string, seen func(kind string)) string {
	return applyPatterns(text, seen, false)
}

func applyPatterns(text string, seen func(kind string), skipCodeNoise bool) string {
	deadline := time.Now().Add(timeLimit)
	redact := func(hits []hit) {
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
	for round := 0; ; round++ {
		hits, limited := spans(text, skipCodeNoise, deadline)
		if len(hits) == 0 {
			return text
		}
		if round >= maxRounds {
			// Still finding secrets after the round cap: fail closed over
			// every start that remains.
			redact(merge(closedRegions(text, positions(startPositions(text)))))
			seen(limitKind)
			return text
		}
		redact(hits)
		if limited {
			seen(limitKind)
		}
	}
}
