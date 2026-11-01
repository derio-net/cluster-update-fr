package renovate

import (
	"fmt"
	"regexp"
	"strings"
)

// The update type of a PR is read from its DIFF at the verified head, never
// from its body (c1d-r3): the body is editable by anyone with
// pull-requests:write — the session App among them — so a major relabelled
// "patch" in the body must not reach the auto-merge path. The body stays
// display-only (untrusted).
//
// The classifier FAILS CLOSED: a diff is classified only when every change
// is a version change and nothing else. Within each change block the i-th
// removed line is paired with the i-th added line (an unpaired line is
// unclassifiable); in each pair every recognised version/digest token is
// replaced by a placeholder and the two lines must then be byte-identical
// (any other change — a repository, a command, a repoURL — is
// unclassifiable). The PR's type is the HIGHEST change across all pairs.

var (
	digestTok = regexp.MustCompile(`sha256:[0-9a-f]{64}`)
	// a dotted version with an optional pre-release/build suffix
	versionTok = regexp.MustCompile(`\bv?\d+(?:\.\d+){1,2}(?:[-+][0-9A-Za-z.-]+)?\b`)
	// bare integers where they are versions: an image tag ":2", and
	// targetRevision / version values
	intTok = regexp.MustCompile(`(:|\btargetRevision:[ \t]*["']?|\bversion:[ \t]*["']?)(\d+)\b`)
)

var typeRank = map[string]int{"digest": 1, "patch": 2, "minor": 3, "major": 4}

type token struct {
	kind, val string // kind: digest | version | int
}

// normalize returns the line with every version token replaced by a
// placeholder, and the tokens in order.
func normalize(line string) (string, []token) {
	var toks []token
	line = digestTok.ReplaceAllStringFunc(line, func(m string) string {
		toks = append(toks, token{"digest", m})
		return "\x00D"
	})
	line = versionTok.ReplaceAllStringFunc(line, func(m string) string {
		toks = append(toks, token{"version", m})
		return "\x00V"
	})
	line = intTok.ReplaceAllStringFunc(line, func(m string) string {
		sub := intTok.FindStringSubmatch(m)
		toks = append(toks, token{"int", sub[2]})
		return sub[1] + "\x00I"
	})
	return line, toks
}

// DiffUpdateType classifies unified-diff patches; "" (with the reason) when
// the diff is not purely a version change.
func DiffUpdateType(patches []string) (string, string) {
	best, pairs := "", 0
	for _, p := range patches {
		if p == "" {
			return "", "a changed file has no reviewable patch"
		}
		var removed, added []string
		flush := func() error {
			defer func() { removed, added = nil, nil }()
			if len(removed) != len(added) {
				return fmt.Errorf("unpaired changed lines (%d removed, %d added)", len(removed), len(added))
			}
			for i := range removed {
				na, ta := normalize(removed[i])
				nb, tb := normalize(added[i])
				if na != nb || len(ta) != len(tb) {
					return fmt.Errorf("a changed line is not only a version change (%.60q)", strings.TrimSpace(added[i]))
				}
				for j := range ta {
					t, err := compare(ta[j], tb[j])
					if err != nil {
						return err
					}
					if t == "" {
						continue
					}
					pairs++
					if typeRank[t] > typeRank[best] {
						best = t
					}
				}
			}
			return nil
		}
		for _, l := range strings.Split(p, "\n") {
			switch {
			case strings.HasPrefix(l, "-"):
				if len(added) > 0 { // a new block began
					if err := flush(); err != nil {
						return "", err.Error()
					}
				}
				removed = append(removed, l[1:])
			case strings.HasPrefix(l, "+"):
				added = append(added, l[1:])
			default:
				if err := flush(); err != nil {
					return "", err.Error()
				}
			}
		}
		if err := flush(); err != nil {
			return "", err.Error()
		}
	}
	if pairs == 0 {
		return "", "no version change found in the diff"
	}
	return best, ""
}

// compare returns the change from a to b ("" when equal).
func compare(a, b token) (string, error) {
	if a == b {
		return "", nil
	}
	if a.kind != b.kind {
		return "", fmt.Errorf("a %s changed into a %s", a.kind, b.kind)
	}
	switch a.kind {
	case "digest":
		return "digest", nil
	case "int":
		return "major", nil // an integer version moving is never routine
	}
	pa, sa := split(a.val)
	pb, sb := split(b.val)
	if len(pa) != len(pb) || sa != sb {
		return "major", nil // components or pre-release/build suffix changed
	}
	for i, t := range []string{"major", "minor", "patch"}[:len(pa)] {
		switch {
		case pb[i] < pa[i]:
			return "major", nil // a downgrade is never routine
		case pb[i] > pa[i]:
			return t, nil
		}
	}
	return "", nil
}

// split parses "v1.2.3-rc1" into [1 2 3] and "-rc1".
func split(v string) ([]int, string) {
	v = strings.TrimPrefix(v, "v")
	suffix := ""
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v, suffix = v[:i], v[i:]
	}
	var out []int
	for _, part := range strings.Split(v, ".") {
		n := 0
		for _, r := range part {
			n = n*10 + int(r-'0')
		}
		out = append(out, n)
	}
	return out, suffix
}
