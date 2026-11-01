package renovate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The update type of a PR is read from its DIFF at the verified head, never
// from its body (c1d-r3): the body is editable by anyone with
// pull-requests:write — the session App among them — so a major relabelled
// "patch" in the body must not reach the auto-merge path. The body stays
// display-only (untrusted).

var (
	versionTok = regexp.MustCompile(`\bv?(\d+)\.(\d+)(?:\.(\d+))?([-+][0-9A-Za-z.-]+)?\b`)
	digestTok  = regexp.MustCompile(`sha256:[0-9a-f]{64}`)
)

var typeRank = map[string]int{"digest": 1, "patch": 2, "minor": 3, "major": 4}

// DiffUpdateType classifies the version changes in unified-diff patches:
// within each change block the i-th version (or digest) on a removed line
// is paired with the i-th on an added line, each pair is compared as
// semver, and the PR's type is the most severe pair. A downgrade counts as
// major. "" (with the reason) when nothing classifiable changed or the
// blocks do not pair up — callers must then take the strictest path.
func DiffUpdateType(patches []string) (string, string) {
	best := ""
	pairs := 0
	for _, p := range patches {
		if p == "" {
			return "", "a changed file has no reviewable patch"
		}
		var old, cur []string
		flush := func() error {
			defer func() { old, cur = nil, nil }()
			if len(old) == 0 && len(cur) == 0 {
				return nil
			}
			if len(old) != len(cur) {
				return fmt.Errorf("versions do not pair up (%d removed, %d added)", len(old), len(cur))
			}
			for i := range old {
				t := compare(old[i], cur[i])
				if t == "" {
					continue // unchanged token on a rewritten line
				}
				pairs++
				if typeRank[t] > typeRank[best] {
					best = t
				}
			}
			return nil
		}
		for _, l := range strings.Split(p, "\n") {
			switch {
			case strings.HasPrefix(l, "-"):
				if len(cur) > 0 { // a new block began
					if err := flush(); err != nil {
						return "", err.Error()
					}
				}
				old = append(old, tokens(l[1:])...)
			case strings.HasPrefix(l, "+"):
				cur = append(cur, tokens(l[1:])...)
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

func tokens(line string) []string {
	var out []string
	out = append(out, digestTok.FindAllString(line, -1)...)
	for _, m := range versionTok.FindAllString(digestTok.ReplaceAllString(line, ""), -1) {
		out = append(out, m)
	}
	return out
}

// compare returns the update type from a to b ("" when equal).
func compare(a, b string) string {
	if a == b {
		return ""
	}
	if strings.HasPrefix(a, "sha256:") || strings.HasPrefix(b, "sha256:") {
		if strings.HasPrefix(a, "sha256:") && strings.HasPrefix(b, "sha256:") {
			return "digest"
		}
		return "major" // a tag swapped for a digest or back: not classifiable as minor
	}
	pa, pb := parse(a), parse(b)
	if pa == nil || pb == nil {
		return "major"
	}
	for i, t := range []string{"major", "minor", "patch"} {
		switch {
		case pb[i] < pa[i]:
			return "major" // a downgrade is never routine
		case pb[i] > pa[i]:
			return t
		}
	}
	return "patch" // same numbers, different pre-release/build suffix
}

func parse(v string) []int {
	m := versionTok.FindStringSubmatch(v)
	if m == nil {
		return nil
	}
	out := make([]int, 3)
	for i := 0; i < 3; i++ {
		if m[i+1] == "" {
			continue
		}
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return nil
		}
		out[i] = n
	}
	return out
}
