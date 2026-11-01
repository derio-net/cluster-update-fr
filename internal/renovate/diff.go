package renovate

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The update type of a PR is read from its DIFF at the verified head, never
// from its body (c1d-r3): the body is editable by anyone with
// pull-requests:write — the session App among them.
//
// The classifier can only say yes in a few known SHAPES and fails closed
// everywhere else:
//
//   - every changed line is paired (i-th removed with i-th added in a
//     change block); an unpaired line → unclassifiable;
//   - each line of a pair must be one of the known version positions —
//     `image: <repo>[:<tag>][@sha256:<digest>]` or `<key>: <value>` /
//     `<KEY>=<value>` for the keys tag, targetRevision, version,
//     appVersion, talos, kubernetes, OMNI_VERSION, OMNI_IMG_TAG — with an
//     optional list marker and quotes; anything else (a comment, a URL,
//     an IP, free text) → unclassifiable;
//   - everything but the version value must be byte-identical (same key,
//     same image repository, nothing after the value);
//   - values parse strictly (ParseUint base 10, ≤9 digits, no leading
//     zeros); a different spelling of the same version → unclassifiable;
//   - the PR's type is the HIGHEST change across all pairs.
//
// An unclassifiable diff takes the session path.

var keyed = regexp.MustCompile(`^([ \t]*(?:-[ \t]+)?["']?(tag|targetRevision|version|appVersion|talos|kubernetes|OMNI_VERSION|OMNI_IMG_TAG)["']?[ \t]*(?::[ \t]*|=)["']?)([^"'\s#]+)(["']?)[ \t]*$`)
var imageLine = regexp.MustCompile(`^([ \t]*(?:-[ \t]+)?["']?image["']?[ \t]*:[ \t]*["']?)([^"'\s#]+)(["']?)[ \t]*$`)
var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

var typeRank = map[string]int{"digest": 1, "patch": 2, "minor": 3, "major": 4}

var errUnclassifiable = fmt.Errorf("not a recognised version change")

// DiffUpdateType classifies unified-diff patches; "" (with the reason) when
// the diff is not purely a version change in a known position.
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
				t, err := classifyPair(removed[i], added[i])
				if err != nil {
					return fmt.Errorf("%v: %.60q", err, strings.TrimSpace(added[i]))
				}
				if t == "" {
					continue
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
				if len(added) > 0 {
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

func classifyPair(a, b string) (string, error) {
	if ma, mb := imageLine.FindStringSubmatch(a), imageLine.FindStringSubmatch(b); ma != nil && mb != nil {
		if ma[1] != mb[1] || ma[3] != mb[3] {
			return "", errUnclassifiable
		}
		return compareImage(ma[2], mb[2])
	}
	ma, mb := keyed.FindStringSubmatch(a), keyed.FindStringSubmatch(b)
	if ma == nil || mb == nil || ma[1] != mb[1] || ma[4] != mb[4] {
		return "", errUnclassifiable // not a known version position, or key/quoting changed
	}
	return compareVersion(ma[3], mb[3])
}

// compareImage: the repository must be identical; the tag is compared as a
// version; a digest-only change (same tag) is "digest".
func compareImage(a, b string) (string, error) {
	ra, ta, da, err := splitImage(a)
	if err != nil {
		return "", err
	}
	rb, tb, db, err := splitImage(b)
	if err != nil {
		return "", err
	}
	if ra != rb || (ta == "") != (tb == "") || (da == "") != (db == "") {
		return "", errUnclassifiable // repository changed, or a tag/digest appeared or vanished
	}
	if ta != tb {
		return compareVersion(ta, tb)
	}
	if da != db {
		return "digest", nil
	}
	if a != b {
		return "", errUnclassifiable
	}
	return "", nil
}

func splitImage(ref string) (repo, tag, digest string, err error) {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref, digest = ref[:i], ref[i+1:]
		if !digestRe.MatchString(digest) {
			return "", "", "", errUnclassifiable
		}
	}
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref, tag = ref[:i], ref[i+1:]
	}
	if ref == "" {
		return "", "", "", errUnclassifiable
	}
	return ref, tag, digest, nil
}

type semVer struct {
	v      bool
	parts  []uint64
	suffix string
}

func parseVersion(s string) (semVer, error) {
	var out semVer
	if strings.HasPrefix(s, "v") {
		out.v, s = true, s[1:]
	}
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		s, out.suffix = s[:i], s[i:]
		if len(out.suffix) < 2 {
			return out, errUnclassifiable
		}
	}
	comps := strings.Split(s, ".")
	if len(comps) > 3 {
		return out, errUnclassifiable
	}
	for _, c := range comps {
		if c == "" || len(c) > 9 || (len(c) > 1 && c[0] == '0') {
			return out, errUnclassifiable
		}
		n, err := strconv.ParseUint(c, 10, 32)
		if err != nil {
			return out, errUnclassifiable
		}
		out.parts = append(out.parts, n)
	}
	return out, nil
}

func compareVersion(a, b string) (string, error) {
	if a == b {
		return "", nil
	}
	va, err := parseVersion(a)
	if err != nil {
		return "", err
	}
	vb, err := parseVersion(b)
	if err != nil {
		return "", err
	}
	if va.v != vb.v {
		return "", errUnclassifiable // a respelling, not a version change
	}
	if len(va.parts) != len(vb.parts) || va.suffix != vb.suffix {
		return "major", nil // components or pre-release/build suffix changed
	}
	if len(va.parts) == 1 {
		if vb.parts[0] != va.parts[0] {
			return "major", nil // a bare integer version moving is never routine
		}
	}
	for i, t := range []string{"major", "minor", "patch"}[:len(va.parts)] {
		switch {
		case vb.parts[i] < va.parts[i]:
			return "major", nil // a downgrade is never routine
		case vb.parts[i] > va.parts[i]:
			return t, nil
		}
	}
	return "", errUnclassifiable // raw differs, numbers equal: never "no change"
}
