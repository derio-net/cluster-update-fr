// Package version parses the semver-ish versions the inventory compares
// (Talos, Kubernetes, Omni, chart and image tags) and computes the gap.
package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// V is a parsed version. Patch defaults to 0 for two-part versions.
type V struct {
	Major, Minor, Patch int
	Pre                 string
}

var re = regexp.MustCompile(`^v?(\d+)\.(\d+)(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$`)

// Parse accepts 1.2.3, v1.2.3, 1.2, and pre-release / build suffixes.
func Parse(s string) (V, error) {
	m := re.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return V{}, fmt.Errorf("version: %q is not a version", s)
	}
	var v V
	v.Major, _ = strconv.Atoi(m[1])
	v.Minor, _ = strconv.Atoi(m[2])
	if m[3] != "" {
		v.Patch, _ = strconv.Atoi(m[3])
	}
	v.Pre = m[4]
	return v, nil
}

// MustParse panics on error; for tests and constants.
func MustParse(s string) V {
	v, err := Parse(s)
	if err != nil {
		panic(err)
	}
	return v
}

func (v V) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Pre != "" {
		s += "-" + v.Pre
	}
	return s
}

// MinorString is "major.minor", the unit of Talos/Kubernetes support windows.
func (v V) MinorString() string { return fmt.Sprintf("%d.%d", v.Major, v.Minor) }

// Compare returns -1, 0 or 1. A pre-release sorts before its release.
func Compare(a, b V) int {
	for _, d := range [][2]int{{a.Major, b.Major}, {a.Minor, b.Minor}, {a.Patch, b.Patch}} {
		if d[0] != d[1] {
			if d[0] < d[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case a.Pre == b.Pre:
		return 0
	case a.Pre == "":
		return 1
	case b.Pre == "":
		return -1
	case a.Pre < b.Pre:
		return -1
	default:
		return 1
	}
}

// Delta is how far one version is behind another, in its most significant
// component only: 1.12.6 → 1.14.5 is {Minor: 2}.
type Delta struct{ Major, Minor, Patch int }

// Behind is the size of the gap in its significant component (0 = current).
func (d Delta) Behind() int { return d.Major + d.Minor + d.Patch }

func (d Delta) String() string {
	switch {
	case d.Major > 0:
		return fmt.Sprintf("%d major", d.Major)
	case d.Minor > 0:
		return fmt.Sprintf("%d minor", d.Minor)
	case d.Patch > 0:
		return fmt.Sprintf("%d patch", d.Patch)
	}
	return "current"
}

// Gap computes how far from is behind to. Ahead or equal is "current".
func Gap(from, to V) Delta {
	if Compare(from, to) >= 0 {
		return Delta{}
	}
	switch {
	case to.Major != from.Major:
		return Delta{Major: to.Major - from.Major}
	case to.Minor != from.Minor:
		return Delta{Minor: to.Minor - from.Minor}
	case to.Patch != from.Patch:
		return Delta{Patch: to.Patch - from.Patch}
	}
	return Delta{} // pre-release only
}

// UpdateType names the update from → to the way Renovate does.
func UpdateType(from, to V) string {
	switch {
	case to.Major != from.Major:
		return "major"
	case to.Minor != from.Minor:
		return "minor"
	default:
		return "patch"
	}
}
