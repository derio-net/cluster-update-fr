// Package frankrepo loads the declarations the console reads from the
// derio-net/frank repository: versions/*.yaml, versions/support-matrix.yaml,
// update-policy.yaml, smoke/*.yaml and the Omni env template.
//
// Loading is tolerant by design: a missing or malformed file is recorded in
// Declarations.Missing / Errors and the rest still loads, so one bad file
// never blanks the console.
package frankrepo

import (
	"context"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Update paths (spec Part 1).
const (
	PathAutoMerge       = "auto-merge"
	PathBatchApprove    = "batch-approve"
	PathSession         = "session"
	PathOperatorRunbook = "operator-runbook"
	PathUnclassified    = "unclassified"
)

// ValidPath reports whether p is one of the four paths.
func ValidPath(p string) bool {
	switch p {
	case PathAutoMerge, PathBatchApprove, PathSession, PathOperatorRunbook:
		return true
	}
	return false
}

// ClusterVersions is versions/<cluster>.yaml.
type ClusterVersions struct {
	Talos      string `yaml:"talos"`
	Kubernetes string `yaml:"kubernetes"`
	ManagedBy  string `yaml:"managed_by"`
}

// Matrix maps a Talos minor to the Kubernetes minors it supports.
type Matrix struct {
	Talos map[string][]string
}

// Kubernetes returns the supported Kubernetes minors for a Talos minor.
func (m Matrix) Kubernetes(talosMinor string) []string { return m.Talos[talosMinor] }

// UnmarshalYAML accepts both `"1.13": [..]` and `"1.13": {kubernetes: [..]}`.
func (m *Matrix) UnmarshalYAML(n *yaml.Node) error {
	var raw struct {
		Talos map[string]yaml.Node `yaml:"talos"`
	}
	if err := n.Decode(&raw); err != nil {
		return err
	}
	m.Talos = map[string][]string{}
	for minor, v := range raw.Talos {
		var list []string
		if v.Kind == yaml.SequenceNode {
			if err := v.Decode(&list); err != nil {
				return err
			}
		} else {
			var obj struct {
				Kubernetes []string `yaml:"kubernetes"`
			}
			if err := v.Decode(&obj); err != nil {
				return err
			}
			list = obj.Kubernetes
		}
		m.Talos[minor] = list
	}
	return nil
}

// Check is one smoke check.
type Check struct {
	Kind   string `yaml:"kind"` // http | tcp | exec-probe | functional
	Target string `yaml:"target"`
	Reason string `yaml:"reason"`
	Expect struct {
		Status int    `yaml:"status"`
		Body   string `yaml:"body"` // regular expression
	} `yaml:"expect"`
}

// Smoke is smoke/<app>.yaml.
type Smoke struct {
	App     string  `yaml:"app"`
	Cluster string  `yaml:"cluster"`
	Checks  []Check `yaml:"checks"`
}

// Rule is one policy rule; every set match field must match.
type Rule struct {
	Match struct {
		App   string `yaml:"app"`
		Image string `yaml:"image"`
		Chart string `yaml:"chart"`
		Dep   string `yaml:"dep"`
	} `yaml:"match"`
	UpdateTypes []string `yaml:"update_types"`
	Path        string   `yaml:"path"`
	Reason      string   `yaml:"reason"`
}

// Policy is update-policy.yaml.
type Policy struct {
	Version           int               `yaml:"version"`
	Defaults          map[string]string `yaml:"defaults"`
	Rules             []Rule            `yaml:"rules"`
	MergeWindowRaw    string            `yaml:"merge_window"`
	ReleaseAgeRaw     string            `yaml:"minimum_release_age"`
	MergeWindow       time.Duration     `yaml:"-"`
	MinimumReleaseAge time.Duration     `yaml:"-"`
	// RequiredCIContexts are the GitHub status contexts that must ALL be
	// green before anything merges (exact names, or "prefix*"); empty =
	// every gitea-actions/* context (c1s-r3).
	RequiredCIContexts []string `yaml:"required_ci_contexts"`
}

// Dep identifies a dependency for policy resolution.
type Dep struct {
	Cluster    string
	App        string
	Kind       string // image | chart | talos | kubernetes | omni
	Name       string // image repository, chart name, or the kind for OS deps
	UpdateType string // patch | minor | major | digest
}

// Resolve returns the dependency's path and the reason (rule or default).
// A dependency nothing covers is PathUnclassified, never a guess.
func (p Policy) Resolve(d Dep) (string, string) {
	for _, r := range p.Rules {
		if !r.matches(d) {
			continue
		}
		if ValidPath(r.Path) {
			return r.Path, r.Reason
		}
		return PathUnclassified, "rule has invalid path " + strconv.Quote(r.Path)
	}
	if def, ok := p.Defaults[d.UpdateType]; ok && ValidPath(def) {
		return def, "default for " + d.UpdateType
	}
	return PathUnclassified, "no rule or default"
}

func (r Rule) matches(d Dep) bool {
	m := r.Match
	if m.App == "" && m.Image == "" && m.Chart == "" && m.Dep == "" {
		return false
	}
	if m.App != "" && !glob(m.App, d.App) {
		return false
	}
	if m.Image != "" && (d.Kind != "image" || !glob(m.Image, d.Name)) {
		return false
	}
	if m.Chart != "" && (d.Kind != "chart" || !glob(m.Chart, d.Name)) {
		return false
	}
	if m.Dep != "" && !glob(m.Dep, d.Kind) && !glob(m.Dep, d.Name) {
		return false
	}
	if len(r.UpdateTypes) > 0 {
		ok := false
		for _, t := range r.UpdateTypes {
			if t == d.UpdateType {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func glob(pattern, s string) bool {
	ok, err := path.Match(pattern, s)
	return err == nil && ok
}

// Declarations is everything loaded from the repo.
type Declarations struct {
	Frank, Hop  ClusterVersions
	OmniVersion string
	Matrix      Matrix
	Policy      Policy
	Smoke       map[string]Smoke
	Missing     []string          // paths not present (not declared)
	Errors      map[string]string // path -> parse error
}

// Paths read by Load.
const (
	FrankVersionsPath = "versions/frank.yaml"
	HopVersionsPath   = "versions/hop.yaml"
	MatrixPath        = "versions/support-matrix.yaml"
	PolicyPath        = "update-policy.yaml"
	SmokeDir          = "smoke"
	OmniEnvPath       = "omni/omni/omni.env.template"
)

var omniRe = regexp.MustCompile(`(?m)^\s*OMNI_VERSION=(v?\d+\.\d+\.\d+\S*)\s*$`)

// Load reads every declaration from src. It returns an error only when the
// context is done or the source is unreachable for every file.
func Load(ctx context.Context, src Source) (*Declarations, error) {
	d := &Declarations{Smoke: map[string]Smoke{}, Errors: map[string]string{}}
	reachable := false
	read := func(p string, out any) {
		b, err := src.Read(ctx, p)
		switch {
		case errors.Is(err, ErrNotFound):
			reachable = true
			d.Missing = append(d.Missing, p)
			return
		case err != nil:
			d.Errors[p] = err.Error()
			return
		}
		reachable = true
		if err := yaml.Unmarshal(b, out); err != nil {
			d.Errors[p] = err.Error()
		}
	}
	read(FrankVersionsPath, &d.Frank)
	read(HopVersionsPath, &d.Hop)
	read(MatrixPath, &d.Matrix)
	read(PolicyPath, &d.Policy)
	d.Policy.MergeWindow = parseDuration(d.Policy.MergeWindowRaw)
	d.Policy.MinimumReleaseAge = parseDuration(d.Policy.ReleaseAgeRaw)

	if b, err := src.Read(ctx, OmniEnvPath); err == nil {
		reachable = true
		if m := omniRe.FindSubmatch(b); m != nil {
			d.OmniVersion = string(m[1])
		}
	} else if errors.Is(err, ErrNotFound) {
		reachable = true
		d.Missing = append(d.Missing, OmniEnvPath)
	} else {
		d.Errors[OmniEnvPath] = err.Error()
	}

	names, err := src.List(ctx, SmokeDir)
	switch {
	case errors.Is(err, ErrNotFound):
		reachable = true
		d.Missing = append(d.Missing, SmokeDir+"/")
	case err != nil:
		d.Errors[SmokeDir] = err.Error()
	default:
		reachable = true
		for _, n := range names {
			var s Smoke
			read(SmokeDir+"/"+n, &s)
			app := s.App
			if app == "" {
				app = strings.TrimSuffix(n, ".yaml")
			}
			if len(s.Checks) > 0 {
				d.Smoke[app] = s
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !reachable {
		return d, fmt.Errorf("frankrepo: source unreachable: %v", d.Errors)
	}
	return d, nil
}

// parseDuration accepts Go durations plus a "d" (days) suffix; "" or bad = 0.
func parseDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0
		}
		return time.Duration(n) * 24 * time.Hour
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return v
}
