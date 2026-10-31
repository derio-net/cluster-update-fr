// Package tracks computes a cluster's OS upgrade track for the Guided
// upgrades section: an ordered sequence of single steps — one Talos minor or
// one Kubernetes minor at a time — that stays inside the Talos↔Kubernetes
// support window from frank's versions/support-matrix.yaml (matrix-driven,
// never hard-coded). Frank's scripts/life_tracks.py implements the same
// rules for its CI; keep them in step.
package tracks

import (
	"fmt"
	"sort"

	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/version"
)

// Step kinds.
const (
	KindTalos      = "talos"
	KindKubernetes = "kubernetes"
)

// Step is one OS step.
type Step struct {
	ID            string // upgrade id, e.g. frank-os-talos-1.13.4
	Cluster       string
	Kind          string
	From, To      string
	Position      int
	OneWay        bool   // Kubernetes minors cannot be rolled back
	Rollback      string // omni-revert | talosctl-rollback | one-way
	TalosClient   string // talosctl pinned for this step
	KubectlClient string // kubectl pinned for this step
}

// Releases are the upstream release tags.
type Releases struct {
	Talos, Kubernetes []string
}

func latestPerMinor(tags []string) map[string]version.V {
	out := map[string]version.V{}
	for _, t := range tags {
		v, err := version.Parse(t)
		if err != nil || v.Pre != "" {
			continue
		}
		if cur, ok := out[v.MinorString()]; !ok || version.Compare(v, cur) > 0 {
			out[v.MinorString()] = v
		}
	}
	return out
}

func supported(m frankrepo.Matrix, talos, k8s version.V) bool {
	for _, k := range m.Kubernetes(talos.MinorString()) {
		if k == k8s.MinorString() {
			return true
		}
	}
	return false
}

func nextMinor(v version.V) string { return fmt.Sprintf("%d.%d", v.Major, v.Minor+1) }

// Next returns the ordered steps from the declared versions to the newest
// stable releases.
func Next(cluster string, decl frankrepo.ClusterVersions, rel Releases, m frankrepo.Matrix) []Step {
	talos, err1 := version.Parse(decl.Talos)
	k8s, err2 := version.Parse(decl.Kubernetes)
	if err1 != nil || err2 != nil {
		return nil
	}
	tMinor, kMinor := latestPerMinor(rel.Talos), latestPerMinor(rel.Kubernetes)
	rollback := "omni-revert"
	if cluster == "hop" {
		rollback = "talosctl-rollback"
	}
	var steps []Step
	add := func(kind string, from, to version.V) {
		s := Step{Cluster: cluster, Kind: kind, From: from.String(), To: to.String(), Position: len(steps) + 1}
		if kind == KindTalos {
			s.Rollback = rollback
			talos = to
		} else {
			s.OneWay = to.Minor != from.Minor || to.Major != from.Major
			s.Rollback = "one-way"
			if !s.OneWay {
				s.Rollback = "previous patch"
			}
			k8s = to
		}
		s.TalosClient, s.KubectlClient = talos.String(), k8s.String()
		s.ID = fmt.Sprintf("%s-os-%s-%s", cluster, map[string]string{KindTalos: "talos", KindKubernetes: "k8s"}[kind], s.To)
		steps = append(steps, s)
	}
	// Patch steps inside the current minors first.
	if v, ok := tMinor[talos.MinorString()]; ok && version.Compare(v, talos) > 0 {
		add(KindTalos, talos, v)
	}
	if v, ok := kMinor[k8s.MinorString()]; ok && version.Compare(v, k8s) > 0 {
		add(KindKubernetes, k8s, v)
	}
	// Minor steps alternate: a Talos minor (when the current Kubernetes minor
	// is inside its window), then the Kubernetes minor it unlocks, and so on;
	// when the next Talos minor does not support the running Kubernetes
	// minor, Kubernetes moves first.
	preferK := false
	for guard := 0; guard < 20; guard++ {
		nt, hasT := tMinor[nextMinor(talos)]
		nk, hasK := kMinor[nextMinor(k8s)]
		canT := hasT && supported(m, nt, k8s)
		canK := hasK && supported(m, talos, nk)
		switch {
		case canK && (preferK || !canT):
			add(KindKubernetes, k8s, nk)
			preferK = false
		case canT:
			add(KindTalos, talos, nt)
			preferK = true
		default:
			return steps
		}
	}
	return steps
}

// Sorted returns tags sorted ascending (helper for display).
func Sorted(tags []string) []string {
	out := append([]string(nil), tags...)
	sort.Slice(out, func(i, j int) bool {
		a, e1 := version.Parse(out[i])
		b, e2 := version.Parse(out[j])
		if e1 != nil || e2 != nil {
			return out[i] < out[j]
		}
		return version.Compare(a, b) < 0
	})
	return out
}
