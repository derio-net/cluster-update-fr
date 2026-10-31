// Package inventory builds R1's inventory: every dependency of Frank, Hop and
// the off-cluster Omni instance, grouped by cluster and service, with its
// declared, running and latest version, the gap, its vulnerabilities and its
// assigned update path.
package inventory

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/live"
	"github.com/derio-net/cluster-update-fr/internal/version"
)

// Kinds of dependency.
const (
	KindTalos      = "talos"
	KindKubernetes = "kubernetes"
	KindOmni       = "omni"
	KindChart      = "chart"
	KindImage      = "image"
)

// Dependency is one inventory row.
type Dependency struct {
	ID                string
	Cluster, Service  string
	Kind, Name        string
	Declared, Running string
	Latest            string
	Gap               string // "2 minor", "current", "" when not comparable
	Behind            int
	UpdateType        string // of declared/running -> latest
	Drift             bool   // declared != running
	Unknown           bool   // the live source was unreachable
	Note              string
	Path, PathReason  string
	Vulns             []live.Vuln
	VulnCounts        map[string]int
}

// ID identifies a dependency across inventory rebuilds (shared with alarms).
func ID(cluster, service, kind, name string) string {
	return cluster + "/" + service + "/" + kind + "/" + name
}

// Input is everything Build needs; nil snapshots mean unreachable.
type Input struct {
	Decl             *frankrepo.Declarations
	Frank, Hop       *live.Snapshot
	OmniRunning      string
	OmniErr          string
	Latest           map[string]string // dependency Name -> latest version
	SessionNamespace string
}

// Inventory is the built result.
type Inventory struct {
	BuiltAt     time.Time
	Deps        []Dependency
	Unreachable map[string]bool
}

// Build assembles the inventory. It never fails: what cannot be read is
// shown as unknown.
func Build(in Input) *Inventory {
	if in.Decl == nil {
		in.Decl = &frankrepo.Declarations{}
	}
	if in.SessionNamespace == "" {
		in.SessionNamespace = "upgrade-sessions"
	}
	inv := &Inventory{BuiltAt: time.Now(), Unreachable: map[string]bool{}}
	b := builder{in: in, inv: inv}
	b.os("frank", in.Decl.Frank, in.Frank)
	b.os("hop", in.Decl.Hop, in.Hop)
	b.omni()
	b.workloads(in.Frank, "frank")
	b.workloads(in.Hop, "hop")
	sort.SliceStable(inv.Deps, func(i, j int) bool {
		a, c := inv.Deps[i], inv.Deps[j]
		if a.Cluster != c.Cluster {
			return clusterOrder(a.Cluster) < clusterOrder(c.Cluster)
		}
		if a.Service != c.Service {
			return a.Service < c.Service
		}
		if a.Kind != c.Kind {
			return a.Kind < c.Kind
		}
		return a.Name < c.Name
	})
	return inv
}

func clusterOrder(c string) int {
	switch c {
	case "frank":
		return 0
	case "hop":
		return 1
	case "omni":
		return 2
	}
	return 3
}

type builder struct {
	in  Input
	inv *Inventory
}

func (b *builder) add(d Dependency) {
	d.setID()
	if d.Latest == "" {
		d.Latest = b.in.Latest[d.Name]
	}
	base := d.Running
	if base == "" || d.Unknown {
		base = d.Declared
	}
	if from, err := version.Parse(base); err == nil {
		if to, err := version.Parse(d.Latest); err == nil {
			g := version.Gap(from, to)
			d.Gap, d.Behind = g.String(), g.Behind()
			if g.Behind() > 0 {
				d.UpdateType = version.UpdateType(from, to)
			}
		}
	}
	if d.Declared != "" && d.Running != "" && !sameVersion(d.Declared, d.Running) {
		d.Drift = true
		if d.Note == "" {
			d.Note = fmt.Sprintf("declared %s, running %s", d.Declared, d.Running)
		}
	}
	ut := d.UpdateType
	if ut == "" {
		ut = "minor" // nothing pending: show the path a routine update would take
	}
	d.Path, d.PathReason = b.in.Decl.Policy.Resolve(frankrepo.Dep{Cluster: d.Cluster, App: d.Service, Kind: d.Kind, Name: d.Name, UpdateType: ut})
	if d.Kind == KindOmni {
		d.Path, d.PathReason = frankrepo.PathOperatorRunbook, "Omni is upgraded by the operator from the laptop"
	}
	if b.isRollouts(d.Cluster, d.Service) && d.Path != frankrepo.PathSession && d.Kind != KindOmni {
		d.Path, d.PathReason = frankrepo.PathSession, "Argo Rollouts app: promote/abort is decided in a session"
	}
	b.inv.Deps = append(b.inv.Deps, d)
}

func sameVersion(a, b string) bool {
	va, ea := version.Parse(a)
	vb, eb := version.Parse(b)
	if ea == nil && eb == nil {
		return version.Compare(va, vb) == 0
	}
	return a == b
}

func (b *builder) isRollouts(cluster, app string) bool {
	snap := b.in.Frank
	if cluster == "hop" {
		snap = b.in.Hop
	}
	if snap == nil {
		return false
	}
	for _, r := range snap.Rollouts {
		if r.App == app {
			return true
		}
	}
	return false
}

func (b *builder) os(cluster string, decl frankrepo.ClusterVersions, snap *live.Snapshot) {
	reachable := snap != nil && snap.OK("nodes")
	if !reachable {
		b.inv.Unreachable[cluster] = true
	}
	for _, kind := range []string{KindTalos, KindKubernetes} {
		d := Dependency{Cluster: cluster, Service: "os", Kind: kind, Name: kind}
		if kind == KindTalos {
			d.Declared = decl.Talos
		} else {
			d.Declared = decl.Kubernetes
		}
		if d.Declared == "" {
			d.Note = "not declared in versions/" + cluster + ".yaml"
		}
		if !reachable {
			d.Unknown = true
			b.add(d)
			continue
		}
		seen := map[string]bool{}
		var versions []string
		for _, n := range snap.Nodes {
			v := n.Talos
			if kind == KindKubernetes {
				v = n.Kubelet
			}
			if v != "" && !seen[v] {
				seen[v] = true
				versions = append(versions, v)
			}
		}
		sort.Strings(versions)
		switch len(versions) {
		case 0:
			d.Unknown = true
		case 1:
			d.Running = versions[0]
		default:
			d.Running = versions[0] // lowest: the node still to upgrade
			d.Drift = true
			d.Note = "nodes run different versions: " + strings.Join(versions, ", ")
		}
		b.add(d)
	}
}

func (b *builder) omni() {
	d := Dependency{Cluster: "omni", Service: "omni", Kind: KindOmni, Name: "omni", Declared: b.in.Decl.OmniVersion, Running: b.in.OmniRunning}
	if d.Running == "" {
		d.Unknown = true
		d.Note = "running version not readable"
		if b.in.OmniErr != "" {
			d.Note += ": " + b.in.OmniErr
		}
	}
	b.add(d)
}

func (b *builder) workloads(snap *live.Snapshot, cluster string) {
	if snap == nil {
		return
	}
	vulns := map[string][]live.Vuln{}
	for _, r := range snap.Vulns {
		vulns[r.Image] = append(vulns[r.Image], r.Vulns...)
	}
	// Images running per namespace, by repository.
	running := map[string]map[string][]string{} // ns -> repo -> tags
	for _, p := range snap.Pods {
		if p.Namespace == b.in.SessionNamespace {
			continue
		}
		for _, img := range p.Images {
			repo, tag := live.SplitImage(live.NormalizeImage(img))
			if running[p.Namespace] == nil {
				running[p.Namespace] = map[string][]string{}
			}
			if !contains(running[p.Namespace][repo], tag) {
				running[p.Namespace][repo] = append(running[p.Namespace][repo], tag)
			}
		}
	}
	for _, app := range snap.Apps {
		if app.DestNamespace == b.in.SessionNamespace {
			continue
		}
		for _, c := range app.Charts {
			b.add(Dependency{Cluster: cluster, Service: app.Name, Kind: KindChart, Name: c.Name, Declared: c.Declared, Running: c.Running})
		}
		done := map[string]bool{}
		for _, img := range app.Images {
			norm := live.NormalizeImage(img)
			repo, tag := live.SplitImage(norm)
			if done[repo] {
				continue
			}
			done[repo] = true
			d := Dependency{Cluster: cluster, Service: app.Name, Kind: KindImage, Name: repo, Declared: tag}
			if tags := running[app.DestNamespace][repo]; len(tags) > 0 {
				sort.Strings(tags)
				d.Running = tags[0]
				if len(tags) > 1 {
					d.Drift = true
					d.Note = "pods run several tags: " + strings.Join(tags, ", ")
				}
			} else if snap.OK("pods") {
				d.Note = "no running pod found"
			} else {
				d.Unknown = true
			}
			ref := repo
			if d.Running != "" {
				ref += ":" + d.Running
			} else if tag != "" {
				ref += ":" + tag
			}
			d.Vulns = dedupe(vulns[ref])
			d.VulnCounts = counts(d.Vulns)
			b.add(d)
		}
	}
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func dedupe(vs []live.Vuln) []live.Vuln {
	seen := map[string]bool{}
	var out []live.Vuln
	for _, v := range vs {
		k := v.ID + "|" + v.Package
		if !seen[k] {
			seen[k] = true
			out = append(out, v)
		}
	}
	return out
}

func counts(vs []live.Vuln) map[string]int {
	m := map[string]int{}
	for _, v := range vs {
		m[v.Severity]++
	}
	return m
}

// ClusterGroup / ServiceGroup are the Inventory page's cluster → service →
// dependency tree.
type ClusterGroup struct {
	Cluster  string
	Services []ServiceGroup
}

// ServiceGroup is one service's dependencies.
type ServiceGroup struct {
	Name string
	Deps []Dependency
}

// Grouped returns the tree in display order.
func (inv *Inventory) Grouped() []ClusterGroup {
	var out []ClusterGroup
	for _, d := range inv.Deps {
		if len(out) == 0 || out[len(out)-1].Cluster != d.Cluster {
			out = append(out, ClusterGroup{Cluster: d.Cluster})
		}
		cg := &out[len(out)-1]
		if len(cg.Services) == 0 || cg.Services[len(cg.Services)-1].Name != d.Service {
			cg.Services = append(cg.Services, ServiceGroup{Name: d.Service})
		}
		sg := &cg.Services[len(cg.Services)-1]
		sg.Deps = append(sg.Deps, d)
	}
	return out
}

// Find returns the dependency with id, or nil.
func (inv *Inventory) Find(id string) *Dependency {
	for i := range inv.Deps {
		if inv.Deps[i].ID == id {
			return &inv.Deps[i]
		}
	}
	return nil
}

// setID fills ID from the identifying fields.
func (d *Dependency) setID() { d.ID = ID(d.Cluster, d.Service, d.Kind, d.Name) }
