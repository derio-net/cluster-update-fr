// Package live reads the running state of a cluster, read-only: pods and
// their images, node versions, ArgoCD Applications (with the revision the
// last sync OPERATION applied — never trusting the Synced status), Argo
// Rollouts and Trivy VulnerabilityReports. Each source fails independently.
package live

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/scrub"
)

// Getter is the read half of kube.Client.
type Getter interface {
	Get(ctx context.Context, path string, out any) error
}

// Options selects the optional sources (CRDs a cluster may not have).
type Options struct {
	Rollouts bool
	Vulns    bool
}

// Pod is one pod and the images it runs.
type Pod struct {
	Namespace, Name, App, Phase string
	Labels                      map[string]string
	Images                      []string
}

// Node is one node's versions.
type Node struct {
	Name, Kubelet, Talos string
	Ready                bool
}

// Chart is a Helm source of an Application.
type Chart struct {
	Name, Repo        string
	Declared, Running string
}

// Source is one Application source with the revision last applied for it.
type Source struct {
	RepoURL, TargetRevision, Chart, Path string
	Applied                              string
}

// Application is an ArgoCD Application's state.
type Application struct {
	Name, DestNamespace      string
	SyncStatus, SyncRevision string
	OperationPhase, Health   string
	OperationFinished        time.Time
	Sources                  []Source
	Images                   []string
	Charts                   []Chart
}

// AppliedRevision returns the revision the last sync OPERATION applied for
// the source whose repoURL contains repo ("" if none). This is the R16
// evidence: status.sync.revision can report Synced at a revision that was
// never applied (frank gotcha: stale-revision for 15 days).
func (a Application) AppliedRevision(repo string) string {
	for _, s := range a.Sources {
		if strings.Contains(s.RepoURL, repo) {
			return s.Applied
		}
	}
	return ""
}

// Rollout is an Argo Rollout's state (read-only; promote/abort happens only
// inside an upgrade session).
type Rollout struct {
	Namespace, Name, App, Phase, Message string
	Paused, Aborted                      bool
	PausedSince                          time.Time
}

// NeedsDecision reports a paused or aborted rollout — a canary `pause: {}`
// never expires, so Paused is not a resting state.
func (r Rollout) NeedsDecision() bool { return r.Paused || r.Aborted }

// Vuln is one vulnerability in an image.
type Vuln struct {
	ID, Severity, Package, Installed, Fixed, Title string
}

// Report is the vulnerabilities of one image.
type Report struct {
	Namespace, Image string
	Vulns            []Vuln
}

// Snapshot is one read of one cluster.
type Snapshot struct {
	Cluster  string
	At       time.Time
	Pods     []Pod
	Nodes    []Node
	Apps     []Application
	Rollouts []Rollout
	Vulns    []Report
	Errors   map[string]string // source -> error (scrubbed)
}

// OK reports whether source was read successfully.
func (s *Snapshot) OK(source string) bool { return s != nil && s.Errors[source] == "" }

// Read reads every source; a failing source is recorded, never fatal.
func Read(ctx context.Context, g Getter, cluster string, o Options) *Snapshot {
	s := &Snapshot{Cluster: cluster, At: time.Now(), Errors: map[string]string{}}
	try := func(name string, f func() error) {
		if err := f(); err != nil {
			s.Errors[name] = scrub.String(err.Error())
		}
	}
	try("pods", func() (err error) { s.Pods, err = readPods(ctx, g); return })
	try("nodes", func() (err error) { s.Nodes, err = readNodes(ctx, g); return })
	try("applications", func() (err error) { s.Apps, err = readApps(ctx, g); return })
	if o.Rollouts {
		try("rollouts", func() (err error) { s.Rollouts, err = readRollouts(ctx, g); return })
	}
	if o.Vulns {
		try("vulnerabilityreports", func() (err error) { s.Vulns, err = readVulns(ctx, g); return })
	}
	return s
}

type meta struct {
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Labels    map[string]string `json:"labels"`
}

// appOf attributes an object to an application by the usual labels.
func appOf(m meta) string {
	for _, k := range []string{"argocd.argoproj.io/instance", "app.kubernetes.io/instance", "app.kubernetes.io/name", "app"} {
		if v := m.Labels[k]; v != "" {
			return v
		}
	}
	return ""
}

func readPods(ctx context.Context, g Getter) ([]Pod, error) {
	var l struct {
		Items []struct {
			Metadata meta `json:"metadata"`
			Spec     struct {
				Containers     []struct{ Image string } `json:"containers"`
				InitContainers []struct{ Image string } `json:"initContainers"`
			} `json:"spec"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := g.Get(ctx, "/api/v1/pods", &l); err != nil {
		return nil, err
	}
	out := make([]Pod, 0, len(l.Items))
	for _, it := range l.Items {
		p := Pod{Namespace: it.Metadata.Namespace, Name: it.Metadata.Name, Labels: it.Metadata.Labels, Phase: it.Status.Phase}
		p.App = appOf(it.Metadata)
		if p.App == "" {
			p.App = p.Namespace
		}
		for _, c := range it.Spec.Containers {
			p.Images = append(p.Images, c.Image)
		}
		for _, c := range it.Spec.InitContainers {
			p.Images = append(p.Images, c.Image)
		}
		out = append(out, p)
	}
	return out, nil
}

var talosRe = regexp.MustCompile(`Talos \(v?([0-9][^)]*)\)`)

func readNodes(ctx context.Context, g Getter) ([]Node, error) {
	var l struct {
		Items []struct {
			Metadata meta `json:"metadata"`
			Status   struct {
				NodeInfo struct {
					KubeletVersion string `json:"kubeletVersion"`
					OSImage        string `json:"osImage"`
				} `json:"nodeInfo"`
				Conditions []struct{ Type, Status string } `json:"conditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := g.Get(ctx, "/api/v1/nodes", &l); err != nil {
		return nil, err
	}
	var out []Node
	for _, it := range l.Items {
		n := Node{Name: it.Metadata.Name, Kubelet: strings.TrimPrefix(it.Status.NodeInfo.KubeletVersion, "v")}
		if m := talosRe.FindStringSubmatch(it.Status.NodeInfo.OSImage); m != nil {
			n.Talos = m[1]
		}
		for _, c := range it.Status.Conditions {
			if c.Type == "Ready" && c.Status == "True" {
				n.Ready = true
			}
		}
		out = append(out, n)
	}
	return out, nil
}

type appSource struct {
	RepoURL        string `json:"repoURL"`
	TargetRevision string `json:"targetRevision"`
	Chart          string `json:"chart"`
	Path           string `json:"path"`
}

func readApps(ctx context.Context, g Getter) ([]Application, error) {
	var l struct {
		Items []struct {
			Metadata meta `json:"metadata"`
			Spec     struct {
				Destination struct {
					Namespace string `json:"namespace"`
				} `json:"destination"`
				Source  *appSource  `json:"source"`
				Sources []appSource `json:"sources"`
			} `json:"spec"`
			Status struct {
				Sync struct {
					Status    string   `json:"status"`
					Revision  string   `json:"revision"`
					Revisions []string `json:"revisions"` // multi-source, aligned with spec.sources
				} `json:"sync"`
				Health struct {
					Status string `json:"status"`
				} `json:"health"`
				OperationState struct {
					Phase      string    `json:"phase"`
					FinishedAt time.Time `json:"finishedAt"`
					Operation  struct {
						Sync struct {
							Revision  string   `json:"revision"`
							Revisions []string `json:"revisions"`
						} `json:"sync"`
					} `json:"operation"`
				} `json:"operationState"`
				Summary struct {
					Images []string `json:"images"`
				} `json:"summary"`
				History []struct {
					Revision  string   `json:"revision"`
					Revisions []string `json:"revisions"`
				} `json:"history"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := g.Get(ctx, "/apis/argoproj.io/v1alpha1/applications", &l); err != nil {
		return nil, err
	}
	var out []Application
	for _, it := range l.Items {
		st := it.Status
		a := Application{
			Name: it.Metadata.Name, DestNamespace: it.Spec.Destination.Namespace,
			SyncStatus: st.Sync.Status, SyncRevision: st.Sync.Revision,
			OperationPhase: st.OperationState.Phase, Health: st.Health.Status,
			OperationFinished: st.OperationState.FinishedAt,
			Images:            st.Summary.Images,
		}
		sources := it.Spec.Sources
		if it.Spec.Source != nil {
			sources = []appSource{*it.Spec.Source}
		}
		opRevs := st.OperationState.Operation.Sync.Revisions
		if len(opRevs) == 0 && st.OperationState.Operation.Sync.Revision != "" {
			opRevs = []string{st.OperationState.Operation.Sync.Revision}
		}
		var histRevs []string
		if n := len(st.History); n > 0 {
			histRevs = st.History[n-1].Revisions
			if len(histRevs) == 0 && st.History[n-1].Revision != "" {
				histRevs = []string{st.History[n-1].Revision}
			}
		}
		for i, src := range sources {
			// Multi-source apps report status.sync.revisions (plural); the
			// displayed sync revision is the git (non-chart) source's.
			if a.SyncRevision == "" && src.Chart == "" && i < len(st.Sync.Revisions) {
				a.SyncRevision = st.Sync.Revisions[i]
			}
			s := Source{RepoURL: src.RepoURL, TargetRevision: src.TargetRevision, Chart: src.Chart, Path: src.Path}
			if i < len(opRevs) {
				s.Applied = opRevs[i]
			}
			a.Sources = append(a.Sources, s)
			if src.Chart != "" {
				c := Chart{Name: src.Chart, Repo: src.RepoURL, Declared: src.TargetRevision}
				if i < len(histRevs) {
					c.Running = histRevs[i]
				}
				a.Charts = append(a.Charts, c)
			}
		}
		out = append(out, a)
	}
	return out, nil
}

func readRollouts(ctx context.Context, g Getter) ([]Rollout, error) {
	var l struct {
		Items []struct {
			Metadata meta `json:"metadata"`
			Spec     struct {
				Paused bool `json:"paused"`
			} `json:"spec"`
			Status struct {
				Phase           string `json:"phase"`
				Message         string `json:"message"`
				Abort           bool   `json:"abort"`
				PauseConditions []struct {
					Reason    string    `json:"reason"`
					StartTime time.Time `json:"startTime"`
				} `json:"pauseConditions"`
			} `json:"status"`
		} `json:"items"`
	}
	if err := g.Get(ctx, "/apis/argoproj.io/v1alpha1/rollouts", &l); err != nil {
		return nil, err
	}
	var out []Rollout
	for _, it := range l.Items {
		r := Rollout{Namespace: it.Metadata.Namespace, Name: it.Metadata.Name, Phase: it.Status.Phase,
			Message: it.Status.Message, Aborted: it.Status.Abort}
		r.App = appOf(it.Metadata)
		if r.App == "" {
			r.App = r.Name
		}
		r.Paused = it.Spec.Paused || it.Status.Phase == "Paused" || len(it.Status.PauseConditions) > 0
		if len(it.Status.PauseConditions) > 0 {
			r.PausedSince = it.Status.PauseConditions[0].StartTime
		}
		out = append(out, r)
	}
	return out, nil
}

type rawVuln struct {
	ID        string `json:"vulnerabilityID"`
	Severity  string `json:"severity"`
	Resource  string `json:"resource"`
	Installed string `json:"installedVersion"`
	Fixed     string `json:"fixedVersion"`
	Title     string `json:"title"`
}

func readVulns(ctx context.Context, g Getter) ([]Report, error) {
	var l struct {
		Items []struct {
			Metadata meta `json:"metadata"`
			Report   struct {
				Registry struct {
					Server string `json:"server"`
				} `json:"registry"`
				Artifact struct {
					Repository string `json:"repository"`
					Tag        string `json:"tag"`
					Digest     string `json:"digest"`
				} `json:"artifact"`
				Vulnerabilities []rawVuln `json:"vulnerabilities"`
			} `json:"report"`
		} `json:"items"`
	}
	if err := g.Get(ctx, "/apis/aquasecurity.github.io/v1alpha1/vulnerabilityreports", &l); err != nil {
		return nil, err
	}
	var out []Report
	for _, it := range l.Items {
		a := it.Report.Artifact
		ref := a.Repository
		if it.Report.Registry.Server != "" {
			ref = it.Report.Registry.Server + "/" + ref
		}
		if a.Tag != "" {
			ref += ":" + a.Tag
		}
		r := Report{Namespace: it.Metadata.Namespace, Image: NormalizeImage(ref)}
		for _, v := range it.Report.Vulnerabilities {
			r.Vulns = append(r.Vulns, Vuln{ID: v.ID, Severity: strings.ToUpper(v.Severity), Package: v.Resource, Installed: v.Installed, Fixed: v.Fixed, Title: v.Title})
		}
		out = append(out, r)
	}
	return out, nil
}

// NormalizeImage canonicalises an image reference: Docker Hub images get
// docker.io/ and library/ made explicit, index.docker.io becomes docker.io.
func NormalizeImage(ref string) string {
	ref = strings.TrimSpace(ref)
	digest := ""
	if i := strings.Index(ref, "@"); i >= 0 {
		ref, digest = ref[:i], ref[i:]
	}
	first, rest, hasSlash := strings.Cut(ref, "/")
	isRegistry := hasSlash && (strings.ContainsAny(first, ".:") || first == "localhost")
	switch {
	case !hasSlash:
		ref = "docker.io/library/" + ref
	case !isRegistry:
		ref = "docker.io/" + ref
	case first == "index.docker.io" || first == "registry-1.docker.io":
		ref = "docker.io/" + rest
	}
	if strings.HasPrefix(ref, "docker.io/") && strings.Count(ref, "/") == 1 {
		ref = "docker.io/library/" + strings.TrimPrefix(ref, "docker.io/")
	}
	return ref + digest
}

// SplitImage returns the repository and the tag ("" when untagged) of a
// normalized reference; a digest is dropped.
func SplitImage(ref string) (repo, tag string) {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	if colon > slash {
		return ref[:colon], ref[colon+1:]
	}
	return ref, ""
}

// OmniVersion reads the running Omni version from the JSON file written by
// the Reader-SA omnictl sidecar: {"version": "..."} or the raw
// `omnictl get sysversion -o json` shape {"spec": {"backendversion": "..."}}.
func OmniVersion(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var v struct {
		Version string `json:"version"`
		Spec    struct {
			BackendVersion string `json:"backendversion"`
		} `json:"spec"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return "", err
	}
	if v.Version != "" {
		return v.Version, nil
	}
	if v.Spec.BackendVersion != "" {
		return v.Spec.BackendVersion, nil
	}
	return "", errors.New("live: omni status has no version")
}
