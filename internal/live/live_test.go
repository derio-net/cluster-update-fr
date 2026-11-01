package live

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureGetter serves testdata/live/<resource>.json for the API paths the
// readers use.
type fixtureGetter struct{ missing map[string]bool }

func (f fixtureGetter) Get(_ context.Context, path string, out any) error {
	name := filepath.Base(path)
	if f.missing[name] {
		return errors.New("the server could not find the requested resource")
	}
	b, err := os.ReadFile("../../testdata/live/" + name + ".json")
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func snapshot(t *testing.T, g Getter) *Snapshot {
	t.Helper()
	return Read(context.Background(), g, "frank", Options{Rollouts: true, Vulns: true})
}

func TestPodsAndImages(t *testing.T) {
	s := snapshot(t, fixtureGetter{})
	if len(s.Pods) != 3 {
		t.Fatalf("pods = %d", len(s.Pods))
	}
	p := s.Pods[0]
	if p.App != "litellm" || len(p.Images) != 2 || p.Images[1] != "busybox:1.37.0" {
		t.Errorf("pod 0 = %+v", p)
	}
	if s.Pods[1].App != "homepage" {
		t.Errorf("label fallback: %+v", s.Pods[1])
	}
	if s.Pods[2].Labels["fr.run/id"] != "frank-os-talos-1.13.4" || s.Pods[2].Phase != "Failed" {
		t.Errorf("session pod = %+v", s.Pods[2])
	}
}

func TestNodes(t *testing.T) {
	s := snapshot(t, fixtureGetter{})
	if len(s.Nodes) != 2 || s.Nodes[0].Talos != "1.12.6" || s.Nodes[0].Kubelet != "1.35.3" || !s.Nodes[0].Ready || s.Nodes[1].Ready {
		t.Errorf("nodes = %+v", s.Nodes)
	}
}

func TestApplications(t *testing.T) {
	s := snapshot(t, fixtureGetter{})
	if len(s.Apps) != 2 {
		t.Fatalf("apps = %d", len(s.Apps))
	}
	l := s.Apps[0]
	if l.Name != "litellm" || l.SyncStatus != "Synced" || l.Health != "Healthy" || l.OperationPhase != "Succeeded" {
		t.Errorf("litellm = %+v", l)
	}
	// Synced at 9c3e…, but the last sync OPERATION applied 4b7d… — the
	// stale-revision gotcha. AppliedRevision reads the operation, never the
	// sync status (multi-source: status.sync.revisions, plural).
	if got := l.AppliedRevision("derio-net/frank"); got != "4b7d0e2c9a1f36d58e2b7c4a0f9d1e3b6a5c8f72" {
		t.Errorf("litellm applied = %q", got)
	}
	if l.SyncRevision != "9c3e1f7a5b2d48e06f1a3c9b7d5e2f4a8c6b1d03" {
		t.Errorf("litellm sync revision (multi-source revisions) = %q", l.SyncRevision)
	}
	if len(l.Charts) != 1 || l.Charts[0].Name != "litellm-helm" || l.Charts[0].Declared != "0.1.700" || l.Charts[0].Running != "0.1.699" {
		t.Errorf("litellm charts = %+v", l.Charts)
	}
	h := s.Apps[1]
	if got := h.AppliedRevision("derio-net/frank"); got != "5e8b2d6f0a4c19e73b5d8f2a6c0e4b9d1f3a7c58" { // single source: revision, singular
		t.Errorf("homepage applied = %q", got)
	}
	if len(h.Images) != 1 || len(h.Charts) != 0 {
		t.Errorf("homepage = %+v", h)
	}
}

func TestRollouts(t *testing.T) {
	s := snapshot(t, fixtureGetter{})
	if len(s.Rollouts) != 3 {
		t.Fatalf("rollouts = %d", len(s.Rollouts))
	}
	if r := s.Rollouts[0]; !r.Paused || r.Aborted || r.App != "litellm" || !r.NeedsDecision() {
		t.Errorf("paused = %+v", r)
	}
	if r := s.Rollouts[1]; !r.Aborted || !r.NeedsDecision() || r.App != "sympozium-api" {
		t.Errorf("aborted = %+v", r)
	}
	if s.Rollouts[2].NeedsDecision() {
		t.Error("healthy rollout needs no decision")
	}
}

func TestVulnerabilityReports(t *testing.T) {
	s := snapshot(t, fixtureGetter{})
	if len(s.Vulns) != 2 {
		t.Fatalf("reports = %d", len(s.Vulns))
	}
	r := s.Vulns[0]
	if r.Image != "ghcr.io/berriai/litellm:v1.80.0" || len(r.Vulns) != 3 || r.Vulns[0].Severity != "CRITICAL" || r.Vulns[0].Fixed != "3.0.9" {
		t.Errorf("report = %+v", r)
	}
	if s.Vulns[1].Image != "docker.io/library/busybox:1.37.0" {
		t.Errorf("docker hub image = %q", s.Vulns[1].Image)
	}
}

func TestOneFailingSourceDoesNotBlankTheOthers(t *testing.T) {
	s := Read(context.Background(), fixtureGetter{missing: map[string]bool{"rollouts": true, "vulnerabilityreports": true}}, "frank", Options{Rollouts: true, Vulns: true})
	if len(s.Pods) != 3 || len(s.Apps) != 2 {
		t.Fatal("pods/apps must still load")
	}
	if s.Errors["rollouts"] == "" || s.Errors["vulnerabilityreports"] == "" || s.Errors["pods"] != "" {
		t.Errorf("errors = %v", s.Errors)
	}
	if s.OK("pods") != true || s.OK("rollouts") != false {
		t.Error("OK()")
	}
}

func TestNormalizeImage(t *testing.T) {
	cases := map[string]string{
		"busybox:1.37.0":                  "docker.io/library/busybox:1.37.0",
		"index.docker.io/library/nginx:1": "docker.io/library/nginx:1",
		"grafana/grafana:12.0.0":          "docker.io/grafana/grafana:12.0.0",
		"ghcr.io/derio-net/x:0.1.0":       "ghcr.io/derio-net/x:0.1.0",
		"registry:5000/team/app:2":        "registry:5000/team/app:2",
		"ghcr.io/a/b:1@sha256:" + hex64(): "ghcr.io/a/b:1@sha256:" + hex64(),
		"ghcr.io/a/b":                     "ghcr.io/a/b",
	}
	for in, want := range cases {
		if got := NormalizeImage(in); got != want {
			t.Errorf("NormalizeImage(%q) = %q, want %q", in, got, want)
		}
	}
	repo, tag := SplitImage("docker.io/library/busybox:1.37.0")
	if repo != "docker.io/library/busybox" || tag != "1.37.0" {
		t.Errorf("SplitImage = %q %q", repo, tag)
	}
	repo, tag = SplitImage("registry:5000/app")
	if repo != "registry:5000/app" || tag != "" {
		t.Errorf("SplitImage port = %q %q", repo, tag)
	}
}

func hex64() string { return strings.Repeat("ab", 32) }

func TestHopScanFromVictoriaLogs(t *testing.T) {
	body, _ := os.ReadFile("../../testdata/live/hop-scan.jsonl")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/select/logsql/query" || !strings.Contains(r.URL.Query().Get("query"), `"hop-scan result"`) {
			w.WriteHeader(400)
			return
		}
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	reports, err := HopScan(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 || reports[0].Image != "docker.io/library/caddy:2.10.0" || reports[0].Namespace != "caddy-system" ||
		len(reports[0].Vulns) != 1 || reports[0].Vulns[0].Fixed != "0.33.0" || reports[0].Vulns[0].ID != "CVE-2026-1000" {
		t.Errorf("reports = %+v", reports)
	}
}

func TestOmniStatus(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.json")
	_ = os.WriteFile(a, []byte(`{"version":"v1.5.0"}`), 0o600)
	b := filepath.Join(dir, "b.json")
	_ = os.WriteFile(b, []byte(`{"metadata":{"id":"current"},"spec":{"backendversion":"1.5.0"}}`), 0o600)
	if v, err := OmniVersion(a); err != nil || v != "v1.5.0" {
		t.Errorf("a = %q %v", v, err)
	}
	if v, err := OmniVersion(b); err != nil || v != "1.5.0" {
		t.Errorf("b = %q %v", v, err)
	}
	if _, err := OmniVersion(filepath.Join(dir, "none")); err == nil {
		t.Error("missing file must error")
	}
}
