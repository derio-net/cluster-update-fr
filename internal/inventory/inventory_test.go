package inventory

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/live"
)

type fixtureGetter struct{}

func (fixtureGetter) Get(_ context.Context, path string, out any) error {
	b, err := os.ReadFile("../../testdata/live/" + filepath.Base(path) + ".json")
	if err != nil {
		return err
	}
	return json.Unmarshal(b, out)
}

func input(t *testing.T) Input {
	t.Helper()
	decl, err := frankrepo.Load(context.Background(), frankrepo.FSSource{Root: "../../testdata/frank"})
	if err != nil {
		t.Fatal(err)
	}
	frank := live.Read(context.Background(), fixtureGetter{}, "frank", live.Options{Rollouts: true, Vulns: true})
	return Input{
		Decl:        decl,
		Frank:       frank,
		Hop:         nil, // unreachable
		OmniRunning: "v1.5.0",
		Latest: map[string]string{
			"talos":                        "1.14.5",
			"kubernetes":                   "1.37.2",
			"omni":                         "v1.13.1",
			"ghcr.io/berriai/litellm":      "v1.80.3",
			"litellm-helm":                 "0.1.705",
			"ghcr.io/gethomepage/homepage": "v1.4.0",
		},
	}
}

func find(inv *Inventory, cluster, service, kind, name string) *Dependency {
	for i := range inv.Deps {
		d := &inv.Deps[i]
		if d.Cluster == cluster && d.Service == service && d.Kind == kind && d.Name == name {
			return d
		}
	}
	return nil
}

func TestOSRowsCompareDeclaredRunningLatest(t *testing.T) {
	inv := Build(input(t))
	talos := find(inv, "frank", "os", "talos", "talos")
	if talos == nil {
		t.Fatal("frank talos row missing")
	}
	if talos.Declared != "1.12.6" || talos.Running != "1.12.6" || talos.Latest != "1.14.5" || talos.Gap != "2 minor" || talos.Drift {
		t.Errorf("talos = %+v", talos)
	}
	if talos.Path != frankrepo.PathSession {
		t.Errorf("talos path = %s", talos.Path)
	}
	k8s := find(inv, "frank", "os", "kubernetes", "kubernetes")
	if k8s == nil || k8s.Running != "1.35.3" || k8s.Gap != "2 minor" {
		t.Errorf("k8s = %+v", k8s)
	}
}

func TestUnreachableClusterShowsUnknownNotMissing(t *testing.T) {
	inv := Build(input(t))
	hop := find(inv, "hop", "os", "talos", "talos")
	if hop == nil {
		t.Fatal("hop talos row must exist from the declaration even when Hop is unreachable")
	}
	if !hop.Unknown || hop.Running != "" || hop.Declared != "1.12.5" {
		t.Errorf("hop talos = %+v", hop)
	}
	if !inv.Unreachable["hop"] {
		t.Error("hop must be flagged unreachable")
	}
}

func TestOmniRow(t *testing.T) {
	inv := Build(input(t))
	o := find(inv, "omni", "omni", "omni", "omni")
	if o == nil || o.Declared != "v1.5.0" || o.Running != "v1.5.0" || o.Latest != "v1.13.1" || o.Path != frankrepo.PathOperatorRunbook || o.Gap != "8 minor" {
		t.Errorf("omni = %+v", o)
	}
}

func TestDeclaredRunningDriftIsFlagged(t *testing.T) {
	in := input(t)
	in.Decl.Frank.Talos = "1.13.4" // declared ahead: a step merged but not applied
	inv := Build(in)
	talos := find(inv, "frank", "os", "talos", "talos")
	if !talos.Drift || talos.Note == "" {
		t.Errorf("drift not flagged: %+v", talos)
	}
}

func TestAppImagesChartsVulnsAndPaths(t *testing.T) {
	inv := Build(input(t))
	img := find(inv, "frank", "litellm", "image", "ghcr.io/berriai/litellm")
	if img == nil {
		t.Fatalf("litellm image row missing: %+v", inv.Deps)
	}
	if img.Declared != "v1.80.0" || img.Running != "v1.80.0" || img.Latest != "v1.80.3" || img.Gap != "3 patch" {
		t.Errorf("litellm image = %+v", img)
	}
	if img.VulnCounts["CRITICAL"] != 1 || img.VulnCounts["HIGH"] != 2 || len(img.Vulns) != 3 {
		t.Errorf("vulns = %+v", img.VulnCounts)
	}
	// litellm is an Argo Rollouts app: always session, whatever the policy.
	if img.Path != frankrepo.PathSession {
		t.Errorf("rollouts app path = %s", img.Path)
	}
	chart := find(inv, "frank", "litellm", "chart", "litellm-helm")
	if chart == nil || chart.Declared != "0.1.700" || chart.Running != "0.1.699" || !chart.Drift {
		t.Errorf("chart = %+v", chart)
	}
	home := find(inv, "frank", "homepage", "image", "ghcr.io/gethomepage/homepage")
	if home == nil || home.Gap != "current" || home.Path != frankrepo.PathBatchApprove {
		// up to date → resolved as a minor (routine) update for display
		t.Errorf("homepage = %+v", home)
	}
	busy := find(inv, "frank", "litellm", "image", "docker.io/library/busybox")
	if busy == nil || busy.Latest != "" || busy.Gap != "" {
		t.Errorf("busybox = %+v", busy)
	}
}

func TestSessionPodsAreNotInventory(t *testing.T) {
	inv := Build(input(t))
	for _, d := range inv.Deps {
		if d.Service == "upgrade-sessions" || d.Name == "ghcr.io/derio-net/upgrade-session" {
			t.Errorf("session pod leaked into the inventory: %+v", d)
		}
	}
}

func TestGroupingIsStable(t *testing.T) {
	inv := Build(input(t))
	groups := inv.Grouped()
	if len(groups) != 3 || groups[0].Cluster != "frank" || groups[1].Cluster != "hop" || groups[2].Cluster != "omni" {
		t.Fatalf("groups = %+v", groups)
	}
	if groups[0].Services[0].Name != "homepage" {
		t.Errorf("services not sorted: %+v", groups[0].Services)
	}
	if ID("frank", "litellm", "image", "x") != "frank/litellm/image/x" {
		t.Error("Key")
	}
}
