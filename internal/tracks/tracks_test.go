package tracks

import (
	"testing"

	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
)

func matrix() frankrepo.Matrix {
	return frankrepo.Matrix{Talos: map[string][]string{
		"1.12": {"1.30", "1.31", "1.32", "1.33", "1.34", "1.35"},
		"1.13": {"1.31", "1.32", "1.33", "1.34", "1.35", "1.36"},
		"1.14": {"1.32", "1.33", "1.34", "1.35", "1.36", "1.37"},
	}}
}

var releases = Releases{
	Talos:      []string{"v1.12.6", "v1.13.0", "v1.13.4", "v1.14.5", "v1.15.0-beta.1"},
	Kubernetes: []string{"v1.35.3", "v1.36.0", "v1.36.2", "v1.37.2", "v1.38.0-rc.0"},
}

func kinds(steps []Step) string {
	s := ""
	for _, st := range steps {
		s += st.Kind + st.To + " "
	}
	return s
}

func TestFrankSequence(t *testing.T) {
	steps := Next("frank", frankrepo.ClusterVersions{Talos: "1.12.6", Kubernetes: "1.35.3"}, releases, matrix())
	want := "talos1.13.4 kubernetes1.36.2 talos1.14.5 kubernetes1.37.2 "
	if kinds(steps) != want {
		t.Fatalf("steps = %q, want %q", kinds(steps), want)
	}
	for _, s := range steps {
		if s.Kind == KindKubernetes && !s.OneWay {
			t.Error("kubernetes minors are one-way")
		}
		if s.Kind == KindTalos && s.Rollback != "omni-revert" {
			t.Errorf("frank talos rollback = %s", s.Rollback)
		}
	}
	if steps[0].ID != "frank-os-talos-1.13.4" || steps[0].Position != 1 || steps[3].Position != 4 {
		t.Errorf("ids/positions = %+v", steps)
	}
	// Each step pins the clients to the step's target.
	if steps[1].TalosClient != "1.13.4" || steps[1].KubectlClient != "1.36.2" {
		t.Errorf("client pins = %+v", steps[1])
	}
}

func TestHopUpgradesKubernetesFirstWhenOutsideTheWindow(t *testing.T) {
	m := matrix()
	m.Talos["1.13"] = []string{"1.35", "1.36"} // pretend 1.34 is out of 1.13's window
	steps := Next("hop", frankrepo.ClusterVersions{Talos: "1.12.5", Kubernetes: "1.34.1"}, Releases{
		Talos: releases.Talos, Kubernetes: append([]string{"v1.35.4"}, releases.Kubernetes...)}, m)
	// 1.12.5 → 1.12.6 is a patch inside the minor; the first MINOR step must
	// be Kubernetes, because 1.34 is outside Talos 1.13's window.
	want := "talos1.12.6 kubernetes1.35.4 talos1.13.4 kubernetes1.36.2 talos1.14.5 kubernetes1.37.2 "
	if kinds(steps) != want {
		t.Fatalf("steps = %q, want %q", kinds(steps), want)
	}
	if steps[0].Rollback != "talosctl-rollback" {
		t.Errorf("hop rollback = %s", steps[0].Rollback)
	}
	for i := 1; i < len(steps); i++ {
		if steps[i].Kind == KindKubernetes && steps[i-1].Kind == KindKubernetes {
			t.Error("never two Kubernetes minors in a row without the Talos step between (one minor at a time)")
		}
	}
}

func TestPatchStepsAndCurrent(t *testing.T) {
	steps := Next("frank", frankrepo.ClusterVersions{Talos: "1.14.4", Kubernetes: "1.37.2"}, releases, matrix())
	if kinds(steps) != "talos1.14.5 " || steps[0].OneWay {
		t.Fatalf("patch = %q", kinds(steps))
	}
	if s := Next("frank", frankrepo.ClusterVersions{Talos: "1.14.5", Kubernetes: "1.37.2"}, releases, matrix()); len(s) != 0 {
		t.Errorf("current = %q", kinds(s))
	}
	if s := Next("frank", frankrepo.ClusterVersions{}, releases, matrix()); len(s) != 0 {
		t.Error("undeclared versions produce no steps")
	}
}
