package session

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/derio-net/cluster-update-fr/internal/kube"
)

var updateGolden = flag.Bool("update-podspec", false, "rewrite testdata/podspec/*.json from the current podSpec")

// goldenLauncher is representative production config (images pinned by
// digest, the in-cluster console URL, the default tailnet settings).
func goldenLauncher() *Launcher {
	return &Launcher{Namespace: "upgrade-sessions",
		Image:          "ghcr.io/derio-net/upgrade-session:1.0.0@sha256:" + hex64('1'),
		ConsoleURL:     "http://cluster-update-fr.cluster-update.svc:8081",
		TailscaleImage: "tailscale/tailscale:v1.82.5@sha256:" + hex64('2')}
}

func hex64(c byte) string { return string(bytes.Repeat([]byte{c}, 64)) }

// goldenRequest is one representative step per type.
func goldenRequest(typ string) Request {
	r := Request{UpgradeID: "golden-" + typ, Type: typ, Cluster: "frank", TalosVersion: "1.13.4", KubectlVersion: "1.36.2"}
	switch typ {
	case TypeChartMajor, TypeStateful, TypeRollouts:
		r.App = map[string]string{TypeChartMajor: "cilium", TypeStateful: "paperclip-db", TypeRollouts: "litellm"}[typ]
		r.TalosVersion, r.KubectlVersion = "1.12.6", "1.35.3"
	case TypeHopOS:
		r.Cluster = "hop"
	}
	return r
}

// renderPodSpec renders exactly what Start creates for req (credential KEYS
// only — the pod spec never carries a credential value).
func renderPodSpec(l *Launcher, req Request) ([]byte, error) {
	data := map[string]string{StepTokenKey: ""}
	for _, k := range typeCreds[req.Type] {
		data[k] = ""
	}
	labels := map[string]string{LabelRunID: req.UpgradeID, LabelType: req.Type, kube.ManagedByLabel: kube.ManagedBy}
	b, err := json.MarshalIndent(l.podSpec(req, PodName(req.UpgradeID), labels, data), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// p5-r1 support: the console's REAL session pod spec per type, as golden
// files frank copies byte-for-byte (like testdata/scrub/cases.json) to test
// its admission and network policies against. Regenerate with
//
//	go test ./internal/session -run TestPodSpecGolden -update-podspec
func TestPodSpecGolden(t *testing.T) {
	l := goldenLauncher()
	for _, typ := range Types {
		t.Run(typ, func(t *testing.T) {
			got, err := renderPodSpec(l, goldenRequest(typ))
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join("..", "..", "testdata", "podspec", typ+".json")
			if *updateGolden {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("%v (regenerate with -update-podspec)", err)
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%s differs from the console's pod spec — regenerate with -update-podspec and hand frank the new file:\n%s", path, got)
			}
		})
	}
}

// The golden files carry the contract frank tests: no command, the image
// pinned by digest, and (hop-os) the sidecar.
func TestPodSpecGoldenContract(t *testing.T) {
	for _, typ := range Types {
		b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "podspec", typ+".json"))
		if err != nil {
			t.Fatal(err)
		}
		var pod struct {
			Spec struct {
				Containers     []map[string]any `json:"containers"`
				InitContainers []map[string]any `json:"initContainers"`
			} `json:"spec"`
		}
		if err := json.Unmarshal(b, &pod); err != nil {
			t.Fatal(err)
		}
		for _, c := range append(pod.Spec.Containers, pod.Spec.InitContainers...) {
			if _, ok := c["command"]; ok {
				t.Errorf("%s: container %v sets command:", typ, c["name"])
			}
			if !digestPinned.MatchString(c["image"].(string)) {
				t.Errorf("%s: container %v image not digest-pinned", typ, c["name"])
			}
		}
		if (len(pod.Spec.InitContainers) == 1) != (typ == TypeHopOS) {
			t.Errorf("%s: init containers %d", typ, len(pod.Spec.InitContainers))
		}
	}
}
