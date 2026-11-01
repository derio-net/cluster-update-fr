package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type workflow struct {
	Jobs map[string]struct {
		If    string `yaml:"if"`
		Steps []struct {
			Uses string         `yaml:"uses"`
			With map[string]any `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func readWorkflow(t *testing.T, name string) workflow {
	t.Helper()
	b, err := os.ReadFile("../../.github/workflows/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var w workflow
	if err := yaml.Unmarshal(b, &w); err != nil {
		t.Fatal(err)
	}
	return w
}

var fullSHA = regexp.MustCompile(`@[0-9a-f]{40}$`)

// Supply chain (c1s-r7): actions by full commit SHA, bases by digest, and
// the release attests provenance + SBOM and publishes the pushed digest.
func TestActionsAndBasesArePinned(t *testing.T) {
	for _, name := range []string{"ci.yml", "release.yml"} {
		for job, j := range readWorkflow(t, name).Jobs {
			for _, s := range j.Steps {
				if s.Uses != "" && !fullSHA.MatchString(s.Uses) {
					t.Errorf("%s/%s: %q is not pinned by full commit SHA", name, job, s.Uses)
				}
			}
		}
	}
	b, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(string(b), "\n") {
		if (strings.HasPrefix(l, "FROM ") || strings.HasPrefix(l, "# syntax=")) && !regexp.MustCompile(`@sha256:[0-9a-f]{64}`).MatchString(l) {
			t.Errorf("Dockerfile line %q is not pinned by digest", l)
		}
	}
	rel := readWorkflow(t, "release.yml")
	attested, digestNoted := false, false
	for _, j := range rel.Jobs {
		for _, s := range j.Steps {
			if strings.HasPrefix(s.Uses, "docker/build-push-action@") {
				attested = s.With["provenance"] == true && s.With["sbom"] == true
			}
		}
	}
	raw, _ := os.ReadFile("../../.github/workflows/release.yml")
	digestNoted = strings.Contains(string(raw), "steps.build.outputs.digest") && strings.Contains(string(raw), "gh release")
	if !attested {
		t.Error("build-push-action must set provenance: true and sbom: true")
	}
	if !digestNoted {
		t.Error("the release must write the pushed image digest into the release notes")
	}
}

// Gitea Actions reads .github/workflows/ as well: the GHCR release must be
// GitHub-only, or the mirror would try to publish too (c1c-r17).
func TestReleaseRunsOnlyOnGitHub(t *testing.T) {
	w := readWorkflow(t, "release.yml")
	if len(w.Jobs) == 0 {
		t.Fatal("release.yml has no jobs")
	}
	for name, j := range w.Jobs {
		if j.If != "github.server_url == 'https://github.com'" {
			t.Errorf("release job %s is not guarded to github.com (if: %q)", name, j.If)
		}
	}
}
