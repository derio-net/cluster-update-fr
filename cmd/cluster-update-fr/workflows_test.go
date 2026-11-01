package main

import (
	"os"
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
