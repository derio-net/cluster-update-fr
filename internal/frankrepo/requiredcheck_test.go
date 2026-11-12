package frankrepo

import (
	"context"
	"testing"

	"gopkg.in/yaml.v3"
)

// p4-r2b: required_ci_checks are {workflow, name} pairs; any other shape
// decodes as Invalid (never passes) without failing the whole policy.
func TestRequiredCheckShape(t *testing.T) {
	src := `required_ci_checks:
  - workflow: .github/workflows/ci.yml
    name: go
  - go
  - {workflow: .github/workflows/ci.yml}
  - {workflow: .github/workflows/ci.yml, name: lint, app: other}
`
	var p Policy
	if err := yaml.Unmarshal([]byte(src), &p); err != nil {
		t.Fatal(err)
	}
	want := []RequiredCheck{{Workflow: ".github/workflows/ci.yml", Name: "go"}, {Invalid: true}, {Invalid: true}, {Invalid: true}}
	if len(p.RequiredCIChecks) != len(want) {
		t.Fatalf("got %+v", p.RequiredCIChecks)
	}
	for i, w := range want {
		if g := p.RequiredCIChecks[i]; g.Invalid != w.Invalid || (!w.Invalid && g != w) {
			t.Errorf("entry %d = %+v, want %+v", i, g, w)
		}
	}
	d, err := Load(context.Background(), fixture())
	if err != nil || d.Policy.CISource != "gitea-statuses" || len(d.Policy.RequiredCIChecks) != 1 || d.Policy.RequiredCIChecks[0].Invalid {
		t.Fatalf("fixture policy: %v %+v", err, d.Policy)
	}
}
