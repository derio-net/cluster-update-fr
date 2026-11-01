package app

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/cidiag"
	"github.com/derio-net/cluster-update-fr/internal/engine"
	"github.com/derio-net/cluster-update-fr/internal/forge"
	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
)

const ciWorkflow = ".github/workflows/ci.yml"

// ciSourcePolicy serves the fixture policy with its ci_source line replaced.
type ciSourcePolicy struct {
	frankrepo.FSSource
	line string
}

func (s ciSourcePolicy) Read(ctx context.Context, path string) ([]byte, error) {
	b, err := s.FSSource.Read(ctx, path)
	if err != nil || path != frankrepo.PolicyPath {
		return b, err
	}
	return []byte(strings.Replace(string(b), "ci_source: gitea-statuses", s.line, 1)), nil
}

func checksApp(t *testing.T, now *time.Time, line string) (*App, *fakeGitHub) {
	t.Helper()
	a, gh, _, _ := newApp(t, now, false)
	a.Repo = ciSourcePolicy{frankrepo.FSSource{Root: "../../testdata/frank"}, line}
	// The bridged Gitea status is green, so only the check-runs decide.
	return a, gh
}

func check(id int64, name, sha, slug, conclusion string, done time.Time) forge.CheckRun {
	r := forge.CheckRun{ID: id, Name: name, HeadSHA: sha, Status: "completed", Conclusion: conclusion, CompletedAt: done}
	r.App.Slug = slug
	r.CheckSuite.ID = 77
	return r
}

func ciRun(id int64, path, sha, conclusion string, updated time.Time) forge.WorkflowRun {
	w := forge.WorkflowRun{ID: id, Name: "ci", Path: path, HeadSHA: sha, Event: "pull_request", Status: "completed", Conclusion: conclusion,
		CheckSuiteID: 77, UpdatedAt: updated}
	w.Repository.FullName, w.HeadRepository.FullName = "derio-net/frank", "derio-net/frank"
	return w
}

func item(v View, id string) (engine.Item, bool) {
	for _, it := range v.Items {
		if it.ID == id {
			return it, true
		}
	}
	return engine.Item{}, false
}

// p4-r2: frank's CI is GitHub Actions check-runs. A passing required
// check-run from the declared workflow's run on the head merges (approved
// on that SHA); the bridged Gitea status alone does not.
func TestGitHubChecksGateTheMerge(t *testing.T) {
	now := t0
	a, gh := checksApp(t, &now, "ci_source: github-checks")
	a.Cycle(context.Background())
	if mergedPR(gh, 7) || len(gh.approved) != 0 {
		t.Fatal("merged with no check-run, on the Gitea status alone")
	}

	gh.checkRuns = map[string][]forge.CheckRun{"h7": {check(1, "go", "h7", cidiag.ActionsApp, "success", t0)}}
	gh.wfRuns = map[string][]forge.WorkflowRun{"h7": {ciRun(4242, ciWorkflow, "h7", "success", t0)}}
	a.Cycle(context.Background())
	if !mergedPR(gh, 7) || len(gh.approved) != 1 || gh.approved[0] != "h7" {
		t.Fatalf("merged=%v approved=%v", gh.merged, gh.approved)
	}
}

func TestGitHubChecksThatDoNotCount(t *testing.T) {
	ok := []forge.WorkflowRun{ciRun(4242, ciWorkflow, "h7", "success", t0)}
	fork := ciRun(4242, ciWorkflow, "h7", "success", t0)
	fork.HeadRepository.FullName = "mallory/frank"
	for name, c := range map[string]struct {
		runs []forge.CheckRun
		wf   []forge.WorkflowRun
	}{
		"another app":          {[]forge.CheckRun{check(1, "go", "h7", "evil-ci", "success", t0)}, ok},
		"an older SHA":         {[]forge.CheckRun{check(1, "go", "h6", cidiag.ActionsApp, "success", t0)}, ok},
		"neutral":              {[]forge.CheckRun{check(1, "go", "h7", cidiag.ActionsApp, "neutral", t0)}, ok},
		"skipped":              {[]forge.CheckRun{check(1, "go", "h7", cidiag.ActionsApp, "skipped", t0)}, ok},
		"another check":        {[]forge.CheckRun{check(1, "lint", "h7", cidiag.ActionsApp, "success", t0)}, ok},
		"no workflow run":      {[]forge.CheckRun{check(1, "go", "h7", cidiag.ActionsApp, "success", t0)}, nil},
		"another workflow":     {[]forge.CheckRun{check(1, "go", "h7", cidiag.ActionsApp, "success", t0)}, []forge.WorkflowRun{ciRun(4242, ".github/workflows/evil.yml", "h7", "success", t0)}},
		"run on another SHA":   {[]forge.CheckRun{check(1, "go", "h7", cidiag.ActionsApp, "success", t0)}, []forge.WorkflowRun{ciRun(4242, ciWorkflow, "h6", "success", t0)}},
		"fork run":             {[]forge.CheckRun{check(1, "go", "h7", cidiag.ActionsApp, "success", t0)}, []forge.WorkflowRun{fork}},
		"run concluded failed": {[]forge.CheckRun{check(1, "go", "h7", cidiag.ActionsApp, "success", t0)}, []forge.WorkflowRun{ciRun(4242, ciWorkflow, "h7", "failure", t0)}},
	} {
		now := t0
		a, gh := checksApp(t, &now, "ci_source: github-checks")
		gh.checkRuns = map[string][]forge.CheckRun{"h7": c.runs}
		gh.wfRuns = map[string][]forge.WorkflowRun{"h7": c.wf}
		v := a.Cycle(context.Background())
		if mergedPR(gh, 7) || len(gh.approved) != 0 {
			t.Errorf("%s: merged/approved", name)
		}
		if it, ok := item(v, "pr-7"); !ok || it.CI == cidiag.Passed {
			t.Errorf("%s: CI %v", name, it.CI)
		}
	}
}

// Unset/unknown ci_source, github-checks with no required checks, or the
// old bare-name shape: nothing passes, nothing is approved.
func TestUnknownCISourceMergesNothing(t *testing.T) {
	green := map[string][]forge.CheckRun{"h7": {check(1, "go", "h7", cidiag.ActionsApp, "success", t0)}}
	wf := map[string][]forge.WorkflowRun{"h7": {ciRun(4242, ciWorkflow, "h7", "success", t0)}}
	for _, line := range []string{"", "ci_source: github",
		"ci_source: github-checks\nrequired_ci_checks: []\nx_old_checks:",
		"ci_source: github-checks\nrequired_ci_checks: [go]\nx_old_checks:",
		"ci_source: github-checks\nrequired_ci_checks: [{workflow: " + ciWorkflow + ", name: go, app: x}]\nx_old_checks:"} {
		now := t0
		a, gh := checksApp(t, &now, line)
		gh.checkRuns, gh.wfRuns = green, wf
		v := a.Cycle(context.Background())
		if mergedPR(gh, 7) || len(gh.approved) != 0 {
			t.Errorf("%q: merged/approved", line)
		}
		if it, ok := item(v, "pr-7"); !ok || it.CI == cidiag.Passed {
			t.Errorf("%q: CI %v (%s)", line, it.CI, it.CIDetail)
		}
	}
}

// A head that changes anything under .github/ ran CI it wrote itself: its
// green checks never pass (the base branch's workflow is not what ran).
func TestCIThatThePRRewroteNeverPasses(t *testing.T) {
	now := t0
	a, gh := checksApp(t, &now, "ci_source: github-checks")
	gh.checkRuns = map[string][]forge.CheckRun{"h7": {check(1, "go", "h7", cidiag.ActionsApp, "success", t0)}}
	gh.wfRuns = map[string][]forge.WorkflowRun{"h7": {ciRun(4242, ciWorkflow, "h7", "success", t0)}}
	pol := frankrepo.Policy{CISource: cidiag.SourceGitHubChecks, RequiredCIChecks: []frankrepo.RequiredCheck{{Workflow: ciWorkflow, Name: "go"}}}
	pr := gh.prs[0]
	if v, why := a.evaluateCI(context.Background(), pr, a.ciRequirement(pol), t0, t0, newCICache()); v != cidiag.Passed {
		t.Fatalf("precondition: %s (%s)", v, why)
	}
	gh.files = map[int][]string{7: {"apps/homepage/manifests/deployment.yaml", ciWorkflow}}
	if v, why := a.evaluateCI(context.Background(), pr, a.ciRequirement(pol), t0, t0, newCICache()); v == cidiag.Passed || !strings.Contains(why, ".github/") {
		t.Fatalf("CI rewritten by the PR passed: %s (%s)", v, why)
	}
}

// Ran and failed: ONE automatic rerun-failed-jobs; failing again after it
// marks the item failed — CI, with no second rerun.
func TestGitHubChecksRerunOnceThenFailed(t *testing.T) {
	now := t0
	a, gh := checksApp(t, &now, "ci_source: github-checks")
	gh.checkRuns = map[string][]forge.CheckRun{"h7": {check(1, "go", "h7", cidiag.ActionsApp, "failure", t0.Add(-time.Hour))}}
	gh.wfRuns = map[string][]forge.WorkflowRun{"h7": {ciRun(4242, ciWorkflow, "h7", "failure", t0.Add(-time.Hour))}}
	a.Cycle(context.Background())
	if len(gh.reruns) != 1 || gh.reruns[0] != 4242 {
		t.Fatalf("reruns = %v, want one rerun of 4242", gh.reruns)
	}

	// The rerun (attempt 2, same run) fails too: a newer check-run, after the retry.
	now = t0.Add(10 * time.Minute)
	gh.checkRuns["h7"] = append(gh.checkRuns["h7"], check(2, "go", "h7", cidiag.ActionsApp, "failure", t0.Add(5*time.Minute)))
	attempt2 := ciRun(4242, ciWorkflow, "h7", "failure", t0.Add(5*time.Minute))
	attempt2.RunAttempt = 2
	gh.wfRuns["h7"] = []forge.WorkflowRun{attempt2}
	a.Cycle(context.Background())
	now = t0.Add(20 * time.Minute)
	v := a.Cycle(context.Background())
	if len(gh.reruns) != 1 {
		t.Fatalf("reruns = %v: at most one retry", gh.reruns)
	}
	if it, ok := item(v, "pr-7"); !ok || it.State != engine.StateFailedCI {
		t.Fatalf("state = %s (%s)", it.State, it.CIDetail)
	}
	if mergedPR(gh, 7) || len(gh.approved) != 0 {
		t.Fatal("merged a PR whose CI failed")
	}
	if err := a.RetryCI(context.Background(), "pr-7", "derio"); err == nil {
		t.Error("the Retry button must refuse after the one retry")
	}
}
