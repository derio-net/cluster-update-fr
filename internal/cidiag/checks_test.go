package cidiag

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/forge"
)

var c0 = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)

const (
	ciYML  = ".github/workflows/ci.yml"
	repoFR = "derio-net/frank"
)

func wr(id int64, path, sha, event, status, conclusion string, suite int64) forge.WorkflowRun {
	w := forge.WorkflowRun{ID: id, Name: path, Path: path, HeadSHA: sha, Event: event, Status: status, Conclusion: conclusion, CheckSuiteID: suite, UpdatedAt: c0}
	w.Repository.FullName, w.HeadRepository.FullName = repoFR, repoFR
	return w
}

func cr(id int64, name, sha string, suite int64, conclusion string, done time.Time) forge.CheckRun {
	r := forge.CheckRun{ID: id, Name: name, HeadSHA: sha, Status: "completed", Conclusion: conclusion, CompletedAt: done}
	r.App.Slug = ActionsApp
	r.CheckSuite.ID = suite
	return r
}

func checksReq() Requirement {
	return Requirement{Source: SourceGitHubChecks, Checks: []CheckRef{{Workflow: ciYML, Name: "go"}, {Workflow: ciYML, Name: "lint"}}}
}

func ev(w []forge.WorkflowRun, c []forge.CheckRun) Evidence {
	return Evidence{SHA: "head", Repo: repoFR, Workflows: w, CheckRuns: c}
}

func TestEvaluateChecks(t *testing.T) {
	okRun := wr(10, ciYML, "head", "pull_request", "completed", "success", 100)
	goOK := cr(1, "go", "head", 100, "success", c0)
	lintOK := cr(2, "lint", "head", 100, "success", c0)
	soon, late := c0.Add(time.Minute), c0.Add(time.Hour)
	fork := okRun
	fork.HeadRepository.FullName = "mallory/frank"
	target := okRun
	target.Event = "pull_request_target"
	chained := okRun
	chained.Event = "workflow_run"
	other := wr(11, ".github/workflows/other.yml", "head", "pull_request", "completed", "success", 101)
	inProgress := okRun
	inProgress.Status, inProgress.Conclusion = "in_progress", ""
	runFailed := okRun
	runFailed.Conclusion = "failure"
	foreignApp := lintOK
	foreignApp.App.Slug = "evil"
	cases := []struct {
		name string
		ev   Evidence
		now  time.Time
		req  Requirement
		want Verdict
	}{
		{"required checks in the declared workflow's run", ev([]forge.WorkflowRun{okRun}, []forge.CheckRun{goOK, lintOK}), soon, checksReq(), Passed},
		{"same-named check from another workflow", ev([]forge.WorkflowRun{okRun, other}, []forge.CheckRun{goOK, cr(3, "lint", "head", 101, "success", c0)}), soon, checksReq(), Missing},
		{"check-run with no workflow run", ev([]forge.WorkflowRun{okRun}, []forge.CheckRun{goOK, cr(3, "lint", "head", 999, "success", c0)}), soon, checksReq(), Missing},
		{"check-run from another app", ev([]forge.WorkflowRun{okRun}, []forge.CheckRun{goOK, foreignApp}), soon, checksReq(), Missing},
		{"workflow run on a different SHA", ev([]forge.WorkflowRun{wr(10, ciYML, "old", "pull_request", "completed", "success", 100)}, []forge.CheckRun{goOK, lintOK}), soon, checksReq(), Pending},
		{"different SHA past the timeout", ev([]forge.WorkflowRun{wr(10, ciYML, "old", "pull_request", "completed", "success", 100)}, []forge.CheckRun{goOK, lintOK}), late, checksReq(), Missing},
		{"check-run on an older SHA", ev([]forge.WorkflowRun{okRun}, []forge.CheckRun{goOK, cr(2, "lint", "old", 100, "success", c0)}), soon, checksReq(), Missing},
		{"fork run", ev([]forge.WorkflowRun{fork}, []forge.CheckRun{goOK, lintOK}), soon, checksReq(), Pending},
		{"pull_request_target run", ev([]forge.WorkflowRun{target}, []forge.CheckRun{goOK, lintOK}), soon, checksReq(), Pending},
		{"workflow_run-chained run", ev([]forge.WorkflowRun{chained}, []forge.CheckRun{goOK, lintOK}), soon, checksReq(), Pending},
		{"run still in progress", ev([]forge.WorkflowRun{inProgress}, []forge.CheckRun{goOK, lintOK}), soon, checksReq(), Pending},
		{"run concluded failure", ev([]forge.WorkflowRun{runFailed}, []forge.CheckRun{goOK, lintOK}), soon, checksReq(), Failed},
		{"neutral is not success", ev([]forge.WorkflowRun{okRun}, []forge.CheckRun{goOK, cr(2, "lint", "head", 100, "neutral", c0)}), soon, checksReq(), Missing},
		{"skipped is not success", ev([]forge.WorkflowRun{okRun}, []forge.CheckRun{goOK, cr(2, "lint", "head", 100, "skipped", c0)}), soon, checksReq(), Missing},
		{"check failure", ev([]forge.WorkflowRun{okRun}, []forge.CheckRun{goOK, cr(2, "lint", "head", 100, "failure", c0)}), soon, checksReq(), Failed},
		// Rerun attempt: the newer check-run in the SAME run's suite wins.
		{"rerun attempt succeeded", ev([]forge.WorkflowRun{okRun}, []forge.CheckRun{goOK, cr(2, "lint", "head", 100, "failure", c0), cr(7, "lint", "head", 100, "success", c0)}), soon, checksReq(), Passed},
		// Never the highest check-run id across runs.
		{"newer same-named success in another run", ev([]forge.WorkflowRun{okRun, other}, []forge.CheckRun{goOK, cr(2, "lint", "head", 100, "failure", c0), cr(50, "lint", "head", 101, "success", c0)}), soon, checksReq(), Failed},
		{"no required checks", ev([]forge.WorkflowRun{okRun}, []forge.CheckRun{goOK, lintOK}), late, Requirement{Source: SourceGitHubChecks}, Pending},
		{"old bare-name shape", ev([]forge.WorkflowRun{okRun}, []forge.CheckRun{goOK, lintOK}), late, Requirement{Source: SourceGitHubChecks, Checks: []CheckRef{{Name: "go", Invalid: true}}}, Pending},
		{"workflow outside .github/workflows", ev([]forge.WorkflowRun{okRun}, []forge.CheckRun{goOK}), late, Requirement{Source: SourceGitHubChecks, Checks: []CheckRef{{Workflow: "ci.yml", Name: "go"}}}, Pending},
		{"workflow path with ..", ev([]forge.WorkflowRun{okRun}, []forge.CheckRun{goOK}), late, Requirement{Source: SourceGitHubChecks, Checks: []CheckRef{{Workflow: ".github/workflows/../ci.yml", Name: "go"}}}, Pending},
	}
	for _, c := range cases {
		if got, why := EvaluateChecks(c.ev, c0, c.now, 30*time.Minute, c.req); got != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, got, why, c.want)
		}
	}
}

// After the one retry the failure it acted on is not a new failure; a
// success from a job the retry did not re-run still counts; a newer failure
// fails.
func TestEvaluateChecksAfterARetry(t *testing.T) {
	req := checksReq()
	req.Since = c0.Add(10 * time.Minute)
	run := wr(10, ciYML, "head", "pull_request", "completed", "failure", 100)
	goOK := cr(1, "go", "head", 100, "success", c0)
	oldFail := cr(2, "lint", "head", 100, "failure", c0.Add(5*time.Minute))
	if v, why := EvaluateChecks(ev([]forge.WorkflowRun{run}, []forge.CheckRun{goOK, oldFail}), c0, c0.Add(11*time.Minute), time.Hour, req); v != Pending {
		t.Errorf("the failure the retry acted on still counts: %s (%s)", v, why)
	}
	rerun := run
	rerun.RunAttempt, rerun.Conclusion, rerun.UpdatedAt = 2, "success", c0.Add(15*time.Minute)
	ok := cr(3, "lint", "head", 100, "success", c0.Add(15*time.Minute))
	if v, why := EvaluateChecks(ev([]forge.WorkflowRun{rerun}, []forge.CheckRun{goOK, oldFail, ok}), c0, c0.Add(16*time.Minute), time.Hour, req); v != Passed {
		t.Errorf("re-run success: %s (%s)", v, why)
	}
	fail := cr(3, "lint", "head", 100, "failure", c0.Add(15*time.Minute))
	rerun.Conclusion = "failure"
	if v, _ := EvaluateChecks(ev([]forge.WorkflowRun{rerun}, []forge.CheckRun{goOK, oldFail, fail}), c0, c0.Add(16*time.Minute), time.Hour, req); v != Failed {
		t.Errorf("a failure after the retry must fail: %s", v)
	}
}

func TestEvaluateChecksWaitsForRenovateReleaseAge(t *testing.T) {
	e := ev([]forge.WorkflowRun{wr(10, ciYML, "head", "push", "completed", "success", 100)},
		[]forge.CheckRun{cr(1, "go", "head", 100, "success", c0), cr(2, "lint", "head", 100, "success", c0)})
	e.Statuses = []forge.Status{{Context: "renovate/stability-days", State: "pending", CreatedAt: c0}}
	if v, _ := EvaluateChecks(e, c0, c0, time.Hour, checksReq()); v != Waiting {
		t.Errorf("verdict %s, want waiting", v)
	}
}

type fakeChecks struct {
	runs      []forge.CheckRun
	wf        []forge.WorkflowRun
	mergeable *bool
	reruns    []int64
	body      string
	err       error
}

func (f *fakeChecks) CheckRuns(context.Context, string) ([]forge.CheckRun, error) {
	return f.runs, f.err
}
func (f *fakeChecks) WorkflowRuns(context.Context, string) ([]forge.WorkflowRun, error) {
	return f.wf, f.err
}
func (f *fakeChecks) RerunFailedJobs(_ context.Context, id int64) error {
	f.reruns = append(f.reruns, id)
	return nil
}
func (f *fakeChecks) PR(_ context.Context, n int) (forge.PR, error) {
	return forge.PR{Number: n, Mergeable: f.mergeable}, nil
}
func (f *fakeChecks) UpdatePRBody(_ context.Context, _ int, body string) error {
	f.body = body
	return nil
}

const rebaseBody = "body\n\n - [ ] <!-- rebase-check -->If you want to rebase/retry this PR, check this box"

func TestDiagnoseAndRecoverChecks(t *testing.T) {
	ctx := context.Background()
	pr := forge.PR{Number: 7, HeadSHA: "head", Body: rebaseBody}
	no := false
	goOK := cr(1, "go", "head", 100, "success", c0)
	lintFail := cr(2, "lint", "head", 100, "failure", c0)
	diag := func(f *fakeChecks) Diagnosis { return DiagnoseChecks(ctx, f, pr, checksReq(), repoFR) }

	// Never ran, conflicting: a run on another SHA or of a fork does not count.
	fork := wr(6, ciYML, "head", "pull_request", "completed", "success", 106)
	fork.HeadRepository.FullName = "mallory/frank"
	f := &fakeChecks{mergeable: &no, wf: []forge.WorkflowRun{wr(5, ciYML, "older", "push", "completed", "success", 105), fork}}
	d := diag(f)
	if d.Cause != NeverRan || !d.Conflicting {
		t.Fatalf("never ran: %+v", d)
	}
	if a, err := RecoverChecks(ctx, f, pr, d); err != nil || a.Kind != ActionRebase || !strings.Contains(f.body, "[x]") {
		t.Fatalf("never ran recover: %+v %v %q", a, err, f.body)
	}

	// Running.
	f = &fakeChecks{wf: []forge.WorkflowRun{wr(40, ciYML, "head", "pull_request", "in_progress", "", 100)}, runs: []forge.CheckRun{goOK}}
	if d := diag(f); d.Cause != Running {
		t.Fatalf("running: %+v", d)
	}

	// Ran and failed: the declared workflow's run is re-run, not another one.
	f = &fakeChecks{wf: []forge.WorkflowRun{wr(41, ".github/workflows/other.yml", "head", "pull_request", "completed", "failure", 101),
		wr(42, ciYML, "head", "pull_request", "completed", "failure", 100)}, runs: []forge.CheckRun{goOK, lintFail}}
	d = diag(f)
	if d.Cause != RanFailed || d.RunID != 42 {
		t.Fatalf("ran-failed: %+v", d)
	}
	if a, err := RecoverChecks(ctx, f, pr, d); err != nil || a.Kind != ActionGitHubRerun || len(f.reruns) != 1 || f.reruns[0] != 42 {
		t.Fatalf("rerun: %+v %v %v", a, err, f.reruns)
	}

	// Ran, result missing: the lint check-run came from another workflow.
	f = &fakeChecks{wf: []forge.WorkflowRun{wr(43, ciYML, "head", "pull_request", "completed", "success", 100),
		wr(44, ".github/workflows/other.yml", "head", "pull_request", "completed", "success", 101)}, runs: []forge.CheckRun{goOK, cr(3, "lint", "head", 101, "success", c0)}}
	d = diag(f)
	if d.Cause != ResultMissing || !strings.Contains(d.Detail, "lint") {
		t.Fatalf("result missing: %+v", d)
	}
	if _, err := RecoverChecks(ctx, f, pr, d); !errors.Is(err, ErrNeedsOperator) || len(f.reruns) != 0 {
		t.Fatalf("result missing must need the operator: %v %v", err, f.reruns)
	}

	// Malformed policy / unreadable: no recovery.
	if d := DiagnoseChecks(ctx, &fakeChecks{}, pr, Requirement{Source: SourceGitHubChecks, Checks: []CheckRef{{Name: "go", Invalid: true}}}, repoFR); d.Cause != Unknown {
		t.Fatalf("malformed checks: %+v", d)
	}
	if d := diag(&fakeChecks{err: errors.New("502")}); d.Cause != Unknown {
		t.Fatalf("unreadable: %+v", d)
	}
}

func TestKnownSource(t *testing.T) {
	for s, want := range map[string]bool{"github-checks": true, "gitea-statuses": true, "": false, "github": false, "GitHub-Checks": false} {
		if KnownSource(s) != want {
			t.Errorf("KnownSource(%q) = %v", s, !want)
		}
	}
}
