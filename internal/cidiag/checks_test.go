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

func cr(id int64, name, sha, slug, status, conclusion string, done time.Time) forge.CheckRun {
	r := forge.CheckRun{ID: id, Name: name, HeadSHA: sha, Status: status, Conclusion: conclusion, CompletedAt: done}
	r.App.Slug = slug
	r.CheckSuite.ID = 900 + id
	return r
}

func checksReq() Requirement {
	return Requirement{Source: SourceGitHubChecks, Checks: []string{"go", "lint"}}
}

func evalChecks(runs []forge.CheckRun, now time.Time, req Requirement) (Verdict, string) {
	return EvaluateChecks(runs, nil, "head", c0, now, 30*time.Minute, req)
}

func TestEvaluateChecks(t *testing.T) {
	ok := func(id int64, name string) forge.CheckRun {
		return cr(id, name, "head", ActionsApp, "completed", "success", c0)
	}
	soon, late := c0.Add(time.Minute), c0.Add(time.Hour)
	cases := []struct {
		name string
		runs []forge.CheckRun
		now  time.Time
		req  Requirement
		want Verdict
	}{
		{"all required succeeded", []forge.CheckRun{ok(1, "go"), ok(2, "lint")}, soon, checksReq(), Passed},
		{"one required absent", []forge.CheckRun{ok(1, "go")}, soon, checksReq(), Pending},
		{"absent past the timeout", []forge.CheckRun{ok(1, "go")}, late, checksReq(), Missing},
		{"from a different app", []forge.CheckRun{ok(1, "go"), cr(2, "lint", "head", "evil-ci", "completed", "success", c0)}, late, checksReq(), Missing},
		{"on an older SHA", []forge.CheckRun{ok(1, "go"), cr(2, "lint", "old", ActionsApp, "completed", "success", c0)}, late, checksReq(), Missing},
		{"neutral is not success", []forge.CheckRun{ok(1, "go"), cr(2, "lint", "head", ActionsApp, "completed", "neutral", c0)}, soon, checksReq(), Missing},
		{"skipped is not success", []forge.CheckRun{ok(1, "go"), cr(2, "lint", "head", ActionsApp, "completed", "skipped", c0)}, soon, checksReq(), Missing},
		{"failure", []forge.CheckRun{ok(1, "go"), cr(2, "lint", "head", ActionsApp, "completed", "failure", c0)}, soon, checksReq(), Failed},
		{"cancelled", []forge.CheckRun{ok(1, "go"), cr(2, "lint", "head", ActionsApp, "completed", "cancelled", c0)}, soon, checksReq(), Failed},
		{"queued", []forge.CheckRun{ok(1, "go"), cr(2, "lint", "head", ActionsApp, "queued", "", time.Time{})}, soon, checksReq(), Pending},
		{"queued past the timeout", []forge.CheckRun{ok(1, "go"), cr(2, "lint", "head", ActionsApp, "queued", "", time.Time{})}, late, checksReq(), Missing},
		{"newest attempt wins", []forge.CheckRun{ok(1, "go"), cr(2, "lint", "head", ActionsApp, "completed", "failure", c0), ok(3, "lint")}, soon, checksReq(), Passed},
		{"no required checks declared", []forge.CheckRun{ok(1, "go")}, late, Requirement{Source: SourceGitHubChecks}, Pending},
		{"blank required check names", []forge.CheckRun{ok(1, "go")}, late, Requirement{Source: SourceGitHubChecks, Checks: []string{" "}}, Pending},
	}
	for _, c := range cases {
		if got, why := evalChecks(c.runs, c.now, c.req); got != c.want {
			t.Errorf("%s: %s (%s), want %s", c.name, got, why, c.want)
		}
	}
}

// After the one retry the failure it acted on is ignored; a success from a
// job the retry did not re-run still counts; a newer failure fails.
func TestEvaluateChecksAfterARetry(t *testing.T) {
	req := checksReq()
	req.Since = c0.Add(10 * time.Minute)
	goOK := cr(1, "go", "head", ActionsApp, "completed", "success", c0)
	oldFail := cr(2, "lint", "head", ActionsApp, "completed", "failure", c0.Add(5*time.Minute))
	if v, why := evalChecks([]forge.CheckRun{goOK, oldFail}, c0.Add(11*time.Minute), req); v != Pending {
		t.Errorf("the failure the retry acted on still counts: %s (%s)", v, why)
	}
	rerunOK := cr(3, "lint", "head", ActionsApp, "completed", "success", c0.Add(15*time.Minute))
	if v, why := evalChecks([]forge.CheckRun{goOK, oldFail, rerunOK}, c0.Add(16*time.Minute), req); v != Passed {
		t.Errorf("re-run success: %s (%s)", v, why)
	}
	rerunFail := cr(3, "lint", "head", ActionsApp, "completed", "failure", c0.Add(15*time.Minute))
	if v, _ := evalChecks([]forge.CheckRun{goOK, oldFail, rerunFail}, c0.Add(16*time.Minute), req); v != Failed {
		t.Errorf("a failure after the retry must fail: %s", v)
	}
}

func TestEvaluateChecksWaitsForRenovateReleaseAge(t *testing.T) {
	runs := []forge.CheckRun{cr(1, "go", "head", ActionsApp, "completed", "success", c0), cr(2, "lint", "head", ActionsApp, "completed", "success", c0)}
	st := []forge.Status{{Context: "renovate/stability-days", State: "pending", CreatedAt: c0}}
	if v, _ := EvaluateChecks(runs, st, "head", c0, c0, time.Hour, checksReq()); v != Waiting {
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
	ok := cr(1, "go", "head", ActionsApp, "completed", "success", c0)
	fail := cr(2, "lint", "head", ActionsApp, "completed", "failure", c0)
	wf := func(id, suite int64, status, conclusion string) forge.WorkflowRun {
		return forge.WorkflowRun{ID: id, Name: "ci", HeadSHA: "head", Status: status, Conclusion: conclusion, CheckSuiteID: suite}
	}

	// Never ran, conflicting: Renovate's rebase checkbox.
	f := &fakeChecks{mergeable: &no, wf: []forge.WorkflowRun{{ID: 5, HeadSHA: "older", Status: "completed", Conclusion: "success"}}}
	d := DiagnoseChecks(ctx, f, pr, checksReq())
	if d.Cause != NeverRan || !d.Conflicting {
		t.Fatalf("never ran: %+v (a run on another SHA does not count)", d)
	}
	if a, err := RecoverChecks(ctx, f, pr, d); err != nil || a.Kind != ActionRebase || !strings.Contains(f.body, "[x]") {
		t.Fatalf("never ran recover: %+v %v %q", a, err, f.body)
	}

	// Running.
	f = &fakeChecks{wf: []forge.WorkflowRun{wf(40, 902, "in_progress", "")}, runs: []forge.CheckRun{ok}}
	if d := DiagnoseChecks(ctx, f, pr, checksReq()); d.Cause != Running {
		t.Fatalf("running: %+v", d)
	}

	// Ran and failed: the failed check's own workflow run is re-run.
	f = &fakeChecks{wf: []forge.WorkflowRun{wf(41, 901, "completed", "success"), wf(42, 902, "completed", "failure")}, runs: []forge.CheckRun{ok, fail}}
	d = DiagnoseChecks(ctx, f, pr, checksReq())
	if d.Cause != RanFailed || d.RunID != 42 {
		t.Fatalf("ran-failed: %+v", d)
	}
	if a, err := RecoverChecks(ctx, f, pr, d); err != nil || a.Kind != ActionGitHubRerun || len(f.reruns) != 1 || f.reruns[0] != 42 {
		t.Fatalf("rerun: %+v %v %v", a, err, f.reruns)
	}

	// Ran, result missing: runs concluded, a required check is absent or
	// came from another app. Needs the operator.
	other := cr(3, "lint", "head", "evil-ci", "completed", "success", c0)
	f = &fakeChecks{wf: []forge.WorkflowRun{wf(43, 901, "completed", "success")}, runs: []forge.CheckRun{ok, other}}
	d = DiagnoseChecks(ctx, f, pr, checksReq())
	if d.Cause != ResultMissing || !strings.Contains(d.Detail, "lint") {
		t.Fatalf("result missing: %+v", d)
	}
	if _, err := RecoverChecks(ctx, f, pr, d); !errors.Is(err, ErrNeedsOperator) || len(f.reruns) != 0 {
		t.Fatalf("result missing must need the operator: %v %v", err, f.reruns)
	}

	// Skipped required check: result missing too, not a pass.
	f = &fakeChecks{wf: []forge.WorkflowRun{wf(44, 901, "completed", "success")}, runs: []forge.CheckRun{ok, cr(4, "lint", "head", ActionsApp, "completed", "skipped", c0)}}
	if d := DiagnoseChecks(ctx, f, pr, checksReq()); d.Cause != ResultMissing {
		t.Fatalf("skipped: %+v", d)
	}

	// No required checks declared / unreadable: no recovery.
	if d := DiagnoseChecks(ctx, &fakeChecks{}, pr, Requirement{Source: SourceGitHubChecks}); d.Cause != Unknown {
		t.Fatalf("no checks declared: %+v", d)
	}
	if d := DiagnoseChecks(ctx, &fakeChecks{err: errors.New("502")}, pr, checksReq()); d.Cause != Unknown {
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
