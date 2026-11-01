package cidiag

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/forge"
)

// CI sources a repo's update-policy.yaml may declare (ci_source, p4-r2).
// Anything else — including unset — means nothing passes CI.
const (
	// SourceGitHubChecks: GitHub Actions check-runs (frank: public,
	// GitHub-hosted runners, never mirrored to Gitea).
	SourceGitHubChecks = "github-checks"
	// SourceGiteaStatuses: bridged gitea-actions/* commit statuses.
	SourceGiteaStatuses = "gitea-statuses"
)

// ActionsApp is the slug of the GitHub Actions app. Necessary but NOT
// sufficient (p4-r2b): every GITHUB_TOKEN-created check-run carries it, so a
// check-run counts only through the workflow run that produced it.
const ActionsApp = "github-actions"

// KnownSource reports whether s is a CI source the console can evaluate.
func KnownSource(s string) bool { return s == SourceGitHubChecks || s == SourceGiteaStatuses }

// CheckRef is one required check: the check-run Name produced by the
// workflow file at Workflow. Invalid entries (wrong policy shape) never pass.
type CheckRef struct {
	Workflow string
	Name     string
	Invalid  bool
}

func (c CheckRef) String() string { return c.Workflow + " / " + c.Name }

// valid: a .yml/.yaml file directly under .github/workflows/.
func (c CheckRef) valid() bool {
	if c.Invalid || c.Name == "" || path.Clean(c.Workflow) != c.Workflow || path.Dir(c.Workflow) != ".github/workflows" {
		return false
	}
	return strings.HasSuffix(c.Workflow, ".yml") || strings.HasSuffix(c.Workflow, ".yaml")
}

// ResultMissing: the workflow run for a required check concluded, but its
// check-run is absent, still queued, or concluded neither pass nor fail
// (neutral/skipped). No automatic recovery: it needs the operator.
const ResultMissing Cause = "result-missing"

// ActionGitHubRerun is a GitHub rerun-failed-jobs request.
const ActionGitHubRerun ActionKind = "github-rerun-failed-jobs"

// Evidence is what github-checks CI is judged on, all for one head SHA.
type Evidence struct {
	SHA       string
	Repo      string // owner/name the runs must live in and come from ("" = only same-repo)
	CheckRuns []forge.CheckRun
	Workflows []forge.WorkflowRun
	Statuses  []forge.Status // only for Renovate's release-age gate
}

// eligibleRun: a run of exactly the declared workflow file, on exactly the
// head SHA, triggered by push or pull_request (never pull_request_target or
// a workflow_run chain), whose head commit came from the repo itself (not a
// fork).
func eligibleRun(w forge.WorkflowRun, ref CheckRef, ev Evidence) bool {
	if ev.SHA == "" || w.HeadSHA != ev.SHA || w.Path != ref.Workflow {
		return false
	}
	if w.Event != "push" && w.Event != "pull_request" {
		return false
	}
	repo, head := w.Repository.FullName, w.HeadRepository.FullName
	if repo == "" || head != repo {
		return false
	}
	return ev.Repo == "" || repo == ev.Repo
}

func checkPassed(r forge.CheckRun) bool { return r.Status == "completed" && r.Conclusion == "success" }

func inconclusive(r forge.CheckRun) bool {
	return r.Status == "completed" && (r.Conclusion == "neutral" || r.Conclusion == "skipped")
}

func checkFailed(r forge.CheckRun) bool {
	return r.Status == "completed" && !checkPassed(r) && !inconclusive(r)
}

type checkState int

const (
	stNoRun checkState = iota
	stRunning
	stPassed
	stFailed
	stMissing
)

type assessed struct {
	state  checkState
	run    forge.WorkflowRun
	detail string
}

// assess judges one required check. The matched run is the newest eligible
// run (GitHub lists each run at its latest attempt); the check-run is the
// newest one with the required name INSIDE that run's check suite, never
// one from another run. Both must have succeeded. After a retry (since), a
// failure that completed at or before it is the one the retry acted on and
// reads as still running.
func assess(ref CheckRef, ev Evidence, since time.Time) assessed {
	var run *forge.WorkflowRun
	for i, w := range ev.Workflows {
		if eligibleRun(w, ref, ev) && (run == nil || w.ID > run.ID) {
			run = &ev.Workflows[i]
		}
	}
	if run == nil {
		return assessed{state: stNoRun, detail: "no " + ref.Workflow + " run on " + short(ev.SHA)}
	}
	a := assessed{run: *run}
	var check *forge.CheckRun
	for i, c := range ev.CheckRuns {
		if c.Name == ref.Name && c.HeadSHA == ev.SHA && c.App.Slug == ActionsApp && run.CheckSuiteID != 0 && c.CheckSuite.ID == run.CheckSuiteID &&
			(check == nil || c.ID > check.ID) {
			check = &ev.CheckRuns[i]
		}
	}
	stale := func(t time.Time) bool { return !since.IsZero() && !t.After(since) }
	switch {
	case check != nil && checkFailed(*check):
		if stale(check.CompletedAt) {
			a.state, a.detail = stRunning, ref.String()+" re-run requested"
			return a
		}
		a.state, a.detail = stFailed, ref.String()+" "+check.Conclusion
	case run.Status != "completed":
		a.state, a.detail = stRunning, ref.Workflow+" run "+run.Status
	case check == nil:
		a.state, a.detail = stMissing, ref.String()+" has no check-run in its workflow run"
	case inconclusive(*check):
		a.state, a.detail = stMissing, ref.String()+" was "+check.Conclusion+", not passed"
	case !checkPassed(*check):
		a.state, a.detail = stMissing, ref.String()+" still "+check.Status
	case run.Conclusion != "success":
		if stale(run.UpdatedAt) {
			a.state, a.detail = stRunning, ref.Workflow+" re-run requested"
			return a
		}
		a.state, a.detail = stFailed, ref.Workflow+" run concluded "+run.Conclusion
	default:
		a.state = stPassed
	}
	return a
}

// usable returns the required checks, or false if there are none or any
// is malformed (nothing passes).
func (r Requirement) usable() ([]CheckRef, bool) {
	if len(r.Checks) == 0 {
		return nil, false
	}
	for _, c := range r.Checks {
		if !c.valid() {
			return nil, false
		}
	}
	return r.Checks, true
}

// EvaluateChecks judges a PR head pushed at headAt (ci_source:
// github-checks). Every required (workflow, name) pair must have an eligible
// workflow run of that file on the head SHA that concluded success, and in
// it a check-run of that name completed with success (neutral/skipped is not
// a pass). No required checks, or a malformed entry, means nothing passes.
func EvaluateChecks(ev Evidence, headAt, now time.Time, timeout time.Duration, req Requirement) (Verdict, string) {
	if req.Since.After(headAt) {
		headAt = req.Since
	}
	late := now.Sub(headAt) > timeout
	required, ok := req.usable()
	if !ok {
		return Pending, "required_ci_checks missing or not [{workflow, name}] pairs in update-policy.yaml: nothing passes"
	}
	pending, why := false, ""
	for _, ref := range required {
		a := assess(ref, ev, req.Since)
		switch a.state {
		case stFailed:
			return Failed, a.detail
		case stMissing:
			return Missing, a.detail
		case stNoRun, stRunning:
			if !pending {
				pending, why = true, a.detail
			}
		}
	}
	if pending {
		if late {
			return Missing, why + " after " + timeout.String()
		}
		return Pending, why
	}
	if s, ok := forge.Latest(ev.Statuses)["renovate/stability-days"]; ok && s.State == "pending" {
		return Waiting, "waiting for Renovate's minimum release age"
	}
	return Passed, "CI passed"
}

func short(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

// ChecksForges is what github-checks diagnosis and recovery need.
type ChecksForges interface {
	CheckRuns(ctx context.Context, sha string) ([]forge.CheckRun, error)
	WorkflowRuns(ctx context.Context, sha string) ([]forge.WorkflowRun, error)
	RerunFailedJobs(ctx context.Context, run int64) error
	PR(ctx context.Context, n int) (forge.PR, error)
	UpdatePRBody(ctx context.Context, n int, body string) error
}

var _ ChecksForges = (*forge.GitHub)(nil)

// DiagnoseChecks gathers the evidence for a held PR on a github-checks repo:
//
//	never ran       no eligible run of a required workflow on the head SHA
//	                (mergeable checked first: a conflicting PR gets no
//	                pull_request run)
//	ran and failed  a required check-run or its workflow run failed
//	ran, missing    the run concluded but the check-run is absent, queued,
//	                neutral or skipped
func DiagnoseChecks(ctx context.Context, f ChecksForges, pr forge.PR, req Requirement, repo string) Diagnosis {
	required, ok := req.usable()
	if !ok {
		return Diagnosis{Cause: Unknown, Detail: "required_ci_checks missing or malformed: nothing passes, needs the operator"}
	}
	wf, err := f.WorkflowRuns(ctx, pr.HeadSHA)
	if err != nil {
		return Diagnosis{Cause: Unknown, Detail: "GitHub workflow runs unreadable: " + err.Error()}
	}
	runs, err := f.CheckRuns(ctx, pr.HeadSHA)
	if err != nil {
		return Diagnosis{Cause: Unknown, Detail: "GitHub check-runs unreadable: " + err.Error()}
	}
	ev := Evidence{SHA: pr.HeadSHA, Repo: repo, CheckRuns: runs, Workflows: wf}
	var all []assessed
	for _, ref := range required {
		all = append(all, assess(ref, ev, time.Time{}))
	}
	for _, a := range all {
		if a.state == stRunning {
			return Diagnosis{Cause: Running, Detail: a.detail}
		}
	}
	for _, a := range all {
		if a.state == stFailed {
			return Diagnosis{Cause: RanFailed, RunID: a.run.ID, Detail: a.detail}
		}
	}
	for _, a := range all {
		if a.state == stMissing {
			return Diagnosis{Cause: ResultMissing, Detail: a.detail}
		}
	}
	for _, a := range all {
		if a.state == stNoRun {
			d := Diagnosis{Cause: NeverRan, Detail: a.detail}
			if p, err := f.PR(ctx, pr.Number); err == nil && p.Mergeable != nil && !*p.Mergeable {
				d.Conflicting, d.Detail = true, a.detail+": the PR conflicts with main, so no merge ref exists"
			}
			return d
		}
	}
	return Diagnosis{Cause: Unknown, Detail: "check-runs agree; nothing to recover"}
}

// RecoverChecks performs the single action matching d on a github-checks
// repo: ran-and-failed → rerun-failed-jobs; never ran → Renovate's rebase
// checkbox (never an empty commit); anything else needs the operator.
func RecoverChecks(ctx context.Context, f ChecksForges, pr forge.PR, d Diagnosis) (Action, error) {
	switch d.Cause {
	case RanFailed:
		if d.RunID == 0 {
			return Action{}, ErrNeedsOperator
		}
		if err := f.RerunFailedJobs(ctx, d.RunID); err != nil {
			return Action{}, err
		}
		return Action{Kind: ActionGitHubRerun, Detail: "re-ran the failed jobs of GitHub Actions run " + itoa64(d.RunID)}, nil
	case NeverRan:
		return rebase(ctx, f, pr)
	case Running:
		return Action{}, ErrNothingToDo
	}
	return Action{}, ErrNeedsOperator
}
