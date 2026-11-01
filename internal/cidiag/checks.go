package cidiag

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/forge"
)

// CI sources a repo's update-policy.yaml may declare (ci_source, p4-r2).
// Anything else — including unset — means nothing passes CI.
const (
	// SourceGitHubChecks: GitHub check-runs from the GitHub Actions app
	// (frank: public, GitHub-hosted runners, never mirrored to Gitea).
	SourceGitHubChecks = "github-checks"
	// SourceGiteaStatuses: bridged gitea-actions/* commit statuses.
	SourceGiteaStatuses = "gitea-statuses"
)

// ActionsApp is the slug of the GitHub Actions app: the only creator whose
// check-runs count (the equivalent of the status-creator check).
const ActionsApp = "github-actions"

// KnownSource reports whether s is a CI source the console can evaluate.
func KnownSource(s string) bool { return s == SourceGitHubChecks || s == SourceGiteaStatuses }

// ResultMissing: the workflow runs for the head concluded, but a required
// check-run is absent, still queued, or concluded neither pass nor fail
// (neutral/skipped). No automatic recovery: it needs the operator (often a
// renamed job that no longer matches required_ci_checks).
const ResultMissing Cause = "result-missing"

// ActionGitHubRerun is a GitHub rerun-failed-jobs request.
const ActionGitHubRerun ActionKind = "github-rerun-failed-jobs"

// latestChecks keeps only the check-runs that count: on exactly sha,
// created by the GitHub Actions app; the newest (highest id) per name.
func latestChecks(runs []forge.CheckRun, sha string) map[string]forge.CheckRun {
	out := map[string]forge.CheckRun{}
	for _, r := range runs {
		if sha == "" || r.HeadSHA != sha || r.App.Slug != ActionsApp {
			continue
		}
		if cur, ok := out[r.Name]; !ok || r.ID > cur.ID {
			out[r.Name] = r
		}
	}
	return out
}

func checkPassed(r forge.CheckRun) bool { return r.Status == "completed" && r.Conclusion == "success" }

// inconclusive: completed, but neither a pass nor a failure.
func inconclusive(r forge.CheckRun) bool {
	return r.Status == "completed" && (r.Conclusion == "neutral" || r.Conclusion == "skipped")
}

func checkFailed(r forge.CheckRun) bool {
	return r.Status == "completed" && !checkPassed(r) && !inconclusive(r)
}

func (r Requirement) checks() []string {
	var out []string
	for _, c := range r.Checks {
		if c = strings.TrimSpace(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// EvaluateChecks reads the GitHub check-runs of the PR head sha pushed at
// headAt (ci_source: github-checks). Every name in req.Checks must have a
// check-run on exactly sha, created by the GitHub Actions app, completed
// with conclusion success — neutral or skipped is not a pass. An empty
// req.Checks means nothing passes. After a retry (req.Since), a failure that
// completed at or before the retry is ignored (it is what the retry acted
// on); a success from a job the retry did not re-run still counts.
func EvaluateChecks(runs []forge.CheckRun, statuses []forge.Status, sha string, headAt, now time.Time, timeout time.Duration, req Requirement) (Verdict, string) {
	if req.Since.After(headAt) {
		headAt = req.Since
	}
	late := now.Sub(headAt) > timeout
	wait := func(detail string) (Verdict, string) {
		if late {
			return Missing, detail + " after " + timeout.String()
		}
		return Pending, detail
	}
	required := req.checks()
	if len(required) == 0 {
		return Pending, "no required_ci_checks declared in update-policy.yaml: nothing passes"
	}
	latest := latestChecks(runs, sha)
	if !req.Since.IsZero() {
		for n, r := range latest {
			if !checkPassed(r) && r.Status == "completed" && !r.CompletedAt.After(req.Since) {
				delete(latest, n) // the result the retry acted on
			}
		}
	}
	sort.Strings(required)
	pending := false
	for _, name := range required {
		r, ok := latest[name]
		switch {
		case !ok:
			return wait("required check " + name + " has not reported on " + short(sha))
		case checkPassed(r):
		case inconclusive(r):
			return Missing, "required check " + name + " was " + r.Conclusion + ", not passed"
		case checkFailed(r):
			return Failed, name + " " + r.Conclusion
		default:
			pending = true
		}
	}
	if pending {
		if late {
			return Missing, "CI still pending after " + timeout.String()
		}
		return Pending, "CI running"
	}
	if s, ok := forge.Latest(statuses)["renovate/stability-days"]; ok && s.State == "pending" {
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

var failedRun = map[string]bool{"failure": true, "cancelled": true, "timed_out": true, "startup_failure": true}

// DiagnoseChecks gathers the evidence for a held PR on a github-checks repo:
//
//	never ran       no workflow run for the head SHA (mergeable checked
//	                first: a conflicting PR gets no pull_request run)
//	ran and failed  a required check-run failed, or its workflow run did
//	ran, missing    runs concluded but a required check-run is absent,
//	                queued, neutral or skipped
func DiagnoseChecks(ctx context.Context, f ChecksForges, pr forge.PR, req Requirement) Diagnosis {
	required := req.checks()
	if len(required) == 0 {
		return Diagnosis{Cause: Unknown, Detail: "no required_ci_checks declared: nothing passes, needs the operator"}
	}
	all, err := f.WorkflowRuns(ctx, pr.HeadSHA)
	if err != nil {
		return Diagnosis{Cause: Unknown, Detail: "GitHub workflow runs unreadable: " + err.Error()}
	}
	var wruns []forge.WorkflowRun
	for _, w := range all {
		if w.HeadSHA == pr.HeadSHA && pr.HeadSHA != "" {
			wruns = append(wruns, w)
		}
	}
	if len(wruns) == 0 {
		d := Diagnosis{Cause: NeverRan, Detail: "no GitHub Actions run for the head commit"}
		if p, err := f.PR(ctx, pr.Number); err == nil && p.Mergeable != nil && !*p.Mergeable {
			d.Conflicting, d.Detail = true, "no GitHub Actions run: the PR conflicts with main, so no merge ref exists"
		}
		return d
	}
	for _, w := range wruns {
		if w.Status != "completed" {
			return Diagnosis{Cause: Running, Detail: "GitHub Actions run " + w.Name + " still " + w.Status}
		}
	}
	runs, err := f.CheckRuns(ctx, pr.HeadSHA)
	if err != nil {
		return Diagnosis{Cause: Unknown, Detail: "GitHub check-runs unreadable: " + err.Error()}
	}
	latest := latestChecks(runs, pr.HeadSHA)
	sort.Strings(required)
	for _, name := range required {
		r, ok := latest[name]
		if !ok || !checkFailed(r) {
			continue
		}
		for _, w := range wruns {
			if w.CheckSuiteID != 0 && w.CheckSuiteID == r.CheckSuite.ID {
				return Diagnosis{Cause: RanFailed, RunID: w.ID, Detail: "required check " + name + " concluded " + r.Conclusion + " (run " + w.Name + ")"}
			}
		}
		for _, w := range wruns {
			if failedRun[w.Conclusion] {
				return Diagnosis{Cause: RanFailed, RunID: w.ID, Detail: "required check " + name + " concluded " + r.Conclusion + "; run " + w.Name + " " + w.Conclusion}
			}
		}
		return Diagnosis{Cause: RanFailed, Detail: "required check " + name + " concluded " + r.Conclusion + "; its workflow run is not identifiable"}
	}
	var missing []string
	for _, name := range required {
		r, ok := latest[name]
		switch {
		case !ok:
			missing = append(missing, name+" (absent)")
		case inconclusive(r):
			missing = append(missing, name+" ("+r.Conclusion+")")
		case r.Status != "completed":
			missing = append(missing, name+" ("+r.Status+")")
		}
	}
	if len(missing) > 0 {
		return Diagnosis{Cause: ResultMissing, Detail: "workflow runs concluded but these required check-runs did not succeed — " + strings.Join(missing, ", ")}
	}
	for _, w := range wruns {
		if failedRun[w.Conclusion] {
			return Diagnosis{Cause: RanFailed, RunID: w.ID, Detail: "run " + w.Name + " concluded " + w.Conclusion}
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
