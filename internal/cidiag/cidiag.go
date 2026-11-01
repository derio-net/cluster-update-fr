// Package cidiag tells WHY a PR has no passing CI signal and performs the
// matching recovery (R28). Merges happen on GitHub; where CI comes from is
// declared per repo (ci_source in update-policy.yaml). For github-checks
// (frank) see checks.go. For gitea-statuses, CI runs on Gitea and its
// statuses arrive through a bridge that can drop events, so "no green check"
// has three different causes needing three different remedies:
//
//	status lost   Gitea has a terminal status GitHub lacks → re-forward it
//	never ran     no Gitea run for the head SHA → conflicting: Renovate
//	              rebase checkbox; else redeliver the GitHub webhook
//	ran, failed   Gitea run concluded failure → re-run via the Gitea API if
//	              the server offers one, else Renovate rebase checkbox
//
// Never an empty commit: path-filtered workflows run nothing for one.
// The one-retry rule (a retry that fails again marks the update failed) is
// the engine's; this package performs single actions.
package cidiag

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/forge"
	"github.com/derio-net/cluster-update-fr/internal/renovate"
)

// BridgePrefix is how the status bridge names Gitea contexts on GitHub.
const BridgePrefix = "gitea-actions/"

// Verdict is the CI signal on GitHub.
type Verdict string

// Verdicts.
const (
	Passed  Verdict = "passed"
	Pending Verdict = "pending"
	Waiting Verdict = "waiting" // Renovate's release-age gate is pending
	Failed  Verdict = "failed"
	Missing Verdict = "missing" // no conclusive signal within the timeout
	// WorkflowChange: the head changes the repo's own CI (.github/); no CI
	// result it produced counts, and it is not a CI failure either — the
	// operator merges it (p4-r2b).
	WorkflowChange Verdict = "workflow-change"
)

// DefaultRequired is used when update-policy.yaml declares no
// required_ci_contexts: at least one bridge context, all of them green.
var DefaultRequired = []string{BridgePrefix + "*"}

// Requirement is what "CI passed" means (c1s-r3): every entry of Contexts
// (an exact context, or a "prefix*" pattern) must be matched by at least one
// status, every matched status must be "success" — a Gitea skipped/warning
// forwarded as success (description "Gitea: skipped") does NOT count — and
// only statuses CREATED by one of Creators (the status bridge's and the
// console's own GitHub identities) are considered at all: anyone with
// statuses:write could otherwise post a green check.
type Requirement struct {
	// Source is the repo's declared ci_source (SourceGitHubChecks or
	// SourceGiteaStatuses); any other value means nothing passes.
	Source string
	// Checks are the required (workflow path, check-run name) pairs
	// (github-checks only); empty or malformed means nothing passes.
	Checks   []CheckRef
	Contexts []string
	Creators []string
	// Excluded logins never count, even when listed in Creators (c1d-r12):
	// the console's own bot, so the console cannot satisfy its own CI gate.
	Excluded []string
	// Since, when set (the time of the update's one CI retry), discards
	// every status created at or before it and measures the timeout from it
	// (c1c-r11): the failure a retry acted on cannot fail the update again.
	Since time.Time
}

var notReallySuccess = regexp.MustCompile(`(?i)\b(skipped|warning)\b`)

func (r Requirement) matches(pattern, ctx string) bool {
	if p, ok := strings.CutSuffix(pattern, "*"); ok {
		return strings.HasPrefix(ctx, p)
	}
	return ctx == pattern
}

// Evaluate reads the GitHub statuses of a PR head pushed at headAt.
func Evaluate(statuses []forge.Status, headAt, now time.Time, timeout time.Duration, req Requirement) (Verdict, string) {
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
	excluded := map[string]bool{}
	for _, c := range req.Excluded {
		excluded[c] = true
	}
	creators := map[string]bool{}
	for _, c := range req.Creators {
		if c != "" && !excluded[c] {
			creators[c] = true
		}
	}
	if len(creators) == 0 {
		return wait("no trusted status creator configured (STATUS_CREATOR_LOGINS)")
	}
	var trusted []forge.Status
	for _, s := range statuses {
		if creators[s.Creator.Login] && (req.Since.IsZero() || s.CreatedAt.After(req.Since)) {
			trusted = append(trusted, s)
		}
	}
	latest := forge.Latest(trusted)
	contexts := make([]string, 0, len(latest))
	for c := range latest {
		contexts = append(contexts, c)
	}
	sort.Strings(contexts)
	required := req.Contexts
	if len(required) == 0 {
		required = DefaultRequired
	}
	pending := false
	for _, want := range required {
		matched := 0
		for _, c := range contexts {
			if !req.matches(want, c) {
				continue
			}
			matched++
			s := latest[c]
			switch {
			case s.State == "failure" || s.State == "error":
				return Failed, s.Context + " " + s.State
			case s.State == "pending":
				pending = true
			case s.State == "success" && notReallySuccess.MatchString(s.Description):
				// terminal and not a pass: no conclusive signal
				return Missing, "required " + s.Context + " was " + strings.ToLower(notReallySuccess.FindString(s.Description)) + ", not passed"
			case s.State != "success":
				return Failed, s.Context + " " + s.State
			}
		}
		if matched == 0 {
			return wait("required CI context " + want + " has not reported")
		}
	}
	if pending {
		if late {
			return Missing, "CI still pending after " + timeout.String()
		}
		return Pending, "CI running"
	}
	// Renovate's own release-age gate only ever DELAYS a merge, so it is
	// read from every status, whoever posted it.
	if s, ok := forge.Latest(statuses)["renovate/stability-days"]; ok && s.State == "pending" {
		return Waiting, "waiting for Renovate's minimum release age"
	}
	return Passed, "CI passed"
}

// Cause is a diagnosis.
type Cause string

// Causes.
const (
	StatusLost Cause = "status-lost"
	NeverRan   Cause = "never-ran"
	RanFailed  Cause = "ran-failed"
	Running    Cause = "running"
	Unknown    Cause = "unknown"
)

// Diagnosis is the evidence behind a cause.
type Diagnosis struct {
	Cause       Cause
	Detail      string
	Lost        []forge.Status // Gitea statuses GitHub lacks (StatusLost)
	RunID       int64          // failed run (RanFailed)
	Conflicting bool           // PR not mergeable (NeverRan)
}

// Forges is what diagnosis and recovery need from GitHub and Gitea.
type Forges interface {
	Statuses(ctx context.Context, sha string) ([]forge.Status, error)
	GiteaStatuses(ctx context.Context, sha string) ([]forge.Status, error)
	Runs(ctx context.Context, sha string) ([]forge.Run, error)
	RerunSupported(ctx context.Context) (bool, error)
	Rerun(ctx context.Context, run int64) error
	PR(ctx context.Context, n int) (forge.PR, error)
	CreateStatus(ctx context.Context, sha string, s forge.Status) error
	UpdatePRBody(ctx context.Context, n int, body string) error
	FindDelivery(ctx context.Context, sha string, limit int) (forge.Delivery, error)
	Redeliver(ctx context.Context, d forge.Delivery) error
}

var terminal = map[string]bool{"success": true, "failure": true, "error": true, "skipped": true, "warning": true}

// Diagnose gathers the evidence for a held PR.
func Diagnose(ctx context.Context, f Forges, pr forge.PR, giteaWeb string) Diagnosis {
	runs, err := f.Runs(ctx, pr.HeadSHA)
	if err != nil {
		return Diagnosis{Cause: Unknown, Detail: "Gitea runs unreadable: " + err.Error()}
	}
	for _, r := range runs {
		if r.Status != "completed" && r.Conclusion == "" {
			return Diagnosis{Cause: Running, Detail: "Gitea run still in progress"}
		}
	}
	for _, r := range runs {
		if r.Conclusion == "failure" || r.Conclusion == "cancelled" {
			return Diagnosis{Cause: RanFailed, RunID: r.ID, Detail: "Gitea run concluded " + r.Conclusion}
		}
	}
	gitea, err := f.GiteaStatuses(ctx, pr.HeadSHA)
	if err != nil {
		return Diagnosis{Cause: Unknown, Detail: "Gitea statuses unreadable: " + err.Error()}
	}
	gh, err := f.Statuses(ctx, pr.HeadSHA)
	if err != nil {
		return Diagnosis{Cause: Unknown, Detail: "GitHub statuses unreadable: " + err.Error()}
	}
	have := map[string]forge.Status{}
	for c, s := range forge.Latest(gh) {
		have[strings.ToLower(c)] = s
	}
	var lost []forge.Status
	for c, s := range forge.Latest(gitea) {
		if !terminal[s.State] || strings.HasPrefix(c, "tekton") {
			continue
		}
		want := Forwarded(s, giteaWeb)
		got, ok := have[strings.ToLower(want.Context)]
		if !ok || got.State != want.State {
			lost = append(lost, s)
		}
	}
	if len(lost) > 0 {
		return Diagnosis{Cause: StatusLost, Lost: lost, Detail: "Gitea has results GitHub never received"}
	}
	if len(runs) == 0 && len(gitea) == 0 {
		d := Diagnosis{Cause: NeverRan, Detail: "no Gitea run for the head commit"}
		if p, err := f.PR(ctx, pr.Number); err == nil && p.Mergeable != nil && !*p.Mergeable {
			d.Conflicting, d.Detail = true, "no Gitea run: the PR conflicts with main, so no merge ref exists"
		}
		return d
	}
	return Diagnosis{Cause: Unknown, Detail: "statuses agree; nothing to recover"}
}

// Forwarded maps a Gitea status to the GitHub status the bridge would have
// posted: Gitea's skipped/warning become success (GitHub rejects them) with
// the real state kept in the description; relative target URLs are resolved
// against the Gitea web URL.
func Forwarded(s forge.Status, giteaWeb string) forge.Status {
	out := forge.Status{Context: BridgePrefix + s.Context, State: s.State, Description: s.Description, TargetURL: s.TargetURL}
	if s.State == "skipped" || s.State == "warning" {
		out.State, out.Description = "success", "Gitea: "+s.State
	}
	if strings.HasPrefix(out.TargetURL, "/") && giteaWeb != "" {
		out.TargetURL = strings.TrimRight(giteaWeb, "/") + out.TargetURL
	}
	return out
}

// ActionKind names a recovery action.
type ActionKind string

// Actions.
const (
	ActionReforward ActionKind = "re-forward-status"
	ActionRebase    ActionKind = "renovate-rebase"
	ActionRedeliver ActionKind = "redeliver-webhook"
	ActionRerun     ActionKind = "gitea-rerun"
)

// Action is what Recover did.
type Action struct {
	Kind   ActionKind
	Detail string
}

// ErrNothingToDo means the diagnosis needs no action (CI running).
var ErrNothingToDo = errors.New("cidiag: nothing to recover")

// ErrNeedsOperator means no automatic recovery applies (e.g. a non-Renovate
// PR when Gitea has no re-run API).
var ErrNeedsOperator = errors.New("cidiag: no automatic recovery; needs the operator")

// Recover performs the single action matching d.
func Recover(ctx context.Context, f Forges, pr forge.PR, d Diagnosis, giteaWeb string) (Action, error) {
	switch d.Cause {
	case StatusLost:
		for _, s := range d.Lost {
			if err := f.CreateStatus(ctx, pr.HeadSHA, Forwarded(s, giteaWeb)); err != nil {
				return Action{}, err
			}
		}
		return Action{Kind: ActionReforward, Detail: "re-forwarded " + itoa(len(d.Lost)) + " status(es)"}, nil
	case NeverRan:
		if !d.Conflicting {
			if del, err := f.FindDelivery(ctx, pr.HeadSHA, 50); err == nil {
				if err := f.Redeliver(ctx, del); err != nil {
					return Action{}, err
				}
				return Action{Kind: ActionRedeliver, Detail: "redelivered the " + del.Event + " webhook"}, nil
			}
		}
		return rebase(ctx, f, pr)
	case RanFailed:
		if ok, err := f.RerunSupported(ctx); err == nil && ok {
			if err := f.Rerun(ctx, d.RunID); err != nil {
				return Action{}, err
			}
			return Action{Kind: ActionRerun, Detail: "re-ran Gitea run " + itoa64(d.RunID)}, nil
		}
		return rebase(ctx, f, pr)
	case Running:
		return Action{}, ErrNothingToDo
	}
	return Action{}, ErrNeedsOperator
}

type bodyEditor interface {
	UpdatePRBody(ctx context.Context, n int, body string) error
}

func rebase(ctx context.Context, f bodyEditor, pr forge.PR) (Action, error) {
	body, err := renovate.TickRebase(pr.Body)
	if err != nil {
		return Action{}, ErrNeedsOperator
	}
	if err := f.UpdatePRBody(ctx, pr.Number, body); err != nil {
		return Action{}, err
	}
	return Action{Kind: ActionRebase, Detail: "ticked Renovate's rebase/retry checkbox"}, nil
}

func itoa(n int) string { return strconv.Itoa(n) }

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// Both must satisfy the diagnosis interface.
var _ Forges = forge.Both{}
