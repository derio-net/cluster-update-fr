// Package verify decides when an update is done (R16): for workloads,
// ArgoCD's last sync OPERATION has applied the merge commit (never the
// Synced status — frank's stale-revision gotcha) and the app's smoke checks
// pass; for OS steps, every node runs the declared version, every node is
// Ready, and the cluster's smoke checks pass. Until then an update is shown
// as "rolled out, unverified"; a failing check fails it, naming the check.
package verify

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/live"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
)

// Check statuses.
const (
	CheckPassed  = "passed"
	CheckFailed  = "failed"
	CheckSkipped = "operator-run" // exec-probe: the console cannot run it
)

// CheckResult is one smoke check's result.
type CheckResult struct {
	Name, Status, Detail string
}

// SmokeResult is an app's smoke run.
type SmokeResult struct {
	App    string
	At     time.Time
	Checks []CheckResult
}

// Passed: at least one check ran and none failed.
func (r SmokeResult) Passed() bool {
	ran := false
	for _, c := range r.Checks {
		switch c.Status {
		case CheckFailed:
			return false
		case CheckPassed:
			ran = true
		}
	}
	return ran
}

// FirstFailure names the first failing check ("" if none).
func (r SmokeResult) FirstFailure() string {
	for _, c := range r.Checks {
		if c.Status == CheckFailed {
			return c.Name + ": " + c.Detail
		}
	}
	return ""
}

// Summary is "n/m smoke checks passed" plus failures.
func (r SmokeResult) Summary() string {
	pass, total := 0, 0
	var fails []string
	for _, c := range r.Checks {
		if c.Status == CheckSkipped {
			continue
		}
		total++
		if c.Status == CheckPassed {
			pass++
		} else {
			fails = append(fails, c.Name+" ("+c.Detail+")")
		}
	}
	s := fmt.Sprintf("%s: %d/%d smoke checks passed", r.App, pass, total)
	if len(fails) > 0 {
		s += "; failed: " + strings.Join(fails, ", ")
	}
	return scrub.String(s)
}

// Runner runs smoke checks.
type Runner struct {
	HTTP    *http.Client
	Timeout time.Duration // per check (default 10s)
}

// Run executes every check of s.
func (r Runner) Run(ctx context.Context, s frankrepo.Smoke) SmokeResult {
	res := SmokeResult{App: s.App, At: time.Now()}
	timeout := r.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	for _, c := range s.Checks {
		name := c.Kind + " " + c.Target
		cctx, cancel := context.WithTimeout(ctx, timeout)
		var cr CheckResult
		switch c.Kind {
		case "http", "functional":
			cr = r.http(cctx, c)
		case "tcp":
			cr = tcp(cctx, c)
		case "exec-probe":
			cr = CheckResult{Status: CheckSkipped, Detail: "operator-run: " + c.Reason}
		default:
			cr = CheckResult{Status: CheckFailed, Detail: "unknown check kind " + c.Kind}
		}
		cancel()
		cr.Name, cr.Detail = name, scrub.String(cr.Detail)
		res.Checks = append(res.Checks, cr)
	}
	return res
}

func (r Runner) http(ctx context.Context, c frankrepo.Check) CheckResult {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Target, nil)
	if err != nil {
		return CheckResult{Status: CheckFailed, Detail: err.Error()}
	}
	client := r.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return CheckResult{Status: CheckFailed, Detail: err.Error()}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	want := c.Expect.Status
	if want == 0 {
		want = 200
	}
	if resp.StatusCode != want {
		snippet := strings.TrimSpace(string(body))
		if len(snippet) > 120 {
			snippet = snippet[:120]
		}
		return CheckResult{Status: CheckFailed, Detail: fmt.Sprintf("status %d, want %d: %s", resp.StatusCode, want, snippet)}
	}
	if c.Expect.Body != "" {
		re, err := regexp.Compile(c.Expect.Body)
		if err != nil {
			return CheckResult{Status: CheckFailed, Detail: "bad body regex: " + err.Error()}
		}
		if !re.Match(body) {
			return CheckResult{Status: CheckFailed, Detail: "body does not match " + c.Expect.Body}
		}
	}
	return CheckResult{Status: CheckPassed, Detail: fmt.Sprintf("status %d", resp.StatusCode)}
}

func tcp(ctx context.Context, c frankrepo.Check) CheckResult {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", c.Target)
	if err != nil {
		return CheckResult{Status: CheckFailed, Detail: err.Error()}
	}
	_ = conn.Close()
	return CheckResult{Status: CheckPassed, Detail: "connected"}
}

// Ancestry answers "does descendant contain ancestor" (GitHub compare API).
type Ancestry interface {
	Contains(ctx context.Context, ancestor, descendant string) (bool, error)
}

// Applied reports whether app's last sync operation applied a revision that
// contains mergeSHA, with the application healthy.
func Applied(ctx context.Context, app live.Application, mergeSHA, repo string, anc Ancestry) (bool, string) {
	rev := app.AppliedRevision(repo)
	if rev == "" {
		return false, app.Name + ": no sync operation recorded for " + repo
	}
	if app.OperationPhase != "Succeeded" {
		return false, app.Name + ": last sync operation " + app.OperationPhase
	}
	ok := rev == mergeSHA
	if !ok && anc != nil {
		var err error
		if ok, err = anc.Contains(ctx, mergeSHA, rev); err != nil {
			return false, app.Name + ": cannot compare revisions: " + err.Error()
		}
	}
	if !ok {
		return false, fmt.Sprintf("%s: last sync operation applied %.8s, not the merge %.8s (Synced at %.8s does not count)", app.Name, rev, mergeSHA, app.SyncRevision)
	}
	if app.Health != "Healthy" {
		return false, app.Name + ": health " + app.Health
	}
	return true, fmt.Sprintf("%s: operationState applied %.8s", app.Name, rev)
}

// Outcome targets.
const (
	OutcomeWaiting  = "waiting" // stay merged (not yet applied)
	OutcomeApplied  = "applied"
	OutcomeVerified = "verified"
	OutcomeFailed   = "failed"
)

// Outcome is a verification step's result.
type Outcome struct {
	To      string
	Reason  string
	Display string
	Rollout string
}

// WorkloadInput is what workload verification reads.
type WorkloadInput struct {
	Apps     []string
	MergeSHA string
	Repo     string
	Snapshot *live.Snapshot
	Ancestry Ancestry
	Smoke    map[string]SmokeResult // latest smoke result per app, run after apply
}

// Workload verifies a chart/image update.
func Workload(ctx context.Context, in WorkloadInput) Outcome {
	if in.Snapshot == nil || !in.Snapshot.OK("applications") {
		return Outcome{To: OutcomeWaiting, Display: "merged, not yet applied", Reason: "cluster unreachable"}
	}
	var rollouts []string
	for _, name := range in.Apps {
		var app *live.Application
		for i := range in.Snapshot.Apps {
			if in.Snapshot.Apps[i].Name == name {
				app = &in.Snapshot.Apps[i]
			}
		}
		if app == nil {
			return Outcome{To: OutcomeWaiting, Display: "merged, not yet applied", Reason: "no Application named " + name}
		}
		ok, why := Applied(ctx, *app, in.MergeSHA, in.Repo, in.Ancestry)
		if !ok {
			return Outcome{To: OutcomeWaiting, Display: "merged, not yet applied", Reason: why}
		}
		rollouts = append(rollouts, why)
	}
	rollout := strings.Join(rollouts, "; ")
	var summaries []string
	for _, name := range in.Apps {
		r, ok := in.Smoke[name]
		if !ok {
			return Outcome{To: OutcomeApplied, Display: "rolled out, unverified", Rollout: rollout, Reason: "smoke test pending for " + name}
		}
		if f := r.FirstFailure(); f != "" {
			return Outcome{To: OutcomeFailed, Rollout: rollout, Reason: "failed at step smoke " + name + " — " + f}
		}
		if !r.Passed() {
			return Outcome{To: OutcomeFailed, Rollout: rollout, Reason: "no runnable smoke check for " + name}
		}
		summaries = append(summaries, r.Summary())
	}
	return Outcome{To: OutcomeVerified, Display: "verified", Rollout: rollout, Reason: strings.Join(summaries, "; ")}
}

// OS verifies an OS step: running == declared on every node, all Ready, and
// the cluster's smoke checks pass. Between merge and that point it reports
// "declared, applying".
func OS(decl frankrepo.ClusterVersions, snap *live.Snapshot, smoke []SmokeResult) Outcome {
	if snap == nil || !snap.OK("nodes") || len(snap.Nodes) == 0 {
		return Outcome{To: OutcomeWaiting, Display: "declared, applying", Reason: "nodes unreadable"}
	}
	var behind, unready []string
	for _, n := range snap.Nodes {
		if (decl.Talos != "" && n.Talos != decl.Talos) || (decl.Kubernetes != "" && n.Kubelet != decl.Kubernetes) {
			behind = append(behind, fmt.Sprintf("%s (talos %s, k8s %s)", n.Name, n.Talos, n.Kubelet))
		}
		if !n.Ready {
			unready = append(unready, n.Name)
		}
	}
	sort.Strings(behind)
	if len(behind) > 0 {
		return Outcome{To: OutcomeWaiting, Display: "declared, applying", Reason: "not yet on the declared version: " + strings.Join(behind, ", ")}
	}
	if len(unready) > 0 {
		return Outcome{To: OutcomeWaiting, Display: "declared, applying", Reason: "nodes not Ready: " + strings.Join(unready, ", ")}
	}
	var summaries []string
	for _, r := range smoke {
		if f := r.FirstFailure(); f != "" {
			return Outcome{To: OutcomeFailed, Reason: "failed at step smoke " + r.App + " — " + f}
		}
		summaries = append(summaries, r.Summary())
	}
	return Outcome{To: OutcomeVerified, Display: "verified", Rollout: fmt.Sprintf("%d nodes on talos %s / k8s %s", len(snap.Nodes), decl.Talos, decl.Kubernetes), Reason: strings.Join(summaries, "; ")}
}

// RolloutDecisions lists paused or aborted rollouts (R18, Needs action).
func RolloutDecisions(snap *live.Snapshot) []live.Rollout {
	if snap == nil {
		return nil
	}
	var out []live.Rollout
	for _, r := range snap.Rollouts {
		if r.NeedsDecision() {
			out = append(out, r)
		}
	}
	return out
}
