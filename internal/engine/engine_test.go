package engine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/cidiag"
	"github.com/derio-net/cluster-update-fr/internal/forge"
	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/inventory"
	"github.com/derio-net/cluster-update-fr/internal/live"
)

var t0 = time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)

type fakeForge struct {
	merged      []int
	mergeSHAs   []string
	mergeErr    error
	branches    []string
	branchMerge []string
	conflict    map[string]bool
	prs         []forge.PR
	bodies      map[int]string
	reverts     []string
	issue       forge.Issue
}

func (f *fakeForge) Merge(_ context.Context, n int, sha string) (string, error) {
	if f.mergeErr != nil {
		return "", f.mergeErr
	}
	f.merged = append(f.merged, n)
	f.mergeSHAs = append(f.mergeSHAs, sha)
	return fmt.Sprintf("merge-%d", n), nil
}
func (f *fakeForge) CreateBranch(_ context.Context, b, _ string) error {
	f.branches = append(f.branches, b)
	return nil
}
func (f *fakeForge) MergeBranch(_ context.Context, _, head, _ string) error {
	if f.conflict[head] {
		return &forge.Error{Status: 409, Message: "conflict"}
	}
	f.branchMerge = append(f.branchMerge, head)
	return nil
}
func (f *fakeForge) CreatePR(_ context.Context, title, head, base, body string) (forge.PR, error) {
	pr := forge.PR{Number: 100 + len(f.prs), Title: title, HeadRef: head, Body: body, HeadSHA: "batchsha"}
	f.prs = append(f.prs, pr)
	return pr, nil
}
func (f *fakeForge) ParentOf(_ context.Context, sha string) (string, error) {
	return "parent-of-" + sha, nil
}
func (f *fakeForge) RestoreFiles(_ context.Context, branch, ref string, files []string, _ string) error {
	for _, p := range files {
		f.reverts = append(f.reverts, branch+"@"+ref+":"+p)
	}
	return nil
}
func (f *fakeForge) FindIssue(context.Context, string) (forge.Issue, error) { return f.issue, nil }
func (f *fakeForge) UpdateIssueBody(_ context.Context, _ int, body string) error {
	f.issue.Body = body
	return nil
}

type memLedger struct {
	holds    map[string]string
	approved map[string]string
	retries  map[string]int
	events   []Event
}

func newLedger() *memLedger {
	return &memLedger{holds: map[string]string{}, approved: map[string]string{}, retries: map[string]int{}}
}
func (l *memLedger) Hold(id string) (bool, string) { by, ok := l.holds[id]; return ok, by }
func (l *memLedger) SetHold(id string, held bool, by string) {
	if held {
		l.holds[id] = by
	} else {
		delete(l.holds, id)
	}
}
func (l *memLedger) Approved(id string) (bool, string) { by, ok := l.approved[id]; return ok, by }
func (l *memLedger) SetApproved(id, by string)         { l.approved[id] = by }
func (l *memLedger) Retries(id string) int             { return l.retries[id] }
func (l *memLedger) AddRetry(id string)                { l.retries[id]++ }
func (l *memLedger) Record(e Event)                    { l.events = append(l.events, e) }

func (l *memLedger) actions() []string {
	var out []string
	for _, e := range l.events {
		out = append(out, e.Action)
	}
	return out
}

func policy() frankrepo.Policy {
	return frankrepo.Policy{
		MergeWindow: 24 * time.Hour,
		Defaults:    map[string]string{"patch": frankrepo.PathAutoMerge, "minor": frankrepo.PathBatchApprove, "major": frankrepo.PathSession},
	}
}

const body = "| Package | Change |\n|---|---|\n| [%s](x) | `%s` -> `%s` |\n\n - [ ] <!-- rebase-check -->If you want to rebase/retry this PR, check this box"

func pr(n int, dep, from, to string, opened time.Time, labels ...string) forge.PR {
	return forge.PR{Number: n, NodeID: fmt.Sprintf("PR_%d", n), Title: "Update " + dep, HeadSHA: fmt.Sprintf("sha%d", n),
		HeadRef: "renovate/" + strings.ReplaceAll(dep, "/", "-"), Author: "frank-renovate[bot]",
		Body: fmt.Sprintf(body, dep, from, to), CreatedAt: opened, UpdatedAt: opened, Labels: labels}
}

func passed() map[string]cidiag.Verdict { return map[string]cidiag.Verdict{} }

func newEngine(f *fakeForge, l *memLedger, now *time.Time, inv *inventory.Inventory) *Engine {
	return &Engine{Forge: f, Ledger: l, Policy: policy(), Now: func() time.Time { return *now },
		Inventory: func() *inventory.Inventory { return inv }}
}

func emptyInv() *inventory.Inventory { return &inventory.Inventory{} }

func build(e *Engine, prs []forge.PR, ci map[string]cidiag.Verdict) []Item {
	verdict := func(p forge.PR) (cidiag.Verdict, string) {
		if v, ok := ci[p.HeadSHA]; ok {
			return v, string(v)
		}
		return cidiag.Passed, "CI passed"
	}
	return e.Build(prs, verdict)
}

func TestAutoMergeCountdownCIAndHold(t *testing.T) {
	f, l := &fakeForge{}, newLedger()
	now := t0
	e := newEngine(f, l, &now, emptyInv())
	p := pr(7, "ghcr.io/gethomepage/homepage", "v1.4.0", "v1.4.1", t0)
	items := build(e, []forge.PR{p}, passed())
	if len(items) != 1 || items[0].Path != frankrepo.PathAutoMerge || !items[0].MergeAt.Equal(t0.Add(24*time.Hour)) || items[0].State != StateCountdown {
		t.Fatalf("item = %+v", items)
	}
	e.Tick(context.Background(), items)
	if len(f.merged) != 0 {
		t.Fatal("merged before the countdown elapsed")
	}
	now = t0.Add(25 * time.Hour)
	// CI failed: never merges.
	items = build(e, []forge.PR{p}, map[string]cidiag.Verdict{"sha7": cidiag.Failed})
	e.Tick(context.Background(), items)
	if len(f.merged) != 0 {
		t.Fatal("merged without passing CI")
	}
	if items[0].State != StateHeldCI {
		t.Errorf("state = %s", items[0].State)
	}
	// Held by the operator: never merges.
	if err := e.Hold(items[0].ID, "derio"); err != nil {
		t.Fatal(err)
	}
	items = build(e, []forge.PR{p}, passed())
	e.Tick(context.Background(), items)
	if len(f.merged) != 0 || items[0].State != StateHeld {
		t.Fatalf("held item merged or wrong state %s", items[0].State)
	}
	_ = e.Unhold(items[0].ID, "derio")
	items = build(e, []forge.PR{p}, passed())
	e.Tick(context.Background(), items)
	if len(f.merged) != 1 || f.mergeSHAs[0] != "sha7" {
		t.Fatalf("merged = %v shas = %v", f.merged, f.mergeSHAs)
	}
	got := l.actions()
	want := []string{"held", "released", "merged"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("history = %v, want %v", got, want)
	}
	if last := l.events[len(l.events)-1]; last.By != ApproverAuto || last.PR != 7 || last.SHA != "merge-7" {
		t.Errorf("merge event = %+v", last)
	}
}

func TestMergeNowNeedsPassingCI(t *testing.T) {
	f, l := &fakeForge{}, newLedger()
	now := t0
	e := newEngine(f, l, &now, emptyInv())
	p := pr(7, "ghcr.io/gethomepage/homepage", "v1.4.0", "v1.4.1", t0)
	items := build(e, []forge.PR{p}, map[string]cidiag.Verdict{"sha7": cidiag.Pending})
	if err := e.MergeNow(context.Background(), items, items[0].ID, "derio"); !errors.Is(err, ErrCINotPassed) {
		t.Fatalf("MergeNow without CI: %v", err)
	}
	items = build(e, []forge.PR{p}, passed())
	if err := e.MergeNow(context.Background(), items, items[0].ID, "derio"); err != nil {
		t.Fatal(err)
	}
	if len(f.merged) != 1 || l.events[0].By != "derio" {
		t.Errorf("merge-now: merged=%v events=%+v", f.merged, l.events)
	}
}

func TestMovedHeadIsNotMergedBlind(t *testing.T) {
	f, l := &fakeForge{mergeErr: &forge.Error{Status: 409, Message: "Head branch was modified"}}, newLedger()
	now := t0.Add(48 * time.Hour)
	e := newEngine(f, l, &now, emptyInv())
	items := build(e, []forge.PR{pr(7, "x/y", "1.0.0", "1.0.1", t0)}, passed())
	e.Tick(context.Background(), items)
	if len(l.events) != 1 || l.events[0].Action != "merge-refused" {
		t.Fatalf("events = %+v", l.events)
	}
}

func TestSecurityFirstAndApproveNow(t *testing.T) {
	f, l := &fakeForge{}, newLedger()
	now := t0
	inv := &inventory.Inventory{Deps: []inventory.Dependency{{
		Cluster: "frank", Service: "caddy", Kind: "image", Name: "docker.io/library/caddy", Path: frankrepo.PathBatchApprove,
		Vulns: []live.Vuln{{ID: "CVE-1", Severity: "CRITICAL", Fixed: "2.10.1"}},
	}}}
	e := newEngine(f, l, &now, inv)
	prs := []forge.PR{
		pr(1, "ghcr.io/gethomepage/homepage", "v1.4.0", "v1.5.0", t0),
		pr(2, "caddy", "2.10.0", "2.10.1", t0),                          // fixes a running Critical
		pr(3, "golang.org/x/net", "v0.30.0", "v0.33.0", t0, "security"), // Renovate vulnerability alert
	}
	items := build(e, prs, passed())
	if !items[0].Security || !items[1].Security || items[2].Security {
		t.Fatalf("security not sorted first: %+v", []bool{items[0].Security, items[1].Security, items[2].Security})
	}
	if items[0].PR.Number != 2 && items[1].PR.Number != 2 {
		t.Error("caddy fix must be a security item")
	}
	var caddy Item
	for _, it := range items {
		if it.PR.Number == 2 {
			caddy = it
		}
	}
	if caddy.Path != frankrepo.PathBatchApprove || !caddy.CanApproveNow() {
		t.Fatalf("caddy = %+v", caddy)
	}
	if err := e.ApproveNow(context.Background(), items, caddy.ID, "derio"); err != nil {
		t.Fatal(err)
	}
	if len(f.merged) != 1 || f.merged[0] != 2 {
		t.Errorf("approve-now must merge the security item alone: %v", f.merged)
	}
	// A security item on the session path offers Start session, not Approve now.
	sess := Item{Path: frankrepo.PathSession, Security: true}
	if sess.CanApproveNow() || !sess.NeedsSession() {
		t.Error("session-path security item")
	}
}

func TestApproveNowWaitsForCIThenMerges(t *testing.T) {
	f, l := &fakeForge{}, newLedger()
	now := t0
	e := newEngine(f, l, &now, emptyInv())
	p := pr(3, "golang.org/x/net", "v0.30.0", "v0.33.0", t0, "security")
	items := build(e, []forge.PR{p}, map[string]cidiag.Verdict{"sha3": cidiag.Pending})
	if err := e.ApproveNow(context.Background(), items, items[0].ID, "derio"); err != nil {
		t.Fatal(err)
	}
	if len(f.merged) != 0 {
		t.Fatal("merged before CI passed")
	}
	items = build(e, []forge.PR{p}, passed())
	if items[0].State != StateApproved {
		t.Fatalf("state = %s", items[0].State)
	}
	e.Tick(context.Background(), items)
	if len(f.merged) != 1 {
		t.Fatal("approved item not merged once CI passed")
	}
	if l.events[len(l.events)-1].By != "derio" {
		t.Error("the approver, not auto, must be recorded")
	}
}

func TestSuggestAndApproveBatch(t *testing.T) {
	f, l := &fakeForge{conflict: map[string]bool{"sha3": true}}, newLedger()
	now := t0
	e := newEngine(f, l, &now, emptyInv())
	prs := []forge.PR{
		pr(1, "a", "1.0.0", "1.1.0", t0),
		pr(2, "b", "1.0.0", "1.1.0", t0),
		pr(3, "c", "1.0.0", "1.1.0", t0),
		pr(4, "d", "1.0.0", "1.0.1", t0), // patch → auto-merge, not batch
	}
	items := build(e, prs, passed())
	suggested := SuggestBatch(items)
	if len(suggested) != 3 {
		t.Fatalf("suggested = %d", len(suggested))
	}
	// The operator edits the batch: drops b.
	pick := []string{suggested[0].ID, suggested[2].ID}
	res, err := e.ApproveBatch(context.Background(), items, pick, "derio")
	if err != nil {
		t.Fatal(err)
	}
	if len(f.prs) != 1 || res.PR.Number != 100 {
		t.Fatalf("one batch PR expected: %+v", f.prs)
	}
	// c1s-r9: each member is merged into the batch by its VERIFIED head SHA,
	// never by branch name (a push after verification must not ride along).
	if strings.Join(f.branchMerge, ",") != "sha1" || len(res.Skipped) != 1 || res.Skipped[0] != "c" {
		t.Errorf("merged=%v skipped=%v", f.branchMerge, res.Skipped)
	}
	if ev := l.events[len(l.events)-1]; ev.Action != "batch-approved" || strings.Join(ev.Members, ",") != suggested[0].ID {
		t.Errorf("the batch record must carry its members (c1c-r3): %+v", ev)
	}
	if ok, by := l.Approved(BatchID(100)); !ok || by != "derio" {
		t.Error("the batch PR is approved for merge once CI passes")
	}
	if !strings.Contains(f.prs[0].Body, "Revert") {
		t.Error("batch PR body must state its rollback")
	}
	if _, err := e.ApproveBatch(context.Background(), items, []string{suggested[0].ID, "nope"}, "derio"); err == nil {
		t.Error("unknown item must be refused")
	}
}

func TestRollbackText(t *testing.T) {
	cases := []struct {
		it   Item
		want string
	}{
		{Item{Path: frankrepo.PathAutoMerge, Kind: "image"}, "revert PR"},
		{Item{Path: frankrepo.PathSession, Kind: "image", Stateful: true}, "Longhorn snapshot"},
		{Item{Path: frankrepo.PathSession, Kind: "talos", Cluster: "frank"}, "through Omni"},
		{Item{Path: frankrepo.PathSession, Kind: "talos", Cluster: "hop"}, "talosctl rollback"},
		{Item{Path: frankrepo.PathSession, Kind: "kubernetes", UpdateType: "minor"}, "ONE-WAY"},
		{Item{Path: frankrepo.PathOperatorRunbook, Kind: "omni"}, "runbook"},
	}
	for _, c := range cases {
		if got := Rollback(c.it); !strings.Contains(got, c.want) {
			t.Errorf("Rollback(%+v) = %q, want %q", c.it, got, c.want)
		}
	}
}

// c1c-r12: the revert PR is the console's own — a branch on
// cluster-update/revert-<n>-, the reverted PR's files restored to the merge
// commit's parent — and opening it changes no state.
func TestRevert(t *testing.T) {
	f, l := &fakeForge{}, newLedger()
	now := t0
	e := newEngine(f, l, &now, emptyInv())
	n, _, err := e.Revert(context.Background(), forge.PR{Number: 7, Title: "Update x", MergeCommitSHA: "m7"}, []string{"apps/x/values.yaml"}, "pr-7", "derio")
	if err != nil || n != 100 {
		t.Fatalf("revert = %d %v", n, err)
	}
	if len(f.branches) != 1 || !strings.HasPrefix(f.branches[0], RevertBranchPrefix+"7-") {
		t.Fatalf("revert branch = %v", f.branches)
	}
	if len(f.reverts) != 1 || f.reverts[0] != f.branches[0]+"@parent-of-m7:apps/x/values.yaml" {
		t.Fatalf("restored = %v", f.reverts)
	}
	if f.prs[0].HeadRef != f.branches[0] || l.events[0].Action != "revert-opened" || l.events[0].Item != "pr-7" || l.events[0].PR != 100 {
		t.Fatalf("pr %+v events %+v", f.prs, l.events)
	}
}

func TestCIRetryAtMostOnce(t *testing.T) {
	f, l := &fakeForge{}, newLedger()
	now := t0.Add(48 * time.Hour)
	e := newEngine(f, l, &now, emptyInv())
	p := pr(7, "x/y", "1.0.0", "1.0.1", t0)
	var attempts int
	e.Diagnose = func(context.Context, forge.PR) cidiag.Diagnosis { return cidiag.Diagnosis{Cause: cidiag.RanFailed} }
	e.Act = func(context.Context, forge.PR, cidiag.Diagnosis) (cidiag.Action, error) {
		attempts++
		return cidiag.Action{Kind: cidiag.ActionRebase}, nil
	}
	items := build(e, []forge.PR{p}, map[string]cidiag.Verdict{"sha7": cidiag.Failed})
	// Auto-merge items auto-retry the ran-and-failed case once.
	e.Tick(context.Background(), items)
	if attempts != 1 {
		t.Fatalf("attempts = %d", attempts)
	}
	items = build(e, []forge.PR{p}, map[string]cidiag.Verdict{"sha7": cidiag.Failed})
	e.Tick(context.Background(), items)
	if attempts != 1 {
		t.Fatalf("a second automatic retry happened: %d", attempts)
	}
	if items[0].State != StateFailedCI {
		t.Errorf("after a failed retry the item is failed — CI: %s", items[0].State)
	}
	if err := e.RetryCI(context.Background(), items, items[0].ID, "derio"); !errors.Is(err, ErrRetryExhausted) {
		t.Errorf("manual retry after exhaustion: %v", err)
	}
}

// c1c-r2: the one-retry budget belongs to the UPDATE, not to a head SHA —
// the retry itself (Renovate rebase) moves the head, and a genuine failure
// must not earn a fresh retry with every rebase.
func TestRetryBudgetSurvivesAMovingHead(t *testing.T) {
	f, l := &fakeForge{}, newLedger()
	now := t0.Add(48 * time.Hour)
	e := newEngine(f, l, &now, emptyInv())
	attempts := 0
	e.Diagnose = func(context.Context, forge.PR) cidiag.Diagnosis { return cidiag.Diagnosis{Cause: cidiag.RanFailed} }
	e.Act = func(context.Context, forge.PR, cidiag.Diagnosis) (cidiag.Action, error) {
		attempts++
		return cidiag.Action{Kind: cidiag.ActionRebase}, nil
	}
	p := pr(7, "x/y", "1.0.0", "1.0.1", t0)
	e.Tick(context.Background(), build(e, []forge.PR{p}, map[string]cidiag.Verdict{"sha7": cidiag.Failed}))
	p.HeadSHA = "sha7-rebased" // the rebase the retry asked for
	items := build(e, []forge.PR{p}, map[string]cidiag.Verdict{"sha7-rebased": cidiag.Failed})
	e.Tick(context.Background(), items)
	if attempts != 1 {
		t.Fatalf("a rebased head earned another retry: %d attempts", attempts)
	}
	if items[0].State != StateFailedCI {
		t.Errorf("state after the retried CI failed on the new head = %s", items[0].State)
	}
	if err := e.RetryCI(context.Background(), items, items[0].ID, "derio"); !errors.Is(err, ErrRetryExhausted) {
		t.Errorf("manual retry on the new head: %v", err)
	}
}

func TestBatchItemsWaitForTheButton(t *testing.T) {
	f, l := &fakeForge{}, newLedger()
	now := t0.Add(48 * time.Hour)
	e := newEngine(f, l, &now, emptyInv())
	attempts := 0
	e.Diagnose = func(context.Context, forge.PR) cidiag.Diagnosis { return cidiag.Diagnosis{Cause: cidiag.NeverRan} }
	e.Act = func(context.Context, forge.PR, cidiag.Diagnosis) (cidiag.Action, error) {
		attempts++
		return cidiag.Action{Kind: cidiag.ActionRedeliver}, nil
	}
	p := pr(1, "a", "1.0.0", "1.1.0", t0)
	items := build(e, []forge.PR{p}, map[string]cidiag.Verdict{"sha1": cidiag.Missing})
	e.Tick(context.Background(), items)
	if attempts != 0 {
		t.Fatal("non-auto-merge items must wait for the Retry button")
	}
	if err := e.RetryCI(context.Background(), items, items[0].ID, "derio"); err != nil || attempts != 1 {
		t.Fatalf("retry: %v attempts=%d", err, attempts)
	}
	if l.events[len(l.events)-1].Action != "ci-retry" || !strings.Contains(l.events[len(l.events)-1].Detail, "never-ran") {
		t.Errorf("diagnosis must be kept in history: %+v", l.events)
	}
}

func TestRolloutsAppAlwaysSession(t *testing.T) {
	f, l := &fakeForge{}, newLedger()
	now := t0
	inv := &inventory.Inventory{Deps: []inventory.Dependency{{Cluster: "frank", Service: "litellm", Kind: "image", Name: "ghcr.io/berriai/litellm", Path: frankrepo.PathSession}}}
	e := newEngine(f, l, &now, inv)
	items := build(e, []forge.PR{pr(7, "ghcr.io/berriai/litellm", "v1.80.0", "v1.80.3", t0)}, passed())
	if items[0].Path != frankrepo.PathSession || items[0].App != "litellm" {
		t.Fatalf("item = %+v", items[0])
	}
	now = t0.Add(48 * time.Hour)
	e.Tick(context.Background(), items)
	if len(f.merged) != 0 {
		t.Fatal("a session-path item must never be auto-merged")
	}
}

func TestItemsInAnOpenBatchAreNotSuggestedAgain(t *testing.T) {
	f, l := &fakeForge{}, newLedger()
	now := t0
	e := newEngine(f, l, &now, emptyInv())
	batch := forge.PR{Number: 100, Title: "Batch update (1): a", HeadRef: BatchBranchPrefix + "x", HeadSHA: "b",
		Body: "- a `1.0.0` → `1.1.0` (#1)", CreatedAt: t0}
	items := build(e, []forge.PR{pr(1, "a", "1.0.0", "1.1.0", t0), pr(2, "b", "1.0.0", "1.1.0", t0), batch}, passed())
	s := SuggestBatch(items)
	if len(s) != 1 || s[0].PR.Number != 2 {
		t.Fatalf("suggested = %+v", s)
	}
	for _, it := range items {
		if it.PR.Number == 1 && it.State != StateInBatch {
			t.Errorf("state = %s", it.State)
		}
		if it.Batch && it.Path != frankrepo.PathBatchApprove {
			t.Errorf("batch PR path = %s", it.Path)
		}
	}
}
