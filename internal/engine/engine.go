// Package engine is the merge engine. The console is the ONLY merger
// (Renovate runs with automerge false): this package decides when an
// auto-merge countdown has elapsed, holds and merge-now, the suggested batch
// and its single PR, security items jumping the queue, and the one-retry CI
// recovery rule (R6, R7, R9, R14, R19, R28).
package engine

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/cidiag"
	"github.com/derio-net/cluster-update-fr/internal/forge"
	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/inventory"
	"github.com/derio-net/cluster-update-fr/internal/live"
	"github.com/derio-net/cluster-update-fr/internal/renovate"
)

// ApproverAuto is the approver recorded for countdown merges.
const ApproverAuto = "auto"

// BatchBranchPrefix starts every console-assembled batch branch.
const BatchBranchPrefix = "cluster-update/batch-"

// Item states.
const (
	StateCountdown = "countdown"     // auto-merge, waiting for MergeAt
	StateReady     = "ready"         // will merge on the next tick
	StateWaiting   = "waiting-ci"    // CI pending / release-age gate
	StateApproved  = "approved"      // approved; merges once CI passes
	StateHeld      = "held"          // held by the operator
	StateHeldCI    = "held-ci"       // no passing CI signal; diagnose + retry
	StateFailedCI  = "failed-ci"     // the one retry failed: needs the operator
	StateBatch     = "batch"         // batch-approve, awaiting the batch
	StateSession   = "needs-session" // session path
	StateRunbook   = "runbook"       // operator-runbook path
	StateInBatch   = "in-batch"      // part of an open console batch PR
)

// Event is one History entry produced by the engine.
type Event struct {
	At     time.Time
	Item   string
	Action string
	By     string
	PR     int
	SHA    string
	Detail string
}

// Ledger persists what the engine decides (implemented by the store).
type Ledger interface {
	Hold(id string) (bool, string)
	SetHold(id string, held bool, by string)
	Approved(id string) (bool, string)
	SetApproved(id, by string)
	Retries(id, sha string) int
	AddRetry(id, sha string)
	Record(e Event)
}

// Forge is the GitHub surface the engine writes through.
type Forge interface {
	Merge(ctx context.Context, n int, sha string) (string, error)
	CreateBranch(ctx context.Context, branch, base string) error
	MergeBranch(ctx context.Context, base, head, message string) error
	CreatePR(ctx context.Context, title, head, base, body string) (forge.PR, error)
	RevertPR(ctx context.Context, nodeID, title, body string) (int, string, error)
}

// Item is one update candidate (an open Renovate or batch PR).
type Item struct {
	ID         string
	PR         forge.PR
	Deps       []renovate.Dep
	Name       string
	From, To   string
	Kind       string
	Cluster    string
	App        string
	Path       string
	PathReason string
	UpdateType string
	Security   bool
	Vulns      []live.Vuln
	Stateful   bool
	Batch      bool // a console-assembled batch PR
	MergeAt    time.Time
	CI         cidiag.Verdict
	CIDetail   string
	State      string
	HeldBy     string
	ApprovedBy string
	Retried    bool
	Rollback   string
}

// CanApproveNow: auto-merge and batch-approve items (security or not) can be
// approved alone, immediately.
func (it Item) CanApproveNow() bool {
	return it.Path == frankrepo.PathAutoMerge || it.Path == frankrepo.PathBatchApprove
}

// NeedsSession: session-path items run as upgrade sessions.
func (it Item) NeedsSession() bool { return it.Path == frankrepo.PathSession }

// Engine merges.
type Engine struct {
	Forge     Forge
	Ledger    Ledger
	Policy    frankrepo.Policy
	Now       func() time.Time
	Inventory func() *inventory.Inventory
	// Diagnose and Act perform CI diagnosis and one recovery action
	// (cidiag.Diagnose / cidiag.Recover bound to the forges).
	Diagnose func(ctx context.Context, pr forge.PR) cidiag.Diagnosis
	Act      func(ctx context.Context, pr forge.PR, d cidiag.Diagnosis) (cidiag.Action, error)
}

// Errors.
var (
	ErrUnknownItem    = errors.New("engine: no such update")
	ErrCINotPassed    = errors.New("engine: CI has not passed")
	ErrWrongPath      = errors.New("engine: not allowed on this update path")
	ErrRetryExhausted = errors.New("engine: CI was already retried once; the update is failed and needs you")
	ErrHeld           = errors.New("engine: update is held")
)

var batchRef = regexp.MustCompile(`\(#(\d+)\)`)

// ItemID names the item of a Renovate PR.
func ItemID(n int) string { return fmt.Sprintf("pr-%d", n) }

// BatchID names the item of a console batch PR.
func BatchID(n int) string { return fmt.Sprintf("batch-%d", n) }

var pathRank = map[string]int{frankrepo.PathAutoMerge: 0, frankrepo.PathBatchApprove: 1, frankrepo.PathSession: 2, frankrepo.PathOperatorRunbook: 3, frankrepo.PathUnclassified: 2}

func stricter(a, b string) string {
	if pathRank[b] > pathRank[a] {
		return b
	}
	return a
}

// Build turns open PRs into items. verdict gives each PR's CI verdict.
func (e *Engine) Build(prs []forge.PR, verdict func(forge.PR) (cidiag.Verdict, string)) []Item {
	now := e.Now()
	var inv *inventory.Inventory
	if e.Inventory != nil {
		inv = e.Inventory()
	}
	var items []Item
	for _, p := range prs {
		isBatch := strings.HasPrefix(p.HeadRef, BatchBranchPrefix)
		if !isBatch && !strings.HasPrefix(p.HeadRef, "renovate/") {
			continue
		}
		it := Item{PR: p, Batch: isBatch}
		if isBatch {
			it.ID = BatchID(p.Number)
		} else {
			it.ID = ItemID(p.Number)
		}
		it.Deps = renovate.ParsePR(p.Body)
		it.Security = renovate.IsSecurity(p.Title, p.Body, p.Labels)
		it.Path = ""
		for i, d := range it.Deps {
			path, reason, kind, cluster, app, stateful, vulns := e.classify(inv, d)
			if i == 0 {
				it.Name, it.From, it.To, it.UpdateType = d.Name, d.From, d.To, d.UpdateType
				it.Kind, it.Cluster, it.App, it.PathReason = kind, cluster, app, reason
			}
			if it.Path == "" {
				it.Path = path
			} else {
				it.Path = stricter(it.Path, path)
			}
			it.Stateful = it.Stateful || stateful
			for _, v := range vulns {
				if live.Alarming(v) && v.Fixed != "" {
					it.Security = true
				}
			}
			it.Vulns = append(it.Vulns, vulns...)
		}
		if isBatch {
			it.Path, it.PathReason = frankrepo.PathBatchApprove, "console batch"
			if it.Name == "" {
				it.Name = p.Title
			}
		}
		if it.Path == "" {
			it.Path, it.PathReason = frankrepo.PathUnclassified, "no parsable update in the PR"
			it.Name = p.Title
		}
		it.MergeAt = p.CreatedAt.Add(e.Policy.MergeWindow)
		it.CI, it.CIDetail = verdict(p)
		it.Rollback = Rollback(it)
		it.State = e.state(it, now)
		items = append(items, it)
	}
	// Items already carried by an open batch PR are not suggested again.
	inBatch := map[int]int{}
	for _, it := range items {
		if it.Batch {
			for _, m := range batchRef.FindAllStringSubmatch(it.PR.Body, -1) {
				var n int
				fmt.Sscanf(m[1], "%d", &n)
				inBatch[n] = it.PR.Number
			}
		}
	}
	for i := range items {
		if b, ok := inBatch[items[i].PR.Number]; ok && !items[i].Batch && items[i].State == StateBatch {
			items[i].State = StateInBatch
			items[i].CIDetail = fmt.Sprintf("in batch #%d", b)
		}
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Security != b.Security {
			return a.Security
		}
		if pathRank[a.Path] != pathRank[b.Path] {
			return pathRank[a.Path] < pathRank[b.Path]
		}
		return a.PR.Number < b.PR.Number
	})
	return items
}

// classify resolves one dependency against the inventory and the policy.
func (e *Engine) classify(inv *inventory.Inventory, d renovate.Dep) (path, reason, kind, cluster, app string, stateful bool, vulns []live.Vuln) {
	norm, _ := live.SplitImage(live.NormalizeImage(d.Name))
	kind = "image"
	if !strings.Contains(d.Name, "/") && !strings.Contains(d.Name, ".") {
		kind = "chart"
	}
	switch strings.ToLower(d.Name) {
	case "siderolabs/talos", "talos":
		kind = inventory.KindTalos
	case "kubernetes/kubernetes", "kubernetes":
		kind = inventory.KindKubernetes
	case "siderolabs/omni", "omni":
		kind = inventory.KindOmni
	}
	var matched []inventory.Dependency
	if inv != nil {
		for _, dep := range inv.Deps {
			if dep.Name == d.Name || dep.Name == norm || (dep.Kind == kind && (kind == inventory.KindTalos || kind == inventory.KindKubernetes || kind == inventory.KindOmni)) {
				matched = append(matched, dep)
			}
		}
	}
	if len(matched) > 0 {
		kind, cluster, app = matched[0].Kind, matched[0].Cluster, matched[0].Service
	}
	path, reason = e.Policy.Resolve(frankrepo.Dep{Cluster: cluster, App: app, Kind: kind, Name: d.Name, UpdateType: d.UpdateType})
	for _, m := range matched {
		vulns = append(vulns, m.Vulns...)
		// A non-default rule on the running dependency (stateful, Rollouts,
		// OS, Omni) is about the dependency, not the update type: it wins.
		if !strings.HasPrefix(m.PathReason, "default for") && pathRank[m.Path] > pathRank[path] {
			path, reason = m.Path, m.PathReason
		}
		if strings.Contains(strings.ToLower(m.PathReason), "stateful") {
			stateful = true
		}
	}
	return
}

func (e *Engine) state(it Item, now time.Time) string {
	if held, by := e.Ledger.Hold(it.ID); held {
		_ = by
		return StateHeld
	}
	ciBad := it.CI == cidiag.Failed || it.CI == cidiag.Missing
	if ciBad && e.Ledger.Retries(it.ID, it.PR.HeadSHA) > 0 {
		return StateFailedCI
	}
	if ciBad {
		return StateHeldCI
	}
	if ok, _ := e.Ledger.Approved(it.ID); ok {
		return StateApproved
	}
	switch it.Path {
	case frankrepo.PathAutoMerge:
		if now.Before(it.MergeAt) {
			return StateCountdown
		}
		if it.CI == cidiag.Passed {
			return StateReady
		}
		return StateWaiting
	case frankrepo.PathBatchApprove:
		return StateBatch
	case frankrepo.PathOperatorRunbook:
		return StateRunbook
	}
	return StateSession
}

func find(items []Item, id string) (*Item, error) {
	for i := range items {
		if items[i].ID == id {
			return &items[i], nil
		}
	}
	return nil, ErrUnknownItem
}

func (e *Engine) record(it Item, action, by, sha, detail string) {
	e.Ledger.Record(Event{At: e.Now(), Item: it.ID, Action: action, By: by, PR: it.PR.Number, SHA: sha, Detail: detail})
}

func (e *Engine) merge(ctx context.Context, it Item, by string) error {
	sha, err := e.Forge.Merge(ctx, it.PR.Number, it.PR.HeadSHA)
	if err != nil {
		e.record(it, "merge-refused", by, "", err.Error())
		return err
	}
	e.record(it, "merged", by, sha, it.Name+" "+it.From+" → "+it.To)
	return nil
}

// Tick merges what is due and performs the automatic CI retry. It returns
// the first merge error, but always visits every item.
func (e *Engine) Tick(ctx context.Context, items []Item) error {
	var first error
	for _, it := range items {
		if it.State == StateHeld || it.Path == frankrepo.PathSession || it.Path == frankrepo.PathOperatorRunbook || it.Path == frankrepo.PathUnclassified {
			continue
		}
		approved, by := e.Ledger.Approved(it.ID)
		due := it.Path == frankrepo.PathAutoMerge && !e.Now().Before(it.MergeAt)
		if it.CI == cidiag.Passed && (due || approved) {
			if !approved {
				by = ApproverAuto
			}
			if err := e.merge(ctx, it, by); err != nil && first == nil {
				first = err
			}
			continue
		}
		e.autoRetry(ctx, it)
	}
	return first
}

// autoRetry: auto-merge items get ONE automatic retry, for the ran-and-failed
// case only; a failure after it is recorded once as failed — CI.
func (e *Engine) autoRetry(ctx context.Context, it Item) {
	if it.CI != cidiag.Failed && it.CI != cidiag.Missing {
		return
	}
	n := e.Ledger.Retries(it.ID, it.PR.HeadSHA)
	if n == 1 {
		e.Ledger.AddRetry(it.ID, it.PR.HeadSHA) // mark the failure recorded
		e.record(it, "failed-ci", ApproverAuto, it.PR.HeadSHA, "CI failed again after one retry: "+it.CIDetail)
		return
	}
	if n > 1 || it.Path != frankrepo.PathAutoMerge || e.Diagnose == nil || e.Act == nil {
		return
	}
	d := e.Diagnose(ctx, it.PR)
	if d.Cause != cidiag.RanFailed {
		return // everything else waits for the button
	}
	e.retry(ctx, it, d, ApproverAuto)
}

func (e *Engine) retry(ctx context.Context, it Item, d cidiag.Diagnosis, by string) error {
	a, err := e.Act(ctx, it.PR, d)
	if err != nil {
		e.record(it, "ci-retry-failed", by, it.PR.HeadSHA, string(d.Cause)+": "+err.Error())
		return err
	}
	e.Ledger.AddRetry(it.ID, it.PR.HeadSHA)
	e.record(it, "ci-retry", by, it.PR.HeadSHA, string(d.Cause)+": "+d.Detail+" → "+a.Detail)
	return nil
}

// RetryCI is the "Retry CI" button: diagnose, then one recovery action.
func (e *Engine) RetryCI(ctx context.Context, items []Item, id, by string) error {
	it, err := find(items, id)
	if err != nil {
		return err
	}
	if e.Ledger.Retries(it.ID, it.PR.HeadSHA) > 0 {
		return ErrRetryExhausted
	}
	if e.Diagnose == nil || e.Act == nil {
		return errors.New("engine: CI recovery not configured")
	}
	return e.retry(ctx, *it, e.Diagnose(ctx, it.PR), by)
}

// Hold stops an item from merging.
func (e *Engine) Hold(id, by string) error {
	e.Ledger.SetHold(id, true, by)
	e.Ledger.Record(Event{At: e.Now(), Item: id, Action: "held", By: by})
	return nil
}

// Unhold releases a hold.
func (e *Engine) Unhold(id, by string) error {
	e.Ledger.SetHold(id, false, by)
	e.Ledger.Record(Event{At: e.Now(), Item: id, Action: "released", By: by})
	return nil
}

// MergeNow merges an auto-merge item before its countdown; CI must pass.
func (e *Engine) MergeNow(ctx context.Context, items []Item, id, by string) error {
	it, err := find(items, id)
	if err != nil {
		return err
	}
	if !it.CanApproveNow() {
		return ErrWrongPath
	}
	if it.State == StateHeld {
		return ErrHeld
	}
	if it.CI != cidiag.Passed {
		return ErrCINotPassed
	}
	return e.merge(ctx, *it, by)
}

// ApproveNow approves one auto-merge or batch-approve item alone (security
// items jump the queue this way): it merges at once when CI has passed,
// otherwise on the first tick after CI passes.
func (e *Engine) ApproveNow(ctx context.Context, items []Item, id, by string) error {
	it, err := find(items, id)
	if err != nil {
		return err
	}
	if !it.CanApproveNow() {
		return ErrWrongPath
	}
	e.Ledger.SetApproved(it.ID, by)
	e.record(*it, "approved", by, "", "")
	if it.CI == cidiag.Passed && it.State != StateHeld {
		return e.merge(ctx, *it, by)
	}
	return nil
}

// SuggestBatch returns the routine items proposed for the next batch.
func SuggestBatch(items []Item) []Item {
	var out []Item
	for _, it := range items {
		if it.Path == frankrepo.PathBatchApprove && !it.Batch && !it.Security && it.State == StateBatch {
			out = append(out, it)
		}
	}
	return out
}

// BatchResult is what ApproveBatch produced.
type BatchResult struct {
	PR       forge.PR
	Included []string
	Skipped  []string // conflicted with the batch
}

// ApproveBatch assembles the operator-edited selection into ONE PR: a batch
// branch from main, each selected Renovate branch merged into it (a conflict
// drops that item, named), then a PR approved for merge once CI passes.
func (e *Engine) ApproveBatch(ctx context.Context, items []Item, ids []string, by string) (BatchResult, error) {
	var sel []Item
	for _, id := range ids {
		it, err := find(items, id)
		if err != nil {
			return BatchResult{}, fmt.Errorf("%w: %s", err, id)
		}
		if it.Path != frankrepo.PathBatchApprove || it.Batch {
			return BatchResult{}, fmt.Errorf("%w: %s", ErrWrongPath, id)
		}
		sel = append(sel, *it)
	}
	if len(sel) == 0 {
		return BatchResult{}, errors.New("engine: empty batch")
	}
	branch := BatchBranchPrefix + e.Now().UTC().Format("20060102-150405")
	if err := e.Forge.CreateBranch(ctx, branch, "main"); err != nil {
		return BatchResult{}, err
	}
	var res BatchResult
	var lines []string
	for _, it := range sel {
		if err := e.Forge.MergeBranch(ctx, branch, it.PR.HeadRef, "batch: "+it.PR.Title); err != nil {
			if forge.IsConflict(err) {
				res.Skipped = append(res.Skipped, it.Name)
				continue
			}
			return res, err
		}
		res.Included = append(res.Included, it.Name)
		lines = append(lines, fmt.Sprintf("- %s `%s` → `%s` (#%d)", it.Name, it.From, it.To, it.PR.Number))
	}
	if len(res.Included) == 0 {
		return res, errors.New("engine: every selected update conflicted; nothing to batch")
	}
	body := "Batch of routine updates approved in the update console by " + by + ".\n\n" + strings.Join(lines, "\n") +
		"\n\n**Rollback:** Revert — one-click revert PR from the console's History.\n"
	if len(res.Skipped) > 0 {
		body += "\nLeft out (conflicted with the batch): " + strings.Join(res.Skipped, ", ") + "\n"
	}
	pr, err := e.Forge.CreatePR(ctx, fmt.Sprintf("Batch update (%d): %s", len(res.Included), strings.Join(res.Included, ", ")), branch, "main", body)
	if err != nil {
		return res, err
	}
	res.PR = pr
	e.Ledger.SetApproved(BatchID(pr.Number), by)
	e.Ledger.Record(Event{At: e.Now(), Item: BatchID(pr.Number), Action: "batch-approved", By: by, PR: pr.Number, Detail: strings.Join(res.Included, ", ")})
	return res, nil
}

// Revert opens the one-click revert PR for a merged PR.
func (e *Engine) Revert(ctx context.Context, merged forge.PR, by string) (int, string, error) {
	n, url, err := e.Forge.RevertPR(ctx, merged.NodeID, "Revert: "+merged.Title, "Reverts #"+fmt.Sprint(merged.Number)+" from the update console ("+by+").")
	if err != nil {
		return 0, "", err
	}
	e.Ledger.Record(Event{At: e.Now(), Item: ItemID(merged.Number), Action: "revert-opened", By: by, PR: n, Detail: url})
	return n, url, nil
}

// Rollback states how an item is undone, shown before it is approved (R19).
func Rollback(it Item) string {
	switch {
	case it.Path == frankrepo.PathOperatorRunbook || it.Kind == inventory.KindOmni:
		return "Operator runbook (docs/runbooks/omni-upgrade.md, backup first); the console only tracks Omni."
	case it.Kind == inventory.KindTalos && it.Cluster == "hop":
		return "talosctl rollback on hop-1, then revert versions/hop.yaml (edge downtime)."
	case it.Kind == inventory.KindTalos:
		return "Revert versions/frank.yaml to the previous Talos version and apply it through Omni (not per-node talosctl rollback — Omni would undo it)."
	case it.Kind == inventory.KindKubernetes && it.UpdateType != "patch":
		return "ONE-WAY: a Kubernetes minor cannot be rolled back."
	case it.Kind == inventory.KindKubernetes:
		return "Re-run talosctl upgrade-k8s to the previous patch."
	case it.Stateful:
		return "Restore the Longhorn snapshot the session takes before merging (steps in the brief), then the revert PR."
	}
	return "One-click revert PR from History (reverts the merge commit)."
}
