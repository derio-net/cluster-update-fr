// Package app runs the console's cycle — read the repo, the clusters and the
// forges; rebuild the inventory; merge what is due; verify; alarm; report;
// reconcile — and serves the actions behind the console's buttons.
package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/alarm"
	"github.com/derio-net/cluster-update-fr/internal/cidiag"
	"github.com/derio-net/cluster-update-fr/internal/config"
	"github.com/derio-net/cluster-update-fr/internal/engine"
	"github.com/derio-net/cluster-update-fr/internal/forge"
	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/inventory"
	"github.com/derio-net/cluster-update-fr/internal/live"
	"github.com/derio-net/cluster-update-fr/internal/metrics"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
	"github.com/derio-net/cluster-update-fr/internal/session"
	"github.com/derio-net/cluster-update-fr/internal/store"
	"github.com/derio-net/cluster-update-fr/internal/tracks"
	"github.com/derio-net/cluster-update-fr/internal/trust"
	"github.com/derio-net/cluster-update-fr/internal/verify"
)

// GitHubAPI is the GitHub surface the app uses (forge.GitHub implements it).
type GitHubAPI interface {
	engine.Forge
	OpenPRs(ctx context.Context) ([]forge.PR, error)
	PR(ctx context.Context, n int) (forge.PR, error)
	Statuses(ctx context.Context, sha string) ([]forge.Status, error)
	Releases(ctx context.Context, ownerRepo string) ([]string, error)
	PRCommits(ctx context.Context, n int) ([]forge.Commit, error)
	PRFiles(ctx context.Context, n int) ([]string, error)
	LastPush(ctx context.Context, branch string) (forge.Push, error)
}

// guardedForge routes every merge through the trust guard (re-verify, pin
// the head SHA); everything else goes straight to GitHub.
type guardedForge struct {
	GitHubAPI
	guard *trust.Guard
}

func (g guardedForge) Merge(ctx context.Context, n int, sha string) (string, error) {
	return g.guard.MergePR(ctx, n, sha)
}

// UntrustedPR is an update-looking PR the console refuses to act on.
type UntrustedPR struct {
	Number int
	Title  string
	Author string
	Reason string
}

// Sender posts to the #security topic.
type Sender interface {
	Send(ctx context.Context, text string) error
}

// App is the console.
type App struct {
	Cfg      *config.Config
	Repo     frankrepo.Source
	Frank    live.Getter
	Hop      live.Getter // nil: no Hop kubeconfig configured
	HopScan  func(ctx context.Context) ([]live.Report, error)
	GitHub   GitHubAPI
	Diag     cidiag.Forges // nil: CI recovery unavailable
	Store    *store.Store
	Launcher *session.Launcher
	Telegram Sender
	Smoke    func(ctx context.Context, s frankrepo.Smoke) verify.SmokeResult
	Ancestry verify.Ancestry
	Now      func() time.Time
	Log      *log.Logger

	once   sync.Once
	engine *engine.Engine
	guard  *trust.Guard
	mu     sync.RWMutex
	view   View
	smoke  map[string]verify.SmokeResult
}

// GuidedStep is an OS step shown under Guided upgrades.
type GuidedStep struct {
	tracks.Step
	Session  *session.Record
	Rollback string
}

// RolloutView is a paused/aborted rollout with its cluster.
type RolloutView struct {
	Cluster string
	live.Rollout
	UpgradeID string
}

// View is the last cycle's result, rendered by the pages.
type View struct {
	Built      time.Time
	Decl       *frankrepo.Declarations
	Inventory  *inventory.Inventory
	Items      []engine.Item
	Untrusted  []UntrustedPR
	Suggested  []engine.Item
	Rollouts   []RolloutView
	Guided     []GuidedStep
	Omni       *inventory.Dependency
	Sessions   []session.Record
	Alarms     []alarm.Record
	Updates    []store.Update
	History    []store.Event
	Errors     []string
	Warnings   []string
	LastScan   time.Time
	LastReport time.Time
	ReportHour int
}

const (
	blobAlarms = "alarms"
	blobOutbox = "alarm-outbox"
	blobReport = "report"
)

type reportState struct {
	LastReport time.Time `json:"last_report"`
	LastScan   time.Time `json:"last_scan"`
	LastItems  []string  `json:"last_items"`
}

func (a *App) now() time.Time {
	if a.Now == nil {
		return time.Now()
	}
	return a.Now()
}

func (a *App) logf(format string, args ...any) {
	if a.Log != nil {
		a.Log.Printf(format, args...)
	}
}

func (a *App) eng(policy frankrepo.Policy) *engine.Engine {
	a.once.Do(func() {
		a.guard = &trust.Guard{Cfg: a.trustConfig()}
		var f engine.Forge
		if a.GitHub != nil {
			a.guard.API, a.guard.Merge = a.GitHub, a.GitHub.Merge
			f = guardedForge{GitHubAPI: a.GitHub, guard: a.guard}
		}
		a.engine = &engine.Engine{Forge: f, Ledger: a.Store, Now: a.now}
		if a.Diag != nil {
			web := a.Cfg.GiteaURL
			a.engine.Diagnose = func(ctx context.Context, pr forge.PR) cidiag.Diagnosis { return cidiag.Diagnose(ctx, a.Diag, pr, web) }
			a.engine.Act = func(ctx context.Context, pr forge.PR, d cidiag.Diagnosis) (cidiag.Action, error) {
				return cidiag.Recover(ctx, a.Diag, pr, d, web)
			}
		}
	})
	a.engine.Policy = policy
	return a.engine
}

func (a *App) trustConfig() trust.Config {
	return trust.Config{Repo: a.Cfg.FrankRepo, RenovateBot: a.Cfg.RenovateBot, ConsoleBot: a.Cfg.ConsoleBot, Committers: a.Cfg.TrustedCommitters}
}

// trusted keeps the items whose PR passes every trust condition, lists the
// rest as untrusted, and hands the verified scopes to the merge guard.
func (a *App) trusted(ctx context.Context, items []engine.Item, cache map[string]error) ([]engine.Item, []UntrustedPR) {
	if a.GitHub == nil {
		return nil, nil
	}
	cfg := a.trustConfig()
	scopes := map[int]trust.Scope{}
	check := func(it engine.Item, scope trust.Scope) error {
		key := fmt.Sprintf("%d@%s", it.PR.Number, it.PR.HeadSHA)
		if err, ok := cache[key]; ok {
			return err
		}
		err := cfg.Check(ctx, a.GitHub, it.PR, scope)
		cache[key] = err
		return err
	}
	var kept []engine.Item
	var bad []UntrustedPR
	refuse := func(it engine.Item, err error) {
		bad = append(bad, UntrustedPR{Number: it.PR.Number, Title: trust.Title(it.PR.Title), Author: trust.Title(it.PR.Author), Reason: scrub.String(err.Error())})
	}
	for _, it := range items {
		if it.Batch {
			continue
		}
		scope := trust.ScopeFor(it)
		if err := check(it, scope); err != nil {
			refuse(it, err)
			continue
		}
		scopes[it.PR.Number] = scope
		kept = append(kept, it)
	}
	for _, it := range items {
		if !it.Batch {
			continue
		}
		var member []trust.Scope
		var err error
		for _, n := range engine.BatchMembers(it.PR.Body) {
			sc, ok := scopes[n]
			if !ok {
				err = fmt.Errorf("batch member #%d is not an open, trusted Renovate PR", n)
				break
			}
			member = append(member, sc)
		}
		if err == nil && len(member) == 0 {
			err = errors.New("batch PR lists no members")
		}
		scope := trust.Union(member...)
		if err == nil {
			err = check(it, scope)
		}
		if err != nil {
			refuse(it, err)
			continue
		}
		scopes[it.PR.Number] = scope
		kept = append(kept, it)
	}
	a.guard.SetScopes(scopes)
	return kept, bad
}

// View returns the last cycle's view.
func (a *App) View() View {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.view
}

// Cycle runs one full pass. Every source fails alone: what cannot be read
// shows as unknown and the rest of the cycle still runs.
func (a *App) Cycle(ctx context.Context) View {
	now := a.now()
	v := View{Built: now, ReportHour: a.Cfg.ReportHour}
	fail := func(what string, err error) {
		v.Errors = append(v.Errors, what+": "+scrub.String(err.Error()))
	}

	decl, err := frankrepo.Load(ctx, a.Repo)
	if err != nil {
		fail("frank repo", err)
	}
	if decl == nil {
		decl = &frankrepo.Declarations{}
	}
	for p, e := range decl.Errors {
		v.Errors = append(v.Errors, p+": "+e)
	}
	v.Decl = decl

	var frank, hop *live.Snapshot
	if a.Frank != nil {
		frank = live.Read(ctx, a.Frank, "frank", live.Options{Rollouts: true, Vulns: true})
		for s, e := range frank.Errors {
			v.Errors = append(v.Errors, "frank "+s+": "+e)
		}
	}
	hopScanned := false
	if a.Hop != nil {
		hop = live.Read(ctx, a.Hop, "hop", live.Options{Rollouts: true})
		for s, e := range hop.Errors {
			v.Errors = append(v.Errors, "hop "+s+": "+e)
		}
		if !hop.OK("nodes") {
			hop = nil
		}
	}
	if hop != nil && a.HopScan != nil {
		if reps, err := a.HopScan(ctx); err != nil {
			fail("hop scan", err)
		} else {
			hop.Vulns, hopScanned = reps, true
		}
	}
	omniRunning, omniErr := "", ""
	if a.Cfg.OmniStatusFile != "" {
		if ov, err := live.OmniVersion(a.Cfg.OmniStatusFile); err != nil {
			omniErr = scrub.String(err.Error())
		} else {
			omniRunning = ov
		}
	}

	var prs []forge.PR
	if a.GitHub != nil {
		if prs, err = a.GitHub.OpenPRs(ctx); err != nil {
			fail("github pull requests", err)
		}
	}
	rel := a.releases(ctx, &v)
	latest := map[string]string{}
	if t := tracks.Sorted(rel.Talos); len(t) > 0 {
		latest[inventory.KindTalos] = strings.TrimPrefix(t[len(t)-1], "v")
	}
	if k := tracks.Sorted(rel.Kubernetes); len(k) > 0 {
		latest[inventory.KindKubernetes] = strings.TrimPrefix(k[len(k)-1], "v")
	}
	if o := tracks.Sorted(rel.Omni); len(o) > 0 {
		latest[inventory.KindOmni] = o[len(o)-1]
	}
	e := a.eng(decl.Policy)
	inv := inventory.Build(inventory.Input{Decl: decl, Frank: frank, Hop: hop, OmniRunning: omniRunning, OmniErr: omniErr,
		Latest: latestFromPRs(prs, latest), SessionNamespace: a.Cfg.SessionNamespace})
	v.Inventory = inv
	for i := range inv.Deps {
		if inv.Deps[i].Kind == inventory.KindOmni {
			v.Omni = &inv.Deps[i]
		}
	}
	e.Inventory = func() *inventory.Inventory { return inv }

	statuses := map[string][]forge.Status{}
	verdict := func(p forge.PR) (cidiag.Verdict, string) {
		st, ok := statuses[p.HeadSHA]
		if !ok && a.GitHub != nil {
			if st, err = a.GitHub.Statuses(ctx, p.HeadSHA); err != nil {
				return cidiag.Pending, "statuses unreadable"
			}
			statuses[p.HeadSHA] = st
		}
		return cidiag.Evaluate(st, p.UpdatedAt, now, a.Cfg.CITimeout)
	}
	trustCache := map[string]error{}
	items, untrusted := a.trusted(ctx, e.Build(prs, verdict), trustCache)
	v.Untrusted = untrusted
	for _, it := range items {
		u := store.Update{ID: it.ID, Title: it.PR.Title, Cluster: it.Cluster, Kind: it.Kind, Name: it.Name, From: it.From, To: it.To,
			Path: it.Path, PR: it.PR.Number, Rollback: it.Rollback}
		if it.App != "" {
			u.Apps = []string{it.App}
		}
		if it.Batch {
			u.Kind = "batch"
		}
		a.Store.Track(u)
	}
	if err := e.Tick(ctx, items); err != nil {
		fail("merge", err)
	}
	items, _ = a.trusted(ctx, e.Build(prs, verdict), trustCache) // states after this tick's merges/holds
	v.Items = items
	v.Suggested = engine.SuggestBatch(items)

	a.verify(ctx, decl, frank, hop, &v)
	a.rollouts(frank, hop, &v)
	v.Guided = a.guided(decl, rel)

	a.alarms(ctx, inv, frank, hop, hopScanned, &v)
	a.reconcile(ctx, prs, frank, &v)
	if a.Launcher != nil {
		for _, end := range a.Launcher.Tick(ctx) {
			a.logf("session %s ended: %s", end.ID, end.Outcome)
		}
		for _, w := range a.Launcher.Warnings() {
			v.Warnings = append(v.Warnings, w)
			a.send(ctx, "⏳ "+escape(w))
		}
		v.Sessions = a.Launcher.Sessions()
	}
	rs := reportState{}
	a.Store.GetBlob(blobReport, &rs)
	if frank != nil && frank.OK("pods") {
		rs.LastScan = now
	}
	a.report(ctx, items, &v, &rs)
	_ = a.Store.PutBlob(blobReport, rs)
	v.LastScan, v.LastReport = rs.LastScan, rs.LastReport

	v.Updates = a.Store.Updates()
	v.History = a.Store.History("")
	if len(v.History) > 200 {
		v.History = v.History[:200]
	}
	if a.Store.Warning != "" {
		v.Warnings = append(v.Warnings, a.Store.Warning)
	}
	if err := a.Store.Save(); err != nil {
		fail("state save", err)
	}
	sort.Strings(v.Errors)
	a.mu.Lock()
	a.view = v
	a.mu.Unlock()
	return v
}

type releaseSet struct{ Talos, Kubernetes, Omni []string }

func (a *App) releases(ctx context.Context, v *View) releaseSet {
	var r releaseSet
	if a.GitHub == nil {
		return r
	}
	for _, x := range []struct {
		repo string
		dst  *[]string
	}{{"siderolabs/talos", &r.Talos}, {"kubernetes/kubernetes", &r.Kubernetes}, {"siderolabs/omni", &r.Omni}} {
		tags, err := a.GitHub.Releases(ctx, x.repo)
		if err != nil {
			v.Errors = append(v.Errors, "releases "+x.repo+": "+scrub.String(err.Error()))
			continue
		}
		*x.dst = tags
	}
	return r
}

// latestFromPRs adds each open Renovate update's target as the dependency's
// latest known version.
func latestFromPRs(prs []forge.PR, base map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for _, p := range prs {
		for _, d := range parseDeps(p) {
			name := d.Name
			if strings.Contains(name, "/") || strings.Contains(name, ".") {
				name, _ = live.SplitImage(live.NormalizeImage(d.Name))
			}
			if _, ok := out[name]; !ok {
				out[name] = d.To
			}
		}
	}
	return out
}

// verify advances merged/applied updates (R16).
func (a *App) verify(ctx context.Context, decl *frankrepo.Declarations, frank, hop *live.Snapshot, v *View) {
	if a.smoke == nil {
		a.smoke = map[string]verify.SmokeResult{}
	}
	for _, u := range a.Store.Updates() {
		if u.State != store.Merged && u.State != store.Applied {
			continue
		}
		var out verify.Outcome
		switch u.Kind {
		case inventory.KindTalos, inventory.KindKubernetes:
			snap, cv := frank, decl.Frank
			if u.Cluster == "hop" {
				snap, cv = hop, decl.Hop
			}
			out = verify.OS(cv, snap, a.clusterSmoke(ctx, decl, u.Cluster))
		case inventory.KindOmni:
			continue // operator runbook: tracked, not verified here
		default:
			snap := frank
			if u.Cluster == "hop" {
				snap = hop
			}
			res := map[string]verify.SmokeResult{}
			if u.State == store.Applied {
				for _, app := range u.Apps {
					if s, ok := decl.Smoke[app]; ok && a.Smoke != nil {
						res[app] = a.Smoke(ctx, s)
					} else {
						res[app] = verify.SmokeResult{App: app}
					}
				}
			}
			if len(u.Apps) == 0 {
				continue // batch / unattributed: shown as rolled out, unverified
			}
			out = verify.Workload(ctx, verify.WorkloadInput{Apps: u.Apps, MergeSHA: u.MergeSHA, Repo: a.Cfg.FrankRepo,
				Snapshot: snap, Ancestry: a.Ancestry, Smoke: res})
		}
		set := func(x *store.Update) {
			if out.Rollout != "" {
				x.Rollout = out.Rollout
			}
			if out.To == verify.OutcomeVerified || out.To == verify.OutcomeFailed {
				x.Verification = out.Reason
			}
		}
		switch out.To {
		case verify.OutcomeApplied:
			if u.State == store.Merged {
				_ = a.Store.Transition(u.ID, store.Applied, "verifier", "", set)
			}
		case verify.OutcomeVerified:
			if u.State == store.Merged {
				_ = a.Store.Transition(u.ID, store.Applied, "verifier", "", set)
			}
			_ = a.Store.Transition(u.ID, store.Verified, "verifier", "", set)
		case verify.OutcomeFailed:
			if u.State == store.Merged {
				_ = a.Store.Transition(u.ID, store.Applied, "verifier", "", set)
			}
			_ = a.Store.Transition(u.ID, store.Failed, "verifier", out.Reason, set)
		}
	}
}

func (a *App) clusterSmoke(ctx context.Context, decl *frankrepo.Declarations, cluster string) []verify.SmokeResult {
	var out []verify.SmokeResult
	if a.Smoke == nil {
		return out
	}
	names := make([]string, 0, len(decl.Smoke))
	for n := range decl.Smoke {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if s := decl.Smoke[n]; s.Cluster == cluster {
			out = append(out, a.Smoke(ctx, s))
		}
	}
	return out
}

func (a *App) rollouts(frank, hop *live.Snapshot, v *View) {
	for _, c := range []struct {
		name string
		snap *live.Snapshot
	}{{"frank", frank}, {"hop", hop}} {
		for _, r := range verify.RolloutDecisions(c.snap) {
			v.Rollouts = append(v.Rollouts, RolloutView{Cluster: c.name, Rollout: r, UpgradeID: rolloutID(c.name, r)})
		}
	}
}

func rolloutID(cluster string, r live.Rollout) string {
	id := "rollout-" + cluster + "-" + r.Namespace + "-" + r.Name
	if len(id) > 63 {
		id = strings.TrimRight(id[:63], "-.")
	}
	return id
}

func (a *App) guided(decl *frankrepo.Declarations, rel releaseSet) []GuidedStep {
	var out []GuidedStep
	for _, c := range []struct {
		name string
		cv   frankrepo.ClusterVersions
	}{{"frank", decl.Frank}, {"hop", decl.Hop}} {
		for _, s := range tracks.Next(c.name, c.cv, tracks.Releases{Talos: rel.Talos, Kubernetes: rel.Kubernetes}, decl.Matrix) {
			g := GuidedStep{Step: s, Rollback: engine.Rollback(engine.Item{Kind: s.Kind, Cluster: s.Cluster, Path: frankrepo.PathSession,
				UpdateType: map[bool]string{true: "minor", false: "patch"}[s.OneWay]})}
			if a.Launcher != nil {
				if r, ok := a.Launcher.Get(s.ID); ok {
					g.Session = &r
				}
			}
			out = append(out, g)
		}
	}
	return out
}

// --- alarms and report ------------------------------------------------------

func (a *App) alarms(ctx context.Context, inv *inventory.Inventory, frank, hop *live.Snapshot, hopScanned bool, v *View) {
	var findings []alarm.Finding
	for _, d := range inv.Deps {
		for _, vu := range d.Vulns {
			findings = append(findings, alarm.Finding{Cluster: d.Cluster, Component: d.ID, Image: d.Name + ":" + d.Running, Vuln: vu})
		}
	}
	scanned := map[string]bool{
		"frank": frank != nil && frank.OK("vulnerabilityreports"),
		"hop":   hop != nil && hopScanned,
	}
	prev := map[string]alarm.Record{}
	a.Store.GetBlob(blobAlarms, &prev)
	next, fired := alarm.Evaluate(prev, findings, scanned, a.now())
	_ = a.Store.PutBlob(blobAlarms, next)

	var outbox []string
	a.Store.GetBlob(blobOutbox, &outbox)
	for _, f := range fired {
		outbox = append(outbox, alarm.FormatAlarm(f, a.Cfg.ConsoleURL))
	}
	var keep []string
	for _, msg := range outbox {
		if err := a.sendErr(ctx, msg); err != nil {
			keep = append(keep, msg)
		}
	}
	if len(keep) > 50 {
		keep = keep[len(keep)-50:] // bounded: a long outage must not flood on recovery
	}
	_ = a.Store.PutBlob(blobOutbox, keep)
	for _, r := range next {
		if r.State != alarm.StateResolved {
			v.Alarms = append(v.Alarms, r)
		}
	}
	sort.Slice(v.Alarms, func(i, j int) bool {
		if live.SeverityRank(v.Alarms[i].Severity) != live.SeverityRank(v.Alarms[j].Severity) {
			return live.SeverityRank(v.Alarms[i].Severity) > live.SeverityRank(v.Alarms[j].Severity)
		}
		return v.Alarms[i].VulnID < v.Alarms[j].VulnID
	})
}

func (a *App) sendErr(ctx context.Context, text string) error {
	if a.Telegram == nil {
		return errors.New("telegram: not configured")
	}
	return a.Telegram.Send(ctx, text)
}

func (a *App) send(ctx context.Context, text string) {
	if err := a.sendErr(ctx, text); err != nil {
		a.logf("telegram: %v", err)
	}
}

func (a *App) report(ctx context.Context, items []engine.Item, v *View, rs *reportState) {
	if !alarm.Due(rs.LastReport, a.now(), a.Cfg.ReportHour) {
		return
	}
	s := alarm.Summary{Rollouts: len(v.Rollouts)}
	prev := map[string]bool{}
	for _, id := range rs.LastItems {
		prev[id] = true
	}
	var ids []string
	for _, it := range items {
		ids = append(ids, it.ID)
		if !prev[it.ID] {
			s.NewSinceLast++
			if len(s.Lines) < 5 {
				s.Lines = append(s.Lines, fmt.Sprintf("%s %s → %s (%s)", it.Name, it.From, it.To, it.Path))
			}
		}
		switch {
		case it.Security:
			s.Security++
		case it.State == engine.StateHeldCI || it.State == engine.StateFailedCI:
			s.HeldCI++
		case it.State == engine.StateBatch:
			s.Batch++
		case it.State == engine.StateCountdown || it.State == engine.StateReady:
			s.Countdowns++
		case it.Path == frankrepo.PathSession || it.Path == frankrepo.PathOperatorRunbook:
			s.Guided++
		}
	}
	s.Guided += len(v.Guided)
	s.Total = s.Security + s.Batch + s.Countdowns + s.Guided + s.HeldCI + s.Rollouts
	if err := a.sendErr(ctx, alarm.FormatReport(s, a.Cfg.ConsoleURL)); err != nil {
		a.logf("daily report not sent: %v", err)
		return // last-report stays old: frank's dead-man rule sees it
	}
	rs.LastReport, rs.LastItems = a.now(), ids
}

func (a *App) reconcile(ctx context.Context, prs []forge.PR, frank *live.Snapshot, v *View) {
	if a.GitHub == nil {
		return
	}
	open := map[int]bool{}
	for _, p := range prs {
		open[p.Number] = true
	}
	merged := map[int]string{}
	for _, u := range a.Store.Updates() {
		if (u.State == store.Pending || u.State == store.Approved || u.State == store.Held) && u.PR > 0 && !open[u.PR] {
			if p, err := a.GitHub.PR(ctx, u.PR); err == nil && p.Merged {
				merged[u.PR] = p.MergeCommitSHA
			}
		}
	}
	var pods []live.Pod
	if frank != nil && frank.OK("pods") {
		for _, p := range frank.Pods {
			if p.Namespace == a.Cfg.SessionNamespace && p.Labels[session.LabelRunID] != "" {
				pods = append(pods, p)
			}
		}
	}
	for _, c := range a.Store.Reconcile(store.ReconcileInput{OpenPRs: open, MergedPRs: merged, SessionPods: pods}) {
		switch c.Kind {
		case store.CleanupPod:
			if a.Launcher != nil {
				if err := a.Launcher.CleanupPod(ctx, c.Target, c.Reason); err != nil {
					v.Errors = append(v.Errors, "cleanup "+c.Target+": "+scrub.String(err.Error()))
					continue
				}
				a.Store.AddEvent(store.Event{Update: c.Target, Action: "cleanup", Reason: c.Reason})
			}
		}
	}
}

// Metrics renders the exported state.
func (a *App) Metrics() string {
	v := a.View()
	s := metrics.Snapshot{LastReport: v.LastReport, LastScan: v.LastScan, Updates: map[string]int{}, VulnsOpen: map[string]map[string]int{}}
	for st, n := range a.Store.CountByState() {
		s.Updates[string(st)] = n
	}
	prev := map[string]alarm.Record{}
	a.Store.GetBlob(blobAlarms, &prev)
	s.Alarms = alarm.Counts(prev, a.now())
	if v.Inventory != nil {
		for _, d := range v.Inventory.Deps {
			if d.Gap != "" {
				s.VersionsBehind = append(s.VersionsBehind, metrics.Behind{Cluster: d.Cluster, Component: d.Service + "/" + d.Name, Value: d.Behind})
			}
			for sev, n := range d.VulnCounts {
				if s.VulnsOpen[d.Cluster] == nil {
					s.VulnsOpen[d.Cluster] = map[string]int{}
				}
				s.VulnsOpen[d.Cluster][sev] += n
			}
		}
	}
	s.TelegramReady = a.Cfg.Telegram.Configured()
	return metrics.Render(s)
}

func escape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}
