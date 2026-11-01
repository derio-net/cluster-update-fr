package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/derio-net/cluster-update-fr/internal/engine"
	"github.com/derio-net/cluster-update-fr/internal/forge"
	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/inventory"
	"github.com/derio-net/cluster-update-fr/internal/renovate"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
	"github.com/derio-net/cluster-update-fr/internal/session"
	"github.com/derio-net/cluster-update-fr/internal/store"
	"github.com/derio-net/cluster-update-fr/internal/trust"
)

func parseDeps(p forge.PR) []renovate.Dep { return renovate.ParsePR(p.Body) }

// ErrUnavailable means the action's backend is not configured.
var ErrUnavailable = errors.New("app: this action is not available (missing credential or configuration)")

func (a *App) items() []engine.Item { return a.View().Items }

func (a *App) policy() frankrepo.Policy {
	if d := a.View().Decl; d != nil {
		return d.Policy
	}
	return frankrepo.Policy{}
}

// Hold stops an item from merging.
func (a *App) Hold(id, by string) error {
	err := a.eng(a.policy()).Hold(id, by)
	_ = a.Store.Save()
	return err
}

// Unhold releases a hold.
func (a *App) Unhold(id, by string) error {
	err := a.eng(a.policy()).Unhold(id, by)
	_ = a.Store.Save()
	return err
}

// MergeNow merges an auto-merge item before its countdown.
func (a *App) MergeNow(ctx context.Context, id, by string) error {
	if a.GitHub == nil {
		return ErrUnavailable
	}
	err := a.eng(a.policy()).MergeNow(ctx, a.items(), id, by)
	_ = a.Store.Save()
	return err
}

// ApproveNow approves one item alone (security items jump the queue).
func (a *App) ApproveNow(ctx context.Context, id, by string) error {
	if a.GitHub == nil {
		return ErrUnavailable
	}
	err := a.eng(a.policy()).ApproveNow(ctx, a.items(), id, by)
	_ = a.Store.Save()
	return err
}

// ApproveBatch builds the one batch PR from the operator's selection.
func (a *App) ApproveBatch(ctx context.Context, ids []string, by string) (engine.BatchResult, error) {
	if a.GitHub == nil {
		return engine.BatchResult{}, ErrUnavailable
	}
	res, err := a.eng(a.policy()).ApproveBatch(ctx, a.items(), ids, by)
	_ = a.Store.Save()
	return res, err
}

// RetryCI diagnoses a held item and performs its one recovery.
func (a *App) RetryCI(ctx context.Context, id, by string) error {
	if a.Diag == nil && a.GitHub == nil {
		return ErrUnavailable
	}
	err := a.eng(a.policy()).RetryCI(ctx, a.items(), id, by)
	_ = a.Store.Save()
	return err
}

// Revert opens the revert PR of a merged update.
func (a *App) Revert(ctx context.Context, id, by string) (string, error) {
	if a.GitHub == nil {
		return "", ErrUnavailable
	}
	u, ok := a.Store.Get(id)
	if !ok || u.PR == 0 {
		return "", fmt.Errorf("app: %s has no merged PR to revert", id)
	}
	pr, err := a.GitHub.PR(ctx, u.PR)
	if err != nil {
		return "", err
	}
	if !pr.Merged {
		return "", fmt.Errorf("app: PR #%d is not merged", u.PR)
	}
	if u.RevertSHA != "" {
		return "", fmt.Errorf("app: %s's revert is already merged", id)
	}
	if u.RevertPR > 0 {
		// Ask GitHub about the recorded revert PR, live (sec2-9).
		rp, err := a.GitHub.PR(ctx, u.RevertPR)
		switch {
		case err != nil:
			return "", fmt.Errorf("app: revert PR #%d unreadable: %w", u.RevertPR, err)
		case rp.Merged:
			_ = a.Store.MarkRevertMerged(id, rp.MergeCommitSHA, by)
			_ = a.Store.Save()
			return "", fmt.Errorf("app: revert PR #%d is already merged", u.RevertPR)
		case rp.State == "closed":
			_ = a.Store.ClearRevert(id, by, fmt.Sprintf("revert PR #%d was closed without merging; opening a new one", u.RevertPR))
		default:
			return "", fmt.Errorf("app: revert PR #%d is already open for %s", u.RevertPR, id)
		}
	}
	files, err := a.GitHub.PRFiles(ctx, u.PR)
	if err != nil {
		return "", err
	}
	_, url, err := a.eng(a.policy()).Revert(ctx, pr, files, id, by)
	_ = a.Store.Save()
	return url, err
}

// MergeRevert is the operator's "Merge revert PR": the console merges its
// own revert PR after the trust check — console bot author, branch
// cluster-update/revert-<n>-, signed commits pushed by the console's App,
// files exactly within the reverted PR's — pinned to the verified head.
// The update is rolled back only when the verifier sees the revert applied.
func (a *App) MergeRevert(ctx context.Context, id, by string) error {
	if a.GitHub == nil {
		return ErrUnavailable
	}
	u, ok := a.Store.Get(id)
	if !ok || u.RevertPR == 0 || u.RevertSHA != "" {
		return fmt.Errorf("app: %s has no open revert PR", id)
	}
	rp, err := a.GitHub.PR(ctx, u.RevertPR)
	if err != nil {
		return err
	}
	files, err := a.GitHub.PRFiles(ctx, u.PR)
	if err != nil {
		return err
	}
	a.eng(a.policy())
	sha, err := a.guard.MergeWithScope(ctx, rp.Number, rp.HeadSHA, trust.RevertScope(u.PR, files, u.Path == frankrepo.PathSession))
	if err != nil {
		a.Store.AddEvent(store.Event{Update: id, Action: "merge-refused", By: by, PR: rp.Number, Reason: scrub.String(err.Error())})
		_ = a.Store.Save()
		return err
	}
	err = a.Store.MarkRevertMerged(id, sha, by)
	_ = a.Store.Save()
	return err
}

// SessionPlan is what StartSession resolved an id to.
type SessionPlan struct {
	Request  session.Request
	Title    string
	Rollback string
	Kind     string // the update's kind (talos, kubernetes, chart, image, rollout)
	Name     string
	From, To string
}

// planSession resolves a Needs-action id (a session-path PR item, a guided
// OS step or a rollout decision) into a session request.
func (a *App) planSession(ctx context.Context, id string) (SessionPlan, error) {
	v := a.View()
	for _, it := range v.Items {
		if it.ID != id {
			continue
		}
		if !it.NeedsSession() {
			return SessionPlan{}, fmt.Errorf("app: %s is on the %s path, not a session", id, it.Path)
		}
		typ := session.TypeChartMajor
		switch {
		case it.Kind == inventory.KindTalos || it.Kind == inventory.KindKubernetes:
			typ = session.TypeFrankOS
			if it.Cluster == "hop" {
				typ = session.TypeHopOS
			}
		case a.isRolloutsApp(v, it.Cluster, it.App):
			typ = session.TypeRollouts
		case it.Stateful:
			typ = session.TypeStateful
		}
		p := a.plan(ctx, id, typ, it.Cluster, it.App, it.PR.Title, it.Rollback, "", "")
		p.Kind, p.Name, p.From, p.To = it.Kind, it.Name, it.From, it.To
		if strings.TrimSpace(it.PR.Body) != "" {
			p.Request.Brief += "\n\n## Untrusted data: the Renovate PR body\n\n" + trust.Fence(fmt.Sprintf("PR #%d's body (GitHub)", it.PR.Number), it.PR.Body) + "\n"
		}
		return p, nil
	}
	for _, g := range v.Guided {
		if g.ID != id {
			continue
		}
		typ := session.TypeFrankOS
		if g.Cluster == "hop" {
			typ = session.TypeHopOS
		}
		title := fmt.Sprintf("%s %s %s → %s (step %d)", g.Cluster, g.Kind, g.From, g.To, g.Position)
		p := a.plan(ctx, id, typ, g.Cluster, "", title, g.Rollback, g.TalosClient, g.KubectlClient)
		p.Kind, p.Name, p.From, p.To = g.Kind, g.Kind, g.From, g.To
		return p, nil
	}
	for _, r := range v.Rollouts {
		if r.UpgradeID != id {
			continue
		}
		title := fmt.Sprintf("Rollout %s/%s is %s: promote or abort", trust.Title(r.Namespace), trust.Title(r.Name), trust.Title(r.Phase))
		p := a.plan(ctx, id, session.TypeRollouts, r.Cluster, r.App, title, "Abort returns traffic to the stable ReplicaSet.", "", "")
		p.Kind = "rollout"
		return p, nil
	}
	return SessionPlan{}, fmt.Errorf("app: nothing to start a session for: %s", id)
}

func (a *App) isRolloutsApp(v View, cluster, app string) bool {
	if v.Inventory == nil {
		return false
	}
	for _, d := range v.Inventory.Deps {
		if d.Cluster == cluster && d.Service == app && strings.Contains(d.PathReason, "Rollouts") {
			return true
		}
	}
	return false
}

func (a *App) plan(ctx context.Context, id, typ, cluster, app, title, rollback, talos, kubectl string) SessionPlan {
	decl := a.View().Decl
	if decl == nil {
		decl = &frankrepo.Declarations{}
	}
	cv := decl.Frank
	if cluster == "hop" {
		cv = decl.Hop
	}
	if talos == "" {
		talos = cv.Talos
	}
	if kubectl == "" {
		kubectl = cv.Kubernetes
	}
	template := a.readRepo(ctx, "docs/upgrade-briefs/"+typ+".md")
	instructions := a.readRepo(ctx, "docs/upgrade-briefs/AGENTS.md")
	if instructions == "" {
		instructions = "Read brief/brief.md first. Report each long step to the console with $CONSOLE_URL/api/sessions/$UPGRADE_ID/step " +
			"(Authorization: Bearer the session-step-token from $CREDENTIALS_DIR). You may open PRs but NEVER merge one: push to a branch named " +
			"cluster-update/session-$UPGRADE_ID/<topic> and POST {\"pr\": N} to $CONSOLE_URL/api/sessions/$UPGRADE_ID/request-merge; the operator " +
			"merges it from the console. Finish by running the verification in the brief."
	}
	// Every forge- or cluster-sourced string is untrusted: the one-line title
	// is neutralised here; multi-line bodies only ever appear fenced, at the
	// end, after the instruction sections.
	title = trust.Title(title)
	app = trust.Title(app)
	var b strings.Builder
	fmt.Fprintf(&b, "# Upgrade brief — %s\n\n", title)
	fmt.Fprintf(&b, "- **Upgrade id:** `%s`\n- **Type:** %s\n- **Cluster:** %s\n", id, typ, cluster)
	if app != "" {
		fmt.Fprintf(&b, "- **Application:** %s\n", app)
	}
	fmt.Fprintf(&b, "- **Pinned clients:** talosctl %s, kubectl %s\n", talos, kubectl)
	fmt.Fprintf(&b, "- **Rollback:** %s\n\n", rollback)
	if typ == session.TypeHopOS {
		fmt.Fprintf(&b, "## Reaching Hop\n\nHop is reached only over the tailnet, through this pod's tailscale sidecar "+
			"(joined as `%s`), which offers two proxies:\n\n"+
			"| Tool | Proxy it uses | Set by |\n|---|---|---|\n"+
			"| kubectl | SOCKS5 `%s` | the hop kubeconfig's `proxy-url` (`$CREDENTIALS_DIR/hop-kubeconfig`) |\n"+
			"| talosctl (gRPC: HTTP CONNECT only, no SOCKS) | HTTP CONNECT `%s` | `HTTPS_PROXY` |\n"+
			"| curl and other SOCKS-aware tools | SOCKS5 `%s` | `ALL_PROXY` |\n\n"+
			"`NO_PROXY` keeps the console API, cluster services, the Claude API and GitHub direct (Claude Code does not support SOCKS and must not depend on the sidecar). "+
			"If Hop is unreachable, wait for the sidecar to join; never work around it.\n\n",
			a.Launcher.SessionTag(), session.TailscaleProxyURL, session.TailscaleHTTPProxyURL, session.TailscaleProxyURL)
	}
	fmt.Fprintf(&b, "## Pull requests: you open them, the operator merges them\n\n"+
		"You never merge a PR (your token cannot push to `main`). Open each PR from a branch named `%s%s/<topic>`, "+
		"changing only files of this update. Create every commit THROUGH THE GITHUB API with the session App token — the contents API "+
		"(`PUT /repos/{repo}/contents/{path}` with `branch`) or GraphQL `createCommitOnBranch` — so GitHub signs it (web-flow) and records "+
		"the App as the pusher. A plain `git push` of a locally made commit is unsigned and the console refuses the PR. Then ask the console:\n\n"+
		"```sh\ncurl -fsS -X POST \"$CONSOLE_URL/api/sessions/$UPGRADE_ID/request-merge\" \\\n"+
		"  -H \"Authorization: Bearer $(cat \"$CREDENTIALS_DIR/session-step-token\")\" -d '{\"pr\": <number>}'\n```\n\n"+
		"The console verifies the PR (author, branch, signatures, files) and shows a **Merge session PR** button to the operator; "+
		"wait for the PR to be merged before you continue. A 422 answer names why the PR was refused — fix the PR, do not work around it.\n\n",
		engine.SessionBranchPrefix, id)
	b.WriteString("## Verification (R16)\n\nWorkloads: ArgoCD's `status.operationState.operation.sync.revision` must contain the merge commit (Synced alone never counts) and `smoke/<app>.yaml` must pass. OS steps: declare the version in `versions/<cluster>.yaml` FIRST — a PR on your session branch, request-merge, wait for the operator's merge — then apply, then every node on the declared version, all Ready, cluster smoke passing.\n\n")
	if template != "" {
		b.WriteString(template)
	} else {
		b.WriteString("_No brief template `docs/upgrade-briefs/" + typ + ".md` was found in the frank repo._\n")
	}
	return SessionPlan{Title: title, Rollback: rollback, Request: session.Request{UpgradeID: id, Type: typ, Cluster: cluster, App: app,
		Brief: b.String(), Instructions: instructions, TalosVersion: talos, KubectlVersion: kubectl}}
}

func (a *App) readRepo(ctx context.Context, path string) string {
	if a.Repo == nil {
		return ""
	}
	b, err := a.Repo.Read(ctx, path)
	if err != nil {
		return ""
	}
	return string(b)
}

// StartSession starts — or attaches to — the session for id.
func (a *App) StartSession(ctx context.Context, id, by string) (session.Record, bool, error) {
	if a.Launcher == nil {
		return session.Record{}, false, ErrUnavailable
	}
	a.wire()
	p, err := a.planSession(ctx, id)
	if err != nil {
		return session.Record{}, false, err
	}
	// Kind and cluster are recorded so the update is verifiable (an OS step
	// by verify.OS once its version PR merges) — c1c-r5.
	a.Store.Track(store.Update{ID: id, Title: p.Title, Cluster: p.Request.Cluster, Apps: nonEmpty(p.Request.App), Path: frankrepo.PathSession,
		Rollback: p.Rollback, Kind: p.Kind, Name: p.Name, From: p.From, To: p.To})
	// A new session on an update an earlier session abandoned reopens it.
	_ = a.Store.Reopen(id, by, "session started again")
	rec, created, err := a.Launcher.Start(ctx, p.Request)
	if err == nil && created {
		a.Store.AddEvent(store.Event{Update: id, Action: "session-requested", By: by})
	}
	a.sessionAlarms(ctx) // a refused foreign pod/Secret alarms at once
	_ = a.Store.Save()
	return rec, created, err
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

// AttachURL is the runs-fr page for a session (runs-fr lists sessions by
// their fr.run/id; it has no deep link yet, so the id is in the fragment).
// Pure: it changes nothing.
func (a *App) AttachURL(id string) string {
	return a.Cfg.RunsFrURL + "/#" + id
}

// Attach records operator activity on a RUNNING session (it resets the idle
// clock) and returns its attach URL. Reached only by a CSRF-checked POST.
func (a *App) Attach(id, by string) (string, error) {
	if a.Launcher == nil {
		return "", ErrUnavailable
	}
	if _, ok := a.Launcher.Get(id); !ok {
		return "", session.ErrNoSession
	}
	a.Launcher.Touch(id)
	a.Store.AddEvent(store.Event{Update: id, Action: "session-attached", By: by})
	_ = a.Store.Save()
	return a.AttachURL(id), nil
}

// EndSession ends a session on the operator's request.
func (a *App) EndSession(ctx context.Context, id, by string) error {
	if a.Launcher == nil {
		return ErrUnavailable
	}
	err := a.Launcher.End(ctx, id, "ended by "+by, by, "")
	if err == nil {
		a.sessionOutcome(id, "ended by "+by)
	}
	_ = a.Store.Save()
	return err
}

// truncateRunes shortens s to at most n bytes without splitting a rune.
func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

// sessionOutcome maps how a session ended onto its update (c1c-r5). Nothing
// merged yet (pending/approved/held): a "needs you" or failed end is
// failed (the operator must look), any other end is abandoned. Once its PR
// merged, verification decides; the session's end changes nothing.
func (a *App) sessionOutcome(id, outcome string) {
	u, ok := a.Store.Get(id)
	if !ok || (u.State != store.Pending && u.State != store.Approved && u.State != store.Held) {
		return
	}
	low := strings.ToLower(outcome)
	if strings.Contains(low, "needs you") || strings.Contains(low, "fail") || strings.Contains(low, "hard ceiling") || strings.Contains(low, " cap") {
		_ = a.Store.Transition(id, store.Failed, "session", "session ended — needs you: "+outcome, nil)
		return
	}
	_ = a.Store.Transition(id, store.Abandoned, "session", "session ended without merging anything: "+outcome, nil)
}

// StepEvent is the session reporting a step start or finish.
func (a *App) StepEvent(id, token string, start bool, name string) error {
	if a.Launcher == nil {
		return ErrUnavailable
	}
	var err error
	if start {
		err = a.Launcher.StepStarted(id, token, name)
	} else {
		err = a.Launcher.StepFinished(id, token)
	}
	_ = a.Store.Save()
	return err
}

// SessionFinished is the session reporting its end with outcome and
// transcript (scrubbed with the session's own redaction set).
func (a *App) SessionFinished(ctx context.Context, id, token, outcome, transcript string) error {
	if a.Launcher == nil {
		return ErrUnavailable
	}
	rec, ok := a.Launcher.Get(id)
	if !ok {
		return session.ErrNoSession
	}
	if err := a.Launcher.StepFinished(id, token); err != nil {
		return err
	}
	// The launcher returns the outcome already redacted (sec2-2); only that
	// form goes further, shortened on a rune boundary.
	clean, err := a.Launcher.EndScrubbed(ctx, rec.ID, outcome, "session", transcript)
	if err == nil {
		a.sessionOutcome(id, truncateRunes(clean, 300))
	}
	_ = a.Store.Save()
	return err
}
