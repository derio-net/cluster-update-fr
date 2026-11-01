package app

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/derio-net/cluster-update-fr/internal/engine"
	"github.com/derio-net/cluster-update-fr/internal/forge"
	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/inventory"
	"github.com/derio-net/cluster-update-fr/internal/renovate"
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
	if a.Diag == nil {
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
	_, url, err := a.eng(a.policy()).Revert(ctx, pr, by)
	_ = a.Store.Save()
	return url, err
}

// SessionPlan is what StartSession resolved an id to.
type SessionPlan struct {
	Request  session.Request
	Title    string
	Rollback string
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
		return a.plan(ctx, id, typ, g.Cluster, "", title, g.Rollback, g.TalosClient, g.KubectlClient), nil
	}
	for _, r := range v.Rollouts {
		if r.UpgradeID != id {
			continue
		}
		title := fmt.Sprintf("Rollout %s/%s is %s: promote or abort", trust.Title(r.Namespace), trust.Title(r.Name), trust.Title(r.Phase))
		return a.plan(ctx, id, session.TypeRollouts, r.Cluster, r.App, title, "Abort returns traffic to the stable ReplicaSet.", "", ""), nil
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
			"(Authorization: Bearer the session-step-token from $CREDENTIALS_DIR), and finish by running the verification in the brief."
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
	b.WriteString("## Verification (R16)\n\nWorkloads: ArgoCD's `status.operationState.operation.sync.revision` must contain the merge commit (Synced alone never counts) and `smoke/<app>.yaml` must pass. OS steps: declare the version in `versions/<cluster>.yaml` FIRST (PR, merged by the console), then apply, then every node on the declared version, all Ready, cluster smoke passing.\n\n")
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
	p, err := a.planSession(ctx, id)
	if err != nil {
		return session.Record{}, false, err
	}
	a.Store.Track(store.Update{ID: id, Title: p.Title, Cluster: p.Request.Cluster, Apps: nonEmpty(p.Request.App), Path: frankrepo.PathSession, Rollback: p.Rollback})
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
func (a *App) AttachURL(id string) string {
	if a.Launcher != nil {
		a.Launcher.Touch(id)
	}
	return a.Cfg.RunsFrURL + "/#" + id
}

// EndSession ends a session on the operator's request.
func (a *App) EndSession(ctx context.Context, id, by string) error {
	if a.Launcher == nil {
		return ErrUnavailable
	}
	err := a.Launcher.End(ctx, id, "ended by "+by, by, "")
	_ = a.Store.Save()
	return err
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
	err := a.Launcher.End(ctx, rec.ID, outcome, "session", transcript)
	_ = a.Store.Save()
	return err
}
