package session

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/kube"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
	"github.com/derio-net/cluster-update-fr/internal/store"
)

// The idle clock runs only from a safe point: while a step is running (a
// Talos rollout, upgrade-k8s, a snapshot, a canary analysis) it is paused,
// and the maximum lifetime only WARNS while a step runs. The session reports
// step start/end with its step token (POST to the console).

// StepStarted pauses the idle clock.
func (l *Launcher) StepStarted(id, token, name string) error {
	return l.step(id, token, true, name)
}

// Authorize checks a session API call's step token (no state change).
func (l *Launcher) Authorize(id, token string) error {
	rec, ok := l.Get(id)
	if !ok {
		return ErrNoSession
	}
	if !l.checkToken(rec, token) {
		return ErrBadToken
	}
	return nil
}

// StepFinished restarts the idle clock from now.
func (l *Launcher) StepFinished(id, token string) error { return l.step(id, token, false, "") }

func (l *Launcher) step(id, token string, running bool, name string) error {
	rec, ok := l.Get(id)
	if !ok {
		return ErrNoSession
	}
	if !l.checkToken(rec, token) {
		return ErrBadToken
	}
	// Session-supplied: capped, then redacted under the time bound before it
	// is stored or rendered.
	if len(name) > MaxStepName {
		return fmt.Errorf("%w: step name is %d bytes, limit %d", ErrFieldTooLarge, len(name), MaxStepName)
	}
	name = l.boundedScrub(l.Scrubber(id), name, "step name")
	now := l.now()
	err := l.update(func(m map[string]Record) error {
		r := m[id]
		switch {
		case running && r.StepRunning:
			// A repeated start while a step already runs neither restarts
			// the step clock nor renames the step: re-sending "start" must
			// not extend the per-step cap.
		case running:
			r.StepRunning, r.StepName, r.StepSince = true, name, now
			r.StepStarts++
		case r.StepRunning:
			r.StepTotal += now.Sub(r.StepSince)
			r.StepRunning, r.StepName = false, ""
		}
		r.LastActivity = now
		m[id] = r
		return nil
	})
	action := "session-step-finished"
	if running {
		action = "session-step-started"
	}
	l.Store.AddEvent(store.Event{Update: id, Action: action, Reason: name})
	return err
}

// Touch records operator activity (attach).
func (l *Launcher) Touch(id string) {
	now := l.now()
	_ = l.update(func(m map[string]Record) error {
		if r, ok := m[id]; ok {
			r.LastActivity = now
			m[id] = r
		}
		return nil
	})
}

// Warnings returns (and clears) pending lifetime warnings.
func (l *Launcher) Warnings() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	w := l.warnings
	l.warnings = nil
	return w
}

// Tick enforces the idle timeout, the maximum lifetime and dead pods.
func (l *Launcher) Tick(ctx context.Context) []Ended {
	// Never between a Start's write-ahead record and its pod create.
	l.startMu.Lock()
	defer l.startMu.Unlock()
	l.RegisterCredentials() // every cycle: rotated credentials are redacted too
	now := l.now()
	var ended []Ended
	for _, r := range l.records() {
		// The hard ceiling and the per-step cap end a session even mid-step:
		// a steered agent reporting a step as running forever must not keep
		// its credentials (c1s-r1). Checked before anything else, and they
		// alarm in #security.
		if l.HardCeiling > 0 && now.Sub(r.StartedAt) > l.HardCeiling {
			ended = append(ended, l.endAlarm(ctx, r, "hard-ceiling", fmt.Sprintf("ended: hard ceiling %s reached (step %q reported running: %v)", l.HardCeiling, r.StepName, r.StepRunning)))
			continue
		}
		if r.StepRunning && l.StepCap > 0 && now.Sub(r.StepSince) > l.StepCap {
			ended = append(ended, l.endAlarm(ctx, r, "step-cap", fmt.Sprintf("ended: step %q ran past the %s per-step cap", r.StepName, l.StepCap)))
			continue
		}
		total := r.StepTotal
		if r.StepRunning {
			total += now.Sub(r.StepSince)
		}
		if l.StepTotalCap > 0 && total > l.StepTotalCap {
			ended = append(ended, l.endAlarm(ctx, r, "step-total", fmt.Sprintf("ended: %s of step-running time passed the %s per-session cap", total.Round(time.Minute), l.StepTotalCap)))
			continue
		}
		if l.MaxStepStarts > 0 && r.StepStarts > l.MaxStepStarts {
			ended = append(ended, l.endAlarm(ctx, r, "step-starts", fmt.Sprintf("ended: %d step starts passed the %d per-session cap", r.StepStarts, l.MaxStepStarts)))
			continue
		}
		var pod livePod
		err := l.Kube.Get(ctx, kube.ObjectPath(l.Namespace, "pods", r.Pod), &pod)
		if err == nil && r.PodUID != "" {
			// Full verification every tick: a replaced pod, a changed spec or
			// an ephemeral container added after start (kubectl debug,
			// sharing the credential volume) ends the session.
			if why := l.verifyOwned(ctx, r, pod); why != "" {
				ended = append(ended, l.endAlarm(ctx, r, "verify", "ended: the session pod failed verification: "+why))
				continue
			}
		}
		switch {
		case kube.IsNotFound(err):
			ended = append(ended, l.endFor(ctx, r, "needs you: the session pod disappeared"))
			continue
		case err != nil:
			continue // unreachable API: decide next tick
		case pod.Status.Phase == "Failed" || pod.Status.Phase == "Succeeded":
			ended = append(ended, l.endFor(ctx, r, "needs you: the session pod stopped ("+pod.Status.Phase+")"))
			continue
		}
		if r.StepRunning {
			if l.MaxLifetime > 0 && now.Sub(r.StartedAt) > l.MaxLifetime && !r.Warned {
				l.mu.Lock()
				l.warnings = append(l.warnings, fmt.Sprintf("session %s passed its %s maximum lifetime while step %q is running; it will end after the step", r.ID, l.MaxLifetime, r.StepName))
				l.mu.Unlock()
				_ = l.update(func(m map[string]Record) error { x := m[r.ID]; x.Warned = true; m[r.ID] = x; return nil })
			}
			continue
		}
		if l.MaxLifetime > 0 && now.Sub(r.StartedAt) > l.MaxLifetime {
			ended = append(ended, l.endFor(ctx, r, "ended: maximum lifetime "+l.MaxLifetime.String()+" reached"))
			continue
		}
		if l.IdleTimeout > 0 && now.Sub(r.LastActivity) > l.IdleTimeout {
			ended = append(ended, l.endFor(ctx, r, "abandoned: idle timeout "+l.IdleTimeout.String()))
		}
	}
	return ended
}

// Orphan is a leftover ReconcileOrphans removed.
type Orphan struct{ Kind, Name, Reason string }

// ReconcileOrphans turns leftovers into nothing (c1c-r16): session pods and
// Secrets the console made (managed-by label) that no session record
// accounts for, and target locks whose holder has no record. Runs under the
// start lock, so a Start between its write-ahead record and its creates is
// never mistaken for a leftover.
func (l *Launcher) ReconcileOrphans(ctx context.Context) ([]Orphan, error) {
	l.startMu.Lock()
	defer l.startMu.Unlock()
	recs, ok := l.recordsChecked()
	if !ok || l.Store.Warning != "" {
		// Fail closed (sec2-10): with no trustworthy record of the running
		// sessions, nothing is an orphan — not a pod, Secret or lock.
		return nil, errors.New("session records unreadable (or the state was reset); orphan reconciliation skipped")
	}
	var out []Orphan
	sel := "?labelSelector=" + url.QueryEscape(kube.ManagedByLabel+"="+kube.ManagedBy)
	for _, res := range []string{"pods", "secrets"} {
		var list struct {
			Items []struct {
				Metadata kube.Meta `json:"metadata"`
			} `json:"items"`
		}
		if err := l.Kube.Get(ctx, "/api/v1/namespaces/"+url.PathEscape(l.Namespace)+"/"+res+sel, &list); err != nil {
			return out, err
		}
		for _, it := range list.Items {
			id := it.Metadata.Labels[LabelRunID]
			if r, ok := recs[id]; ok && it.Metadata.Name != "" && (it.Metadata.Name == r.Pod || it.Metadata.Name == SecretName(id) || it.Metadata.Name == BriefName(id)) {
				continue
			}
			if err := l.Kube.Delete(ctx, l.Namespace, res, it.Metadata.Name); err != nil && !kube.IsNotFound(err) {
				return out, err
			}
			o := Orphan{Kind: res, Name: it.Metadata.Name, Reason: "no session record for " + id}
			l.Store.AddEvent(store.Event{Update: id, Action: "cleanup", By: "reconciler", Reason: o.Kind + "/" + o.Name + ": " + o.Reason})
			out = append(out, o)
		}
	}
	held := map[string]string{}
	l.Store.GetBlob(lockBlob, &held)
	for target, holder := range held {
		if _, ok := recs[holder]; !ok {
			Locks{Store: l.Store}.Release(target, holder)
			out = append(out, Orphan{Kind: "lock", Name: target, Reason: "held by " + holder + ", which has no session"})
			l.Store.AddEvent(store.Event{Update: holder, Action: "cleanup", By: "reconciler", Reason: "released lock " + target})
		}
	}
	return out, nil
}

// RegisterCredentials adds every file under CredDir (whatever its name, so a
// credential frank adds later is covered too) to the GLOBAL redaction set
// (c1s-r5): console logs, pages, Telegram and error texts never show one,
// even with no session running. Called at startup and on every Tick, so a
// rotated value is registered within one cycle. Old values stay registered.
func (l *Launcher) RegisterCredentials() {
	if l.CredDir == "" {
		return
	}
	entries, err := os.ReadDir(l.CredDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		p := filepath.Join(l.CredDir, e.Name())
		st, err := os.Stat(p) // follows the ..data symlinks of a mounted Secret
		if err != nil || !st.Mode().IsRegular() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
			scrub.Register("session-"+e.Name(), string(b))
		}
	}
}

func (l *Launcher) endFor(ctx context.Context, r Record, outcome string) Ended {
	_ = l.End(ctx, r.ID, outcome, "lifecycle", "")
	return Ended{ID: r.ID, Outcome: outcome}
}

// endAlarm ends a session forcibly and marks the end as a security alarm.
// If the cleanup fails (API unreachable) the record stays and the next tick
// tries again; the alarm says so. Alarms are de-duplicated by (session,
// kind, cleanup state): a stuck cleanup alarms once, and again only when its
// state changes (e.g. the cleanup finally completes).
func (l *Launcher) endAlarm(ctx context.Context, r Record, kind, outcome string) Ended {
	e := Ended{ID: r.ID, Outcome: outcome, Alarm: true}
	state := "done"
	if err := l.End(ctx, r.ID, outcome, "lifecycle", ""); err != nil {
		e.Outcome += " — CLEANUP INCOMPLETE: " + scrub.String(err.Error())
		state = "incomplete"
	}
	key := alarmKey(r.ID, kind, r.PodUID, state)
	l.alarm(key, "session "+r.ID+" "+e.Outcome)
	if state == "done" {
		// Resolved: drop the stuck-state key (if any) so a new incident on
		// a later session with this id alarms afresh.
		l.resolveAlarm(alarmKey(r.ID, kind, r.PodUID, "incomplete"))
	}
	return e
}

// End deletes the session's pod and Secrets, releases its lock, and keeps
// the outcome and the scrubbed transcript in History. Idempotent.
func (l *Launcher) End(ctx context.Context, id, outcome, by, transcript string) error {
	_, err := l.EndScrubbed(ctx, id, outcome, by, transcript)
	return err
}

// EndScrubbed is End, returning the outcome as it was stored — redacted
// with the session's set under the time bound — so callers never carry the
// raw session-supplied text any further (sec2-2).
func (l *Launcher) EndScrubbed(ctx context.Context, id, outcome, by, transcript string) (string, error) {
	if len(transcript) > l.transcriptMax() {
		return "", fmt.Errorf("%w: %d bytes, limit %d", ErrTranscriptTooLarge, len(transcript), l.transcriptMax())
	}
	if len(outcome) > l.outcomeMax() {
		return "", fmt.Errorf("%w: outcome is %d bytes, limit %d", ErrFieldTooLarge, len(outcome), l.outcomeMax())
	}
	rec, ok := l.Get(id)
	set := l.Scrubber(id)
	outcome = l.boundedScrub(set, outcome, "outcome")
	cerr := l.cleanup(ctx, PodName(id))
	if cerr != nil && !errors.Is(cerr, kube.ErrForbiddenWrite) {
		return outcome, cerr // API trouble: keep the record, retry next tick
	}
	if !ok {
		return outcome, cerr
	}
	Locks{Store: l.Store}.Release(rec.Target, id)
	_ = l.update(func(m map[string]Record) error { delete(m, id); return nil })
	if transcript != "" {
		clean := l.scrubTranscript(set, transcript)
		_ = l.Store.Edit(id, func(u *store.Update) { u.Transcript = clean })
	}
	l.Store.AddEvent(store.Event{At: l.now(), Update: id, Action: "session-ended", By: by, Reason: outcome})
	l.mu.Lock()
	delete(l.sets, id)
	delete(l.tokens, id)
	onEnd := l.onEnd
	l.mu.Unlock()
	if onEnd != nil {
		onEnd(id)
	}
	return outcome, cerr // a foreign object under the session's name is left and reported
}

// ErrTranscriptTooLarge: the finish call's transcript exceeds the cap; the
// session is not ended and may finish again with less.
var ErrTranscriptTooLarge = errors.New("session: transcript too large")

func (l *Launcher) transcriptMax() int {
	if l.TranscriptMax <= 0 {
		return 1 << 20
	}
	return l.TranscriptMax
}

// TranscriptLimit is the cap the session API enforces on request bodies.
func (l *Launcher) TranscriptLimit() int { return l.transcriptMax() }

// Session API field caps (every session-supplied field is capped and goes
// through the bounded scrubber before it is stored or rendered).
const (
	MaxStepName       = 256  // bytes
	DefaultOutcomeMax = 4096 // bytes
)

// ErrFieldTooLarge: a session-supplied field exceeds its cap.
var ErrFieldTooLarge = errors.New("session: field too large")

func (l *Launcher) outcomeMax() int {
	if l.OutcomeMax <= 0 {
		return DefaultOutcomeMax
	}
	return l.OutcomeMax
}

// scrubTranscript redacts a transcript under the time bound.
func (l *Launcher) scrubTranscript(set *scrub.Set, text string) string {
	return l.boundedScrub(set, text, "transcript")
}

// boundedScrub redacts session-supplied text under a time limit. Text whose
// redaction does not finish in time is WITHHELD, never stored unredacted.
func (l *Launcher) boundedScrub(set *scrub.Set, text, what string) string {
	if text == "" {
		return ""
	}
	fn := l.scrubFn
	if fn == nil {
		fn = scrub.Transcript
	}
	timeout := l.ScrubTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	done := make(chan string, 1)
	go func() { done <- fn(set, text) }()
	select {
	case s := <-done:
		return s
	case <-time.After(timeout):
		return fmt.Sprintf("[%s withheld: redaction of %d bytes did not finish within %s]", what, len(text), timeout)
	}
}

// CleanupPod removes a leftover session pod (and its Secrets) found by
// reconciliation; for a tracked session it ends it.
func (l *Launcher) CleanupPod(ctx context.Context, pod, reason string) error {
	for _, r := range l.records() {
		if r.Pod == pod {
			return l.End(ctx, r.ID, "cleaned up: "+reason, "reconciler", "")
		}
	}
	return l.cleanup(ctx, pod)
}

// cleanup deletes pod and its Secrets, ignoring what is already gone. The
// one cleanup path used by End, the lifecycle and reconciliation.
//
// An object under the session's name that is not the console's (no
// managed-by label) is refused by the kube client; cleanup carries on with
// the rest and returns an error wrapping kube.ErrForbiddenWrite naming it.
func (l *Launcher) cleanup(ctx context.Context, pod string) error {
	var foreign []string
	for _, o := range []struct{ res, name string }{{"pods", pod}, {"secrets", pod + "-creds"}, {"secrets", pod + "-brief"}} {
		err := l.Kube.Delete(ctx, l.Namespace, o.res, o.name)
		switch {
		case err == nil || kube.IsNotFound(err):
		case errors.Is(err, kube.ErrForbiddenWrite):
			foreign = append(foreign, o.res+"/"+o.name)
		default:
			return err
		}
	}
	if len(foreign) > 0 {
		return fmt.Errorf("%w: left in place, not the console's: %s", kube.ErrForbiddenWrite, strings.Join(foreign, ", "))
	}
	return nil
}
