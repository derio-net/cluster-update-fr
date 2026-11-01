package session

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
	now := l.now()
	err := l.update(func(m map[string]Record) error {
		r := m[id]
		r.StepRunning, r.StepName, r.LastActivity = running, name, now
		if running {
			r.StepSince = now
		}
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
	now := l.now()
	var ended []Ended
	for _, r := range l.records() {
		// The hard ceiling and the per-step cap end a session even mid-step:
		// a steered agent reporting a step as running forever must not keep
		// its credentials (c1s-r1). Checked before anything else, and they
		// alarm in #security.
		if l.HardCeiling > 0 && now.Sub(r.StartedAt) > l.HardCeiling {
			ended = append(ended, l.endAlarm(ctx, r, fmt.Sprintf("ended: hard ceiling %s reached (step %q reported running: %v)", l.HardCeiling, r.StepName, r.StepRunning)))
			continue
		}
		if r.StepRunning && l.StepCap > 0 && now.Sub(r.StepSince) > l.StepCap {
			ended = append(ended, l.endAlarm(ctx, r, fmt.Sprintf("ended: step %q ran past the %s per-step cap", r.StepName, l.StepCap)))
			continue
		}
		var pod livePod
		err := l.Kube.Get(ctx, kube.ObjectPath(l.Namespace, "pods", r.Pod), &pod)
		switch {
		case err == nil && r.PodUID != "" && pod.Metadata.UID != r.PodUID:
			ended = append(ended, l.endAlarm(ctx, r, fmt.Sprintf("ended: the session pod was replaced (UID %q, recorded %q)", pod.Metadata.UID, r.PodUID)))
			continue
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

func (l *Launcher) endFor(ctx context.Context, r Record, outcome string) Ended {
	_ = l.End(ctx, r.ID, outcome, "lifecycle", "")
	return Ended{ID: r.ID, Outcome: outcome}
}

// endAlarm ends a session forcibly and marks the end as a security alarm.
// If the cleanup fails (API unreachable) the record stays and the next tick
// tries again; the alarm says so.
func (l *Launcher) endAlarm(ctx context.Context, r Record, outcome string) Ended {
	e := Ended{ID: r.ID, Outcome: outcome, Alarm: true}
	if err := l.End(ctx, r.ID, outcome, "lifecycle", ""); err != nil {
		e.Outcome += " — CLEANUP INCOMPLETE: " + scrub.String(err.Error())
	}
	l.alarm("session " + r.ID + " " + e.Outcome)
	return e
}

// End deletes the session's pod and Secrets, releases its lock, and keeps
// the outcome and the scrubbed transcript in History. Idempotent.
func (l *Launcher) End(ctx context.Context, id, outcome, by, transcript string) error {
	rec, ok := l.Get(id)
	set := l.Scrubber(id)
	cerr := l.cleanup(ctx, PodName(id))
	if cerr != nil && !errors.Is(cerr, kube.ErrForbiddenWrite) {
		return cerr // API trouble: keep the record, retry next tick
	}
	if !ok {
		return cerr
	}
	Locks{Store: l.Store}.Release(rec.Target, id)
	_ = l.update(func(m map[string]Record) error { delete(m, id); return nil })
	if transcript != "" {
		clean := scrub.Transcript(set, transcript)
		_ = l.Store.Edit(id, func(u *store.Update) { u.Transcript = clean })
	}
	l.Store.AddEvent(store.Event{At: l.now(), Update: id, Action: "session-ended", By: by, Reason: set.String(outcome)})
	l.mu.Lock()
	delete(l.sets, id)
	delete(l.tokens, id)
	l.mu.Unlock()
	return cerr // a foreign object under the session's name is left and reported
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
