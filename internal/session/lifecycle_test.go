package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/kube"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
	"github.com/derio-net/cluster-update-fr/internal/store"
)

func start(t *testing.T, l *Launcher, id, typ string) {
	t.Helper()
	if _, _, err := l.Start(context.Background(), req(id, typ, "litellm")); err != nil {
		t.Fatal(err)
	}
}

func TestIdleClockPausesWhileAStepRuns(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	start(t, l, "pr-1", TypeRollouts)
	tok := l.StepToken("pr-1")
	if tok == "" {
		t.Fatal("no step token")
	}
	now = now.Add(time.Hour)
	if err := l.StepStarted("pr-1", tok, "canary analysis"); err != nil {
		t.Fatal(err)
	}
	if err := l.StepStarted("pr-1", "wrong", "x"); err == nil {
		t.Error("a wrong step token must be refused")
	}
	now = now.Add(4 * time.Hour) // far past idle, but a step is running
	if ended := l.Tick(context.Background()); len(ended) != 0 {
		t.Fatalf("ended during a running step: %+v", ended)
	}
	if err := l.StepFinished("pr-1", tok); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour + 59*time.Minute) // idle clock restarted at StepFinished
	if ended := l.Tick(context.Background()); len(ended) != 0 {
		t.Fatalf("idle clock did not restart from the step end: %+v", ended)
	}
	now = now.Add(2 * time.Minute)
	ended := l.Tick(context.Background())
	if len(ended) != 1 || !strings.Contains(ended[0].Outcome, "idle") {
		t.Fatalf("idle end = %+v", ended)
	}
	if _, ok := k.objects["pods/"+PodName("pr-1")]; ok {
		t.Error("pod not deleted")
	}
	if _, ok := k.objects["secrets/"+SecretName("pr-1")]; ok {
		t.Error("credentials not deleted")
	}
	if (Locks{Store: l.Store}).Holder(Target(TypeRollouts, "frank", "litellm")) != "" {
		t.Error("lock not released")
	}
}

func TestMaxLifetimeWarnsInsteadOfKillingARunningStep(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	start(t, l, "frank-os-1", TypeFrankOS)
	tok := l.StepToken("frank-os-1")
	_ = l.StepStarted("frank-os-1", tok, "talos rollout")
	now = now.Add(9 * time.Hour)
	if ended := l.Tick(context.Background()); len(ended) != 0 {
		t.Fatal("max lifetime killed a running step")
	}
	w := l.Warnings()
	if len(w) != 1 || !strings.Contains(w[0], "frank-os-1") {
		t.Fatalf("warnings = %v", w)
	}
	l.Tick(context.Background())
	if len(l.Warnings()) != 0 {
		t.Error("the lifetime warning is sent once")
	}
	_ = l.StepFinished("frank-os-1", tok)
	if ended := l.Tick(context.Background()); len(ended) != 1 || !strings.Contains(ended[0].Outcome, "lifetime") {
		t.Fatalf("after the step, max lifetime ends the session: %+v", ended)
	}
}

// c1s-r1: a session that reports a step as running forever still ends —
// at the hard ceiling, or when one step passes the per-step cap — with its
// pod and credentials deleted and a #security alarm.
func TestHardCeilingAndStepCapEndEvenMidStep(t *testing.T) {
	for _, tc := range []struct {
		name    string
		advance []time.Duration // StepStarted is re-sent before each advance (a steered agent)
		want    string
	}{
		{"hard ceiling", []time.Duration{3 * time.Hour, 3 * time.Hour, 3 * time.Hour, 3 * time.Hour, 3*time.Hour + time.Minute, time.Hour}, "hard ceiling"},
		{"step cap", []time.Duration{4*time.Hour + time.Minute}, "per-step cap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Unix(0, 0)
			k := newFake()
			l := launcher(t, k, &now)
			l.HardCeiling, l.StepCap = 16*time.Hour, 4*time.Hour
			start(t, l, "frank-os-1", TypeFrankOS)
			tok := l.StepToken("frank-os-1")
			var ended []Ended
			for _, d := range tc.advance {
				_ = l.StepFinished("frank-os-1", tok)
				_ = l.StepStarted("frank-os-1", tok, "talos rollout")
				now = now.Add(d)
				if ended = l.Tick(context.Background()); len(ended) > 0 {
					break
				}
			}
			if len(ended) != 1 || !ended[0].Alarm || !strings.Contains(ended[0].Outcome, tc.want) {
				t.Fatalf("ended = %+v", ended)
			}
			if _, ok := k.objects["secrets/"+SecretName("frank-os-1")]; ok {
				t.Error("credentials survived the forced end")
			}
			if _, ok := k.objects["pods/"+PodName("frank-os-1")]; ok {
				t.Error("pod survived the forced end")
			}
			if a := l.Alarms(); len(a) != 1 || !strings.Contains(a[0], tc.want) {
				t.Errorf("alarms = %v", a)
			}
		})
	}
}

// Re-sending "start" while a step runs does not restart its clock.
func TestRepeatedStepStartDoesNotExtendTheCap(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	l.StepCap = 4 * time.Hour
	start(t, l, "pr-1", TypeChartMajor)
	tok := l.StepToken("pr-1")
	var ended []Ended
	for i := 0; i < 5 && len(ended) == 0; i++ {
		_ = l.StepStarted("pr-1", tok, fmt.Sprintf("helm upgrade %d", i))
		now = now.Add(time.Hour + time.Minute)
		ended = l.Tick(context.Background())
	}
	if len(ended) != 1 || !strings.Contains(ended[0].Outcome, "per-step cap") || !strings.Contains(ended[0].Outcome, "helm upgrade 0") {
		t.Fatalf("ended = %+v", ended)
	}
}

// Many short steps hit the per-session step-time cap, and a flood of step
// starts hits the start-count cap.
func TestTotalStepTimeAndStartCountCaps(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	l.StepCap, l.StepTotalCap = 4*time.Hour, 8*time.Hour
	l.MaxLifetime, l.HardCeiling = 100*time.Hour, 200*time.Hour
	start(t, l, "pr-2", TypeChartMajor)
	tok := l.StepToken("pr-2")
	var ended []Ended
	for i := 0; i < 20 && len(ended) == 0; i++ {
		_ = l.StepStarted("pr-2", tok, "step")
		now = now.Add(3 * time.Hour)
		_ = l.StepFinished("pr-2", tok)
		ended = l.Tick(context.Background())
	}
	if len(ended) != 1 || !strings.Contains(ended[0].Outcome, "per-session cap") {
		t.Fatalf("total cap: %+v", ended)
	}

	l.MaxStepStarts, l.StepTotalCap = 3, 0
	start(t, l, "pr-3", TypeChartMajor)
	tok = l.StepToken("pr-3")
	for i := 0; i < 4; i++ {
		_ = l.StepStarted("pr-3", tok, "s")
		_ = l.StepFinished("pr-3", tok)
	}
	if ended = l.Tick(context.Background()); len(ended) != 1 || !strings.Contains(ended[0].Outcome, "step starts") {
		t.Fatalf("start cap: %+v", ended)
	}
}

// An ephemeral container (kubectl debug) added to a running session pod
// ends the session at the next tick; and is refused at attach.
func TestEphemeralContainerEndsTheSession(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	start(t, l, "pr-4", TypeChartMajor)
	k.objects["pods/"+PodName("pr-4")]["spec"].(map[string]any)["ephemeralContainers"] = []any{map[string]any{"name": "debugger", "image": "busybox"}}
	if _, _, err := l.Start(context.Background(), req("pr-4", TypeChartMajor, "litellm")); !errors.Is(err, ErrForeignObject) {
		t.Fatalf("attach to a pod with an ephemeral container: %v", err)
	}
	start(t, l, "pr-5", TypeChartMajor)
	k.objects["pods/"+PodName("pr-5")]["spec"].(map[string]any)["ephemeralContainers"] = []any{map[string]any{"name": "debugger"}}
	ended := l.Tick(context.Background())
	if len(ended) != 1 || !ended[0].Alarm || !strings.Contains(ended[0].Outcome, "ephemeral") {
		t.Fatalf("tick: %+v", ended)
	}
	if _, ok := k.objects["secrets/"+SecretName("pr-5")]; ok {
		t.Error("credentials survived")
	}
}

// c1s-r5: every credential under SESSION_SECRET_DIR is in the GLOBAL
// redaction set from startup (before any session exists, so console logs
// and pages never show one) and again after it rotates.
func TestSessionCredentialsAreRegisteredGlobally(t *testing.T) {
	now := time.Unix(0, 0)
	l := launcher(t, newFake(), &now)
	omni := "omni-" + strings.Repeat("Gq7", 8) // unique to this test
	if err := os.WriteFile(filepath.Join(l.CredDir, "omni-sa-key"), []byte(omni), 0o600); err != nil {
		t.Fatal(err)
	}
	if out := scrub.String("log: " + omni); !strings.Contains(out, "Gq7Gq7") {
		t.Fatal("precondition: the value must not be registered yet")
	}
	l.RegisterCredentials()
	if out := scrub.String("log: " + omni); strings.Contains(out, "Gq7Gq7") {
		t.Fatalf("omni key not redacted globally: %q", out)
	}
	rotated := "omni-" + strings.Repeat("Rt9", 8)
	if err := os.WriteFile(filepath.Join(l.CredDir, "omni-sa-key"), []byte(rotated), 0o600); err != nil {
		t.Fatal(err)
	}
	l.Tick(context.Background()) // every cycle re-reads the directory
	if out := scrub.String("log: " + rotated); strings.Contains(out, "Rt9Rt9") {
		t.Fatalf("rotated key not redacted: %q", out)
	}
}

// c1s-r11: an oversize transcript is refused (the session is not ended, it
// may retry with less); redaction runs under a time limit, and a transcript
// whose redaction does not finish is withheld, never stored raw.
func TestTranscriptCapAndScrubTimeout(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	l.TranscriptMax = 1 << 10
	start(t, l, "pr-8", TypeChartMajor)
	l.Store.Track(store.Update{ID: "pr-8", Title: "x"})
	if err := l.End(context.Background(), "pr-8", "done", "session", strings.Repeat("a", 2<<10)); !errors.Is(err, ErrTranscriptTooLarge) {
		t.Fatalf("oversize transcript: %v", err)
	}
	if _, ok := l.Get("pr-8"); !ok {
		t.Fatal("a refused transcript must not end the session")
	}
	l.ScrubTimeout = time.Nanosecond
	l.scrubFn = func(_ *scrub.Set, s string) string { time.Sleep(50 * time.Millisecond); return s }
	if err := l.End(context.Background(), "pr-8", "done", "session", "secret-ish text"); err != nil {
		t.Fatal(err)
	}
	u, _ := l.Store.Get("pr-8")
	if strings.Contains(u.Transcript, "secret-ish") || !strings.Contains(u.Transcript, "withheld") {
		t.Fatalf("transcript after a scrub timeout = %q", u.Transcript)
	}
}

// Every session-supplied field is capped and redacted under the time bound:
// the outcome cannot bypass the transcript's limits, nor can a step name.
func TestEverySessionFieldIsCappedAndBoundedScrubbed(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	start(t, l, "pr-9", TypeChartMajor)
	tok := l.StepToken("pr-9")
	if err := l.StepStarted("pr-9", tok, strings.Repeat("n", MaxStepName+1)); !errors.Is(err, ErrFieldTooLarge) {
		t.Errorf("oversize step name: %v", err)
	}
	if err := l.End(context.Background(), "pr-9", strings.Repeat("o", DefaultOutcomeMax+1), "session", ""); !errors.Is(err, ErrFieldTooLarge) {
		t.Errorf("oversize outcome: %v", err)
	}
	if _, ok := l.Get("pr-9"); !ok {
		t.Fatal("a refused outcome must not end the session")
	}
	l.ScrubTimeout = time.Nanosecond
	l.scrubFn = func(_ *scrub.Set, s string) string { time.Sleep(50 * time.Millisecond); return s }
	if err := l.StepStarted("pr-9", tok, "leaky step name"); err != nil {
		t.Fatal(err)
	}
	if r, _ := l.Get("pr-9"); strings.Contains(r.StepName, "leaky") {
		t.Errorf("step name stored unredacted after a scrub timeout: %q", r.StepName)
	}
	if err := l.End(context.Background(), "pr-9", "leaky outcome", "session", ""); err != nil {
		t.Fatal(err)
	}
	for _, e := range l.Store.History("pr-9") {
		if strings.Contains(e.Reason, "leaky") {
			t.Errorf("History holds unredacted session text after a scrub timeout: %q", e.Reason)
		}
	}
}

// c1c-r16: Secrets and pods the console made that no session record
// accounts for, and locks whose holder has no session, are reconciled away;
// a live session is untouched.
func TestReconcileOrphans(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	start(t, l, "pr-live", TypeChartMajor)
	_, _, _ = l.Start(context.Background(), req("pr-gone", TypeStateful, "gitea"))
	// pr-gone's record vanishes (e.g. restored from an older state file);
	// its pod, Secrets and lock are left behind.
	_ = l.update(func(m map[string]Record) error { delete(m, "pr-gone"); return nil })
	k.objects["secrets/"+SecretName("pr-orphan")] = map[string]any{"metadata": map[string]any{"name": SecretName("pr-orphan"),
		"labels": map[string]any{kube.ManagedByLabel: kube.ManagedBy, LabelRunID: "pr-orphan"}}}
	orphans, err := l.ReconcileOrphans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"pods/" + PodName("pr-gone"), "secrets/" + SecretName("pr-gone"), "secrets/" + BriefName("pr-gone"), "secrets/" + SecretName("pr-orphan")} {
		if _, ok := k.objects[gone]; ok {
			t.Errorf("%s survived", gone)
		}
	}
	for _, kept := range []string{"pods/" + PodName("pr-live"), "secrets/" + SecretName("pr-live")} {
		if _, ok := k.objects[kept]; !ok {
			t.Errorf("the live session's %s was removed", kept)
		}
	}
	if h := (Locks{Store: l.Store}).Holder(Target(TypeStateful, "frank", "gitea")); h != "" {
		t.Errorf("orphan lock still held by %q", h)
	}
	if (Locks{Store: l.Store}).Holder(Target(TypeChartMajor, "frank", "litellm")) != "pr-live" {
		t.Error("the live session's lock was released")
	}
	if len(orphans) != 5 {
		t.Errorf("orphans = %+v", orphans)
	}
}

// c1d-r8: a write never replaces undecodable session records with {}.
func TestUpdateNeverOverwritesUnreadableRecords(t *testing.T) {
	now := time.Unix(0, 0)
	l := launcher(t, newFake(), &now)
	bad := json.RawMessage(`{"pr-1": 7}`)
	_ = l.Store.UpdateBlob(sessionBlob, func(json.RawMessage) (json.RawMessage, error) { return bad, nil })
	if err := l.update(func(m map[string]Record) error { m["x"] = Record{ID: "x"}; return nil }); err == nil {
		t.Fatal("update over unreadable records succeeded")
	}
	if raw, _ := l.Store.RawBlob(sessionBlob); string(raw) != string(bad) {
		t.Fatalf("records overwritten: %s", raw)
	}
}

// sec2-10: unreadable session records make nothing an orphan.
func TestOrphansNotReapedWhenRecordsAreUnreadable(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	start(t, l, "pr-1", TypeChartMajor)
	_ = l.Store.UpdateBlob(sessionBlob, func(json.RawMessage) (json.RawMessage, error) { return json.RawMessage(`{"pr-1": 7}`), nil })
	n := len(k.objects)
	if _, err := l.ReconcileOrphans(context.Background()); err == nil {
		t.Fatal("orphan reconciliation ran on unreadable records")
	}
	if len(k.objects) != n {
		t.Fatalf("objects deleted on unreadable records: %d → %d", n, len(k.objects))
	}
}

type flakySecrets struct {
	*fakeKube
	code int
}

func (f flakySecrets) Get(ctx context.Context, path string, out any) error {
	if strings.Contains(path, "/secrets/") {
		return &kube.APIError{Code: f.code, Reason: "x"}
	}
	return f.fakeKube.Get(ctx, path, out)
}

// c1d-r2: a transient Secret read error is "unknown", not a mismatch: the
// session is not killed and no false alarm fires — until it persists for
// verifyUnknownLimit cycles, which ends the session (and alarms).
func TestTransientVerifyErrorsDoNotKill(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	start(t, l, "pr-1", TypeChartMajor)
	l.Kube = flakySecrets{k, 503}
	for i := 1; i < verifyUnknownLimit; i++ {
		if ended := l.Tick(context.Background()); len(ended) != 0 {
			t.Fatalf("killed on a transient error: %+v", ended)
		}
		if a := l.Alarms(); len(a) != 0 {
			t.Fatalf("false alarm after %d unknown cycles: %v", i, a)
		}
	}
	if ended := l.Tick(context.Background()); len(ended) != 1 || !strings.Contains(ended[0].Outcome, "could not be verified") {
		t.Fatalf("at the unknown limit the session must end: %+v", ended)
	}
	if _, ok := k.objects["pods/"+PodName("pr-1")]; ok {
		t.Fatal("pod survived the unknown limit")
	}
}

// An unknown verify result never suspends the time bounds: the hard
// ceiling still fires while every verification read fails.
func TestCeilingFiresWhileVerifyReadsFail(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	l.HardCeiling = 16 * time.Hour
	start(t, l, "pr-1", TypeChartMajor)
	l.Kube = flakySecrets{k, 503}
	now = now.Add(17 * time.Hour)
	if ended := l.Tick(context.Background()); len(ended) != 1 || !strings.Contains(ended[0].Outcome, "hard ceiling") {
		t.Fatalf("ceiling while unverifiable: %+v", ended)
	}
	// Max lifetime and idle too.
	k2 := newFake()
	l2 := launcher(t, k2, &now)
	start(t, l2, "pr-2", TypeChartMajor)
	l2.Kube = flakySecrets{k2, 503}
	now = now.Add(9 * time.Hour)
	if ended := l2.Tick(context.Background()); len(ended) != 1 || !strings.Contains(ended[0].Outcome, "maximum lifetime") {
		t.Fatalf("max lifetime while unverifiable: %+v", ended)
	}
}

// A 403 is evidence, not a transient error: a mismatch that ends the session.
func TestForbiddenVerifyReadIsAMismatch(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	start(t, l, "pr-1", TypeChartMajor)
	l.Kube = flakySecrets{k, 403}
	if ended := l.Tick(context.Background()); len(ended) != 1 || !strings.Contains(ended[0].Outcome, "failed verification") {
		t.Fatalf("403 on a recorded Secret: %+v", ended)
	}
}

type stuckDelete struct{ *fakeKube }

func (s stuckDelete) Delete(_ context.Context, _, res, _ string) error {
	return &kube.APIError{Code: 500, Reason: "InternalError"}
}
func (s stuckDelete) DeleteUID(_ context.Context, _, _, _, _ string) error {
	return &kube.APIError{Code: 500, Reason: "InternalError"}
}

// c1d-r1: stripping the managed-by label from a running session pod does
// not shield it: it is deleted by its recorded uid; and while it cannot be
// deleted the record and lock stay, so no second session can start.
func TestStrippedLabelDoesNotShieldTheSessionPod(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	l.HardCeiling = 16 * time.Hour
	start(t, l, "pr-1", TypeChartMajor)
	pod := k.objects["pods/"+PodName("pr-1")]
	delete(pod["metadata"].(map[string]any)["labels"].(map[string]any), kube.ManagedByLabel)
	now = now.Add(17 * time.Hour)
	l.Tick(context.Background())
	if _, ok := k.objects["pods/"+PodName("pr-1")]; ok {
		t.Fatal("a session pod with a stripped label survived the hard ceiling")
	}
	if _, ok := l.Get("pr-1"); ok {
		t.Error("record kept after its pod was deleted")
	}

	// Deletion impossible: the record and the lock stay.
	k2 := newFake()
	l2 := launcher(t, k2, &now)
	start(t, l2, "pr-2", TypeChartMajor)
	l2.Kube = stuckDelete{k2}
	if err := l2.End(context.Background(), "pr-2", "ended", "derio", ""); err == nil {
		t.Fatal("End reported success with the pod still there")
	}
	if _, ok := l2.Get("pr-2"); !ok {
		t.Fatal("record dropped while the pod still exists")
	}
	if (Locks{Store: l2.Store}).Holder(Target(TypeChartMajor, "frank", "litellm")) != "pr-2" {
		t.Fatal("lock released while the pod still exists")
	}
}

// A cleanup that keeps failing alarms once, not once per cycle; when it
// finally completes (a state change) it alarms again.
func TestStuckCleanupAlarmsOnce(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	l.HardCeiling = 16 * time.Hour
	start(t, l, "pr-7", TypeChartMajor)
	l.Kube = stuckDelete{k}
	now = now.Add(17 * time.Hour)
	var alarms []string
	for i := 0; i < 5; i++ {
		l.Tick(context.Background())
		alarms = append(alarms, l.Alarms()...)
	}
	if len(alarms) != 1 || !strings.Contains(alarms[0], "CLEANUP INCOMPLETE") {
		t.Fatalf("alarms over 5 stuck ticks = %v", alarms)
	}
	l.Kube = k
	l.Tick(context.Background())
	if a := l.Alarms(); len(a) != 1 || strings.Contains(a[0], "INCOMPLETE") {
		t.Fatalf("completion must alarm once more: %v", a)
	}
}

func TestEndKeepsAScrubbedTranscript(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	start(t, l, "hop-os-1", TypeHopOS)
	l.Store.Track(store.Update{ID: "hop-os-1", Title: "Hop Talos 1.13.4"})
	secret := "hop-kube-" + strings.Repeat("Hk5", 8)
	transcript := "$ cat kubeconfig\n\x1b[32m" + secret + "\x1b[0m\nupgrade done"
	if err := l.End(context.Background(), "hop-os-1", "verified: hop on 1.13.4", "derio", transcript); err != nil {
		t.Fatal(err)
	}
	u, _ := l.Store.Get("hop-os-1")
	if strings.Contains(u.Transcript, "Hk5Hk5") || !strings.Contains(u.Transcript, "upgrade done") {
		t.Fatalf("transcript = %q", u.Transcript)
	}
	h := l.Store.History("hop-os-1")
	if len(h) == 0 || h[0].Action != "session-ended" || !strings.Contains(h[0].Reason, "verified") {
		t.Fatalf("history = %+v", h)
	}
	// Ending twice is harmless.
	if err := l.End(context.Background(), "hop-os-1", "again", "derio", ""); err != nil {
		t.Errorf("second end: %v", err)
	}
}

func TestDeadPodEndsAsNeedsYou(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	start(t, l, "pr-5", TypeStateful)
	k.phase = "Failed"
	ended := l.Tick(context.Background())
	if len(ended) != 1 || !strings.Contains(ended[0].Outcome, "needs you") {
		t.Fatalf("dead pod = %+v", ended)
	}
	if _, ok := k.objects["secrets/"+SecretName("pr-5")]; ok {
		t.Error("leftover credentials of a dead session")
	}
}

func TestCleanupOrphan(t *testing.T) {
	now := time.Unix(0, 0)
	k := newFake()
	l := launcher(t, k, &now)
	start(t, l, "pr-6", TypeChartMajor)
	if err := l.CleanupPod(context.Background(), PodName("pr-6"), "orphan"); err != nil {
		t.Fatal(err)
	}
	if len(k.objects) != 0 {
		t.Errorf("leftovers: %v", k.objects)
	}
	if err := l.CleanupPod(context.Background(), "us-not-ours-xyz", "x"); err != nil {
		t.Errorf("cleaning an already-gone pod is fine: %v", err)
	}
}
