package session

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

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
