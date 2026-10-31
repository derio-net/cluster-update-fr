package session

import (
	"context"
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
