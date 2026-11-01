package store

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/engine"
	"github.com/derio-net/cluster-update-fr/internal/live"
)

var t0 = time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s, dir
}

// Single writer (c1s-r6): a second console on the same state directory (a
// second replica, or a RollingUpdate overlap) must refuse to start rather
// than race the first one's writes.
func TestSecondWriterIsRefused(t *testing.T) {
	s, dir := open(t)
	if _, err := Open(dir, nil); !errors.Is(err, ErrLocked) {
		t.Fatalf("second Open on a held state dir: %v", err)
	}
	s.Close()
	s2, err := Open(dir, nil)
	if err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	s2.Close()
}

func TestLifecycleAndHistory(t *testing.T) {
	s, _ := open(t)
	s.Track(Update{ID: "pr-7", Title: "Update litellm", Cluster: "frank", Apps: []string{"litellm"}, Path: "auto-merge", PR: 7})
	steps := []struct {
		to   State
		by   string
		with func(*Update)
	}{
		{Approved, "derio", nil},
		{Merged, "auto", func(u *Update) { u.MergeSHA = "abc" }},
		{Applied, "verifier", func(u *Update) { u.Rollout = "operationState at abc" }},
		{Verified, "verifier", func(u *Update) { u.Verification = "2/2 smoke checks passed" }},
	}
	for _, st := range steps {
		if err := s.Transition("pr-7", st.to, st.by, "", st.with); err != nil {
			t.Fatalf("→ %s: %v", st.to, err)
		}
	}
	u, _ := s.Get("pr-7")
	if u.State != Verified || u.MergeSHA != "abc" || u.Verification == "" {
		t.Fatalf("update = %+v", u)
	}
	h := s.History("pr-7")
	if len(h) != 4 || h[0].To != Verified || h[3].From != Pending || h[3].By != "derio" {
		t.Fatalf("history = %+v", h)
	}
	if h[0].Verification == "" || h[1].Rollout == "" {
		t.Error("history must carry rollout and verification results")
	}
}

func TestIllegalTransitions(t *testing.T) {
	s, _ := open(t)
	s.Track(Update{ID: "u", Title: "x"})
	if err := s.Transition("u", Verified, "x", "", nil); !errors.Is(err, ErrIllegal) {
		t.Errorf("pending → verified: %v", err)
	}
	_ = s.Transition("u", Abandoned, "reconciler", "PR closed", nil)
	if err := s.Transition("u", Approved, "x", "", nil); !errors.Is(err, ErrIllegal) {
		t.Errorf("abandoned is terminal: %v", err)
	}
	if err := s.Transition("missing", Approved, "x", "", nil); !errors.Is(err, ErrUnknown) {
		t.Errorf("unknown: %v", err)
	}
}

func TestFailureStatesNeedANamedReason(t *testing.T) {
	s, _ := open(t)
	s.Track(Update{ID: "u", Title: "x"})
	_ = s.Transition("u", Approved, "x", "", nil)
	_ = s.Transition("u", Merged, "x", "", nil)
	if err := s.Transition("u", Failed, "verifier", "", nil); !errors.Is(err, ErrNeedsReason) {
		t.Errorf("failed without reason: %v", err)
	}
	if err := s.Transition("u", Failed, "verifier", "failed at step smoke litellm /health, rolled back", nil); err != nil {
		t.Fatal(err)
	}
	u, _ := s.Get("u")
	if u.Reason != "failed at step smoke litellm /health, rolled back" {
		t.Errorf("reason = %q", u.Reason)
	}
	_ = s.Transition("u", RolledBack, "derio", "revert PR #12", nil)
	if u, _ := s.Get("u"); u.State != RolledBack {
		t.Error("failed → rolled-back allowed")
	}
}

func TestPersistenceAndCorruptFile(t *testing.T) {
	s, dir := open(t)
	s.Track(Update{ID: "u", Title: "x"})
	s.SetHold("u", true, "derio")
	s.Record(engine.Event{At: t0, Item: "pr-1", Action: "merged", By: "auto", PR: 1, SHA: "m"})
	if err := s.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "state.json.tmp")); !os.IsNotExist(err) {
		t.Error("temp file left behind: save must write temp then rename")
	}
	s.Close()
	s2, err := Open(dir, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	if held, by := s2.Hold("u"); !held || by != "derio" {
		t.Error("hold not persisted")
	}
	if len(s2.History("")) == 0 {
		t.Error("history not persisted")
	}
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2.Close()
	s3, err := Open(dir, func() time.Time { return t0 })
	if err != nil {
		t.Fatalf("a corrupt state file must not stop the console: %v", err)
	}
	if len(s3.Updates()) != 0 || s3.Warning == "" {
		t.Errorf("corrupt file: updates=%d warning=%q", len(s3.Updates()), s3.Warning)
	}
	matches, _ := filepath.Glob(filepath.Join(dir, "state.json.corrupt-*"))
	if len(matches) != 1 {
		t.Errorf("corrupt file must be moved aside, found %v", matches)
	}
}

func TestLedgerDrivesUpdates(t *testing.T) {
	s, _ := open(t)
	s.Track(Update{ID: "pr-1", Title: "Update a", PR: 1})
	s.Record(engine.Event{At: t0, Item: "pr-1", Action: "approved", By: "derio", PR: 1})
	s.Record(engine.Event{At: t0, Item: "pr-1", Action: "merged", By: "derio", PR: 1, SHA: "m1"})
	u, _ := s.Get("pr-1")
	if u.State != Merged || u.MergeSHA != "m1" || u.Approver != "derio" {
		t.Fatalf("update = %+v", u)
	}
	s.Record(engine.Event{At: t0, Item: "batch-100", Action: "batch-approved", By: "derio", PR: 100, Detail: "a, b"})
	if b, ok := s.Get("batch-100"); !ok || b.State != Approved || b.PR != 100 {
		t.Fatalf("batch = %+v", b)
	}
	s.Track(Update{ID: "pr-2", Title: "Update b", PR: 2})
	s.Record(engine.Event{At: t0, Item: "pr-2", Action: "failed-ci", By: "auto", PR: 2, Detail: "CI failed again"})
	if u, _ := s.Get("pr-2"); u.State != Failed || !strings.Contains(u.Reason, "failed — CI") {
		t.Fatalf("failed-ci = %+v", u)
	}
	s.SetApproved("pr-3", "derio")
	if ok, by := s.Approved("pr-3"); !ok || by != "derio" {
		t.Error("approval")
	}
	s.AddRetry("pr-2")
	if s.Retries("pr-2") != 1 || s.Retries("pr-3") != 0 {
		t.Error("retries are per update")
	}
	if !s.RetriedAt("pr-2").Equal(t0) || !s.RetriedAt("pr-3").IsZero() {
		t.Error("the retry time is recorded once")
	}
}

func TestReconcileNamesEveryLeftover(t *testing.T) {
	s, _ := open(t)
	now := t0
	s.now = func() time.Time { return now }
	s.Track(Update{ID: "pr-1", Title: "a", PR: 1})
	_ = s.Transition("pr-1", Approved, "derio", "", nil) // PR then closed unmerged
	s.Track(Update{ID: "pr-2", Title: "b", PR: 2})
	_ = s.Transition("pr-2", Approved, "derio", "", nil)
	_ = s.Transition("pr-2", Merged, "auto", "", func(u *Update) { u.MergeSHA = "m" })
	s.Track(Update{ID: "pr-3", Title: "c", PR: 3, Session: "us-pr-3"}) // open PR, fine
	now = t0.Add(5 * time.Hour)
	out, _ := s.Reconcile(ReconcileInput{
		OpenPRs: map[int]bool{3: true},
		SessionPods: []live.Pod{
			{Namespace: "upgrade-sessions", Name: "us-gone", Labels: map[string]string{"fr.run/id": "frank-os-old"}},
			{Namespace: "upgrade-sessions", Name: "us-pr-3", Labels: map[string]string{"fr.run/id": "pr-3"}},
		},
		StaleBranches: []string{"cluster-update/batch-20261030-1000"},
		ApplyTimeout:  2 * time.Hour,
	})
	if u, _ := s.Get("pr-1"); u.State != Abandoned || !strings.Contains(u.Reason, "closed") {
		t.Errorf("pr-1 = %+v", u)
	}
	if u, _ := s.Get("pr-2"); u.State != Failed || !strings.Contains(u.Reason, "not applied") {
		t.Errorf("pr-2 = %+v", u)
	}
	if u, _ := s.Get("pr-3"); u.State != Pending {
		t.Errorf("pr-3 must be untouched: %+v", u)
	}
	kinds := map[string]string{}
	for _, c := range out {
		kinds[c.Target] = c.Kind
	}
	if kinds["us-gone"] != CleanupPod || kinds["us-pr-3"] != "" {
		t.Errorf("pods: %+v", out)
	}
	if kinds["cluster-update/batch-20261030-1000"] != CleanupBranch {
		t.Errorf("branches: %+v", out)
	}
}

// c1c-r4: a held update whose PR got merged anyway (by hand on GitHub, or a
// batch) becomes merged — the reconciler may do what a person may not —
// and a transition the reconciler cannot make is reported, not dropped.
func TestReconcileMovesHeldToMergedAndReportsErrors(t *testing.T) {
	s, _ := open(t)
	s.Track(Update{ID: "pr-1", Title: "a", PR: 1})
	_ = s.Transition("pr-1", Held, "derio", "held by derio", nil)
	if err := s.Transition("pr-1", Merged, "derio", "", nil); err == nil {
		t.Fatal("held → merged stays illegal for everyone but the reconciler")
	}
	_, errs := s.Reconcile(ReconcileInput{OpenPRs: map[int]bool{}, MergedPRs: map[int]string{1: "m1"}})
	if u, _ := s.Get("pr-1"); u.State != Merged || u.MergeSHA != "m1" {
		t.Fatalf("held PR merged on GitHub: %+v", u)
	}
	if len(errs) != 0 {
		t.Errorf("errors = %v", errs)
	}
}

// c1c-r6: a failed update is where the operator REPAIRS it — often from its
// session. Its pod is not reaped; only terminal states and unknown ids are.
func TestReconcileKeepsTheSessionOfAFailedUpdate(t *testing.T) {
	s, _ := open(t)
	s.Track(Update{ID: "frank-os-1", Title: "x"})
	_ = s.Transition("frank-os-1", Failed, "verifier", "failed at step smoke", nil)
	s.Track(Update{ID: "pr-4", Title: "y", PR: 4})
	_ = s.Transition("pr-4", Abandoned, "x", "gone", nil)
	out, _ := s.Reconcile(ReconcileInput{OpenPRs: map[int]bool{}, SessionPods: []live.Pod{
		{Name: "us-repair", Labels: map[string]string{"fr.run/id": "frank-os-1"}},
		{Name: "us-done", Labels: map[string]string{"fr.run/id": "pr-4"}},
	}})
	got := map[string]bool{}
	for _, c := range out {
		got[c.Target] = true
	}
	if got["us-repair"] {
		t.Error("the session repairing a failed update was reaped")
	}
	if !got["us-done"] {
		t.Error("the session of a terminal update must be reaped")
	}
}

func TestConcurrentUse(t *testing.T) {
	s, _ := open(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := "u" + string(rune('a'+i))
			s.Track(Update{ID: id, Title: id})
			_ = s.Transition(id, Approved, "x", "", nil)
			_ = s.Save()
		}(i)
	}
	wg.Wait()
	if len(s.Updates()) != 20 {
		t.Errorf("updates = %d", len(s.Updates()))
	}
}

func TestCountsByState(t *testing.T) {
	s, _ := open(t)
	s.Track(Update{ID: "a"})
	s.Track(Update{ID: "b"})
	_ = s.Transition("b", Approved, "x", "", nil)
	c := s.CountByState()
	if c[Pending] != 1 || c[Approved] != 1 || len(AllStates) != 9 {
		t.Errorf("counts = %v", c)
	}
}
