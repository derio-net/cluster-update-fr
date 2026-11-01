package cidiag

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/forge"
)

var t0 = time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)

const bridge = "status-bridge[bot]"

func st(ctx, state string, at time.Time) forge.Status {
	s := forge.Status{Context: ctx, State: state, CreatedAt: at}
	s.Creator.Login = bridge
	return s
}

var anyBridge = Requirement{Creators: []string{bridge}}

// c1s-r3: a declared set of required contexts, each green, each posted by a
// trusted creator; skipped/warning forwarded as success is not a pass.
func TestEvaluateRequiredContexts(t *testing.T) {
	timeout := 30 * time.Minute
	// c1d-r12: the console bot is excluded even if it is (mis)listed as a
	// creator — the console never satisfies its own CI gate.
	req := Requirement{Contexts: []string{"gitea-actions/ci / go (push)", "gitea-actions/ci / image (push)"}, Creators: []string{bridge, "cluster-update-fr[bot]"},
		Excluded: []string{"cluster-update-fr[bot]"}}
	forged := st("gitea-actions/ci / image (push)", "success", t0)
	forged.Creator.Login = "mallory"
	skipped := st("gitea-actions/ci / image (push)", "success", t0)
	skipped.Description = "Gitea: skipped"
	reforwarded := st("gitea-actions/ci / image (push)", "success", t0)
	reforwarded.Creator.Login = "cluster-update-fr[bot]"
	cases := []struct {
		name     string
		statuses []forge.Status
		want     Verdict
	}{
		{"any one green context is not enough", []forge.Status{st("gitea-actions/ci / go (push)", "success", t0)}, Pending},
		{"both required green", []forge.Status{st("gitea-actions/ci / go (push)", "success", t0), st("gitea-actions/ci / image (push)", "success", t0)}, Passed},
		{"a required context posted by an untrusted account does not count", []forge.Status{st("gitea-actions/ci / go (push)", "success", t0), forged}, Pending},
		{"skipped is not success", []forge.Status{st("gitea-actions/ci / go (push)", "success", t0), skipped}, Missing},
		{"the console's own status never counts (c1d-r12)", []forge.Status{st("gitea-actions/ci / go (push)", "success", t0), reforwarded}, Pending},
	}
	for _, c := range cases {
		if v, d := Evaluate(c.statuses, t0, t0.Add(time.Minute), timeout, req); v != c.want {
			t.Errorf("%s: got %s (%s), want %s", c.name, v, d, c.want)
		}
	}
	// Excluded alone (no creator configured): nothing passes, whoever posted.
	only := Requirement{Excluded: []string{"cluster-update-fr[bot]"}}
	if v, _ := Evaluate([]forge.Status{reforwarded, st("gitea-actions/ci / go (push)", "success", t0)}, t0, t0.Add(time.Minute), timeout, only); v == Passed {
		t.Error("no STATUS_CREATOR_LOGINS, yet CI passed")
	}
	// Creators that are ALL excluded count as none configured.
	self := Requirement{Creators: []string{"cluster-update-fr[bot]"}, Excluded: []string{"cluster-update-fr[bot]"}}
	if v, _ := Evaluate([]forge.Status{reforwarded}, t0, t0.Add(time.Minute), timeout, self); v == Passed {
		t.Error("the console satisfied its own CI gate")
	}
	if v, _ := Evaluate([]forge.Status{st("gitea-actions/ci / go", "success", t0)}, t0, t0.Add(time.Minute), timeout, Requirement{}); v == Passed {
		t.Error("with no trusted creator configured nothing may pass")
	}
}

func TestEvaluate(t *testing.T) {
	timeout := 30 * time.Minute
	cases := []struct {
		name     string
		statuses []forge.Status
		now      time.Time
		want     Verdict
	}{
		{"nothing yet, inside timeout", nil, t0.Add(5 * time.Minute), Pending},
		{"nothing past timeout", nil, t0.Add(time.Hour), Missing},
		{"pending past timeout", []forge.Status{st("gitea-actions/ci / go", "pending", t0)}, t0.Add(time.Hour), Missing},
		{"pending inside timeout", []forge.Status{st("gitea-actions/ci / go", "pending", t0)}, t0.Add(time.Minute), Pending},
		{"passed", []forge.Status{st("gitea-actions/ci / go", "pending", t0), st("gitea-actions/ci / go", "success", t0.Add(time.Minute))}, t0.Add(time.Hour), Passed},
		{"one failed", []forge.Status{st("gitea-actions/ci / go", "success", t0), st("gitea-actions/ci / image", "failure", t0)}, t0.Add(time.Minute), Failed},
		{"error is a failure", []forge.Status{st("gitea-actions/ci / go", "error", t0)}, t0.Add(time.Minute), Failed},
		{"only non-gitea statuses do not count", []forge.Status{st("renovate/artifacts", "success", t0)}, t0.Add(time.Hour), Missing},
		{"release age gate pending", []forge.Status{st("gitea-actions/ci / go", "success", t0), st("renovate/stability-days", "pending", t0)}, t0.Add(time.Hour), Waiting},
	}
	for _, c := range cases {
		v, _ := Evaluate(c.statuses, t0, c.now, timeout, anyBridge)
		if v != c.want {
			t.Errorf("%s: got %s, want %s", c.name, v, c.want)
		}
	}
}

// c1c-r11: after a retry, only results NEWER than the retry count: the old
// failure the retry acted on must not fail the update a second time.
func TestEvaluateAfterARetryNeedsANewerResult(t *testing.T) {
	timeout := 30 * time.Minute
	old := st("gitea-actions/ci / go", "failure", t0)
	retried := t0.Add(time.Minute)
	req := Requirement{Creators: []string{bridge}, Since: retried}
	if v, d := Evaluate([]forge.Status{old}, t0, retried.Add(time.Minute), timeout, req); v != Pending {
		t.Errorf("only the pre-retry failure: %s (%s), want pending", v, d)
	}
	if v, _ := Evaluate([]forge.Status{old}, t0, retried.Add(timeout+time.Minute), timeout, req); v != Missing {
		t.Errorf("no new result within the timeout after the retry: %s", v)
	}
	again := st("gitea-actions/ci / go", "failure", retried.Add(5*time.Minute))
	if v, _ := Evaluate([]forge.Status{old, again}, t0, retried.Add(10*time.Minute), timeout, req); v != Failed {
		t.Errorf("a newer failure: %s, want failed", v)
	}
	green := st("gitea-actions/ci / go", "success", retried.Add(5*time.Minute))
	if v, _ := Evaluate([]forge.Status{old, green}, t0, retried.Add(10*time.Minute), timeout, req); v != Passed {
		t.Errorf("a newer pass: %s", v)
	}
}

// fakeForges records every action so tests can assert what was (and was
// never) attempted.
type fakeForges struct {
	ghStatuses    []forge.Status
	giteaStatuses []forge.Status
	runs          []forge.Run
	rerun         bool
	delivery      *forge.Delivery
	pr            forge.PR

	created     []forge.Status
	bodies      []string
	redelivered []forge.Delivery
	reruns      []int64
}

func (f *fakeForges) Statuses(context.Context, string) ([]forge.Status, error) {
	return f.ghStatuses, nil
}
func (f *fakeForges) GiteaStatuses(context.Context, string) ([]forge.Status, error) {
	return f.giteaStatuses, nil
}
func (f *fakeForges) Runs(context.Context, string) ([]forge.Run, error) { return f.runs, nil }
func (f *fakeForges) RerunSupported(context.Context) (bool, error)      { return f.rerun, nil }
func (f *fakeForges) Rerun(_ context.Context, id int64) error {
	if !f.rerun {
		return forge.ErrUnsupported
	}
	f.reruns = append(f.reruns, id)
	return nil
}
func (f *fakeForges) PR(context.Context, int) (forge.PR, error) { return f.pr, nil }
func (f *fakeForges) CreateStatus(_ context.Context, _ string, s forge.Status) error {
	f.created = append(f.created, s)
	return nil
}
func (f *fakeForges) UpdatePRBody(_ context.Context, _ int, body string) error {
	f.bodies = append(f.bodies, body)
	return nil
}
func (f *fakeForges) FindDelivery(context.Context, string, int) (forge.Delivery, error) {
	if f.delivery == nil {
		return forge.Delivery{}, forge.ErrNotFound
	}
	return *f.delivery, nil
}
func (f *fakeForges) Redeliver(_ context.Context, d forge.Delivery) error {
	f.redelivered = append(f.redelivered, d)
	return nil
}

const renovateBody = " - [ ] <!-- rebase-check -->If you want to rebase/retry this PR, check this box"

func yes() *bool { b := true; return &b }
func no() *bool  { b := false; return &b }

func TestStatusLostIsReForwardedWithTheBridgeMapping(t *testing.T) {
	f := &fakeForges{
		giteaStatuses: []forge.Status{
			{ID: 1, Context: "ci / go (pull_request)", State: "success", Description: "ok", TargetURL: "/derio-net/frank/actions/runs/4", CreatedAt: t0},
			{ID: 2, Context: "ci / image (pull_request)", State: "skipped", TargetURL: "/derio-net/frank/actions/runs/4", CreatedAt: t0},
		},
		runs: []forge.Run{{ID: 4, Status: "completed", Conclusion: "success"}},
		pr:   forge.PR{Number: 7, HeadSHA: "abc", Body: renovateBody, Mergeable: yes()},
	}
	d := Diagnose(context.Background(), f, f.pr, "http://gitea.example")
	if d.Cause != StatusLost || len(d.Lost) != 2 {
		t.Fatalf("diagnosis = %+v", d)
	}
	a, err := Recover(context.Background(), f, f.pr, d, "http://gitea.example")
	if err != nil || a.Kind != ActionReforward {
		t.Fatalf("recover = %+v %v", a, err)
	}
	if len(f.created) != 2 {
		t.Fatalf("created = %+v", f.created)
	}
	byCtx := map[string]forge.Status{}
	for _, s := range f.created {
		byCtx[s.Context] = s
	}
	g := byCtx["gitea-actions/ci / go (pull_request)"]
	if g.State != "success" || g.Description != "ok" || g.TargetURL != "http://gitea.example/derio-net/frank/actions/runs/4" {
		t.Errorf("forwarded = %+v", g)
	}
	sk := byCtx["gitea-actions/ci / image (pull_request)"]
	if sk.State != "success" || sk.Description != "Gitea: skipped" {
		t.Errorf("skipped must map to success with the real state kept visible: %+v", sk)
	}
}

func TestNeverRanConflictingAsksRenovateToRebase(t *testing.T) {
	f := &fakeForges{pr: forge.PR{Number: 7, HeadSHA: "abc", Body: renovateBody, Mergeable: no()}}
	d := Diagnose(context.Background(), f, f.pr, "")
	if d.Cause != NeverRan || !d.Conflicting {
		t.Fatalf("diagnosis = %+v", d)
	}
	a, err := Recover(context.Background(), f, f.pr, d, "")
	if err != nil || a.Kind != ActionRebase || len(f.bodies) != 1 || len(f.redelivered) != 0 {
		t.Fatalf("recover = %+v %v bodies=%d redelivered=%d", a, err, len(f.bodies), len(f.redelivered))
	}
}

func TestNeverRanMergeableRedeliversTheWebhook(t *testing.T) {
	f := &fakeForges{
		pr:       forge.PR{Number: 7, HeadSHA: "abc", Body: renovateBody, Mergeable: yes()},
		delivery: &forge.Delivery{HookID: 5, ID: 100, Event: "pull_request"},
	}
	d := Diagnose(context.Background(), f, f.pr, "")
	a, err := Recover(context.Background(), f, f.pr, d, "")
	if err != nil || a.Kind != ActionRedeliver || len(f.redelivered) != 1 || len(f.bodies) != 0 {
		t.Fatalf("recover = %+v %v", a, err)
	}
	// No delivery found: fall back to the rebase checkbox.
	f2 := &fakeForges{pr: forge.PR{Number: 7, HeadSHA: "abc", Body: renovateBody, Mergeable: yes()}}
	a2, err := Recover(context.Background(), f2, f2.pr, Diagnose(context.Background(), f2, f2.pr, ""), "")
	if err != nil || a2.Kind != ActionRebase {
		t.Fatalf("fallback = %+v %v", a2, err)
	}
}

func TestRanFailedReRunsWhenSupportedElseRebase(t *testing.T) {
	failed := []forge.Run{{ID: 41, Status: "completed", Conclusion: "failure"}}
	failedSt := []forge.Status{{Context: "ci / go", State: "failure", CreatedAt: t0}}
	f := &fakeForges{runs: failed, giteaStatuses: failedSt, rerun: true,
		ghStatuses: []forge.Status{{Context: "gitea-actions/ci / go", State: "failure", CreatedAt: t0}},
		pr:         forge.PR{Number: 7, HeadSHA: "abc", Body: renovateBody, Mergeable: yes()}}
	d := Diagnose(context.Background(), f, f.pr, "")
	if d.Cause != RanFailed || d.RunID != 41 {
		t.Fatalf("diagnosis = %+v", d)
	}
	a, err := Recover(context.Background(), f, f.pr, d, "")
	if err != nil || a.Kind != ActionRerun || len(f.reruns) != 1 {
		t.Fatalf("recover = %+v %v", a, err)
	}
	// Gitea 1.25.4: no re-run API → Renovate rebase checkbox.
	f.rerun, f.reruns = false, nil
	a, err = Recover(context.Background(), f, f.pr, d, "")
	if err != nil || a.Kind != ActionRebase || len(f.reruns) != 0 {
		t.Fatalf("fallback = %+v %v", a, err)
	}
}

func TestNonRenovatePRWithoutRerunNeedsTheOperator(t *testing.T) {
	f := &fakeForges{runs: []forge.Run{{ID: 41, Status: "completed", Conclusion: "failure"}},
		pr: forge.PR{Number: 9, HeadSHA: "abc", Body: "console batch PR", Mergeable: yes()}}
	d := Diagnose(context.Background(), f, f.pr, "")
	_, err := Recover(context.Background(), f, f.pr, d, "")
	if !errors.Is(err, ErrNeedsOperator) {
		t.Fatalf("err = %v", err)
	}
}

func TestRunningIsNotDiagnosedAsLost(t *testing.T) {
	f := &fakeForges{runs: []forge.Run{{ID: 41, Status: "running"}},
		pr: forge.PR{Number: 7, HeadSHA: "abc", Body: renovateBody}}
	d := Diagnose(context.Background(), f, f.pr, "")
	if d.Cause != Running {
		t.Fatalf("diagnosis = %+v", d)
	}
	if _, err := Recover(context.Background(), f, f.pr, d, ""); !errors.Is(err, ErrNothingToDo) {
		t.Errorf("a running CI must not be retried: %v", err)
	}
}
