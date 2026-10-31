package verify

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/live"
)

func check(kind, target string, status int, body string) frankrepo.Check {
	c := frankrepo.Check{Kind: kind, Target: target}
	c.Expect.Status, c.Expect.Body = status, body
	return c
}

func TestSmokeRunner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write([]byte(`{"data":[1]}`))
		case "/leaky":
			w.WriteHeader(500)
			_, _ = w.Write([]byte("boom tok" + "en: " + strings.Repeat("Sm0", 8)))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	r := Runner{HTTP: srv.Client()}
	smoke := frankrepo.Smoke{App: "litellm", Cluster: "frank", Checks: []frankrepo.Check{
		check("http", srv.URL+"/ok", 200, ""),
		check("functional", srv.URL+"/ok", 200, `"data"`),
		check("tcp", ln.Addr().String(), 0, ""),
		{Kind: "exec-probe", Target: "kubectl exec …", Reason: "no network surface"},
	}}
	res := r.Run(context.Background(), smoke)
	if !res.Passed() || len(res.Checks) != 4 {
		t.Fatalf("results = %+v", res)
	}
	if res.Checks[3].Status != CheckSkipped {
		t.Errorf("exec-probe must be reported as operator-run, not pass/fail: %+v", res.Checks[3])
	}
	bad := r.Run(context.Background(), frankrepo.Smoke{App: "x", Checks: []frankrepo.Check{
		check("http", srv.URL+"/leaky", 200, ""),
		check("functional", srv.URL+"/ok", 200, `"nope"`),
	}})
	if bad.Passed() || bad.Checks[0].Status != CheckFailed || bad.Checks[1].Status != CheckFailed {
		t.Fatalf("bad = %+v", bad)
	}
	if strings.Contains(bad.Summary(), "Sm0Sm0Sm0") {
		t.Errorf("response bodies must be scrubbed: %q", bad.Summary())
	}
	if !strings.Contains(bad.FirstFailure(), "/leaky") {
		t.Errorf("the failing check must be named: %q", bad.FirstFailure())
	}
	if (Runner{}).Run(context.Background(), frankrepo.Smoke{App: "none"}).Passed() {
		t.Error("an app with no checks cannot be verified")
	}
}

func app(applied, health, phase string) live.Application {
	return live.Application{Name: "litellm", SyncStatus: "Synced", SyncRevision: "newest", Health: health, OperationPhase: phase,
		Sources: []live.Source{{RepoURL: "https://github.com/derio-net/frank", Applied: applied}}}
}

type ancestry map[string]bool

func (a ancestry) Contains(_ context.Context, ancestor, descendant string) (bool, error) {
	if ancestor == descendant {
		return true, nil
	}
	return a[ancestor+".."+descendant], nil
}

func TestAppliedReadsTheOperationNotTheSyncStatus(t *testing.T) {
	ctx := context.Background()
	anc := ancestry{"merge..later": true}
	cases := []struct {
		name string
		a    live.Application
		want bool
	}{
		{"applied exactly", app("merge", "Healthy", "Succeeded"), true},
		{"applied a descendant", app("later", "Healthy", "Succeeded"), true},
		{"Synced but last operation older (stale-revision gotcha)", app("older", "Healthy", "Succeeded"), false},
		{"operation failed", app("merge", "Healthy", "Failed"), false},
		{"degraded", app("merge", "Degraded", "Succeeded"), false},
	}
	for _, c := range cases {
		got, why := Applied(ctx, c.a, "merge", "derio-net/frank", anc)
		if got != c.want {
			t.Errorf("%s: %v (%s)", c.name, got, why)
		}
	}
}

func TestWorkloadOutcome(t *testing.T) {
	ctx := context.Background()
	anc := ancestry{}
	snap := &live.Snapshot{Apps: []live.Application{app("merge", "Healthy", "Succeeded")}, Errors: map[string]string{}}
	pass := SmokeResult{App: "litellm", Checks: []CheckResult{{Name: "http", Status: CheckPassed}}}
	fail := SmokeResult{App: "litellm", Checks: []CheckResult{{Name: "GET /health", Status: CheckFailed, Detail: "500"}}}
	if o := Workload(ctx, WorkloadInput{Apps: []string{"litellm"}, MergeSHA: "merge", Repo: "derio-net/frank", Snapshot: snap, Ancestry: anc, Smoke: map[string]SmokeResult{"litellm": pass}}); o.To != OutcomeVerified {
		t.Errorf("pass: %+v", o)
	}
	o := Workload(ctx, WorkloadInput{Apps: []string{"litellm"}, MergeSHA: "merge", Repo: "derio-net/frank", Snapshot: snap, Ancestry: anc, Smoke: map[string]SmokeResult{"litellm": fail}})
	if o.To != OutcomeFailed || !strings.Contains(o.Reason, "GET /health") {
		t.Errorf("fail: %+v", o)
	}
	stale := &live.Snapshot{Apps: []live.Application{app("older", "Healthy", "Succeeded")}, Errors: map[string]string{}}
	if o := Workload(ctx, WorkloadInput{Apps: []string{"litellm"}, MergeSHA: "merge", Repo: "derio-net/frank", Snapshot: stale, Ancestry: anc}); o.To != OutcomeWaiting || !strings.Contains(o.Display, "rolled out, unverified") && !strings.Contains(o.Display, "not yet applied") {
		t.Errorf("stale: %+v", o)
	}
	if o := Workload(ctx, WorkloadInput{Apps: []string{"ghost"}, MergeSHA: "merge", Repo: "derio-net/frank", Snapshot: snap, Ancestry: anc}); o.To != OutcomeWaiting {
		t.Errorf("unknown app must wait, not pass: %+v", o)
	}
	// Applied but no smoke result yet: applied, unverified.
	if o := Workload(ctx, WorkloadInput{Apps: []string{"litellm"}, MergeSHA: "merge", Repo: "derio-net/frank", Snapshot: snap, Ancestry: anc}); o.To != OutcomeApplied {
		t.Errorf("no smoke yet: %+v", o)
	}
}

func TestOSOutcome(t *testing.T) {
	decl := frankrepo.ClusterVersions{Talos: "1.13.4", Kubernetes: "1.35.3"}
	nodes := func(talos ...string) *live.Snapshot {
		s := &live.Snapshot{Errors: map[string]string{}}
		for i, v := range talos {
			s.Nodes = append(s.Nodes, live.Node{Name: string(rune('a' + i)), Talos: v, Kubelet: "1.35.3", Ready: true})
		}
		return s
	}
	pass := []SmokeResult{{App: "a", Checks: []CheckResult{{Status: CheckPassed}}}}
	if o := OS(decl, nodes("1.13.4", "1.13.4"), pass); o.To != OutcomeVerified {
		t.Errorf("all upgraded: %+v", o)
	}
	o := OS(decl, nodes("1.13.4", "1.12.6"), pass)
	if o.To != OutcomeWaiting || !strings.Contains(o.Display, "declared, applying") || !strings.Contains(o.Reason, "b") {
		t.Errorf("half way: %+v", o)
	}
	unready := nodes("1.13.4")
	unready.Nodes[0].Ready = false
	if o := OS(decl, unready, pass); o.To == OutcomeVerified {
		t.Errorf("an unready node cannot verify: %+v", o)
	}
	failSmoke := []SmokeResult{{App: "grafana", Checks: []CheckResult{{Name: "dashboards", Status: CheckFailed}}}}
	if o := OS(decl, nodes("1.13.4"), failSmoke); o.To != OutcomeFailed || !strings.Contains(o.Reason, "grafana") {
		t.Errorf("smoke failure: %+v", o)
	}
	if o := OS(decl, &live.Snapshot{Errors: map[string]string{"nodes": "unreachable"}}, pass); o.To != OutcomeWaiting {
		t.Errorf("unreachable must wait: %+v", o)
	}
}

func TestRolloutDecisions(t *testing.T) {
	snap := &live.Snapshot{Rollouts: []live.Rollout{{Name: "a", Paused: true}, {Name: "b"}, {Name: "c", Aborted: true}}}
	d := RolloutDecisions(snap)
	if len(d) != 2 || d[0].Name != "a" || d[1].Name != "c" {
		t.Errorf("decisions = %+v", d)
	}
}
