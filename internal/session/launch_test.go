package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/kube"
)

// fakeKube stores created objects by "resource/name" and enforces the real
// client's write policy, so a launcher bug cannot hide behind the fake.
type fakeKube struct {
	mu      sync.Mutex
	objects map[string]map[string]any
	creates []string
	deletes []string
	policy  kube.WritePolicy
	phase   string // pod phase reported by Get
}

func newFake() *fakeKube {
	return &fakeKube{objects: map[string]map[string]any{}, policy: kube.WritePolicy{SessionNamespace: "upgrade-sessions"}, phase: "Running"}
}

func asMap(obj any) map[string]any {
	b, _ := json.Marshal(obj)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func nameOf(m map[string]any) string { return m["metadata"].(map[string]any)["name"].(string) }

func (f *fakeKube) Create(_ context.Context, ns, res string, obj any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := asMap(obj)
	if ns != f.policy.SessionNamespace {
		return kube.ErrForbiddenWrite
	}
	k := res + "/" + nameOf(m)
	if _, ok := f.objects[k]; ok {
		return &kube.APIError{Code: 409, Reason: "AlreadyExists"}
	}
	f.objects[k] = m
	f.creates = append(f.creates, k)
	return nil
}

func (f *fakeKube) Delete(_ context.Context, ns, res, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ns != f.policy.SessionNamespace {
		return kube.ErrForbiddenWrite
	}
	k := res + "/" + name
	f.deletes = append(f.deletes, k)
	if _, ok := f.objects[k]; !ok {
		return &kube.APIError{Code: 404, Reason: "NotFound"}
	}
	delete(f.objects, k)
	return nil
}

func (f *fakeKube) Get(_ context.Context, path string, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	parts := strings.Split(path, "/")
	k := parts[len(parts)-2] + "/" + parts[len(parts)-1]
	m, ok := f.objects[k]
	if !ok {
		return &kube.APIError{Code: 404, Reason: "NotFound"}
	}
	if strings.HasPrefix(k, "pods/") {
		m["status"] = map[string]any{"phase": f.phase}
	}
	b, _ := json.Marshal(m)
	return json.Unmarshal(b, out)
}

func credDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"github-token":    "gh-" + strings.Repeat("Ss1", 8),
		"omni-sa-key":     "omni-" + strings.Repeat("Ok2", 8),
		"talosconfig":     "context: frank\ncontexts:\n  frank:\n    ke" + "y: " + strings.Repeat("Tk3", 8),
		"hop-talosconfig": "hop-talos-" + strings.Repeat("Ht4", 8),
		"hop-kubeconfig":  "hop-kube-" + strings.Repeat("Hk5", 8),
		"omni-host":       "never-injected-" + strings.Repeat("X", 8),
	}
	for k, v := range files {
		if err := os.WriteFile(filepath.Join(dir, k), []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func launcher(t *testing.T, k *fakeKube, now *time.Time) *Launcher {
	t.Helper()
	return &Launcher{Kube: k, Store: newStore(t), Namespace: "upgrade-sessions", Image: "ghcr.io/derio-net/upgrade-session:1.0.0",
		CredDir: credDir(t), ConsoleURL: "http://cluster-update-fr.cluster-update.svc:8080", Now: func() time.Time { return *now },
		IdleTimeout: 2 * time.Hour, MaxLifetime: 8 * time.Hour}
}

func req(id, typ, app string) Request {
	cluster := "frank"
	if typ == TypeHopOS {
		cluster = "hop"
	}
	return Request{UpgradeID: id, Type: typ, Cluster: cluster, App: app, Brief: "# Brief\nTarget: " + id,
		Instructions: "Read brief.md first.", TalosVersion: "1.13.4", KubectlVersion: "1.36.2"}
}

func secretKeys(m map[string]any) []string {
	var keys []string
	for k := range m["stringData"].(map[string]any) {
		keys = append(keys, k)
	}
	return keys
}

func TestStartBuildsAHardenedPodPerType(t *testing.T) {
	now := time.Unix(1000, 0)
	wantCreds := map[string][]string{
		TypeChartMajor: {"github-token"},
		TypeStateful:   {"github-token"},
		TypeRollouts:   {"github-token"},
		TypeFrankOS:    {"github-token", "omni-sa-key", "talosconfig"},
		TypeHopOS:      {"github-token", "hop-talosconfig", "hop-kubeconfig"},
	}
	for _, typ := range Types {
		t.Run(typ, func(t *testing.T) {
			k := newFake()
			l := launcher(t, k, &now)
			id := typ + "-up-1"
			s, created, err := l.Start(context.Background(), req(id, typ, "paperclip-db"))
			if err != nil || !created {
				t.Fatalf("Start: %v created=%v", err, created)
			}
			pod := k.objects["pods/"+PodName(id)]
			meta := pod["metadata"].(map[string]any)
			labels := meta["labels"].(map[string]any)
			if labels[LabelRunID] != id || labels[LabelType] != typ {
				t.Errorf("labels = %v", labels)
			}
			spec := pod["spec"].(map[string]any)
			psc := spec["securityContext"].(map[string]any)
			if psc["runAsNonRoot"] != true || psc["seccompProfile"].(map[string]any)["type"] != "RuntimeDefault" {
				t.Errorf("pod securityContext = %v", psc)
			}
			c := spec["containers"].([]any)[0].(map[string]any)
			csc := c["securityContext"].(map[string]any)
			if csc["readOnlyRootFilesystem"] != true || csc["allowPrivilegeEscalation"] != false ||
				csc["capabilities"].(map[string]any)["drop"].([]any)[0] != "ALL" {
				t.Errorf("container securityContext = %v", csc)
			}
			if c["image"] != "ghcr.io/derio-net/upgrade-session:1.0.0" {
				t.Errorf("image = %v", c["image"])
			}
			env := map[string]string{}
			for _, e := range c["env"].([]any) {
				em := e.(map[string]any)
				if v, ok := em["value"].(string); ok {
					env[em["name"].(string)] = v
				}
			}
			if env["TALOSCTL_VERSION"] != "1.13.4" || env["KUBECTL_VERSION"] != "1.36.2" || env["UPGRADE_ID"] != id || env["DISABLE_AUTOUPDATER"] != "1" {
				t.Errorf("env = %v", env)
			}
			needsSA := typ != TypeHopOS
			if (spec["automountServiceAccountToken"] == true) != needsSA {
				t.Errorf("automount = %v for %s", spec["automountServiceAccountToken"], typ)
			}
			if needsSA && spec["serviceAccountName"] != "upgrade-session-"+typ {
				t.Errorf("serviceAccountName = %v", spec["serviceAccountName"])
			}
			creds := k.objects["secrets/"+SecretName(id)]
			keys := secretKeys(creds)
			want := append(wantCreds[typ], "session-step-token")
			if len(keys) != len(want) {
				t.Errorf("credential keys = %v, want %v", keys, want)
			}
			for _, k := range keys {
				if k == "omni-host" {
					t.Error("no session ever receives the Omni host")
				}
			}
			brief := k.objects["secrets/"+BriefName(id)]
			bd := brief["stringData"].(map[string]any)
			if bd["AGENTS.md"] != bd["CLAUDE.md"] || bd["brief.md"] == nil {
				t.Errorf("brief secret = %v", bd)
			}
			if s.Pod != PodName(id) || s.Target == "" {
				t.Errorf("session = %+v", s)
			}
		})
	}
}

func TestStartTwiceAttachesInsteadOfCreating(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newFake()
	l := launcher(t, k, &now)
	if _, created, err := l.Start(context.Background(), req("pr-7", TypeStateful, "paperclip-db")); err != nil || !created {
		t.Fatal(err)
	}
	n := len(k.creates)
	s, created, err := l.Start(context.Background(), req("pr-7", TypeStateful, "paperclip-db"))
	if err != nil || created || len(k.creates) != n || s.Pod != PodName("pr-7") {
		t.Fatalf("second start: created=%v err=%v creates %d→%d", created, err, n, len(k.creates))
	}
	// A different upgrade on the same app is refused, naming the holder.
	_, _, err = l.Start(context.Background(), req("pr-8", TypeStateful, "paperclip-db"))
	var le *LockedError
	if !errors.As(err, &le) || le.Holder != "pr-7" {
		t.Fatalf("lock conflict: %v", err)
	}
	if len(k.creates) != n {
		t.Error("a refused start must create nothing")
	}
}

func TestPodGoneMidCreateIsTreatedAsExisting(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newFake()
	l := launcher(t, k, &now)
	// Someone (a racing start) already created the pod but not via us.
	k.objects["pods/"+PodName("pr-9")] = map[string]any{"metadata": map[string]any{"name": PodName("pr-9")}}
	_, created, err := l.Start(context.Background(), req("pr-9", TypeChartMajor, "grafana"))
	if err != nil || created {
		t.Fatalf("existing pod: created=%v err=%v", created, err)
	}
}

func TestSessionSecretsAreScrubbed(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newFake()
	l := launcher(t, k, &now)
	if _, _, err := l.Start(context.Background(), req("frank-os-1", TypeFrankOS, "")); err != nil {
		t.Fatal(err)
	}
	set := l.Scrubber("frank-os-1")
	omni := "omni-" + strings.Repeat("Ok2", 8)
	out := set.String("agent printed " + omni + " and " + base64.StdEncoding.EncodeToString([]byte(omni)))
	if strings.Contains(out, "Ok2Ok2") || strings.Contains(out, base64.StdEncoding.EncodeToString([]byte(omni))) {
		t.Fatalf("session credential leaked: %q", out)
	}
}

func TestBadRequests(t *testing.T) {
	now := time.Unix(1000, 0)
	l := launcher(t, newFake(), &now)
	if _, _, err := l.Start(context.Background(), req("bad id", TypeChartMajor, "x")); err == nil {
		t.Error("invalid id accepted")
	}
	if _, _, err := l.Start(context.Background(), req("ok-1", "root-shell", "x")); err == nil {
		t.Error("unknown type accepted")
	}
	l.Image = ""
	if _, _, err := l.Start(context.Background(), req("ok-2", TypeChartMajor, "x")); err == nil {
		t.Error("no session image configured must refuse, not start an unpinned pod")
	}
}
