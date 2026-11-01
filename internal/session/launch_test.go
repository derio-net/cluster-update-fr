package session

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/kube"
	"github.com/derio-net/cluster-update-fr/internal/store"
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
	uids    int
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
	f.uids++
	m["metadata"].(map[string]any)["uid"] = fmt.Sprintf("uid-%d", f.uids)
	f.objects[k] = m
	f.creates = append(f.creates, k)
	return nil
}

// DeleteUID: the exact object by uid, labels ignored; another uid → 409.
func (f *fakeKube) DeleteUID(_ context.Context, ns, res, name, uid string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ns != f.policy.SessionNamespace || uid == "" {
		return kube.ErrForbiddenWrite
	}
	k := res + "/" + name
	f.deletes = append(f.deletes, k)
	m, ok := f.objects[k]
	if !ok {
		return &kube.APIError{Code: 404, Reason: "NotFound"}
	}
	if m["metadata"].(map[string]any)["uid"] != uid {
		return &kube.APIError{Code: 409, Reason: "Conflict"}
	}
	delete(f.objects, k)
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
	m, ok := f.objects[k]
	if !ok {
		return &kube.APIError{Code: 404, Reason: "NotFound"}
	}
	// The real client reads the live object and refuses one without the
	// console's managed-by label.
	if labels, _ := m["metadata"].(map[string]any)["labels"].(map[string]any); labels[kube.ManagedByLabel] != kube.ManagedBy {
		return kube.ErrForbiddenWrite
	}
	delete(f.objects, k)
	return nil
}

func (f *fakeKube) Get(_ context.Context, path string, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if p, q, ok := strings.Cut(path, "?labelSelector="); ok { // a list
		res := p[strings.LastIndex(p, "/")+1:]
		sel, _ := url.QueryUnescape(q)
		lk, lv, _ := strings.Cut(sel, "=")
		var items []any
		for k, m := range f.objects {
			if !strings.HasPrefix(k, res+"/") {
				continue
			}
			if labels, _ := m["metadata"].(map[string]any)["labels"].(map[string]any); labels[lk] == lv {
				items = append(items, m)
			}
		}
		b, _ := json.Marshal(map[string]any{"items": items})
		return json.Unmarshal(b, out)
	}
	parts := strings.Split(path, "/")
	k := parts[len(parts)-2] + "/" + parts[len(parts)-1]
	m, ok := f.objects[k]
	if !ok {
		return &kube.APIError{Code: 404, Reason: "NotFound"}
	}
	if strings.HasPrefix(k, "pods/") {
		m["status"] = map[string]any{"phase": f.phase}
	}
	if sd, ok := m["stringData"].(map[string]any); ok { // the API server returns data, base64
		cp := map[string]any{}
		for k, v := range m {
			cp[k] = v
		}
		data := map[string]any{}
		for k, v := range sd {
			data[k] = base64.StdEncoding.EncodeToString([]byte(v.(string)))
		}
		delete(cp, "stringData")
		cp["data"] = data
		m = cp
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

// p5-relay-1: the pod matches the upgrade-session image's interface
// (agent-images#171) — uid 1000, HOME /home/claude on an emptyDir, /tmp an
// emptyDir, read-only root, all caps dropped, NO command (the image's tini
// entrypoint runs; frank's admission policy refuses command:), and the
// client minors the image selects.
func TestPodMatchesTheUpgradeSessionImage(t *testing.T) {
	now := time.Unix(1000, 0)
	cases := []struct {
		typ, talos, k8s, wantTalos, wantK8s string
	}{
		{TypeFrankOS, "1.13.4", "1.36.2", "1.13", "1.36"},
		{TypeHopOS, "v1.14.0", "1.37.1", "1.14", "1.37"},
		{TypeChartMajor, "1.12.6", "1.35.3", "1.12", "1.35"},
		{TypeStateful, "", "", DefaultTalosMinor, DefaultK8sMinor},            // nothing named: current cluster
		{TypeRollouts, "1.9.5", "1.30.0", DefaultTalosMinor, DefaultK8sMinor}, // unsupported: never passed through
	}
	for _, c := range cases {
		k := newFake()
		l := launcher(t, k, &now)
		id := c.typ + "-img-1"
		r := req(id, c.typ, "paperclip-db")
		r.TalosVersion, r.KubectlVersion = c.talos, c.k8s
		if _, _, err := l.Start(context.Background(), r); err != nil {
			t.Fatalf("%s: %v", c.typ, err)
		}
		spec := k.objects["pods/"+PodName(id)]["spec"].(map[string]any)
		psc := spec["securityContext"].(map[string]any)
		if psc["runAsUser"] != float64(1000) {
			t.Errorf("%s: runAsUser = %v", c.typ, psc["runAsUser"])
		}
		var agent map[string]any
		for _, x := range spec["containers"].([]any) {
			if x.(map[string]any)["name"] == "session" {
				agent = x.(map[string]any)
			}
		}
		if agent == nil {
			t.Fatalf("%s: no session container", c.typ)
		}
		if _, ok := agent["command"]; ok {
			t.Errorf("%s: the session container sets command: (the admission policy refuses it)", c.typ)
		}
		csc := agent["securityContext"].(map[string]any)
		if csc["readOnlyRootFilesystem"] != true || csc["capabilities"].(map[string]any)["drop"].([]any)[0] != "ALL" {
			t.Errorf("%s: container securityContext = %v", c.typ, csc)
		}
		env := map[string]string{}
		for _, e := range agent["env"].([]any) {
			em := e.(map[string]any)
			if v, ok := em["value"].(string); ok {
				env[em["name"].(string)] = v
			}
		}
		if env["HOME"] != "/home/claude" || env["UPGRADE_TALOS_MINOR"] != c.wantTalos || env["UPGRADE_K8S_MINOR"] != c.wantK8s {
			t.Errorf("%s: env HOME=%q talos=%q k8s=%q", c.typ, env["HOME"], env["UPGRADE_TALOS_MINOR"], env["UPGRADE_K8S_MINOR"])
		}
		mounts := map[string]string{}
		for _, m := range agent["volumeMounts"].([]any) {
			mm := m.(map[string]any)
			mounts[mm["mountPath"].(string)] = mm["name"].(string)
		}
		empty := map[string]bool{}
		for _, v := range spec["volumes"].([]any) {
			vm := v.(map[string]any)
			if _, ok := vm["emptyDir"]; ok {
				empty[vm["name"].(string)] = true
			}
		}
		for _, p := range []string{"/home/claude", "/tmp"} {
			if !empty[mounts[p]] {
				t.Errorf("%s: %s is not an emptyDir (mounts %v)", c.typ, p, mounts)
			}
		}
		if mounts["/home/claude/brief"] != "brief" || mounts["/home/claude/AGENTS.md"] != "brief" {
			t.Errorf("%s: brief not under /home/claude: %v", c.typ, mounts)
		}
	}
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

// A pod nobody recorded and whose step token cannot be recovered is never
// attached to: Start fails loudly and the lock is not left held (c1s-r6).
func TestUnrecordedPodWithoutTokenIsNotAttached(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newFake()
	l := launcher(t, k, &now)
	k.objects["pods/"+PodName("pr-9")] = map[string]any{"metadata": map[string]any{"name": PodName("pr-9")}}
	_, created, err := l.Start(context.Background(), req("pr-9", TypeChartMajor, "grafana"))
	if err == nil || created {
		t.Fatalf("planted pod: created=%v err=%v", created, err)
	}
	if _, ok := l.Get("pr-9"); ok {
		t.Error("no record may be made for a pod whose token is unknown")
	}
	if h := (Locks{Store: l.Store}).Holder(Target(TypeChartMajor, "frank", "grafana")); h != "" {
		t.Errorf("lock leaked to %q", h)
	}
	if a := l.Alarms(); len(a) != 1 || !strings.Contains(a[0], "not the console's own") {
		t.Errorf("alarms = %v", a)
	}
	if _, ok := k.objects["pods/"+PodName("pr-9")]; !ok {
		t.Error("an unlabelled pod is not ours to delete; it must be left and reported")
	}
}

// Alarm de-dup is per incident: the same stuck planted pod alarms once over
// repeated starts; a different planted pod for the same id alarms again.
func TestForeignPodAlarmsOncePerIncident(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newFake()
	l := launcher(t, k, &now)
	plant := func(uid string) {
		k.objects["pods/"+PodName("pr-9")] = map[string]any{"metadata": map[string]any{"name": PodName("pr-9"), "uid": uid}}
	}
	plant("uid-planted-1")
	for i := 0; i < 3; i++ {
		_, _, _ = l.Start(context.Background(), req("pr-9", TypeChartMajor, "grafana"))
	}
	if a := l.Alarms(); len(a) != 1 {
		t.Fatalf("same stuck pod over 3 starts: %d alarms %v", len(a), a)
	}
	plant("uid-planted-2")
	_, _, _ = l.Start(context.Background(), req("pr-9", TypeChartMajor, "grafana"))
	if a := l.Alarms(); len(a) != 1 {
		t.Fatalf("a second, different planted pod must alarm again: %v", a)
	}
}

// Attach proves identity: the live pod must have the UID recorded at
// create time, our labels, the recorded image/ServiceAccount/Secret mounts,
// and the Secrets their recorded UIDs. Any mismatch: never attached, the
// (managed) pod deleted, the record dropped, an alarm raised.
func TestAttachRefusesAReplacedOrTamperedPod(t *testing.T) {
	cases := map[string]func(k *fakeKube, id string){
		"record lost": nil,
		"different pod UID": func(k *fakeKube, id string) {
			k.objects["pods/"+PodName(id)]["metadata"].(map[string]any)["uid"] = "uid-planted"
		},
		"tampered image": func(k *fakeKube, id string) {
			c := k.objects["pods/"+PodName(id)]["spec"].(map[string]any)["containers"].([]any)[0].(map[string]any)
			c["image"] = "evil/shell:latest"
		},
		"tampered ServiceAccount": func(k *fakeKube, id string) {
			k.objects["pods/"+PodName(id)]["spec"].(map[string]any)["serviceAccountName"] = "cluster-admin"
		},
		"replaced creds Secret": func(k *fakeKube, id string) {
			k.objects["secrets/"+SecretName(id)]["metadata"].(map[string]any)["uid"] = "uid-swapped"
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			now := time.Unix(1000, 0)
			k := newFake()
			l := launcher(t, k, &now)
			if _, _, err := l.Start(context.Background(), req("pr-5", TypeChartMajor, "grafana")); err != nil {
				t.Fatal(err)
			}
			if tamper == nil {
				_ = l.Store.PutBlob(sessionBlob, map[string]Record{})
			} else {
				tamper(k, "pr-5")
			}
			_, _, err := l.Start(context.Background(), req("pr-5", TypeChartMajor, "grafana"))
			if !errors.Is(err, ErrForeignObject) {
				t.Fatalf("attach after %s: %v", name, err)
			}
			if _, ok := l.Get("pr-5"); ok {
				t.Error("record kept")
			}
			if _, ok := k.objects["pods/"+PodName("pr-5")]; ok {
				t.Error("a managed pod that failed verification must be deleted")
			}
			if a := l.Alarms(); len(a) == 0 {
				t.Error("no #security alarm")
			}
		})
	}
	// The untouched case still attaches.
	now := time.Unix(1000, 0)
	k := newFake()
	l := launcher(t, k, &now)
	if _, _, err := l.Start(context.Background(), req("pr-6", TypeChartMajor, "grafana")); err != nil {
		t.Fatal(err)
	}
	if _, created, err := l.Start(context.Background(), req("pr-6", TypeChartMajor, "grafana")); err != nil || created {
		t.Fatalf("clean attach: created=%v err=%v", created, err)
	}
}

// Write-ahead (c1s-r6): the lock and the record are on disk before the pod
// is created, so a crash right after the create leaves nothing unaccounted.
func TestLockAndRecordAreSavedBeforeThePod(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newFake()
	dir := t.TempDir()
	st, err := store.Open(dir, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	l := launcher(t, k, &now)
	l.Store = st
	var onDisk string
	l.Kube = podHook{k, func() {
		b, _ := os.ReadFile(filepath.Join(dir, "state.json"))
		onDisk = string(b)
	}}
	if _, _, err := l.Start(context.Background(), req("pr-3", TypeChartMajor, "grafana")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(onDisk, "session-locks") || !strings.Contains(onDisk, "token_hash") {
		t.Fatalf("state on disk at pod create lacks the lock or the record:\n%s", onDisk)
	}
}

// c1s-r2: an existing object under a session's Secret name is never mounted
// blindly. A pre-planted (unlabelled) or other-session Secret fails the
// start loudly; a stale Secret of this session is replaced, so the pod
// mounts exactly the token whose hash the record holds.
func TestSecretNameConflictsAreNeverAdoptedBlindly(t *testing.T) {
	now := time.Unix(1000, 0)
	managed := map[string]any{kube.ManagedByLabel: kube.ManagedBy, LabelRunID: "pr-4"}
	for name, planted := range map[string]map[string]any{
		"unlabelled":    {"name": SecretName("pr-4")},
		"other session": {"name": SecretName("pr-4"), "labels": managed, "annotations": map[string]any{AnnotationOwner: "pr-99"}},
	} {
		t.Run(name, func(t *testing.T) {
			k := newFake()
			l := launcher(t, k, &now)
			k.objects["secrets/"+SecretName("pr-4")] = map[string]any{"metadata": planted, "stringData": map[string]any{StepTokenKey: "attacker"}}
			_, _, err := l.Start(context.Background(), req("pr-4", TypeChartMajor, "grafana"))
			if !errors.Is(err, ErrForeignObject) {
				t.Fatalf("Start over a foreign Secret: %v", err)
			}
			if _, ok := k.objects["pods/"+PodName("pr-4")]; ok {
				t.Error("a pod was created mounting a Secret the console did not write")
			}
			if _, ok := l.Get("pr-4"); ok {
				t.Error("record left behind")
			}
		})
	}
	t.Run("stale of ours", func(t *testing.T) {
		k := newFake()
		l := launcher(t, k, &now)
		k.objects["secrets/"+SecretName("pr-4")] = map[string]any{
			"metadata":   map[string]any{"name": SecretName("pr-4"), "labels": managed, "annotations": map[string]any{AnnotationOwner: "pr-4", AnnotationContentHash: "old"}},
			"stringData": map[string]any{StepTokenKey: "old-token"}}
		if _, created, err := l.Start(context.Background(), req("pr-4", TypeChartMajor, "grafana")); err != nil || !created {
			t.Fatalf("Start: created=%v err=%v", created, err)
		}
		sd := k.objects["secrets/"+SecretName("pr-4")]["stringData"].(map[string]any)
		if sd[StepTokenKey] != l.StepToken("pr-4") {
			t.Errorf("mounted token %v is not the recorded one", sd[StepTokenKey])
		}
		if err := l.StepStarted("pr-4", l.StepToken("pr-4"), "x"); err != nil {
			t.Errorf("step reporting broken: %v", err)
		}
	})
}

type podHook struct {
	*fakeKube
	before func()
}

func (p podHook) Create(ctx context.Context, ns, res string, obj any) error {
	if res == "pods" {
		p.before()
	}
	return p.fakeKube.Create(ctx, ns, res, obj)
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

type brokenKube struct{ *fakeKube }

func (brokenKube) Get(context.Context, string, any) error {
	return &kube.APIError{Code: 503, Reason: "ServiceUnavailable"}
}

func TestAPIErrorBeforeCreateReleasesTheLock(t *testing.T) {
	now := time.Unix(1000, 0)
	l := launcher(t, newFake(), &now)
	l.Kube = brokenKube{newFake()}
	if _, _, err := l.Start(context.Background(), req("pr-1", TypeStateful, "gitea")); err == nil {
		t.Fatal("want error")
	}
	if h := (Locks{Store: l.Store}).Holder(Target(TypeStateful, "frank", "gitea")); h != "" {
		t.Errorf("lock leaked to %q", h)
	}
}
