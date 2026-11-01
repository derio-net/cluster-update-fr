package session

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func envOf(c map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	for _, e := range c["env"].([]any) {
		em := e.(map[string]any)
		out[em["name"].(string)] = em
	}
	return out
}

func mountsOf(c map[string]any) map[string]string {
	out := map[string]string{}
	for _, m := range c["volumeMounts"].([]any) {
		mm := m.(map[string]any)
		out[mm["name"].(string)] = mm["mountPath"].(string)
	}
	return out
}

// p5-relay-2: hop-os sessions reach Hop through a userspace tailscale
// sidecar (the session image has none), shaped like frank's hop-scan: own
// uid, own state volume, SOCKS5 on localhost:1055, tag:frank-updater, the
// auth key from the session Secret — never visible to the agent container.
func TestHopOSGetsAnIsolatedTailscaleSidecar(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newFake()
	l := launcher(t, k, &now)
	id := "hop-os-ts-1"
	if _, _, err := l.Start(context.Background(), req(id, TypeHopOS, "")); err != nil {
		t.Fatal(err)
	}
	spec := k.objects["pods/"+PodName(id)]["spec"].(map[string]any)
	ics, _ := spec["initContainers"].([]any)
	if len(ics) != 1 {
		t.Fatalf("init containers = %v", ics)
	}
	ts := ics[0].(map[string]any)
	if ts["name"] != "tailscale" || ts["image"] != testTailscaleImage || ts["restartPolicy"] != "Always" {
		t.Errorf("sidecar = %v %v %v", ts["name"], ts["image"], ts["restartPolicy"])
	}
	if _, ok := ts["command"]; ok {
		t.Error("the sidecar sets command:")
	}
	te := envOf(ts)
	for k, v := range map[string]string{"TS_USERSPACE": "true", "TS_SOCKS5_SERVER": "localhost:1055", "TS_OUTBOUND_HTTP_PROXY_LISTEN": "localhost:1056",
		"TS_STATE_DIR": "/ts-state", "TS_KUBE_SECRET": ""} {
		if te[k] == nil || te[k]["value"] != v {
			t.Errorf("sidecar %s = %v", k, te[k])
		}
	}
	if !strings.Contains(te["TS_EXTRA_ARGS"]["value"].(string), "--advertise-tags=tag:frank-session") ||
		!strings.Contains(te["TS_EXTRA_ARGS"]["value"].(string), "--login-server=https://headscale.hop.derio.net") {
		t.Errorf("TS_EXTRA_ARGS = %v", te["TS_EXTRA_ARGS"])
	}
	ref := te["TS_AUTHKEY"]["valueFrom"].(map[string]any)["secretKeyRef"].(map[string]any)
	if ref["name"] != SecretName(id) || ref["key"] != TailscaleAuthKey {
		t.Errorf("TS_AUTHKEY ref = %v", ref)
	}
	tsc := ts["securityContext"].(map[string]any)
	if tsc["runAsUser"] == float64(SessionUID) || tsc["runAsUser"] == nil || tsc["capabilities"].(map[string]any)["drop"].([]any)[0] != "ALL" {
		t.Errorf("sidecar securityContext = %v (needs its own uid)", tsc)
	}
	if mountsOf(ts)["ts-state"] != "/ts-state" || mountsOf(ts)["credentials"] != "" {
		t.Errorf("sidecar mounts = %v", mountsOf(ts))
	}

	agent := spec["containers"].([]any)[0].(map[string]any)
	if _, ok := mountsOf(agent)["ts-state"]; ok {
		t.Error("the agent container mounts the tailscale state")
	}
	ae := envOf(agent)
	// p5-r4: talosctl (grpc-go) and Claude Code (Node) speak only HTTP
	// CONNECT through HTTPS_PROXY — neither supports SOCKS — so HTTPS_PROXY is
	// the sidecar's HTTP CONNECT proxy; ALL_PROXY keeps the SOCKS5 one for
	// the tools that honour it (curl); kubectl uses the kubeconfig's
	// proxy-url (socks5).
	for k, v := range map[string]string{"HTTPS_PROXY": "http://localhost:1056", "ALL_PROXY": "socks5://localhost:1055"} {
		if ae[k] == nil || ae[k]["value"] != v {
			t.Errorf("agent %s = %v, want %s", k, ae[k], v)
		}
	}
	np, _ := ae["NO_PROXY"]["value"].(string)
	for _, host := range []string{"cluster-update-fr.cluster-update.svc", ".anthropic.com", "github.com", "localhost"} {
		if !strings.Contains(np, host) {
			t.Errorf("NO_PROXY %q must keep %s off the tailnet proxy", np, host)
		}
	}
	// The auth key is in the Secret but NOT projected into the agent's volume.
	for _, v := range spec["volumes"].([]any) {
		vm := v.(map[string]any)
		if vm["name"] != "credentials" {
			continue
		}
		items := vm["secret"].(map[string]any)["items"].([]any)
		keys := map[string]bool{}
		for _, it := range items {
			keys[it.(map[string]any)["key"].(string)] = true
		}
		if keys[TailscaleAuthKey] || !keys["hop-kubeconfig"] || !keys[StepTokenKey] {
			t.Errorf("credentials items = %v", keys)
		}
	}
	if !strings.Contains(strings.Join(secretKeys(k.objects["secrets/"+SecretName(id)]), ","), TailscaleAuthKey) {
		t.Error("the auth key must be in the session Secret")
	}

	// Attach proves the sidecar too; a swapped sidecar image is refused.
	if _, created, err := l.Start(context.Background(), req(id, TypeHopOS, "")); err != nil || created {
		t.Fatalf("re-attach: created=%v err=%v", created, err)
	}
	pod := k.objects["pods/"+PodName(id)]
	pod["spec"].(map[string]any)["initContainers"].([]any)[0].(map[string]any)["image"] = "evil/tailscale:latest"
	if _, _, err := l.Start(context.Background(), req(id, TypeHopOS, "")); err == nil {
		t.Fatal("a pod with a swapped sidecar image was attached")
	}
}

// p5-r3: the session tag is configurable, defaults to tag:frank-session, and
// can never be hop-scan's tag:frank-updater (or malformed).
func TestSessionTailscaleTag(t *testing.T) {
	now := time.Unix(1000, 0)
	argsOf := func(k *fakeKube, id string) string {
		spec := k.objects["pods/"+PodName(id)]["spec"].(map[string]any)
		ts := spec["initContainers"].([]any)[0].(map[string]any)
		return envOf(ts)["TS_EXTRA_ARGS"]["value"].(string)
	}
	k := newFake()
	l := launcher(t, k, &now)
	if _, _, err := l.Start(context.Background(), req("hop-os-tag-1", TypeHopOS, "")); err != nil {
		t.Fatal(err)
	}
	if a := argsOf(k, "hop-os-tag-1"); !strings.Contains(a, "--advertise-tags=tag:frank-session") || strings.Contains(a, "frank-updater") {
		t.Errorf("default tag: %s", a)
	}
	k = newFake()
	l = launcher(t, k, &now)
	l.TailscaleTag = "tag:upgrade-sessions"
	if _, _, err := l.Start(context.Background(), req("hop-os-tag-2", TypeHopOS, "")); err != nil {
		t.Fatal(err)
	}
	if a := argsOf(k, "hop-os-tag-2"); !strings.Contains(a, "--advertise-tags=tag:upgrade-sessions") {
		t.Errorf("configured tag: %s", a)
	}
	for _, bad := range []string{"tag:frank-updater", "frank-session", "tag:", "tag:a b", "tag:x,tag:frank-updater"} {
		k := newFake()
		l := launcher(t, k, &now)
		l.TailscaleTag = bad
		if _, _, err := l.Start(context.Background(), req("hop-os-tag-3", TypeHopOS, "")); !errors.Is(err, ErrBadTailscaleTag) || len(k.creates) != 0 {
			t.Errorf("tag %q: err=%v creates=%d", bad, err, len(k.creates))
		}
	}
}

// Other types get no sidecar and no proxy; an unpinned or missing sidecar
// image refuses hop-os before anything is created.
func TestTailscaleSidecarOnlyForHopOSAndPinned(t *testing.T) {
	now := time.Unix(1000, 0)
	k := newFake()
	l := launcher(t, k, &now)
	if _, _, err := l.Start(context.Background(), req("frank-os-1", TypeFrankOS, "")); err != nil {
		t.Fatal(err)
	}
	spec := k.objects["pods/"+PodName("frank-os-1")]["spec"].(map[string]any)
	if ics, _ := spec["initContainers"].([]any); len(ics) != 0 {
		t.Errorf("frank-os got init containers: %v", ics)
	}
	if envOf(spec["containers"].([]any)[0].(map[string]any))["ALL_PROXY"] != nil {
		t.Error("frank-os got the tailnet proxy")
	}
	for _, img := range []string{"", "tailscale/tailscale:v1.82.5", "tailscale/tailscale@sha256:abc"} {
		k := newFake()
		l := launcher(t, k, &now)
		l.TailscaleImage = img
		if _, _, err := l.Start(context.Background(), req("hop-os-2", TypeHopOS, "")); !errors.Is(err, ErrNoTailscaleImage) || len(k.creates) != 0 {
			t.Errorf("image %q: err=%v creates=%d", img, err, len(k.creates))
		}
	}
}
