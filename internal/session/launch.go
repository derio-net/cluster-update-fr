package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/kube"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
	"github.com/derio-net/cluster-update-fr/internal/store"
)

// Kube is the part of kube.Client the launcher uses. Every write goes
// through kube.Client's allowlist (session namespace only).
type Kube interface {
	Get(ctx context.Context, path string, out any) error
	Create(ctx context.Context, ns, resource string, obj any) error
	Delete(ctx context.Context, ns, resource, name string) error
	// DeleteUID deletes the exact object with uid (precondition), whatever
	// its labels — for objects whose uid the console recorded at create.
	DeleteUID(ctx context.Context, ns, resource, name, uid string) error
}

// Credentials injected per type: file names under CredDir (mounted by frank
// from SOPS/ESO Secrets). Nothing else is ever copied — in particular no
// type receives anything granting access to the Omni host.
var typeCreds = map[string][]string{
	TypeChartMajor: {"github-token"},
	TypeStateful:   {"github-token"},
	TypeRollouts:   {"github-token"},
	TypeFrankOS:    {"github-token", "omni-sa-key", "talosconfig"},
	TypeHopOS:      {"github-token", "hop-talosconfig", "hop-kubeconfig", TailscaleAuthKey},
}

// TailscaleAuthKey is the hop-os credential the tailscale sidecar joins the
// tailnet with. It sits in the session's creds Secret but is projected ONLY
// into the sidecar's env, never into the agent container's volume.
const TailscaleAuthKey = "tailscale-authkey"

// Hop's tailnet, reached by hop-os sessions through a userspace tailscale
// sidecar (the session image has no tailscale): SOCKS5 on localhost:1055,
// joined as tag:frank-updater, with its own uid and state volume.
const (
	TailscaleSOCKS     = "localhost:1055"
	TailscaleProxyURL  = "socks5://" + TailscaleSOCKS
	TailscaleTag       = "tag:frank-updater"
	TailscaleUID       = 65531
	DefaultLoginServer = "https://headscale.hop.derio.net"
)

var digestPinned = regexp.MustCompile(`^[^\s@]+@sha256:[0-9a-f]{64}$`)

// ErrNoTailscaleImage: a hop-os session needs the tailscale sidecar image,
// pinned by digest.
var ErrNoTailscaleImage = errors.New("session: SESSION_TAILSCALE_IMAGE is not set or not pinned by digest (…@sha256:<64 hex>); hop-os sessions cannot reach Hop")

// Types whose pod runs with frank's per-type ServiceAccount
// upgrade-session-<type> (read-only rollout checks; Longhorn snapshot or
// Rollout status rights where frank binds them). Hop steps use the Hop
// kubeconfig instead and get no in-cluster token.
var typeSA = map[string]bool{TypeChartMajor: true, TypeStateful: true, TypeRollouts: true, TypeFrankOS: true}

// StepTokenKey is the credential the session uses to tell the console a step
// started or finished (it pauses the idle clock).
const StepTokenKey = "session-step-token"

// Request starts a session.
type Request struct {
	UpgradeID      string
	Type           string
	Cluster        string
	App            string
	Brief          string // generated brief (Markdown)
	Instructions   string // AGENTS.md == CLAUDE.md content
	TalosVersion   string // pinned per step (±1 minor client skew)
	KubectlVersion string
}

// Record is a running session (persisted).
type Record struct {
	ID           string        `json:"id"`
	Type         string        `json:"type"`
	Target       string        `json:"target"`
	Pod          string        `json:"pod"`
	Cluster      string        `json:"cluster"`
	App          string        `json:"app,omitempty"`
	StartedAt    time.Time     `json:"started_at"`
	LastActivity time.Time     `json:"last_activity"`
	StepRunning  bool          `json:"step_running"`
	StepName     string        `json:"step_name,omitempty"`
	StepSince    time.Time     `json:"step_since,omitempty"`
	StepTotal    time.Duration `json:"step_total,omitempty"`  // finished steps' running time
	StepStarts   int           `json:"step_starts,omitempty"` // steps started
	Warned       bool          `json:"warned"`
	TokenHash    string        `json:"token_hash"`
	// What was created, recorded right after create: an attach proves the
	// live pod and Secrets are still exactly these objects.
	Image      string            `json:"image,omitempty"`
	Sidecar    string            `json:"sidecar_image,omitempty"` // hop-os: the tailscale sidecar image
	PodUID     string            `json:"pod_uid,omitempty"`
	SecretUIDs map[string]string `json:"secret_uids,omitempty"`
	// VerifyUnknown counts consecutive cycles the pod could not be verified.
	VerifyUnknown int `json:"verify_unknown,omitempty"`
	// MergeWaiting: a trusted merge request waits for the operator; the
	// idle clock is paused (the ceiling and max lifetime still bound it).
	MergeWaiting bool `json:"merge_waiting,omitempty"`
}

// Ended reports a session the lifecycle ended. Alarm marks a forced end (hard
// ceiling, per-step cap) that must be raised in #security.
type Ended struct {
	ID, Outcome string
	Alarm       bool
}

// Launcher starts, tracks and ends sessions.
type Launcher struct {
	Kube        Kube
	Store       *store.Store
	Namespace   string
	Image       string
	CredDir     string
	ConsoleURL  string // in-cluster URL the session posts step events to
	Now         func() time.Time
	IdleTimeout time.Duration
	MaxLifetime time.Duration
	HardCeiling time.Duration // ends the session even mid-step (0 = off)
	StepCap     time.Duration // ends a session whose one step runs longer (0 = off)
	// StepTotalCap bounds the session's summed step-running time and
	// MaxStepStarts the number of steps it may start (0 = off): many short
	// steps cannot stand in for one long one.
	StepTotalCap  time.Duration
	MaxStepStarts int
	// TranscriptMax caps a finished session's transcript (bytes, 0 = 1 MiB);
	// ScrubTimeout bounds its redaction (0 = 10s) — c1s-r11.
	TranscriptMax int
	OutcomeMax    int // finish outcome cap (bytes, 0 = 4 KiB)
	ScrubTimeout  time.Duration
	// TailscaleImage (digest-pinned) and TailscaleLoginServer: the hop-os
	// sidecar.
	TailscaleImage       string
	TailscaleLoginServer string
	scrubFn              func(*scrub.Set, string) string // tests

	startMu  sync.Mutex // serialises Start and the lifecycle Tick
	mu       sync.Mutex
	sets     map[string]*scrub.Set
	tokens   map[string]string // in memory only; the store keeps a hash
	warnings []string
	alarms   []string
	onEnd    func(id string)
}

// SetOnEnd registers a hook run after a session ended and its record is
// gone (the app drops the session's pending merge requests — sec2-5).
func (l *Launcher) SetOnEnd(fn func(id string)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.onEnd = fn
}

const sessionBlob = "sessions"

// Errors.
var (
	ErrUnknownType = errors.New("session: unknown upgrade type")
	ErrNoImage     = errors.New("session: SESSION_IMAGE is not configured")
	ErrNoSession   = errors.New("session: no such session")
	ErrBadToken    = errors.New("session: step token refused")
)

func (l *Launcher) now() time.Time {
	if l.Now == nil {
		return time.Now()
	}
	return l.Now()
}

func (l *Launcher) records() map[string]Record {
	m, _ := l.recordsChecked()
	return m
}

// recordsChecked also reports whether the records were READ: an absent
// blob is "no sessions" (true); a present but undecodable one is not —
// nothing may be deleted as an orphan on its strength (sec2-10).
func (l *Launcher) recordsChecked() (map[string]Record, bool) {
	m := map[string]Record{}
	raw, ok := l.Store.RawBlob(sessionBlob)
	if !ok {
		return m, true
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]Record{}, false
	}
	return m, true
}

func (l *Launcher) update(fn func(m map[string]Record) error) error {
	return l.Store.UpdateBlob(sessionBlob, func(cur json.RawMessage) (json.RawMessage, error) {
		m := map[string]Record{}
		if len(cur) > 0 {
			if err := json.Unmarshal(cur, &m); err != nil {
				// Never overwrite unreadable session records with {} (c1d-r8):
				// that would forget every running session and its token.
				return nil, fmt.Errorf("session: records unreadable: %w", err)
			}
		}
		if err := fn(m); err != nil {
			return nil, err
		}
		return json.Marshal(m)
	})
}

// Sessions lists the running sessions.
func (l *Launcher) Sessions() []Record {
	var out []Record
	for _, r := range l.records() {
		out = append(out, r)
	}
	return out
}

// Get returns one session.
func (l *Launcher) Get(id string) (Record, bool) {
	r, ok := l.records()[id]
	return r, ok
}

// Start launches the session for req, or returns the running one (created
// false). A different upgrade holding the same target is refused.
func (l *Launcher) Start(ctx context.Context, req Request) (Record, bool, error) {
	if err := ValidUpgradeID(req.UpgradeID); err != nil {
		return Record{}, false, err
	}
	creds, ok := typeCreds[req.Type]
	if !ok {
		return Record{}, false, fmt.Errorf("%w: %q", ErrUnknownType, req.Type)
	}
	if l.Image == "" {
		return Record{}, false, ErrNoImage
	}
	if req.Type == TypeHopOS && !digestPinned.MatchString(l.TailscaleImage) {
		return Record{}, false, ErrNoTailscaleImage
	}
	// Starts are serialised: the console is the single writer of its state
	// (store.ErrLocked), so in-process serialisation makes every Start
	// observe the previous one's records and objects.
	l.startMu.Lock()
	defer l.startMu.Unlock()
	target := Target(req.Type, req.Cluster, req.App)
	locks := Locks{Store: l.Store}
	if err := locks.Acquire(target, req.UpgradeID); err != nil {
		return Record{}, false, err
	}
	// An error before anything exists must not leave the lock held.
	release := func() {
		if _, ok := l.Get(req.UpgradeID); !ok {
			locks.Release(target, req.UpgradeID)
			_ = l.Store.Save()
		}
	}
	// Write-ahead: the lock is on disk before any pod can exist, so a crash
	// after the create never leaves a pod nobody's lock covers.
	if err := l.Store.Save(); err != nil {
		release()
		return Record{}, false, err
	}
	pod := PodName(req.UpgradeID)
	var existing livePod
	if err := l.Kube.Get(ctx, kube.ObjectPath(l.Namespace, "pods", pod), &existing); err == nil {
		// Attach ONLY to the pod this console created for this id: a
		// write-ahead record must exist, the pod's UID must be the one
		// recorded at create time, and its labels and security-relevant spec
		// (image, ServiceAccount, the Secrets it mounts, their UIDs) must be
		// what podSpec built. Anything else is never handed to the operator.
		rec, ok := l.Get(req.UpgradeID)
		why := "no write-ahead record with a pod UID for this upgrade id"
		if ok && rec.TokenHash != "" && rec.PodUID != "" {
			var unknown bool
			if why, unknown = l.verifyOwned(ctx, rec, existing); unknown {
				// Could not tell (API trouble): neither attach nor destroy.
				return Record{}, false, fmt.Errorf("session: cannot verify pod %s right now (%s); try again", pod, why)
			}
		}
		if why == "" {
			l.Touch(req.UpgradeID)
			rec, _ = l.Get(req.UpgradeID)
			return rec, false, nil
		}
		return Record{}, false, l.refuseUnknown(ctx, req.UpgradeID, target, pod, existing, why)
	} else if !kube.IsNotFound(err) {
		release()
		return Record{}, false, err
	}

	token, err := randomToken()
	if err != nil {
		release()
		return Record{}, false, err
	}
	sum := sha256.Sum256([]byte(token))
	now := l.now()
	rec := Record{ID: req.UpgradeID, Type: req.Type, Target: target, Pod: pod, Cluster: req.Cluster, App: req.App,
		StartedAt: now, LastActivity: now, TokenHash: hex.EncodeToString(sum[:]), Image: l.Image, SecretUIDs: map[string]string{}}
	if req.Type == TypeHopOS {
		rec.Sidecar = l.TailscaleImage
	}
	// Write-ahead: the record (and its token hash) is on disk before the pod.
	if err := l.update(func(m map[string]Record) error { m[rec.ID] = rec; return nil }); err != nil {
		release()
		return Record{}, false, err
	}
	if err := l.Store.Save(); err != nil {
		_ = l.update(func(m map[string]Record) error { delete(m, rec.ID); return nil })
		release()
		return Record{}, false, err
	}
	set := scrub.NewSet(scrub.Global())
	set.Add("session-step-token", token)
	data := map[string]string{StepTokenKey: token}
	for _, key := range creds {
		b, err := os.ReadFile(filepath.Join(l.CredDir, key))
		if err != nil {
			continue // optional: the step stops at the brief's credential check
		}
		data[key] = string(b)
		set.Add(key, string(b))
	}
	labels := map[string]string{LabelRunID: req.UpgradeID, LabelType: req.Type, kube.ManagedByLabel: kube.ManagedBy}
	secret := func(name string, d map[string]string) map[string]any {
		return map[string]any{"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
			"metadata": map[string]any{"name": name, "namespace": l.Namespace, "labels": labels,
				"annotations": map[string]string{AnnotationOwner: req.UpgradeID, AnnotationContentHash: contentHash(d)}},
			"stringData": d}
	}
	brief := map[string]string{"brief.md": req.Brief, "AGENTS.md": req.Instructions, "CLAUDE.md": req.Instructions}
	created := []struct{ res, name string }{}
	rollback := func() {
		for _, c := range created {
			_ = l.Kube.Delete(context.Background(), l.Namespace, c.res, c.name)
		}
		_ = l.update(func(m map[string]Record) error { delete(m, req.UpgradeID); return nil })
		locks.Release(target, req.UpgradeID)
		_ = l.Store.Save()
	}
	for _, obj := range []struct {
		res, name string
		content   map[string]string // nil for the pod
		body      any
	}{
		{"secrets", SecretName(req.UpgradeID), data, secret(SecretName(req.UpgradeID), data)},
		{"secrets", BriefName(req.UpgradeID), brief, secret(BriefName(req.UpgradeID), brief)},
		{"pods", pod, nil, l.podSpec(req, pod, labels, data)},
	} {
		adopted, err := l.createOwned(ctx, req.UpgradeID, obj.res, obj.name, obj.content, obj.body)
		if err != nil {
			rollback()
			return Record{}, false, err
		}
		if !adopted {
			created = append(created, struct{ res, name string }{obj.res, obj.name})
		}
		// Record the UID of exactly the object that now carries the name, so
		// a later attach can prove it is still the same one.
		var got struct {
			Metadata kube.Meta `json:"metadata"`
		}
		if err := l.Kube.Get(ctx, kube.ObjectPath(l.Namespace, obj.res, obj.name), &got); err != nil || got.Metadata.UID == "" {
			rollback()
			return Record{}, false, fmt.Errorf("session: %s/%s created but its UID is unreadable: %v", obj.res, obj.name, err)
		}
		if obj.res == "pods" {
			rec.PodUID = got.Metadata.UID
		} else {
			rec.SecretUIDs[obj.name] = got.Metadata.UID
		}
	}
	if err := l.update(func(m map[string]Record) error { m[rec.ID] = rec; return nil }); err != nil {
		rollback()
		return Record{}, false, err
	}
	_ = l.Store.Save()
	l.mu.Lock()
	if l.sets == nil {
		l.sets, l.tokens = map[string]*scrub.Set{}, map[string]string{}
	}
	l.sets[rec.ID], l.tokens[rec.ID] = set, token
	l.mu.Unlock()
	_ = l.Store.Edit(req.UpgradeID, func(u *store.Update) { u.Session = pod })
	l.clearAlarmKeys(req.UpgradeID) // a fresh session: its incidents alarm anew
	l.Store.AddEvent(store.Event{Update: req.UpgradeID, Action: "session-started", Reason: req.Type + " session " + pod})
	return rec, true, nil
}

// Ownership annotations on every Secret the console creates.
const (
	AnnotationOwner       = "cluster-update.fr/upgrade-id"
	AnnotationContentHash = "cluster-update.fr/content-hash"
)

// ErrForeignObject: a session object name is taken by something the console
// will not mount (c1s-r2).
var ErrForeignObject = errors.New("session: an object with the session's name exists and is not this session's")

func contentHash(d map[string]string) string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%d:%s=%d:%s\n", len(k), k, len(d[k]), d[k])
	}
	return hex.EncodeToString(h.Sum(nil))
}

// createOwned creates an object; on AlreadyExists it never mounts what it
// finds blindly (c1s-r2). A Secret is adopted only when it is the console's
// (managed-by label), this session's (owner annotation = upgrade id) AND its
// LIVE content hashes to exactly what would have been written. A stale one
// of ours (owner matches, content does not) is deleted and recreated. A
// pod is never adopted on a create conflict (its live spec carries server
// defaults and cannot be compared); a stale one of ours is replaced. Any
// object that is not ours fails the start loudly.
func (l *Launcher) createOwned(ctx context.Context, id, res, name string, content map[string]string, body any) (adopted bool, err error) {
	err = l.Kube.Create(ctx, l.Namespace, res, body)
	if err == nil || !kube.IsConflict(err) {
		return false, err
	}
	var live struct {
		Metadata kube.Meta         `json:"metadata"`
		Data     map[string]string `json:"data"`
	}
	if err := l.Kube.Get(ctx, kube.ObjectPath(l.Namespace, res, name), &live); err != nil {
		return false, fmt.Errorf("session: %s/%s exists but is unreadable: %w", res, name, err)
	}
	ours := live.Metadata.Labels[kube.ManagedByLabel] == kube.ManagedBy && live.Metadata.Annotations[AnnotationOwner] == id
	if res == "pods" && live.Metadata.Labels[kube.ManagedByLabel] == kube.ManagedBy && live.Metadata.Labels[LabelRunID] == id {
		ours = true
	}
	if !ours {
		msg := fmt.Sprintf("session %s: %s/%s exists and is not this session's; start refused", id, res, name)
		l.alarm(alarmKey(id, "foreign-"+res, live.Metadata.UID, name), msg)
		l.Store.AddEvent(store.Event{Update: id, Action: "session-refused", Reason: msg})
		return false, fmt.Errorf("%w: %s/%s", ErrForeignObject, res, name)
	}
	if content != nil {
		decoded := map[string]string{}
		ok := true
		for k, v := range live.Data {
			b, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				ok = false
				break
			}
			decoded[k] = string(b)
		}
		if ok && live.Metadata.Annotations[AnnotationContentHash] == contentHash(content) && contentHash(decoded) == contentHash(content) {
			return true, nil
		}
	}
	if err := l.Kube.Delete(ctx, l.Namespace, res, name); err != nil && !kube.IsNotFound(err) {
		return false, fmt.Errorf("session: stale %s/%s could not be replaced: %w", res, name, err)
	}
	l.Store.AddEvent(store.Event{Update: id, Action: "session-replaced-stale", Reason: res + "/" + name})
	return false, l.Kube.Create(ctx, l.Namespace, res, body)
}

// livePod is the part of a live pod the attach check compares.
type livePod struct {
	Metadata kube.Meta `json:"metadata"`
	Spec     struct {
		ServiceAccountName string `json:"serviceAccountName"`
		Containers         []struct {
			Image string `json:"image"`
		} `json:"containers"`
		InitContainers []struct {
			Name  string `json:"name"`
			Image string `json:"image"`
		} `json:"initContainers"`
		EphemeralContainers []json.RawMessage `json:"ephemeralContainers"`
		Volumes             []struct {
			Name   string `json:"name"`
			Secret *struct {
				SecretName string `json:"secretName"`
			} `json:"secret"`
		} `json:"volumes"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase"`
	} `json:"status"`
}

// verifyOwned returns "" when live is exactly the pod this console created
// for rec, else the first mismatch. unknown is true when it could not tell
// (a transient API error): only NotFound or a different UID is a mismatch
// (c1d-r2).
func (l *Launcher) verifyOwned(ctx context.Context, rec Record, live livePod) (string, bool) {
	m := live.Metadata
	switch {
	case m.UID != rec.PodUID:
		return fmt.Sprintf("pod UID %q is not the recorded %q (the pod was replaced)", m.UID, rec.PodUID), false
	case m.Labels[kube.ManagedByLabel] != kube.ManagedBy || m.Labels[LabelRunID] != rec.ID || m.Labels[LabelType] != rec.Type:
		return "pod labels are not this session's", false
	case len(live.Spec.EphemeralContainers) != 0:
		return "an ephemeral container was added to the pod (it would share the credential volume)", false
	case len(live.Spec.Containers) != 1 || live.Spec.Containers[0].Image != rec.Image:
		return "pod containers/image differ from what the console created", false
	}
	// Only a hop-os pod carries an init container: exactly its tailscale
	// sidecar, at the image recorded at create time.
	ics := live.Spec.InitContainers
	if rec.Type == TypeHopOS {
		if rec.Sidecar == "" || len(ics) != 1 || ics[0].Name != "tailscale" || ics[0].Image != rec.Sidecar {
			return "pod init containers differ from the console's tailscale sidecar", false
		}
	} else if len(ics) != 0 {
		return "pod has init containers the console did not create", false
	}
	wantSA := ""
	if typeSA[rec.Type] {
		wantSA = "upgrade-session-" + rec.Type
	}
	if sa := live.Spec.ServiceAccountName; sa != wantSA && !(wantSA == "" && sa == "default") {
		return fmt.Sprintf("pod ServiceAccount %q is not %q", sa, wantSA), false
	}
	wantVol := map[string]string{"credentials": SecretName(rec.ID), "brief": BriefName(rec.ID)}
	seen := 0
	for _, v := range live.Spec.Volumes {
		if v.Secret == nil {
			continue
		}
		if wantVol[v.Name] != v.Secret.SecretName {
			return fmt.Sprintf("pod mounts Secret %q as volume %q", v.Secret.SecretName, v.Name), false
		}
		seen++
	}
	if seen != len(wantVol) {
		return "pod does not mount exactly the session's two Secrets", false
	}
	for name, uid := range rec.SecretUIDs {
		var s struct {
			Metadata kube.Meta `json:"metadata"`
		}
		err := l.Kube.Get(ctx, kube.ObjectPath(l.Namespace, "secrets", name), &s)
		switch {
		case kube.IsNotFound(err):
			return "Secret " + name + " is gone", false
		case err != nil && kube.IsTransient(err):
			// A transient read error proves nothing: unknown, not a mismatch.
			return "Secret " + name + " unreadable: " + scrub.String(err.Error()), true
		case err != nil: // 403, a decode error: a mismatch
			return "Secret " + name + " refused or malformed: " + scrub.String(err.Error()), false
		}
		if s.Metadata.UID != uid {
			return fmt.Sprintf("Secret %s UID %q is not the recorded %q (it was replaced)", name, s.Metadata.UID, uid), false
		}
	}
	if len(rec.SecretUIDs) != len(wantVol) {
		return "the record does not hold both Secret UIDs", false
	}
	return "", false
}

// refuseUnknown handles a pod under a session's name that the console cannot
// prove is its own: never attached; deleted (with its Secrets) when it
// carries our managed-by label, else left in place and refused; always
// alarmed in #security. The record and lock for the id are dropped.
func (l *Launcher) refuseUnknown(ctx context.Context, id, target, pod string, live livePod, why string) error {
	action := "refused and left in place (not created by the console)"
	if live.Metadata.Labels[kube.ManagedByLabel] == kube.ManagedBy {
		action = "deleted with its Secrets"
		if err := l.cleanup(ctx, pod); err != nil {
			action = "could NOT be deleted: " + scrub.String(err.Error())
		}
	}
	_ = l.update(func(m map[string]Record) error { delete(m, id); return nil })
	Locks{Store: l.Store}.Release(target, id)
	_ = l.Store.Save()
	msg := fmt.Sprintf("session %s: pod %s is not the console's own (%s); %s", id, pod, why, action)
	// Keyed on the incident's identity — this object's UID and the reason —
	// so only the exact same stuck state is suppressed; a different planted
	// pod for the same id alarms again.
	key := alarmKey(id, "foreign-pod", live.Metadata.UID, why+"|"+strings.SplitN(action, ":", 2)[0])
	l.alarm(key, msg)
	if action == "deleted with its Secrets" {
		l.resolveAlarm(key) // resolved: the next incident under this name is new
	}
	l.Store.AddEvent(store.Event{Update: id, Action: "session-refused", By: "launcher", Reason: msg})
	return fmt.Errorf("%w: %s", ErrForeignObject, msg)
}

const alarmKeysBlob = "session-alarm-keys"

// alarm queues a #security alarm for the app to send, once per key: the
// same (session, reason, state) never alarms twice, so a cleanup stuck for
// hours is one message, not one per cycle. Keys persist across restarts and
// are cleared when a fresh session is created for the id.
//
// The de-dup key and the outbox entry are written in ONE atomic store update
// (c1d-r7): a recorded key always has its queued alarm, and vice versa.
func (l *Launcher) alarm(key, msg string) {
	msg = scrub.String(msg)
	fresh := false
	_ = l.Store.UpdateBlobs([]string{alarmKeysBlob, store.OutboxBlob}, func(m map[string]json.RawMessage) error {
		keys := map[string]bool{}
		if raw, ok := m[alarmKeysBlob]; ok {
			if err := json.Unmarshal(raw, &keys); err != nil {
				return err
			}
		}
		if keys == nil { // a "null" blob
			keys = map[string]bool{}
		}
		if keys[key] {
			return nil
		}
		keys[key], fresh = true, true
		ob := store.LoadOutbox(m[store.OutboxBlob])
		ob.Append(true, "🚨 <b>Upgrade session</b> — "+html.EscapeString(msg))
		kb, err1 := json.Marshal(keys)
		obb, err2 := json.Marshal(ob)
		if err1 != nil || err2 != nil {
			return errors.New("session: alarm not encodable")
		}
		m[alarmKeysBlob], m[store.OutboxBlob] = kb, obb
		return nil
	})
	if !fresh {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.alarms = append(l.alarms, msg) // shown in the console; already queued for #security
}

// alarmKey names one incident: (subject, object UID, reason) — never a broad
// category. The reason is hashed so keys stay short.
func alarmKey(subject, kind, uid, reason string) string {
	sum := sha256.Sum256([]byte(reason))
	return subject + "|" + kind + "|" + uid + "|" + hex.EncodeToString(sum[:8])
}

func (l *Launcher) resolveAlarm(key string) {
	_ = store.UpdateJSON(l.Store, alarmKeysBlob, func(m *map[string]bool) error {
		delete(*m, key)
		return nil
	})
}

func (l *Launcher) clearAlarmKeys(id string) {
	_ = store.UpdateJSON(l.Store, alarmKeysBlob, func(m *map[string]bool) error {
		for k := range *m {
			if strings.HasPrefix(k, id+"|") {
				delete(*m, k)
			}
		}
		return nil
	})
}

// Alarms returns (and clears) pending security alarms: forced ends at the
// hard ceiling or step cap, and refused foreign session objects.
func (l *Launcher) Alarms() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.alarms
	l.alarms = nil
	return a
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// The upgrade-session image's interface (agent-images#171): user `claude`
// uid 1000, HOME /home/claude, ENTRYPOINT tini → upgrade-session-entrypoint.
// The pod never sets `command:` (frank's admission policy refuses it), so
// the image's own entrypoint always runs.
const (
	SessionUID  = 1000
	SessionHome = "/home/claude"
)

// Supported client minors of the image (talosctl / kubectl it can select).
var (
	talosMinors = map[string]bool{"1.12": true, "1.13": true, "1.14": true}
	k8sMinors   = map[string]bool{"1.34": true, "1.35": true, "1.36": true, "1.37": true}
)

// Defaults when a step names no (supported) version: frank's current
// cluster (Talos 1.12, Kubernetes 1.35).
const (
	DefaultTalosMinor = "1.12"
	DefaultK8sMinor   = "1.35"
)

// minorOf reduces "v1.13.4" / "1.13" to "1.13" if allowed has it, else def.
func minorOf(version string, allowed map[string]bool, def string) string {
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		if m := parts[0] + "." + parts[1]; allowed[m] {
			return m
		}
	}
	return def
}

// noProxy keeps the console's own session API off the tailnet proxy.
func noProxy(consoleURL string) string {
	hosts := []string{"localhost", "127.0.0.1", ".svc", ".cluster.local"}
	if u, err := url.Parse(consoleURL); err == nil && u.Hostname() != "" {
		hosts = append(hosts, u.Hostname())
	}
	return strings.Join(hosts, ",")
}

func (l *Launcher) podSpec(req Request, name string, labels map[string]string, data map[string]string) map[string]any {
	env := []map[string]any{
		{"name": "HOME", "value": SessionHome},
		{"name": "UPGRADE_TALOS_MINOR", "value": minorOf(req.TalosVersion, talosMinors, DefaultTalosMinor)},
		{"name": "UPGRADE_K8S_MINOR", "value": minorOf(req.KubectlVersion, k8sMinors, DefaultK8sMinor)},
		{"name": "UPGRADE_ID", "value": req.UpgradeID},
		{"name": "UPGRADE_TYPE", "value": req.Type},
		{"name": "UPGRADE_CLUSTER", "value": req.Cluster},
		{"name": "UPGRADE_APP", "value": req.App},
		{"name": "TALOSCTL_VERSION", "value": req.TalosVersion},
		{"name": "KUBECTL_VERSION", "value": req.KubectlVersion},
		{"name": "CONSOLE_URL", "value": l.ConsoleURL},
		{"name": "DISABLE_AUTOUPDATER", "value": "1"},
		{"name": "CREDENTIALS_DIR", "value": "/run/credentials"},
	}
	hop := req.Type == TypeHopOS
	if hop {
		// The agent reaches Hop only through the sidecar's SOCKS5: the hop
		// kubeconfig names proxy-url socks5://localhost:1055; talosctl (gRPC)
		// honours ALL_PROXY / HTTPS_PROXY.
		env = append(env,
			map[string]any{"name": "ALL_PROXY", "value": TailscaleProxyURL},
			map[string]any{"name": "HTTPS_PROXY", "value": TailscaleProxyURL},
			map[string]any{"name": "NO_PROXY", "value": noProxy(l.ConsoleURL)})
	}
	// The creds volume projects only the agent's keys: the tailscale auth
	// key reaches the sidecar's env and nothing else.
	var items []map[string]any
	for k := range data {
		if k != TailscaleAuthKey {
			items = append(items, map[string]any{"key": k, "path": k})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i]["key"].(string) < items[j]["key"].(string) })
	spec := map[string]any{
		"restartPolicy":                "Never",
		"automountServiceAccountToken": typeSA[req.Type],
		"enableServiceLinks":           false,
		"securityContext": map[string]any{
			"runAsNonRoot": true, "runAsUser": SessionUID, "runAsGroup": SessionUID, "fsGroup": SessionUID,
			"seccompProfile": map[string]any{"type": "RuntimeDefault"},
		},
		"containers": []map[string]any{{
			"name": "session", "image": l.Image, "imagePullPolicy": "IfNotPresent",
			"stdin": true, "tty": true,
			"env": env,
			"securityContext": map[string]any{
				"allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
				"capabilities": map[string]any{"drop": []string{"ALL"}},
			},
			"resources": map[string]any{
				"requests": map[string]any{"cpu": "100m", "memory": "512Mi"},
				"limits":   map[string]any{"cpu": "2", "memory": "4Gi"},
			},
			"volumeMounts": []map[string]any{
				{"name": "home", "mountPath": SessionHome},
				{"name": "tmp", "mountPath": "/tmp"},
				{"name": "credentials", "mountPath": "/run/credentials", "readOnly": true},
				{"name": "brief", "mountPath": SessionHome + "/brief", "readOnly": true},
				{"name": "brief", "mountPath": SessionHome + "/AGENTS.md", "subPath": "AGENTS.md", "readOnly": true},
				{"name": "brief", "mountPath": SessionHome + "/CLAUDE.md", "subPath": "CLAUDE.md", "readOnly": true},
			},
		}},
		"volumes": []map[string]any{
			{"name": "home", "emptyDir": map[string]any{"sizeLimit": "4Gi"}},
			{"name": "tmp", "emptyDir": map[string]any{"sizeLimit": "1Gi"}},
			{"name": "credentials", "secret": map[string]any{"secretName": SecretName(req.UpgradeID), "defaultMode": 0o400, "items": items}},
			{"name": "brief", "secret": map[string]any{"secretName": BriefName(req.UpgradeID), "defaultMode": 0o444}},
		},
	}
	if typeSA[req.Type] {
		spec["serviceAccountName"] = "upgrade-session-" + req.Type
	}
	if hop {
		login := l.TailscaleLoginServer
		if login == "" {
			login = DefaultLoginServer
		}
		// Native sidecar, as frank's hop-scan CronJob: own uid, own state
		// volume (node key + tailscaled socket mounted ONLY here), userspace
		// networking, SOCKS5 on localhost:1055.
		spec["initContainers"] = []map[string]any{{
			"name": "tailscale", "image": l.TailscaleImage, "imagePullPolicy": "IfNotPresent", "restartPolicy": "Always",
			"env": []map[string]any{
				{"name": "TS_USERSPACE", "value": "true"},
				{"name": "TS_STATE_DIR", "value": "/ts-state"},
				{"name": "TS_SOCKET", "value": "/ts-state/tailscaled.sock"},
				{"name": "TS_KUBE_SECRET", "value": ""},
				{"name": "TS_SOCKS5_SERVER", "value": TailscaleSOCKS},
				{"name": "TS_AUTHKEY", "valueFrom": map[string]any{"secretKeyRef": map[string]any{"name": SecretName(req.UpgradeID), "key": TailscaleAuthKey}}},
				{"name": "TS_EXTRA_ARGS", "value": "--login-server=" + login + " --hostname=frank-upgrade-" + req.UpgradeID + " --advertise-tags=" + TailscaleTag},
			},
			"securityContext": map[string]any{
				"runAsUser": TailscaleUID, "runAsGroup": TailscaleUID, "allowPrivilegeEscalation": false, "readOnlyRootFilesystem": true,
				"capabilities": map[string]any{"drop": []string{"ALL"}},
			},
			"resources": map[string]any{
				"requests": map[string]any{"cpu": "20m", "memory": "64Mi"},
				"limits":   map[string]any{"cpu": "200m", "memory": "256Mi"},
			},
			"volumeMounts": []map[string]any{{"name": "ts-state", "mountPath": "/ts-state"}, {"name": "ts-tmp", "mountPath": "/tmp"}},
		}}
		spec["volumes"] = append(spec["volumes"].([]map[string]any),
			map[string]any{"name": "ts-state", "emptyDir": map[string]any{"sizeLimit": "64Mi"}},
			map[string]any{"name": "ts-tmp", "emptyDir": map[string]any{"sizeLimit": "64Mi"}})
	}
	return map[string]any{"apiVersion": "v1", "kind": "Pod",
		"metadata": map[string]any{"name": name, "namespace": l.Namespace, "labels": labels}, "spec": spec}
}

// Scrubber returns the session's redaction set (the console's own literals
// as parent). After a console restart it is rebuilt from the creds Secret.
func (l *Launcher) Scrubber(id string) *scrub.Set {
	l.mu.Lock()
	set, ok := l.sets[id]
	l.mu.Unlock()
	if ok {
		return set
	}
	set = scrub.NewSet(scrub.Global())
	var sec struct {
		Data map[string]string `json:"data"`
	}
	if err := l.Kube.Get(context.Background(), kube.ObjectPath(l.Namespace, "secrets", SecretName(id)), &sec); err == nil {
		for k, v := range sec.Data {
			if b, err := base64.StdEncoding.DecodeString(v); err == nil {
				set.Add(k, string(b))
			}
		}
	}
	l.mu.Lock()
	if l.sets == nil {
		l.sets, l.tokens = map[string]*scrub.Set{}, map[string]string{}
	}
	l.sets[id] = set
	l.mu.Unlock()
	return set
}

// StepToken returns the in-memory step token (tests, and the brief writer).
func (l *Launcher) StepToken(id string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tokens[id]
}

func (l *Launcher) checkToken(rec Record, token string) bool {
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(rec.TokenHash)) == 1
}
