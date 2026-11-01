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
	"os"
	"path/filepath"
	"sort"
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
}

// Credentials injected per type: file names under CredDir (mounted by frank
// from SOPS/ESO Secrets). Nothing else is ever copied — in particular no
// type receives anything granting access to the Omni host.
var typeCreds = map[string][]string{
	TypeChartMajor: {"github-token"},
	TypeStateful:   {"github-token"},
	TypeRollouts:   {"github-token"},
	TypeFrankOS:    {"github-token", "omni-sa-key", "talosconfig"},
	TypeHopOS:      {"github-token", "hop-talosconfig", "hop-kubeconfig"},
}

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
	ID           string    `json:"id"`
	Type         string    `json:"type"`
	Target       string    `json:"target"`
	Pod          string    `json:"pod"`
	Cluster      string    `json:"cluster"`
	App          string    `json:"app,omitempty"`
	StartedAt    time.Time `json:"started_at"`
	LastActivity time.Time `json:"last_activity"`
	StepRunning  bool      `json:"step_running"`
	StepName     string    `json:"step_name,omitempty"`
	StepSince    time.Time `json:"step_since,omitempty"`
	Warned       bool      `json:"warned"`
	TokenHash    string    `json:"token_hash"`
}

// Ended reports a session the lifecycle ended.
type Ended struct {
	ID, Outcome string
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

	startMu  sync.Mutex // serialises Start and the lifecycle Tick
	mu       sync.Mutex
	sets     map[string]*scrub.Set
	tokens   map[string]string // in memory only; the store keeps a hash
	warnings []string
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
	m := map[string]Record{}
	l.Store.GetBlob(sessionBlob, &m)
	return m
}

func (l *Launcher) update(fn func(m map[string]Record) error) error {
	return l.Store.UpdateBlob(sessionBlob, func(cur json.RawMessage) (json.RawMessage, error) {
		m := map[string]Record{}
		if len(cur) > 0 {
			_ = json.Unmarshal(cur, &m)
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
	var existing struct{}
	if err := l.Kube.Get(ctx, kube.ObjectPath(l.Namespace, "pods", pod), &existing); err == nil {
		if rec, ok := l.Get(req.UpgradeID); ok && rec.TokenHash != "" {
			l.Touch(req.UpgradeID)
			rec, _ = l.Get(req.UpgradeID)
			return rec, false, nil
		}
		// A pod with no record (the console restarted between the create
		// and the record, or the state was lost): the step token must be
		// recovered from its own creds Secret, or the session cannot report
		// steps and is ended instead of running unaccounted for.
		rec, err := l.adopt(ctx, req, target, pod)
		if err != nil {
			_ = l.cleanup(ctx, pod)
			_ = l.update(func(m map[string]Record) error { delete(m, req.UpgradeID); return nil })
			locks.Release(target, req.UpgradeID)
			_ = l.Store.Save()
			l.Store.AddEvent(store.Event{Update: req.UpgradeID, Action: "session-ended", By: "launcher", Reason: "found a session pod with no record: " + err.Error()})
			return Record{}, false, fmt.Errorf("session: pod %s had no record and could not be adopted (%v); it was ended — start again", pod, err)
		}
		return rec, false, nil
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
		StartedAt: now, LastActivity: now, TokenHash: hex.EncodeToString(sum[:])}
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
		{"pods", pod, nil, l.podSpec(req, pod, labels)},
	} {
		adopted, err := l.createOwned(ctx, req.UpgradeID, obj.res, obj.name, obj.content, obj.body)
		if err != nil {
			rollback()
			return Record{}, false, err
		}
		if !adopted {
			created = append(created, struct{ res, name string }{obj.res, obj.name})
		}
	}
	l.mu.Lock()
	if l.sets == nil {
		l.sets, l.tokens = map[string]*scrub.Set{}, map[string]string{}
	}
	l.sets[rec.ID], l.tokens[rec.ID] = set, token
	l.mu.Unlock()
	_ = l.Store.Edit(req.UpgradeID, func(u *store.Update) { u.Session = pod })
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
		l.Store.AddEvent(store.Event{Update: id, Action: "session-refused", Reason: res + "/" + name + " exists and is not this session's"})
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

// adopt rebuilds the record of a running pod that has none, from its creds
// Secret: the Secret must be the console's (managed-by label) and this
// session's (run-id label), and must hold a step token. The token hash is
// recomputed from it; nothing about the pod is trusted otherwise.
func (l *Launcher) adopt(ctx context.Context, req Request, target, pod string) (Record, error) {
	var sec struct {
		Metadata kube.Meta         `json:"metadata"`
		Data     map[string]string `json:"data"`
	}
	if err := l.Kube.Get(ctx, kube.ObjectPath(l.Namespace, "secrets", SecretName(req.UpgradeID)), &sec); err != nil {
		return Record{}, fmt.Errorf("creds Secret unreadable: %w", err)
	}
	if sec.Metadata.Labels[kube.ManagedByLabel] != kube.ManagedBy || sec.Metadata.Labels[LabelRunID] != req.UpgradeID ||
		sec.Metadata.Annotations[AnnotationOwner] != req.UpgradeID {
		return Record{}, errors.New("creds Secret is not this session's")
	}
	decoded := map[string]string{}
	for k, v := range sec.Data {
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return Record{}, errors.New("creds Secret is not decodable")
		}
		decoded[k] = string(b)
	}
	if contentHash(decoded) != sec.Metadata.Annotations[AnnotationContentHash] {
		return Record{}, errors.New("creds Secret content does not match the hash the console wrote")
	}
	tok := []byte(decoded[StepTokenKey])
	if len(tok) == 0 {
		return Record{}, errors.New("creds Secret holds no step token")
	}
	sum := sha256.Sum256(tok)
	now := l.now()
	rec := Record{ID: req.UpgradeID, Type: req.Type, Target: target, Pod: pod, Cluster: req.Cluster, App: req.App,
		StartedAt: now, LastActivity: now, TokenHash: hex.EncodeToString(sum[:])}
	if err := l.update(func(m map[string]Record) error { m[rec.ID] = rec; return nil }); err != nil {
		return Record{}, err
	}
	_ = l.Store.Save()
	l.Store.AddEvent(store.Event{Update: req.UpgradeID, Action: "session-adopted", Reason: "rebuilt the record of running pod " + pod + " from its creds Secret"})
	return rec, nil
}

func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (l *Launcher) podSpec(req Request, name string, labels map[string]string) map[string]any {
	env := []map[string]any{
		{"name": "HOME", "value": "/home/agent"},
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
	spec := map[string]any{
		"restartPolicy":                "Never",
		"automountServiceAccountToken": typeSA[req.Type],
		"enableServiceLinks":           false,
		"securityContext": map[string]any{
			"runAsNonRoot": true, "runAsUser": 1000, "runAsGroup": 1000, "fsGroup": 1000,
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
				{"name": "home", "mountPath": "/home/agent"},
				{"name": "tmp", "mountPath": "/tmp"},
				{"name": "credentials", "mountPath": "/run/credentials", "readOnly": true},
				{"name": "brief", "mountPath": "/home/agent/brief", "readOnly": true},
				{"name": "brief", "mountPath": "/home/agent/AGENTS.md", "subPath": "AGENTS.md", "readOnly": true},
				{"name": "brief", "mountPath": "/home/agent/CLAUDE.md", "subPath": "CLAUDE.md", "readOnly": true},
			},
		}},
		"volumes": []map[string]any{
			{"name": "home", "emptyDir": map[string]any{"sizeLimit": "4Gi"}},
			{"name": "tmp", "emptyDir": map[string]any{"sizeLimit": "1Gi"}},
			{"name": "credentials", "secret": map[string]any{"secretName": SecretName(req.UpgradeID), "defaultMode": 0o400}},
			{"name": "brief", "secret": map[string]any{"secretName": BriefName(req.UpgradeID), "defaultMode": 0o444}},
		},
	}
	if typeSA[req.Type] {
		spec["serviceAccountName"] = "upgrade-session-" + req.Type
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
