package kube

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func server(t *testing.T, h http.HandlerFunc) (*Client, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		if r.Header.Get("Authorization") != "Bearer sa" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	c := &Client{Server: srv.URL, Token: func() string { return "sa" }, HTTP: srv.Client()}
	return c, &calls
}

func TestListDecodesItems(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/pods" {
			w.WriteHeader(404)
			return
		}
		_, _ = w.Write([]byte(`{"items":[{"metadata":{"name":"a"}},{"metadata":{"name":"b"}}]}`))
	})
	var out struct {
		Items []struct {
			Metadata struct{ Name string } `json:"metadata"`
		} `json:"items"`
	}
	if err := c.Get(context.Background(), "/api/v1/pods", &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Items) != 2 || out.Items[1].Metadata.Name != "b" {
		t.Errorf("items = %+v", out.Items)
	}
}

func TestAPIErrorsAreTyped(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"kind":"Status","message":"pods is forbidden","reason":"Forbidden","code":403}`))
	})
	err := c.Get(context.Background(), "/api/v1/pods", &struct{}{})
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != 403 || !strings.Contains(apiErr.Message, "forbidden") {
		t.Fatalf("err = %v", err)
	}
	if IsNotFound(err) || IsConflict(err) {
		t.Error("403 is neither not-found nor conflict")
	}
}

func TestWritesOutsideTheSessionNamespaceNeverLeave(t *testing.T) {
	c, calls := server(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{}`))
	})
	ctx := context.Background()
	// No write policy at all (e.g. the Hop client): every write refused.
	if err := c.Create(ctx, "upgrade-sessions", "pods", map[string]any{}); !errors.Is(err, ErrForbiddenWrite) {
		t.Fatalf("write without policy: %v", err)
	}
	c.Writes = &WritePolicy{SessionNamespace: "upgrade-sessions"}
	const ns = "upgrade-sessions"
	for _, bad := range []struct{ ns, res, name string }{
		{"default", "pods", "x"},
		{ns, "deployments", "x"},
		{ns, "configmaps", "x"},
		{ns, "roles", "upgrade-session-x"},
		{ns, "clusterrolebindings", "upgrade-session-x"},
		{ns, "nodes", "mini-1"},
		{"paperclip", "secrets", "x"},
		{"paperclip", "rolebindings", "upgrade-session-x"}, // other namespace, even with our prefix
		// validator/request differentials: names that would re-route the path
		{ns, "rolebindings", "upgrade-session-x/../../../apis/rbac.authorization.k8s.io/v1/clusterrolebindings/foo"},
		{ns, "pods", "../secrets/x"},
		{ns, "pods", "x%2F..%2Fsecrets"},
		{ns, "pods", "x?dryRun=All"},
		{ns, "pods", "x#frag"},
		{ns, "pods", "X-Upper"},
		{ns, "pods", "-leading"},
		{ns, "pods", "trailing-"},
		{ns, "pods", "dot.ted"},
		{ns, "pods", ""},
		{ns, "pods", strings.Repeat("a", 254)},
		{ns + "/../kube-system", "pods", "x"},
		{"Upgrade-Sessions", "pods", "x"},
	} {
		obj := map[string]any{"metadata": map[string]any{"name": bad.name}}
		if err := c.Create(ctx, bad.ns, bad.res, obj); !errors.Is(err, ErrForbiddenWrite) {
			t.Errorf("Create %s/%s/%s: %v", bad.ns, bad.res, bad.name, err)
		}
		if err := c.Delete(ctx, bad.ns, bad.res, bad.name); !errors.Is(err, ErrForbiddenWrite) {
			t.Errorf("Delete %s/%s/%s: %v", bad.ns, bad.res, bad.name, err)
		}
	}
	if n := atomic.LoadInt32(calls); n != 0 {
		t.Fatalf("refused writes must not reach the API server, saw %d calls", n)
	}
	// The body's own namespace must agree with the URL's.
	if err := c.Create(ctx, ns, "pods", map[string]any{"metadata": map[string]any{"name": "s-1", "namespace": "kube-system"}}); !errors.Is(err, ErrForbiddenWrite) {
		t.Errorf("mismatched metadata.namespace: %v", err)
	}
	if n := atomic.LoadInt32(calls); n != 0 {
		t.Fatalf("refused writes must not reach the API server, saw %d calls", n)
	}
	managed := map[string]any{ManagedByLabel: ManagedBy}
	for _, bad := range []map[string]any{
		{"name": "us-s-1"}, // no managed-by label
		{"name": "us-s-1", "labels": map[string]any{ManagedByLabel: "helm"}}, // someone else's
		{"name": "s-1", "labels": managed},                                   // no session prefix
	} {
		if err := c.Create(ctx, ns, "pods", map[string]any{"metadata": bad}); !errors.Is(err, ErrForbiddenWrite) {
			t.Errorf("Create %v: %v", bad, err)
		}
	}
	if n := atomic.LoadInt32(calls); n != 0 {
		t.Fatalf("refused writes must not reach the API server, saw %d calls", n)
	}
	for _, ok := range []struct{ ns, res, name string }{
		{ns, "pods", "us-s-1"},
		{ns, "secrets", "us-s-1-creds"},
	} {
		obj := map[string]any{"metadata": map[string]any{"name": ok.name, "labels": managed}}
		if err := c.Create(ctx, ok.ns, ok.res, obj); err != nil {
			t.Errorf("Create %v: %v", ok, err)
		}
	}
}

// A RoleBinding is a privilege grant: the console never writes one, in any
// namespace, with any name (c1s-r4).
func TestRoleBindingCreateIsRefused(t *testing.T) {
	c, calls := server(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) })
	c.Writes = &WritePolicy{SessionNamespace: "upgrade-sessions"}
	obj := map[string]any{"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
		"metadata": map[string]any{"name": "us-s-1", "labels": map[string]any{ManagedByLabel: ManagedBy}}}
	if err := c.Create(context.Background(), "upgrade-sessions", "rolebindings", obj); !errors.Is(err, ErrForbiddenWrite) {
		t.Fatalf("RoleBinding create: %v", err)
	}
	if err := c.Delete(context.Background(), "upgrade-sessions", "rolebindings", "us-s-1"); !errors.Is(err, ErrForbiddenWrite) {
		t.Fatalf("RoleBinding delete: %v", err)
	}
	if n := atomic.LoadInt32(calls); n != 0 {
		t.Fatalf("saw %d calls", n)
	}
}

// c1d-r1: an object whose uid the console recorded is deleted with that uid
// as a precondition whatever its labels now say; no uid → refused.
func TestDeleteUIDIgnoresLabelsButPinsTheUID(t *testing.T) {
	var body string
	c, calls := server(t, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	})
	c.Writes = &WritePolicy{SessionNamespace: "upgrade-sessions"}
	if err := c.DeleteUID(context.Background(), "upgrade-sessions", "pods", "us-x", ""); !errors.Is(err, ErrForbiddenWrite) {
		t.Fatalf("no uid: %v", err)
	}
	if err := c.DeleteUID(context.Background(), "kube-system", "pods", "us-x", "u1"); !errors.Is(err, ErrForbiddenWrite) {
		t.Fatalf("other namespace: %v", err)
	}
	if n := atomic.LoadInt32(calls); n != 0 {
		t.Fatalf("refused deletes sent %d requests", n)
	}
	if err := c.DeleteUID(context.Background(), "upgrade-sessions", "pods", "us-x", "u1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `"uid":"u1"`) {
		t.Errorf("delete body = %s", body)
	}
}

// A delete reads the object first and refuses one the console did not make;
// the delete it does send is pinned to the uid it checked.
func TestDeleteNeedsTheManagedByLabel(t *testing.T) {
	var deletes []string
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/us-planted"):
			_, _ = w.Write([]byte(`{"metadata":{"name":"us-planted","uid":"u1","labels":{"app":"x"}}}`))
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/us-ours"):
			_, _ = w.Write([]byte(`{"metadata":{"name":"us-ours","uid":"u2","labels":{"app.kubernetes.io/managed-by":"cluster-update-fr"}}}`))
		case r.Method == http.MethodDelete:
			b, _ := io.ReadAll(r.Body)
			deletes = append(deletes, r.URL.Path+" "+string(b))
		default:
			w.WriteHeader(404)
		}
	})
	c.Writes = &WritePolicy{SessionNamespace: "upgrade-sessions"}
	ctx := context.Background()
	if err := c.Delete(ctx, "upgrade-sessions", "secrets", "us-planted"); !errors.Is(err, ErrForbiddenWrite) {
		t.Errorf("unlabelled delete: %v", err)
	}
	if err := c.Delete(ctx, "upgrade-sessions", "secrets", "us-ours"); err != nil {
		t.Errorf("labelled delete: %v", err)
	}
	if len(deletes) != 1 || !strings.Contains(deletes[0], "/us-ours") || !strings.Contains(deletes[0], `"uid":"u2"`) {
		t.Errorf("deletes = %v", deletes)
	}
}

func TestCreateConflictAndDeleteNotFound(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			if !strings.HasSuffix(r.URL.Path, "/namespaces/upgrade-sessions/pods") {
				t.Errorf("POST path %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 409, "reason": "AlreadyExists", "message": "exists"})
		case http.MethodGet, http.MethodDelete:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 404, "reason": "NotFound"})
		}
	})
	c.Writes = &WritePolicy{SessionNamespace: "upgrade-sessions"}
	err := c.Create(context.Background(), "upgrade-sessions", "pods", map[string]any{"metadata": map[string]any{"name": "us-p", "labels": map[string]any{ManagedByLabel: ManagedBy}}})
	if !IsConflict(err) {
		t.Errorf("want conflict, got %v", err)
	}
	if err := c.Delete(context.Background(), "upgrade-sessions", "pods", "us-p"); !IsNotFound(err) {
		t.Errorf("want not found, got %v", err)
	}
}

func TestFromKubeconfig(t *testing.T) {
	dir := t.TempDir()
	kc := filepath.Join(dir, "kubeconfig")
	// Values are placeholders; the client must read them, not validate them.
	content := `apiVersion: v1
kind: Config
current-context: hop
contexts:
- name: other
  context: {cluster: other, user: other}
- name: hop
  context: {cluster: hop, user: reader}
clusters:
- name: other
  cluster: {server: "https://other:6443"}
- name: hop
  cluster: {server: "https://hop-1:6443", insecure-skip-tls-verify: true}
users:
- name: other
  user: {}
- name: reader
  user:
    token: tkn
`
	if err := os.WriteFile(kc, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := FromKubeconfig(kc)
	if err != nil {
		t.Fatal(err)
	}
	if c.Server != "https://hop-1:6443" || c.Token() != "tkn" {
		t.Errorf("client = %s / %q", c.Server, c.Token())
	}
	if c.Writes != nil {
		t.Error("a kubeconfig client is read-only")
	}
	if _, err := FromKubeconfig(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing kubeconfig must error")
	}
}

func TestPathSegmentsAreEscaped(t *testing.T) {
	if p := ObjectPath("upgrade-sessions", "pods", "a/../b?c"); strings.Contains(p, "/../") || strings.Contains(p, "?") {
		t.Errorf("ObjectPath not escaped: %q", p)
	}
}
