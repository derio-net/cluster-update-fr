package kube

import (
	"context"
	"encoding/json"
	"errors"
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
	for _, bad := range []struct{ ns, res, name string }{
		{"default", "pods", "x"},
		{"upgrade-sessions", "deployments", "x"},
		{"upgrade-sessions", "configmaps", "x"},
		{"paperclip", "secrets", "x"},
		{"paperclip", "rolebindings", "not-ours"},
		{"paperclip", "roles", "upgrade-session-x"},
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
	for _, ok := range []struct{ ns, res, name string }{
		{"upgrade-sessions", "pods", "s-1"},
		{"upgrade-sessions", "secrets", "s-1-creds"},
		{"paperclip", "rolebindings", "upgrade-session-s-1"},
	} {
		obj := map[string]any{"metadata": map[string]any{"name": ok.name}}
		if err := c.Create(ctx, ok.ns, ok.res, obj); err != nil {
			t.Errorf("Create %v: %v", ok, err)
		}
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
		case http.MethodDelete:
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]any{"code": 404, "reason": "NotFound"})
		}
	})
	c.Writes = &WritePolicy{SessionNamespace: "upgrade-sessions"}
	err := c.Create(context.Background(), "upgrade-sessions", "pods", map[string]any{"metadata": map[string]any{"name": "p"}})
	if !IsConflict(err) {
		t.Errorf("want conflict, got %v", err)
	}
	if err := c.Delete(context.Background(), "upgrade-sessions", "pods", "p"); !IsNotFound(err) {
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
