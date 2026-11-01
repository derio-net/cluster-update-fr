package frankrepo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func fixture() Source { return FSSource{Root: "../../testdata/frank"} }

func TestLoadDeclarations(t *testing.T) {
	d, err := Load(context.Background(), fixture())
	if err != nil {
		t.Fatal(err)
	}
	if d.Frank.Talos != "1.12.6" || d.Frank.Kubernetes != "1.35.3" || d.Frank.ManagedBy != "omni" {
		t.Errorf("frank = %+v", d.Frank)
	}
	if d.Hop.Talos != "1.12.5" || d.Hop.Kubernetes != "1.34.1" || d.Hop.ManagedBy != "talosctl" {
		t.Errorf("hop = %+v", d.Hop)
	}
	if d.OmniVersion != "v1.5.0" {
		t.Errorf("omni = %q", d.OmniVersion)
	}
	if got := d.Matrix.Kubernetes("1.13"); len(got) != 6 || got[5] != "1.36" {
		t.Errorf("matrix 1.13 = %v", got)
	}
	s, ok := d.Smoke["litellm"]
	if !ok || s.Cluster != "frank" || len(s.Checks) != 2 || s.Checks[1].Expect.Body != `"data"` || s.Checks[0].Expect.Status != 200 {
		t.Errorf("smoke litellm = %+v", s)
	}
	if d.Policy.MergeWindow != 24*time.Hour || d.Policy.MinimumReleaseAge != 72*time.Hour {
		t.Errorf("policy windows = %v %v", d.Policy.MergeWindow, d.Policy.MinimumReleaseAge)
	}
	if len(d.Missing) != 0 {
		t.Errorf("Missing = %v", d.Missing)
	}
}

func TestPolicyResolve(t *testing.T) {
	d, err := Load(context.Background(), fixture())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		dep  Dep
		want string
	}{
		{Dep{App: "paperclip-db", Kind: "image", Name: "postgres", UpdateType: "patch"}, PathSession},
		{Dep{App: "litellm", Kind: "chart", Name: "litellm", UpdateType: "patch"}, PathSession},
		{Dep{Kind: "omni", Name: "omni", UpdateType: "minor"}, PathOperatorRunbook},
		{Dep{Kind: "talos", Name: "talos", UpdateType: "patch"}, PathSession},
		{Dep{App: "homepage", Kind: "image", Name: "ghcr.io/derio-net/blog", UpdateType: "patch"}, PathBatchApprove},
		{Dep{App: "cilium", Kind: "chart", Name: "cilium", UpdateType: "minor"}, PathSession},
		{Dep{App: "homepage", Kind: "image", Name: "ghcr.io/gethomepage/homepage", UpdateType: "patch"}, PathAutoMerge},
		{Dep{App: "homepage", Kind: "image", Name: "ghcr.io/gethomepage/homepage", UpdateType: "minor"}, PathBatchApprove},
		{Dep{App: "homepage", Kind: "image", Name: "ghcr.io/gethomepage/homepage", UpdateType: "major"}, PathSession},
	}
	for _, c := range cases {
		got, rule := d.Policy.Resolve(c.dep)
		if got != c.want {
			t.Errorf("Resolve(%+v) = %s (%s), want %s", c.dep, got, rule, c.want)
		}
	}
	// A dependency no rule and no default covers is unclassified, never guessed.
	empty := Policy{}
	if got, _ := empty.Resolve(Dep{Kind: "image", Name: "x", UpdateType: "patch"}); got != PathUnclassified {
		t.Errorf("empty policy resolved to %q", got)
	}
}

func TestMissingFilesAreNamedNotFatal(t *testing.T) {
	d, err := Load(context.Background(), FSSource{Root: t.TempDir()})
	if err != nil {
		t.Fatalf("an empty repo must load with Missing set, not fail: %v", err)
	}
	if len(d.Missing) < 4 {
		t.Errorf("Missing = %v", d.Missing)
	}
	if d.Frank.Talos != "" {
		t.Error("undeclared must stay empty")
	}
}

func TestGitHubSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tkn" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/repos/derio-net/frank/contents/versions/frank.yaml":
			if r.URL.Query().Get("ref") != "main" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{
				"encoding": "base64",
				"content":  base64.StdEncoding.EncodeToString([]byte("talos: \"1.12.6\"\n")),
			})
		case "/repos/derio-net/frank/commits/main":
			_ = json.NewEncoder(w).Encode(map[string]string{"sha": "5e8b2d6f0a4c19e73b5d8f2a6c0e4b9d1f3a7c58"})
		case "/repos/derio-net/frank/contents/smoke":
			_ = json.NewEncoder(w).Encode([]map[string]string{{"name": "a.yaml", "type": "file"}, {"name": "README.md", "type": "file"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	src := GitHubSource{API: srv.URL, Repo: "derio-net/frank", Ref: "main", Token: func() string { return "tkn" }, HTTP: srv.Client()}
	b, err := src.Read(context.Background(), "versions/frank.yaml")
	if err != nil || string(b) != "talos: \"1.12.6\"\n" {
		t.Fatalf("Read = %q, %v", b, err)
	}
	if _, err := src.Read(context.Background(), "nope.yaml"); !errors.Is(err, ErrNotFound) {
		t.Errorf("404 must be ErrNotFound, got %v", err)
	}
	names, err := src.List(context.Background(), "smoke")
	if err != nil || len(names) != 1 || names[0] != "a.yaml" {
		t.Errorf("List = %v %v", names, err)
	}
	// sec2-8: Pin fixes the ref to its commit, so a Load reads one revision.
	pinned, rev, err := src.Pin(context.Background())
	if err != nil || rev != "5e8b2d6f0a4c19e73b5d8f2a6c0e4b9d1f3a7c58" || pinned.(GitHubSource).Ref != rev {
		t.Fatalf("Pin = %v %q %v", pinned, rev, err)
	}
}
