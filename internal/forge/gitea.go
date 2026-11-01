package forge

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Gitea is the Gitea mirror of the repository, where CI runs.
type Gitea struct {
	URL   string // base URL; the API lives under /api/v1
	Repo  string
	Token func() string
	HTTP  *http.Client

	mu        sync.Mutex
	rerunPath string // discovered from the swagger; "" = unsupported
	probed    bool
}

func (g *Gitea) c() client { return client{base: g.URL, auth: g.Token, http: g.HTTP, scheme: "token"} }

func (g *Gitea) repo(path string) string { return "/api/v1/repos/" + g.Repo + path }

// Run is a Gitea Actions workflow run.
type Run struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	HeadSHA    string `json:"head_sha"`
	Title      string `json:"display_title"`
	Event      string `json:"event"`
}

// Runs lists the workflow runs for a head sha.
func (g *Gitea) Runs(ctx context.Context, sha string) ([]Run, error) {
	var out struct {
		Runs []Run `json:"workflow_runs"`
	}
	err := g.c().do(ctx, http.MethodGet, g.repo("/actions/runs?head_sha="+url.QueryEscape(sha)+"&limit=50"), nil, &out, false)
	return out.Runs, err
}

// Job is one job of a run.
type Job struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}

// Jobs lists the jobs of a run.
func (g *Gitea) Jobs(ctx context.Context, run int64) ([]Job, error) {
	var out struct {
		Jobs []Job `json:"jobs"`
	}
	err := g.c().do(ctx, http.MethodGet, g.repo(fmt.Sprintf("/actions/runs/%d/jobs", run)), nil, &out, false)
	return out.Jobs, err
}

// Statuses lists the commit statuses Gitea holds for sha.
func (g *Gitea) Statuses(ctx context.Context, sha string) ([]Status, error) {
	var raw []struct {
		ID          int64     `json:"id"`
		Context     string    `json:"context"`
		State       string    `json:"status"`
		StateAlt    string    `json:"state"`
		Description string    `json:"description"`
		TargetURL   string    `json:"target_url"`
		CreatedAt   time.Time `json:"created_at"`
	}
	if err := g.c().do(ctx, http.MethodGet, g.repo("/commits/"+url.PathEscape(sha)+"/statuses?limit=50"), nil, &raw, false); err != nil {
		return nil, err
	}
	out := make([]Status, 0, len(raw))
	for _, r := range raw {
		st := r.State
		if st == "" {
			st = r.StateAlt
		}
		out = append(out, Status{ID: r.ID, Context: r.Context, State: st, Description: r.Description, TargetURL: r.TargetURL, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

// RerunSupported probes the server's swagger for a run re-run endpoint.
// Gitea 1.25.4 (measured 2026-10-31) has none; the console then falls back
// to Renovate's rebase checkbox, never to an empty commit.
func (g *Gitea) RerunSupported(ctx context.Context) (bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.probed {
		return g.rerunPath != "", nil
	}
	var sw struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := g.c().do(ctx, http.MethodGet, "/swagger.v1.json", nil, &sw, false); err != nil {
		return false, err
	}
	g.probed = true
	for p, ops := range sw.Paths {
		if _, post := ops["post"]; post && strings.Contains(p, "/actions/runs/{") && strings.HasSuffix(p, "/rerun") && !strings.Contains(p, "/jobs/") {
			g.rerunPath = p
		}
	}
	return g.rerunPath != "", nil
}

// Rerun re-runs a workflow run through the advertised endpoint.
func (g *Gitea) Rerun(ctx context.Context, run int64) error {
	if ok, err := g.RerunSupported(ctx); err != nil {
		return err
	} else if !ok {
		return ErrUnsupported
	}
	owner, name, _ := strings.Cut(g.Repo, "/")
	g.mu.Lock()
	p := g.rerunPath
	g.mu.Unlock()
	p = strings.ReplaceAll(p, "{owner}", url.PathEscape(owner))
	p = strings.ReplaceAll(p, "{repo}", url.PathEscape(name))
	start := strings.Index(p, "/actions/runs/{")
	end := strings.Index(p[start+len("/actions/runs/{"):], "}")
	p = p[:start] + fmt.Sprintf("/actions/runs/%d", run) + p[start+len("/actions/runs/{")+end+1:]
	return g.c().do(ctx, http.MethodPost, "/api/v1"+p, nil, nil, true)
}
