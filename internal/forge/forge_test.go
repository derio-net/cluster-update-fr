package forge

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type call struct {
	Method, Path, Query string
	Body                map[string]any
}

func fake(t *testing.T, routes map[string]string) (*httptest.Server, *[]call) {
	t.Helper()
	var calls []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := call{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery}
		if b, _ := io.ReadAll(r.Body); len(b) > 0 {
			_ = json.Unmarshal(b, &c.Body)
		}
		calls = append(calls, c)
		key := r.Method + " " + r.URL.Path
		body, ok := routes[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
			return
		}
		if strings.HasPrefix(body, "!") { // "!409 {...}" sets a status
			code := body[1:4]
			body = body[5:]
			switch code {
			case "409":
				w.WriteHeader(http.StatusConflict)
			case "405":
				w.WriteHeader(http.StatusMethodNotAllowed)
			case "422":
				w.WriteHeader(http.StatusUnprocessableEntity)
			}
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func gh(srv *httptest.Server, token string) *GitHub {
	return &GitHub{API: srv.URL, Repo: "derio-net/frank", Token: func() string { return token }, HTTP: srv.Client()}
}

func TestGitHubPullRequests(t *testing.T) {
	srv, calls := fake(t, map[string]string{
		"GET /repos/derio-net/frank/pulls":         `[{"number":7,"node_id":"PR_7","title":"Update litellm","body":"b","state":"open","created_at":"2026-10-30T10:00:00Z","head":{"sha":"abc","ref":"renovate/litellm"},"user":{"login":"frank-renovate[bot]"},"labels":[{"name":"security"}]}]`,
		"GET /repos/derio-net/frank/pulls/7":       `{"number":7,"title":"Update litellm","state":"open","mergeable":false,"mergeable_state":"dirty","head":{"sha":"abc","ref":"renovate/litellm"},"merged":false}`,
		"PUT /repos/derio-net/frank/pulls/7/merge": `{"sha":"m3rg3","merged":true}`,
		"PATCH /repos/derio-net/frank/pulls/7":     `{"number":7}`,
	})
	g := gh(srv, "tkn")
	ctx := context.Background()
	prs, err := g.OpenPRs(ctx)
	if err != nil || len(prs) != 1 || prs[0].HeadSHA != "abc" || prs[0].HeadRef != "renovate/litellm" || !prs[0].HasLabel("security") || prs[0].Author != "frank-renovate[bot]" {
		t.Fatalf("OpenPRs = %+v, %v", prs, err)
	}
	pr, err := g.PR(ctx, 7)
	if err != nil || pr.Mergeable == nil || *pr.Mergeable || pr.MergeableState != "dirty" {
		t.Fatalf("PR = %+v, %v", pr, err)
	}
	sha, err := g.Merge(ctx, 7, "abc")
	if err != nil || sha != "m3rg3" {
		t.Fatalf("Merge = %q, %v", sha, err)
	}
	last := (*calls)[len(*calls)-1]
	if last.Body["sha"] != "abc" || last.Body["merge_method"] != "squash" {
		t.Errorf("merge must pin the expected head sha and squash: %+v", last.Body)
	}
	if err := g.UpdatePRBody(ctx, 7, "new"); err != nil {
		t.Fatal(err)
	}
}

func TestMergeConflictIsTyped(t *testing.T) {
	srv, _ := fake(t, map[string]string{
		"PUT /repos/derio-net/frank/pulls/7/merge": `!409 {"message":"Head branch was modified. Review and try the merge again."}`,
	})
	_, err := gh(srv, "tkn").Merge(context.Background(), 7, "old")
	var fe *Error
	if !errors.As(err, &fe) || fe.Status != 409 {
		t.Fatalf("err = %v", err)
	}
}

func TestWritesWithoutCredentialAreRefusedLocally(t *testing.T) {
	srv, calls := fake(t, map[string]string{})
	g := gh(srv, "")
	ctx := context.Background()
	if _, err := g.Merge(ctx, 1, "x"); !errors.Is(err, ErrNoCredential) {
		t.Errorf("Merge: %v", err)
	}
	if err := g.CreateStatus(ctx, "x", Status{Context: "c", State: "success"}); !errors.Is(err, ErrNoCredential) {
		t.Errorf("CreateStatus: %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("no request may be sent without a credential: %+v", *calls)
	}
}

func TestStatusesIssuesAndRevert(t *testing.T) {
	srv, calls := fake(t, map[string]string{
		"GET /repos/derio-net/frank/commits/abc/statuses": `[{"id":2,"context":"gitea-actions/ci / go","state":"success","created_at":"2026-10-30T10:05:00Z"},{"id":1,"context":"gitea-actions/ci / go","state":"pending","created_at":"2026-10-30T10:00:00Z"}]`,
		"POST /repos/derio-net/frank/statuses/abc":        `{"id":3}`,
		"GET /repos/derio-net/frank/issues":               `[{"number":1,"title":"Dependency Dashboard","body":"x"},{"number":2,"title":"other","body":"y","pull_request":{}}]`,
		"PATCH /repos/derio-net/frank/issues/1":           `{"number":1}`,
		"POST /repos/derio-net/frank/issues":              `{"number":9,"html_url":"https://github.com/derio-net/frank/issues/9"}`,
		"POST /graphql":                                   `{"data":{"revertPullRequest":{"revertPullRequest":{"number":12,"url":"https://github.com/derio-net/frank/pull/12"}}}}`,
		"POST /repos/derio-net/frank/git/refs":            `{"ref":"refs/heads/x"}`,
		"POST /repos/derio-net/frank/merges":              `{"sha":"m"}`,
		"POST /repos/derio-net/frank/pulls":               `{"number":13,"html_url":"u","head":{"sha":"h","ref":"x"}}`,
		"GET /repos/derio-net/frank/git/ref/heads/main":   `{"object":{"sha":"basesha"}}`,
	})
	g := gh(srv, "tkn")
	ctx := context.Background()
	st, err := g.Statuses(ctx, "abc")
	if err != nil || len(st) != 2 || Latest(st)["gitea-actions/ci / go"].State != "success" {
		t.Fatalf("Statuses = %+v, %v", st, err)
	}
	if err := g.CreateStatus(ctx, "abc", Status{Context: "gitea-actions/ci / go", State: "success", Description: "d", TargetURL: "u"}); err != nil {
		t.Fatal(err)
	}
	iss, err := g.FindIssue(ctx, "Dependency Dashboard")
	if err != nil || iss.Number != 1 {
		t.Fatalf("FindIssue = %+v %v", iss, err)
	}
	if err := g.UpdateIssueBody(ctx, 1, "z"); err != nil {
		t.Fatal(err)
	}
	if n, url, err := g.CreateIssue(ctx, "t", "b"); err != nil || n != 9 || url == "" {
		t.Fatalf("CreateIssue = %d %q %v", n, url, err)
	}
	n, url, err := g.RevertPR(ctx, "PR_7", "Revert x", "why")
	if err != nil || n != 12 || !strings.HasSuffix(url, "/pull/12") {
		t.Fatalf("RevertPR = %d %q %v", n, url, err)
	}
	if err := g.CreateBranch(ctx, "x", "main"); err != nil {
		t.Fatal(err)
	}
	if err := g.MergeBranch(ctx, "x", "renovate/a", "msg"); err != nil {
		t.Fatal(err)
	}
	pr, err := g.CreatePR(ctx, "t", "x", "main", "b")
	if err != nil || pr.Number != 13 {
		t.Fatalf("CreatePR = %+v %v", pr, err)
	}
	var sawGraphQL bool
	for _, c := range *calls {
		if c.Path == "/graphql" {
			sawGraphQL = true
			if !strings.Contains(c.Body["query"].(string), "revertPullRequest") {
				t.Errorf("graphql query = %v", c.Body["query"])
			}
		}
	}
	if !sawGraphQL {
		t.Error("revert must use the revertPullRequest mutation")
	}
}

func TestMergeBranchConflict(t *testing.T) {
	srv, _ := fake(t, map[string]string{"POST /repos/derio-net/frank/merges": `!409 {"message":"Merge conflict"}`})
	err := gh(srv, "tkn").MergeBranch(context.Background(), "x", "renovate/a", "m")
	if !IsConflict(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestWebhookDeliveries(t *testing.T) {
	srv, calls := fake(t, map[string]string{
		"GET /repos/derio-net/frank/hooks":                            `[{"id":5,"active":true,"config":{"url":"http://192.168.55.223:8080"}}]`,
		"GET /repos/derio-net/frank/hooks/5/deliveries":               `[{"id":100,"event":"pull_request","action":"synchronize"},{"id":99,"event":"push"}]`,
		"GET /repos/derio-net/frank/hooks/5/deliveries/100":           `{"id":100,"event":"pull_request","request":{"payload":{"pull_request":{"head":{"sha":"abc"}}}}}`,
		"GET /repos/derio-net/frank/hooks/5/deliveries/99":            `{"id":99,"event":"push","request":{"payload":{"after":"zzz"}}}`,
		"POST /repos/derio-net/frank/hooks/5/deliveries/100/attempts": `{}`,
	})
	g := gh(srv, "tkn")
	d, err := g.FindDelivery(context.Background(), "abc", 50)
	if err != nil || d.HookID != 5 || d.ID != 100 {
		t.Fatalf("FindDelivery = %+v %v", d, err)
	}
	if err := g.Redeliver(context.Background(), d); err != nil {
		t.Fatal(err)
	}
	if _, err := g.FindDelivery(context.Background(), "nope", 50); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing delivery: %v", err)
	}
	if (*calls)[len(*calls)-1].Path == "" {
		t.Error("no calls recorded")
	}
}

func TestErrorBodiesAreScrubbed(t *testing.T) {
	tok := "gh" + "s_" + strings.Repeat("Ab12", 9)
	srv, _ := fake(t, map[string]string{"GET /repos/derio-net/frank/pulls/1": `!422 {"message":"bad credentials ` + tok + `"}`})
	_, err := gh(srv, "tkn").PR(context.Background(), 1)
	if err == nil || strings.Contains(err.Error(), tok) {
		t.Fatalf("error leaked a token: %v", err)
	}
}

func TestGitea(t *testing.T) {
	srv, calls := fake(t, map[string]string{
		"GET /api/v1/repos/derio-net/frank/actions/runs":         `{"workflow_runs":[{"id":41,"status":"completed","conclusion":"failure","head_sha":"abc","display_title":"ci"}],"total_count":1}`,
		"GET /api/v1/repos/derio-net/frank/actions/runs/41/jobs": `{"jobs":[{"id":410,"name":"go","status":"completed","conclusion":"failure"}]}`,
		"GET /api/v1/repos/derio-net/frank/commits/abc/statuses": `[{"id":1,"context":"ci / go (push)","state":"failure","created_at":"2026-10-30T10:00:00Z","target_url":"/derio-net/frank/actions/runs/41"}]`,
		"GET /swagger.v1.json":                                   `{"paths":{"/repos/{owner}/{repo}/actions/runs":{}}}`,
	})
	g := &Gitea{URL: srv.URL, Repo: "derio-net/frank", Token: func() string { return "t" }, HTTP: srv.Client()}
	ctx := context.Background()
	runs, err := g.Runs(ctx, "abc")
	if err != nil || len(runs) != 1 || runs[0].Conclusion != "failure" || runs[0].ID != 41 {
		t.Fatalf("Runs = %+v %v", runs, err)
	}
	if !strings.Contains((*calls)[0].Query, "head_sha=abc") {
		t.Errorf("runs must be filtered by head_sha: %q", (*calls)[0].Query)
	}
	jobs, err := g.Jobs(ctx, 41)
	if err != nil || len(jobs) != 1 || jobs[0].Conclusion != "failure" {
		t.Fatalf("Jobs = %+v %v", jobs, err)
	}
	st, err := g.Statuses(ctx, "abc")
	if err != nil || len(st) != 1 || st[0].State != "failure" {
		t.Fatalf("Statuses = %+v %v", st, err)
	}
	ok, err := g.RerunSupported(ctx)
	if err != nil || ok {
		t.Fatalf("Gitea 1.25 swagger has no rerun path: %v %v", ok, err)
	}
	if err := g.Rerun(ctx, 41); !errors.Is(err, ErrUnsupported) {
		t.Errorf("Rerun on a server without the API: %v", err)
	}
}

func TestGiteaRerunWhenAdvertised(t *testing.T) {
	srv, calls := fake(t, map[string]string{
		"GET /swagger.v1.json": `{"paths":{"/repos/{owner}/{repo}/actions/runs/{run}/rerun":{"post":{}}}}`,
		"POST /api/v1/repos/derio-net/frank/actions/runs/41/rerun": `{}`,
	})
	g := &Gitea{URL: srv.URL, Repo: "derio-net/frank", Token: func() string { return "t" }, HTTP: srv.Client()}
	if ok, _ := g.RerunSupported(context.Background()); !ok {
		t.Fatal("advertised rerun not detected")
	}
	if err := g.Rerun(context.Background(), 41); err != nil {
		t.Fatal(err)
	}
	if (*calls)[len(*calls)-1].Method != http.MethodPost {
		t.Error("rerun must POST")
	}
}

func TestContainsAndDeleteBranch(t *testing.T) {
	srv, calls := fake(t, map[string]string{
		"GET /repos/derio-net/frank/compare/m...later":                        `{"status":"ahead"}`,
		"GET /repos/derio-net/frank/compare/m...older":                        `{"status":"behind"}`,
		"DELETE /repos/derio-net/frank/git/refs/heads/cluster-update/batch-1": ``,
	})
	g := gh(srv, "tkn")
	if ok, err := g.Contains(context.Background(), "m", "later"); err != nil || !ok {
		t.Errorf("ahead: %v %v", ok, err)
	}
	if ok, _ := g.Contains(context.Background(), "m", "older"); ok {
		t.Error("behind must not contain")
	}
	if err := g.DeleteBranch(context.Background(), "cluster-update/batch-1"); err != nil {
		t.Fatal(err)
	}
	if (*calls)[len(*calls)-1].Method != http.MethodDelete {
		t.Error("delete")
	}
}

func TestReleases(t *testing.T) {
	srv, _ := fake(t, map[string]string{"GET /repos/siderolabs/talos/releases": `[{"tag_name":"v1.14.5"},{"tag_name":"v1.15.0-beta.1","prerelease":true},{"tag_name":"v9","draft":true}]`})
	tags, err := gh(srv, "").Releases(context.Background(), "siderolabs/talos")
	if err != nil || len(tags) != 1 || tags[0] != "v1.14.5" {
		t.Fatalf("Releases = %v %v", tags, err)
	}
}
