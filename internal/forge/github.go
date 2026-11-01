package forge

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// GitHub is the derio-net/frank repository on GitHub.
type GitHub struct {
	API   string
	Repo  string
	Token func() string
	HTTP  *http.Client
}

func (g *GitHub) c() client {
	return client{base: g.API, auth: g.Token, http: g.HTTP, scheme: "Bearer"}
}

func (g *GitHub) repo(path string) string { return "/repos/" + g.Repo + path }

// PR is a pull request.
type PR struct {
	Number         int
	NodeID         string
	Title, Body    string
	State          string
	Draft          bool
	HeadSHA        string
	HeadRef        string
	Author         string
	Labels         []string
	CreatedAt      time.Time
	UpdatedAt      time.Time
	Mergeable      *bool
	MergeableState string
	Merged         bool
	MergeCommitSHA string
	URL            string
	HeadRepo       string // owner/name the head branch lives in ("" = deleted fork)
	BaseRepo       string
	BaseRef        string
}

type ghRepo struct {
	FullName string `json:"full_name"`
}

// HasLabel reports whether the PR carries label.
func (p PR) HasLabel(label string) bool {
	for _, l := range p.Labels {
		if l == label {
			return true
		}
	}
	return false
}

type ghPR struct {
	Number    int       `json:"number"`
	NodeID    string    `json:"node_id"`
	Title     string    `json:"title"`
	Body      string    `json:"body"`
	State     string    `json:"state"`
	Draft     bool      `json:"draft"`
	HTMLURL   string    `json:"html_url"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Head      struct {
		SHA  string  `json:"sha"`
		Ref  string  `json:"ref"`
		Repo *ghRepo `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref  string  `json:"ref"`
		Repo *ghRepo `json:"repo"`
	} `json:"base"`
	User struct {
		Login string `json:"login"`
	} `json:"user"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
	Mergeable      *bool  `json:"mergeable"`
	MergeableState string `json:"mergeable_state"`
	Merged         bool   `json:"merged"`
	MergeCommitSHA string `json:"merge_commit_sha"`
}

func (p ghPR) pr() PR {
	out := PR{Number: p.Number, NodeID: p.NodeID, Title: p.Title, Body: p.Body, State: p.State, Draft: p.Draft,
		HeadSHA: p.Head.SHA, HeadRef: p.Head.Ref, Author: p.User.Login, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
		Mergeable: p.Mergeable, MergeableState: p.MergeableState, Merged: p.Merged, MergeCommitSHA: p.MergeCommitSHA, URL: p.HTMLURL}
	for _, l := range p.Labels {
		out.Labels = append(out.Labels, l.Name)
	}
	if p.Head.Repo != nil {
		out.HeadRepo = p.Head.Repo.FullName
	}
	if p.Base.Repo != nil {
		out.BaseRepo = p.Base.Repo.FullName
	}
	out.BaseRef = p.Base.Ref
	return out
}

// OpenPRs lists open pull requests (first 100).
func (g *GitHub) OpenPRs(ctx context.Context) ([]PR, error) {
	var raw []ghPR
	if err := g.c().do(ctx, http.MethodGet, g.repo("/pulls?state=open&per_page=100"), nil, &raw, false); err != nil {
		return nil, err
	}
	out := make([]PR, 0, len(raw))
	for _, p := range raw {
		out = append(out, p.pr())
	}
	return out, nil
}

// PR fetches one pull request, including mergeability.
func (g *GitHub) PR(ctx context.Context, n int) (PR, error) {
	var raw ghPR
	if err := g.c().do(ctx, http.MethodGet, g.repo(fmt.Sprintf("/pulls/%d", n)), nil, &raw, false); err != nil {
		return PR{}, err
	}
	return raw.pr(), nil
}

// Merge squash-merges PR n only if its head is still sha (a PR that moved is
// never merged blind) and returns the merge commit sha.
func (g *GitHub) Merge(ctx context.Context, n int, sha string) (string, error) {
	var out struct {
		SHA string `json:"sha"`
	}
	err := g.c().do(ctx, http.MethodPut, g.repo(fmt.Sprintf("/pulls/%d/merge", n)),
		map[string]string{"sha": sha, "merge_method": "squash"}, &out, true)
	return out.SHA, err
}

// UpdatePRBody replaces a PR's body (ticking Renovate's rebase checkbox).
func (g *GitHub) UpdatePRBody(ctx context.Context, n int, body string) error {
	return g.c().do(ctx, http.MethodPatch, g.repo(fmt.Sprintf("/pulls/%d", n)), map[string]string{"body": body}, nil, true)
}

// Status is a commit status.
type Status struct {
	ID          int64     `json:"id"`
	Context     string    `json:"context"`
	State       string    `json:"state"`
	Description string    `json:"description"`
	TargetURL   string    `json:"target_url"`
	CreatedAt   time.Time `json:"created_at"`
	// Creator is the GitHub account that posted the status (c1s-r3: only the
	// status bridge's and the console's statuses count as CI).
	Creator struct {
		Login string `json:"login"`
	} `json:"creator"`
}

// Statuses lists every status of a commit (newest first, as GitHub returns).
func (g *GitHub) Statuses(ctx context.Context, sha string) ([]Status, error) {
	var out []Status
	err := g.c().do(ctx, http.MethodGet, g.repo("/commits/"+url.PathEscape(sha)+"/statuses?per_page=100"), nil, &out, false)
	return out, err
}

// CreateStatus posts a commit status (re-forwarding a lost Gitea status).
func (g *GitHub) CreateStatus(ctx context.Context, sha string, s Status) error {
	in := map[string]string{"state": s.State, "context": s.Context, "description": s.Description, "target_url": s.TargetURL}
	return g.c().do(ctx, http.MethodPost, g.repo("/statuses/"+url.PathEscape(sha)), in, nil, true)
}

// Latest reduces statuses to the newest per context (by time, then id).
func Latest(statuses []Status) map[string]Status {
	sorted := append([]Status(nil), statuses...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if !sorted[i].CreatedAt.Equal(sorted[j].CreatedAt) {
			return sorted[i].CreatedAt.Before(sorted[j].CreatedAt)
		}
		return sorted[i].ID < sorted[j].ID
	})
	out := map[string]Status{}
	for _, s := range sorted {
		out[s.Context] = s
	}
	return out
}

// Issue is an issue (the Dependency Dashboard).
type Issue struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	URL    string `json:"html_url"`
}

// FindIssue returns the open issue (not PR) with exactly this title.
func (g *GitHub) FindIssue(ctx context.Context, title string) (Issue, error) {
	var raw []struct {
		Issue
		PullRequest *struct{} `json:"pull_request"`
	}
	if err := g.c().do(ctx, http.MethodGet, g.repo("/issues?state=open&per_page=100"), nil, &raw, false); err != nil {
		return Issue{}, err
	}
	for _, i := range raw {
		if i.PullRequest == nil && i.Title == title {
			return i.Issue, nil
		}
	}
	return Issue{}, ErrNotFound
}

// UpdateIssueBody replaces an issue's body (ticking dashboard approvals).
func (g *GitHub) UpdateIssueBody(ctx context.Context, n int, body string) error {
	return g.c().do(ctx, http.MethodPatch, g.repo(fmt.Sprintf("/issues/%d", n)), map[string]string{"body": body}, nil, true)
}

// CreateIssue opens an issue and returns its number and URL.
func (g *GitHub) CreateIssue(ctx context.Context, title, body string) (int, string, error) {
	var out Issue
	err := g.c().do(ctx, http.MethodPost, g.repo("/issues"), map[string]string{"title": title, "body": body}, &out, true)
	return out.Number, out.URL, err
}

// ParentOf returns a commit's first parent (for a squash merge on main:
// main as it was before the merge).
func (g *GitHub) ParentOf(ctx context.Context, sha string) (string, error) {
	var out struct {
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
	}
	if err := g.c().do(ctx, http.MethodGet, g.repo("/commits/"+url.PathEscape(sha)), nil, &out, false); err != nil {
		return "", err
	}
	if len(out.Parents) == 0 {
		return "", fmt.Errorf("forge: commit %.12s has no parent", sha)
	}
	return out.Parents[0].SHA, nil
}

func contentsPath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return "/contents/" + strings.Join(segs, "/")
}

type content struct {
	SHA     string `json:"sha"`
	Content string `json:"content"`
}

func (g *GitHub) content(ctx context.Context, p, ref string) (content, bool, error) {
	var c content
	err := g.c().do(ctx, http.MethodGet, g.repo(contentsPath(p)+"?ref="+url.QueryEscape(ref)), nil, &c, false)
	if errors.Is(err, ErrNotFound) {
		return content{}, false, nil
	}
	return c, err == nil, err
}

// RestoreFiles commits, on branch, each file's content as it is at ref —
// a file absent at ref is deleted — through the contents API, so every
// commit is made (and signed) by GitHub for the console's App. One commit
// per file; a file already equal to ref is left alone.
func (g *GitHub) RestoreFiles(ctx context.Context, branch, ref string, files []string, message string) error {
	for _, p := range files {
		want, atRef, err := g.content(ctx, p, ref)
		if err != nil {
			return err
		}
		cur, onBranch, err := g.content(ctx, p, branch)
		if err != nil {
			return err
		}
		switch {
		case atRef && onBranch && cur.SHA == want.SHA:
			continue // already as at ref
		case atRef:
			body := map[string]string{"message": message, "content": strings.ReplaceAll(want.Content, "\n", ""), "branch": branch}
			if onBranch {
				body["sha"] = cur.SHA
			}
			if err := g.c().do(ctx, http.MethodPut, g.repo(contentsPath(p)), body, nil, true); err != nil {
				return err
			}
		case onBranch:
			body := map[string]string{"message": message, "sha": cur.SHA, "branch": branch}
			if err := g.c().do(ctx, http.MethodDelete, g.repo(contentsPath(p)), body, nil, true); err != nil {
				return err
			}
		}
	}
	return nil
}

// CreateBranch creates branch from the head of base.
func (g *GitHub) CreateBranch(ctx context.Context, branch, base string) error {
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	if err := g.c().do(ctx, http.MethodGet, g.repo("/git/ref/heads/"+base), nil, &ref, false); err != nil {
		return err
	}
	return g.c().do(ctx, http.MethodPost, g.repo("/git/refs"), map[string]string{"ref": "refs/heads/" + branch, "sha": ref.Object.SHA}, nil, true)
}

// MergeBranch merges head into base (the batch branch); 409 = conflict.
func (g *GitHub) MergeBranch(ctx context.Context, base, head, message string) error {
	return g.c().do(ctx, http.MethodPost, g.repo("/merges"), map[string]string{"base": base, "head": head, "commit_message": message}, nil, true)
}

// CreatePR opens a pull request.
func (g *GitHub) CreatePR(ctx context.Context, title, head, base, body string) (PR, error) {
	var raw ghPR
	err := g.c().do(ctx, http.MethodPost, g.repo("/pulls"), map[string]string{"title": title, "head": head, "base": base, "body": body}, &raw, true)
	return raw.pr(), err
}

// Delivery is one webhook delivery.
type Delivery struct {
	HookID, ID int64
	Event      string
}

// FindDelivery finds, among the newest limit deliveries of every repo hook,
// a push or pull_request delivery whose payload names sha.
func (g *GitHub) FindDelivery(ctx context.Context, sha string, limit int) (Delivery, error) {
	var hooks []struct {
		ID     int64 `json:"id"`
		Active bool  `json:"active"`
	}
	if err := g.c().do(ctx, http.MethodGet, g.repo("/hooks"), nil, &hooks, false); err != nil {
		return Delivery{}, err
	}
	for _, h := range hooks {
		if !h.Active {
			continue
		}
		var ds []struct {
			ID    int64  `json:"id"`
			Event string `json:"event"`
		}
		if err := g.c().do(ctx, http.MethodGet, g.repo(fmt.Sprintf("/hooks/%d/deliveries?per_page=%d", h.ID, limit)), nil, &ds, false); err != nil {
			return Delivery{}, err
		}
		for _, d := range ds {
			if d.Event != "push" && d.Event != "pull_request" {
				continue
			}
			var full struct {
				Request struct {
					Payload struct {
						After       string `json:"after"`
						PullRequest struct {
							Head struct {
								SHA string `json:"sha"`
							} `json:"head"`
						} `json:"pull_request"`
					} `json:"payload"`
				} `json:"request"`
			}
			if err := g.c().do(ctx, http.MethodGet, g.repo(fmt.Sprintf("/hooks/%d/deliveries/%d", h.ID, d.ID)), nil, &full, false); err != nil {
				continue
			}
			p := full.Request.Payload
			if p.After == sha || p.PullRequest.Head.SHA == sha {
				return Delivery{HookID: h.ID, ID: d.ID, Event: d.Event}, nil
			}
		}
	}
	return Delivery{}, ErrNotFound
}

// Redeliver asks GitHub to send a delivery again (re-drives the mirror sync
// without any cluster write).
func (g *GitHub) Redeliver(ctx context.Context, d Delivery) error {
	return g.c().do(ctx, http.MethodPost, g.repo(fmt.Sprintf("/hooks/%d/deliveries/%d/attempts", d.HookID, d.ID)), nil, nil, true)
}

// Contains reports whether descendant includes ancestor (compare API: the
// descendant is "ahead" of or "identical" to the ancestor).
func (g *GitHub) Contains(ctx context.Context, ancestor, descendant string) (bool, error) {
	var out struct {
		Status string `json:"status"`
	}
	if err := g.c().do(ctx, http.MethodGet, g.repo("/compare/"+url.PathEscape(ancestor)+"..."+url.PathEscape(descendant)), nil, &out, false); err != nil {
		return false, err
	}
	return out.Status == "ahead" || out.Status == "identical", nil
}

// DeleteBranch removes a branch the console created (a stale batch branch).
// Only the console's own cluster-update/ branches can ever be deleted.
func (g *GitHub) DeleteBranch(ctx context.Context, branch string) error {
	if !strings.HasPrefix(branch, "cluster-update/") || strings.Contains(branch, "..") {
		return fmt.Errorf("forge: refusing to delete branch %q (not the console's)", branch)
	}
	return g.c().do(ctx, http.MethodDelete, g.repo("/git/refs/heads/"+branch), nil, nil, true)
}

// Branches lists the branch names starting with prefix (matching-refs).
func (g *GitHub) Branches(ctx context.Context, prefix string) ([]string, error) {
	var raw []struct {
		Ref string `json:"ref"`
	}
	if err := g.c().do(ctx, http.MethodGet, g.repo("/git/matching-refs/heads/"+prefix), nil, &raw, false); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range raw {
		out = append(out, strings.TrimPrefix(r.Ref, "refs/heads/"))
	}
	return out, nil
}

// Releases lists the newest release tags of a public repository
// (siderolabs/talos, kubernetes/kubernetes, siderolabs/omni).
func (g *GitHub) Releases(ctx context.Context, ownerRepo string) ([]string, error) {
	var raw []struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := g.c().do(ctx, http.MethodGet, "/repos/"+ownerRepo+"/releases?per_page=100", nil, &raw, false); err != nil {
		return nil, err
	}
	var out []string
	for _, r := range raw {
		if !r.Draft && !r.Prerelease {
			out = append(out, r.Tag)
		}
	}
	return out, nil
}

// Commit is one commit of a pull request with its GitHub identities.
type Commit struct {
	SHA       string
	Author    string // GitHub ACCOUNT login of the author ("" if not linked)
	Committer string // GitHub ACCOUNT login of the committer ("" if not linked)
	Verified  bool   // commit.verification.verified
	Reason    string // commit.verification.reason ("valid" when verified)
	Payload   string // commit.verification.payload: the signed commit object
}

// PRCommits lists a pull request's commits (GitHub caps the list at 250).
func (g *GitHub) PRCommits(ctx context.Context, n int) ([]Commit, error) {
	var raw []struct {
		SHA    string `json:"sha"`
		Author *struct {
			Login string `json:"login"`
		} `json:"author"`
		Committer *struct {
			Login string `json:"login"`
		} `json:"committer"`
		Commit struct {
			Verification struct {
				Verified bool   `json:"verified"`
				Reason   string `json:"reason"`
				Payload  string `json:"payload"`
			} `json:"verification"`
		} `json:"commit"`
	}
	if err := g.c().do(ctx, http.MethodGet, g.repo(fmt.Sprintf("/pulls/%d/commits?per_page=100", n)), nil, &raw, false); err != nil {
		return nil, err
	}
	out := make([]Commit, 0, len(raw))
	for _, c := range raw {
		v := c.Commit.Verification
		x := Commit{SHA: c.SHA, Verified: v.Verified, Reason: v.Reason, Payload: v.Payload}
		if c.Author != nil {
			x.Author = c.Author.Login
		}
		if c.Committer != nil {
			x.Committer = c.Committer.Login
		}
		out = append(out, x)
	}
	return out, nil
}

// PRFiles lists the paths a pull request changes (first 100; more is
// reported as an error so the caller can refuse to trust it).
func (g *GitHub) PRFiles(ctx context.Context, n int) ([]string, error) {
	var raw []struct {
		Filename         string `json:"filename"`
		PreviousFilename string `json:"previous_filename"`
	}
	if err := g.c().do(ctx, http.MethodGet, g.repo(fmt.Sprintf("/pulls/%d/files?per_page=100", n)), nil, &raw, false); err != nil {
		return nil, err
	}
	if len(raw) >= 100 {
		return nil, fmt.Errorf("forge: PR #%d changes 100 or more files", n)
	}
	var out []string
	for _, f := range raw {
		out = append(out, f.Filename)
		if f.PreviousFilename != "" {
			out = append(out, f.PreviousFilename)
		}
	}
	return out, nil
}

// FilePatch is one changed file with its unified diff hunk text.
type FilePatch struct {
	Status string // added | removed | modified | renamed | …
	Patch  string // "" when GitHub omits it (binary, too large)
}

// PRPatches returns each changed file's status and patch, by path.
func (g *GitHub) PRPatches(ctx context.Context, n int) (map[string]FilePatch, error) {
	var raw []struct {
		Filename string `json:"filename"`
		Status   string `json:"status"`
		Patch    string `json:"patch"`
	}
	if err := g.c().do(ctx, http.MethodGet, g.repo(fmt.Sprintf("/pulls/%d/files?per_page=100", n)), nil, &raw, false); err != nil {
		return nil, err
	}
	out := map[string]FilePatch{}
	for _, f := range raw {
		out[f.Filename] = FilePatch{Status: f.Status, Patch: f.Patch}
	}
	return out, nil
}

// Push is the most recent push to a branch.
type Push struct {
	After string    // the SHA the ref moved to
	Actor string    // GitHub account that pushed
	At    time.Time // when GitHub recorded the push
}

// LastPush returns the newest push (or force push) to branch, from the
// repository activity API — GitHub's own record of who moved the ref.
func (g *GitHub) LastPush(ctx context.Context, branch string) (Push, error) {
	var raw []struct {
		After        string    `json:"after"`
		ActivityType string    `json:"activity_type"`
		Timestamp    time.Time `json:"timestamp"`
		Actor        *struct {
			Login string `json:"login"`
		} `json:"actor"`
	}
	q := "/activity?per_page=1&ref=" + url.QueryEscape("refs/heads/"+branch)
	if err := g.c().do(ctx, http.MethodGet, g.repo(q), nil, &raw, false); err != nil {
		return Push{}, err
	}
	if len(raw) == 0 {
		return Push{}, ErrNotFound
	}
	p := Push{After: raw[0].After, At: raw[0].Timestamp}
	if raw[0].Actor != nil {
		p.Actor = raw[0].Actor.Login
	}
	return p, nil
}
