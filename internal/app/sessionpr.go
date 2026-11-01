package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/engine"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
	"github.com/derio-net/cluster-update-fr/internal/store"
	"github.com/derio-net/cluster-update-fr/internal/trust"
)

// Session PRs are merged by the console, on the operator's click (spec
// Part 2; c1c-r1). A session opens its PR on
// cluster-update/session-<upgrade-id>/… with the session App's bot and never
// merges it: it asks through the step API (request-merge). The console runs
// the full trust check against THAT session's scope — session bot author,
// its own branch prefix, verified commits pushed by the bot, files within
// the session's update — and lists it under Needs action. The operator's
// "Merge session PR" re-verifies and merges pinned to the verified head.

const blobSessionPRs = "session-merge-requests"

// SessionPR is one merge request from a session.
type SessionPR struct {
	Session     string    `json:"session"`
	PR          int       `json:"pr"`
	HeadSHA     string    `json:"head_sha"`
	Title       string    `json:"title"`
	Branch      string    `json:"branch"`
	RequestedAt time.Time `json:"requested_at"`
	Untrusted   string    `json:"untrusted,omitempty"` // why it cannot be merged
}

// ErrBadRequest is a malformed session API call.
var ErrBadRequest = errors.New("app: bad request")

func (a *App) sessionPRs() []SessionPR {
	m := map[string]SessionPR{}
	a.Store.GetBlob(blobSessionPRs, &m)
	out := make([]SessionPR, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PR < out[j].PR })
	return out
}

func (a *App) sessionScope(id string) (trust.Scope, error) {
	u, ok := a.Store.Get(id)
	if !ok {
		return trust.Scope{}, fmt.Errorf("app: no update %s for this session", id)
	}
	it := engine.Item{Kind: u.Kind, Cluster: u.Cluster}
	if len(u.Apps) > 0 {
		it.App = u.Apps[0]
	}
	return trust.SessionScope(id, it), nil
}

// RequestMerge is the session asking the console to merge its PR. The
// session is authenticated by its step token; the PR must pass the trust
// check for this session's scope. A failing PR is listed (read-only, with
// the reason) and the session is told why.
func (a *App) RequestMerge(ctx context.Context, id, token string, pr int) error {
	if a.Launcher == nil || a.GitHub == nil {
		return ErrUnavailable
	}
	if err := a.Launcher.Authorize(id, token); err != nil {
		return err
	}
	if pr <= 0 || pr > 1<<30 {
		return fmt.Errorf("%w: pr must be a pull request number", ErrBadRequest)
	}
	p, err := a.GitHub.PR(ctx, pr)
	if err != nil {
		return err
	}
	if p.State != "open" || p.Merged {
		return fmt.Errorf("%w: PR #%d is not open", ErrBadRequest, pr)
	}
	scope, err := a.sessionScope(id)
	if err != nil {
		return err
	}
	a.eng(a.policy())
	checkErr := a.trustConfig().Check(ctx, a.GitHub, p, scope)
	req := SessionPR{Session: id, PR: pr, HeadSHA: p.HeadSHA, Title: trust.Title(p.Title), Branch: trust.Title(p.HeadRef), RequestedAt: a.now()}
	if checkErr != nil {
		req.Untrusted = scrub.String(checkErr.Error())
	}
	_ = store.UpdateJSON(a.Store, blobSessionPRs, func(m *map[string]SessionPR) error {
		if *m == nil {
			*m = map[string]SessionPR{}
		}
		(*m)[strconv.Itoa(pr)] = req
		return nil
	})
	reason := fmt.Sprintf("session asked the console to merge PR #%d", pr)
	if checkErr != nil {
		reason += " — untrusted: " + req.Untrusted
	}
	a.Store.AddEvent(store.Event{Update: id, Action: "session-merge-requested", By: "session", PR: pr, SHA: p.HeadSHA, Reason: reason})
	_ = a.Store.Save()
	if checkErr != nil {
		return fmt.Errorf("%w: PR #%d fails the trust check: %v", ErrBadRequest, pr, checkErr)
	}
	return nil
}

// MergeSessionPR is the operator's "Merge session PR": re-verify against the
// session's scope, merge pinned to the head verified at request time, and
// record the merge on the session's update (it now verifies like any
// other merged update — an OS step through verify.OS).
func (a *App) MergeSessionPR(ctx context.Context, pr int, by string) error {
	if a.GitHub == nil {
		return ErrUnavailable
	}
	m := map[string]SessionPR{}
	a.Store.GetBlob(blobSessionPRs, &m)
	req, ok := m[strconv.Itoa(pr)]
	if !ok {
		return fmt.Errorf("app: no session asked to merge PR #%d", pr)
	}
	if req.Untrusted != "" {
		return fmt.Errorf("app: PR #%d failed the trust check (%s); it will not be merged", pr, req.Untrusted)
	}
	scope, err := a.sessionScope(req.Session)
	if err != nil {
		return err
	}
	a.eng(a.policy())
	sha, err := a.guard.MergeWithScope(ctx, pr, req.HeadSHA, scope)
	if err != nil {
		a.Store.AddEvent(store.Event{Update: req.Session, Action: "merge-refused", By: by, PR: pr, Reason: scrub.String(err.Error())})
		_ = a.Store.Save()
		return err
	}
	_ = store.UpdateJSON(a.Store, blobSessionPRs, func(m *map[string]SessionPR) error {
		delete(*m, strconv.Itoa(pr))
		return nil
	})
	err = a.Store.MarkMerged(req.Session, sha, pr, by, fmt.Sprintf("session PR #%d merged by %s", pr, by))
	_ = a.Store.Save()
	return err
}
