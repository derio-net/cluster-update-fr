package app

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
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
	URL         string    `json:"url,omitempty"`
	// Files is what the operator reviews before clicking (c1d-r5): every
	// changed file at the verified head, sensitive ones flagged, and
	// Application source/destination/sync changes called out.
	Files []ReviewFile `json:"files,omitempty"`
}

// ReviewFile is one changed file of a session PR, as shown for review.
type ReviewFile struct {
	Name      string   `json:"name"`
	Sensitive bool     `json:"sensitive,omitempty"`
	Notes     []string `json:"notes,omitempty"`
}

// Key is the request's identity: (session, PR) — never the PR alone, so
// one session's request can never overwrite another's (sec2-4).
func (r SessionPR) Key() string { return r.Session + "#" + strconv.Itoa(r.PR) }

// ParseSessionPRKey splits a Key.
func ParseSessionPRKey(k string) (string, int, error) {
	i := strings.LastIndex(k, "#")
	if i <= 0 {
		return "", 0, fmt.Errorf("%w: bad session PR key", ErrBadRequest)
	}
	n, err := strconv.Atoi(k[i+1:])
	if err != nil || n <= 0 {
		return "", 0, fmt.Errorf("%w: bad session PR key", ErrBadRequest)
	}
	return k[:i], n, nil
}

// branchSession is the session a head branch belongs to ("" if none):
// cluster-update/session-<id>/<topic>.
func branchSession(head string) string {
	rest, ok := strings.CutPrefix(head, engine.SessionBranchPrefix)
	if !ok {
		return ""
	}
	id, _, ok := strings.Cut(rest, "/")
	if !ok {
		return ""
	}
	return id
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
	sort.Slice(out, func(i, j int) bool {
		if out[i].PR != out[j].PR {
			return out[i].PR < out[j].PR
		}
		return out[i].Session < out[j].Session
	})
	return out
}

// clearSessionPRs drops a session's pending requests when it ends (sec2-5):
// a request outlives nothing it was made for.
func (a *App) clearSessionPRs(id string) {
	var dropped []int
	_ = store.UpdateJSON(a.Store, blobSessionPRs, func(m *map[string]SessionPR) error {
		for k, r := range *m {
			if r.Session == id {
				dropped = append(dropped, r.PR)
				delete(*m, k)
			}
		}
		return nil
	})
	for _, n := range dropped {
		a.Store.AddEvent(store.Event{Update: id, Action: "session-merge-request-dropped", PR: n, Reason: "the session ended"})
	}
}

// mergeableStates: a session's PR may merge into an update that has merged
// nothing yet, or is mid-rollout / being repaired; never a terminal one.
func mergeable(s store.State) bool {
	switch s {
	case store.Pending, store.Approved, store.Held, store.Merged, store.Applied, store.Failed:
		return true
	}
	return false
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
	// A PR belongs to the session whose branch it is on: the head branch
	// cluster-update/session-<id>/… names exactly one session (sec2-3), and
	// the trust check below verifies it against THIS session's prefix. No
	// first-come claim exists, so no session can block another's PR.
	if owner := branchSession(p.HeadRef); owner != id {
		a.Store.AddEvent(store.Event{Update: id, Action: "session-merge-refused", By: "session", PR: pr,
			Reason: fmt.Sprintf("PR #%d is on another session's branch", pr)})
		_ = a.Store.Save()
		return fmt.Errorf("%w: PR #%d is not on this session's branch prefix %s%s/", ErrBadRequest, pr, engine.SessionBranchPrefix, id)
	}
	a.eng(a.policy())
	checkErr := a.trustConfig().Check(ctx, a.GitHub, p, scope)
	req := SessionPR{Session: id, PR: pr, HeadSHA: p.HeadSHA, Title: trust.Title(p.Title), Branch: trust.Title(p.HeadRef), RequestedAt: a.now(),
		URL: fmt.Sprintf("https://github.com/%s/pull/%d", a.Cfg.FrankRepo, pr)}
	if changed, err := a.GitHub.Compare(ctx, p.BaseRef, p.HeadSHA); err == nil {
		for _, c := range changed {
			req.Files = append(req.Files, ReviewFile{Name: trust.Title(c.Name), Sensitive: trust.IsSensitive(c.Name), Notes: trust.ReviewNotes(c.Patch)})
		}
	} else if checkErr == nil {
		checkErr = fmt.Errorf("its changes cannot be shown for review: %w", err)
	}
	if checkErr != nil {
		req.Untrusted = scrub.String(checkErr.Error())
	}
	_ = store.UpdateJSON(a.Store, blobSessionPRs, func(m *map[string]SessionPR) error {
		if *m == nil {
			*m = map[string]SessionPR{}
		}
		(*m)[req.Key()] = req
		return nil
	})
	reason := fmt.Sprintf("session asked the console to merge PR #%d", pr)
	if checkErr != nil {
		reason += " — untrusted: " + req.Untrusted
	}
	a.Store.AddEvent(store.Event{Update: id, Action: "session-merge-requested", By: "session", PR: pr, SHA: p.HeadSHA, Reason: reason})
	// Waiting for the operator is not idleness (c1d-r4): a trusted request
	// pauses the idle clock; the ceiling and max lifetime still bound it.
	a.Launcher.SetMergeWaiting(id, a.hasTrustedRequest(id))
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
func (a *App) MergeSessionPR(ctx context.Context, key, by string) error {
	if a.GitHub == nil || a.Launcher == nil {
		return ErrUnavailable
	}
	sess, pr, err := ParseSessionPRKey(key)
	if err != nil {
		return err
	}
	m := map[string]SessionPR{}
	a.Store.GetBlob(blobSessionPRs, &m)
	req, ok := m[key]
	if !ok || req.Session != sess || req.PR != pr {
		return fmt.Errorf("app: session %s has no pending request to merge PR #%d", sess, pr)
	}
	if req.Untrusted != "" {
		return fmt.Errorf("app: PR #%d failed the trust check (%s); it will not be merged", pr, req.Untrusted)
	}
	// The session must still be running and its update open (sec2-5/6):
	// a stored request is never acted on for a session that is gone, nor
	// merged into an update already verified, rolled back or abandoned.
	if _, running := a.Launcher.Get(sess); !running {
		a.clearSessionPRs(sess)
		return fmt.Errorf("app: session %s is no longer running; its request for PR #%d was dropped", sess, pr)
	}
	if u, ok := a.Store.Get(sess); !ok || !mergeable(u.State) {
		return fmt.Errorf("app: update %s is %s; a session PR cannot be merged into it", sess, u.State)
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
		delete(*m, key)
		return nil
	})
	err = a.Store.MarkMerged(req.Session, sha, pr, by, fmt.Sprintf("session PR #%d merged by %s", pr, by))
	a.Launcher.SetMergeWaiting(req.Session, a.hasTrustedRequest(req.Session))
	_ = a.Store.Save()
	return err
}

// hasTrustedRequest: the session has a trusted request waiting.
func (a *App) hasTrustedRequest(id string) bool {
	for _, r := range a.sessionPRs() {
		if r.Session == id && r.Untrusted == "" {
			return true
		}
	}
	return false
}
