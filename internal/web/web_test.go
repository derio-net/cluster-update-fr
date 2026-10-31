package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/app"
	"github.com/derio-net/cluster-update-fr/internal/cidiag"
	"github.com/derio-net/cluster-update-fr/internal/engine"
	"github.com/derio-net/cluster-update-fr/internal/forge"
	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/identity"
	"github.com/derio-net/cluster-update-fr/internal/inventory"
	"github.com/derio-net/cluster-update-fr/internal/live"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
	"github.com/derio-net/cluster-update-fr/internal/session"
	"github.com/derio-net/cluster-update-fr/internal/store"
	"github.com/derio-net/cluster-update-fr/internal/tracks"
)

type call struct{ action, id, by string }

type fakeBackend struct {
	view    app.View
	calls   []call
	started map[string]bool
	lockErr error
}

var leak = "gh" + "s_" + strings.Repeat("Lk34", 9)

func (f *fakeBackend) View() app.View             { return f.view }
func (f *fakeBackend) Metrics() string            { return "cluster_update_updates{state=\"pending\"} 1\n" }
func (f *fakeBackend) rec(a, id, by string)       { f.calls = append(f.calls, call{a, id, by}) }
func (f *fakeBackend) Hold(id, by string) error   { f.rec("hold", id, by); return nil }
func (f *fakeBackend) Unhold(id, by string) error { f.rec("unhold", id, by); return nil }
func (f *fakeBackend) MergeNow(_ context.Context, id, by string) error {
	f.rec("merge-now", id, by)
	return engine.ErrCINotPassed
}
func (f *fakeBackend) ApproveNow(_ context.Context, id, by string) error {
	f.rec("approve-now", id, by)
	return nil
}
func (f *fakeBackend) ApproveBatch(_ context.Context, ids []string, by string) (engine.BatchResult, error) {
	f.rec("approve-batch", strings.Join(ids, ","), by)
	return engine.BatchResult{PR: forge.PR{Number: 100}, Included: ids}, nil
}
func (f *fakeBackend) RetryCI(_ context.Context, id, by string) error {
	f.rec("retry-ci", id, by)
	return nil
}
func (f *fakeBackend) Revert(_ context.Context, id, by string) (string, error) {
	f.rec("revert", id, by)
	return "https://github.com/derio-net/frank/pull/12", nil
}
func (f *fakeBackend) StartSession(_ context.Context, id, by string) (session.Record, bool, error) {
	f.rec("start-session", id, by)
	if f.lockErr != nil {
		return session.Record{}, false, f.lockErr
	}
	created := !f.started[id]
	f.started[id] = true
	return session.Record{ID: id, Pod: session.PodName(id)}, created, nil
}
func (f *fakeBackend) EndSession(_ context.Context, id, by string) error {
	f.rec("end-session", id, by)
	return nil
}
func (f *fakeBackend) AttachURL(id string) string { return "https://sessions.cluster.derio.net/#" + id }
func (f *fakeBackend) StepEvent(id, token string, start bool, name string) error {
	if token != "good" {
		return session.ErrBadToken
	}
	f.rec("step", id, name)
	return nil
}
func (f *fakeBackend) SessionFinished(_ context.Context, id, token, outcome, transcript string) error {
	if token != "good" {
		return session.ErrBadToken
	}
	f.rec("finished", id, outcome)
	return nil
}

func view() app.View {
	sec := engine.Item{ID: "pr-2", PR: forge.PR{Number: 2, Title: "Update caddy " + leak}, Name: "caddy", From: "2.10.0", To: "2.10.1",
		Path: frankrepo.PathBatchApprove, Security: true, State: engine.StateBatch, CI: cidiag.Passed, Rollback: "One-click revert PR",
		Vulns: []live.Vuln{{ID: "CVE-1", Severity: "CRITICAL", Fixed: "2.10.1"}}}
	batch := engine.Item{ID: "pr-3", PR: forge.PR{Number: 3, Title: "Update a"}, Name: "a <b>", From: "1.0", To: "1.1",
		Path: frankrepo.PathBatchApprove, State: engine.StateBatch, CI: cidiag.Passed, Rollback: "revert"}
	count := engine.Item{ID: "pr-4", PR: forge.PR{Number: 4}, Name: "homepage", Path: frankrepo.PathAutoMerge, State: engine.StateCountdown,
		MergeAt: time.Date(2026, 11, 1, 10, 0, 0, 0, time.UTC), CI: cidiag.Passed, Rollback: "revert"}
	held := engine.Item{ID: "pr-5", PR: forge.PR{Number: 5}, Name: "x", Path: frankrepo.PathBatchApprove, State: engine.StateHeldCI, CI: cidiag.Missing, CIDetail: "no CI status", Rollback: "revert"}
	sess := engine.Item{ID: "pr-6", PR: forge.PR{Number: 6}, Name: "paperclip-db", Path: frankrepo.PathSession, State: engine.StateSession, Rollback: "Longhorn snapshot"}
	return app.View{
		Built:     time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC),
		Items:     []engine.Item{sec, batch, count, held, sess},
		Suggested: []engine.Item{batch},
		Rollouts:  []app.RolloutView{{Cluster: "frank", Rollout: live.Rollout{Namespace: "litellm", Name: "litellm", Phase: "Paused", Paused: true}, UpgradeID: "rollout-frank-litellm-litellm"}},
		Guided: []app.GuidedStep{{Step: tracks.Step{ID: "frank-os-talos-1.13.4", Cluster: "frank", Kind: "talos", From: "1.12.6", To: "1.13.4", Position: 1},
			Rollback: "Revert versions/frank.yaml through Omni"}, {Step: tracks.Step{ID: "frank-os-k8s-1.36.2", Cluster: "frank", Kind: "kubernetes", From: "1.35.3", To: "1.36.2", Position: 2, OneWay: true}, Rollback: "ONE-WAY"}},
		Omni: &inventory.Dependency{Name: "omni", Running: "v1.5.0", Latest: "v1.13.1", Path: frankrepo.PathOperatorRunbook},
		Inventory: &inventory.Inventory{Deps: []inventory.Dependency{
			{ID: "frank/os/talos/talos", Cluster: "frank", Service: "os", Kind: "talos", Name: "talos", Declared: "1.12.6", Running: "1.12.6", Latest: "1.14.5", Gap: "2 minor", Path: "session"},
			{ID: "hop/os/talos/talos", Cluster: "hop", Service: "os", Kind: "talos", Name: "talos", Declared: "1.12.5", Unknown: true, Path: "session"},
		}},
		Updates: []store.Update{{ID: "pr-1", Title: "Update grafana", State: store.Verified, Approver: "auto", PR: 1, Rollout: "operationState applied abc", Verification: "2/2 smoke checks passed"}},
		History: []store.Event{{At: time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC), Update: "pr-1", Action: "merged", By: "auto", PR: 1, Reason: "with " + leak}},
		Errors:  []string{"hop nodes: unreachable"},
	}
}

// fakeAuth stands in for identity.JWT (verified in its own package):
// X-authentik-jwt "valid:<user>" is a verified operator, "nogroup:<user>"
// a verified user outside the operator group, anything else unverified.
type fakeAuth struct{}

func (fakeAuth) Authenticate(r *http.Request) (identity.Identity, error) {
	tok := r.Header.Get(identity.HeaderJWT)
	switch {
	case strings.HasPrefix(tok, "valid:"):
		u := strings.TrimPrefix(tok, "valid:")
		if plain := r.Header.Get(identity.HeaderUser); plain != "" && plain != u {
			return identity.Identity{}, identity.ErrUnauthenticated
		}
		return identity.Identity{User: u, Groups: []string{"ops"}}, nil
	case strings.HasPrefix(tok, "nogroup:"):
		return identity.Identity{}, identity.ErrForbidden
	}
	return identity.Identity{}, identity.ErrUnauthenticated
}

func newServer(t *testing.T) (*fakeBackend, http.Handler) {
	b, h := newHandlers(t)
	return b, h.UI
}

func newHandlers(t *testing.T) (*fakeBackend, Handlers) {
	t.Helper()
	b := &fakeBackend{view: view(), started: map[string]bool{}}
	return b, New(b, Options{Auth: fakeAuth{}, Secret: []byte("test-secret-0123456789")})
}

var jar = map[string]*http.Cookie{}

func get(h http.Handler, path, user string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if user != "" {
		r.Header.Set(identity.HeaderJWT, "valid:"+user)
	}
	if c, ok := jar[user]; ok {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func post(h http.Handler, path, user string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if user != "" {
		r.Header.Set(identity.HeaderJWT, "valid:"+user)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.Name == "cuf_flash" {
			jar[user] = c
		}
	}
	return w
}

// flash follows a redirect and returns the page's status message.
func flash(h http.Handler, user string) string {
	body := get(h, "/", user).Body.String()
	i := strings.Index(body, `<p class="msg">`)
	if i < 0 {
		return ""
	}
	rest := body[i+len(`<p class="msg">`):]
	return rest[:strings.Index(rest, "</p>")]
}

func TestEveryPageNeedsAVerifiedIdentity(t *testing.T) {
	_, hs := newHandlers(t)
	h := hs.UI
	for _, p := range []string{"/", "/inventory", "/history"} {
		if w := get(h, p, ""); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without identity = %d", p, w.Code)
		}
	}
	// The plain username header alone is never enough.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(identity.HeaderUser, "derio")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("bare username header = %d", w.Code)
	}
	// A verified token whose plain header disagrees.
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(identity.HeaderJWT, "valid:derio")
	r.Header.Set(identity.HeaderUser, "admin")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("header mismatch = %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set(identity.HeaderJWT, "nogroup:derio")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("wrong group = %d", w.Code)
	}
	if w := get(h, "/", "<script>alert(1)</script>"); w.Code != http.StatusUnauthorized {
		t.Errorf("a malformed username must be refused, got %d", w.Code)
	}
	refusing := New(&fakeBackend{view: view()}, Options{Secret: []byte("x")})
	if w := get(refusing.UI, "/", "derio"); w.Code != http.StatusServiceUnavailable {
		t.Errorf("no verifier configured must fail closed, got %d", w.Code)
	}
}

func TestListenersAreSeparate(t *testing.T) {
	_, hs := newHandlers(t)
	if w := get(hs.Ops, "/healthz", ""); w.Code != 200 {
		t.Errorf("ops healthz = %d", w.Code)
	}
	if w := get(hs.Ops, "/metrics", ""); w.Code != 200 || !strings.Contains(w.Body.String(), "cluster_update_updates") {
		t.Errorf("ops metrics = %d", w.Code)
	}
	for _, path := range []string{"/", "/inventory", "/act/hold", "/api/sessions/x/step"} {
		if w := post(hs.Ops, path, "derio", url.Values{"id": {"pr-4"}}); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("ops port served %s: %d", path, w.Code)
		}
		if w := get(hs.Ops, path, "derio"); w.Code == 200 {
			t.Errorf("ops port served GET %s", path)
		}
	}
	for _, path := range []string{"/", "/metrics", "/act/hold"} {
		if w := post(hs.Session, path, "derio", url.Values{"id": {"pr-4"}}); w.Code != http.StatusNotFound && w.Code != http.StatusMethodNotAllowed {
			t.Errorf("session port served %s: %d", path, w.Code)
		}
	}
	if w := get(hs.UI, "/metrics", "derio"); w.Code == 200 {
		t.Error("the UI port must not serve metrics")
	}
}

func TestMessagesCannotBeInjectedThroughTheURL(t *testing.T) {
	_, h := newServer(t)
	body := get(h, "/?msg=Your+session+expired,+log+in+at+evil.example&m=merged", "derio").Body.String()
	if strings.Contains(body, "evil.example") || strings.Contains(body, `class="msg"`) {
		t.Error("URL text was rendered as a console message")
	}
	// A flash cookie signed for another user is ignored.
	b, hs := newHandlers(t)
	_ = b
	tok := csrfFor(t, hs.UI, "mallory")
	post(hs.UI, "/act/hold", "mallory", url.Values{"id": {"pr-4"}, "csrf": {tok}})
	jar["derio"] = jar["mallory"]
	if m := flash(hs.UI, "derio"); m != "" {
		t.Errorf("another user's flash was shown: %q", m)
	}
	delete(jar, "derio")
}

func TestNeedsActionPage(t *testing.T) {
	_, h := newServer(t)
	w := get(h, "/", "derio")
	body := w.Body.String()
	if w.Code != 200 {
		t.Fatalf("code %d", w.Code)
	}
	order := []string{"Security", "Suggested batch", "Auto-merge countdowns", "Guided upgrades", "Rollouts waiting", "Held — CI"}
	last := -1
	for _, s := range order {
		i := strings.Index(body, s)
		if i < 0 || i < last {
			t.Fatalf("section %q missing or out of order", s)
		}
		last = i
	}
	for _, want := range []string{"Approve now", "Approve batch", "Hold", "Merge now", "Start session", "Retry CI", "no CI status",
		"ONE-WAY", "operator runbook", "v1.13.1", "Longhorn snapshot", "a &lt;b&gt;", "2026-11-01 10:00"} {
		if !strings.Contains(body, want) {
			t.Errorf("Needs action missing %q", want)
		}
	}
	// Each item shows its rollback BEFORE its approve button.
	sec := body[strings.Index(body, "Update caddy"):]
	if strings.Index(sec, "Rollback") > strings.Index(sec, "Approve now") {
		t.Error("rollback must be shown before the approve button")
	}
	if len(scrub.Find(body)) != 0 || strings.Contains(body, leak) {
		t.Errorf("token rendered: %v", scrub.Find(body))
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("CSP header")
	}
}

func TestInventoryAndHistoryPages(t *testing.T) {
	_, h := newServer(t)
	inv := get(h, "/inventory", "derio").Body.String()
	for _, want := range []string{"frank", "hop", "talos", "1.12.6", "1.14.5", "2 minor", "unknown"} {
		if !strings.Contains(inv, want) {
			t.Errorf("inventory missing %q", want)
		}
	}
	hist := get(h, "/history", "derio").Body.String()
	for _, want := range []string{"Update grafana", "verified", "auto", "operationState applied", "2/2 smoke checks passed", "Revert"} {
		if !strings.Contains(hist, want) {
			t.Errorf("history missing %q", want)
		}
	}
	if strings.Contains(hist, leak) {
		t.Error("history rendered a token")
	}
}

func csrfFor(t *testing.T, h http.Handler, user string) string {
	t.Helper()
	body := get(h, "/", user).Body.String()
	i := strings.Index(body, `name="csrf" value="`)
	if i < 0 {
		t.Fatal("no csrf field")
	}
	rest := body[i+len(`name="csrf" value="`):]
	return rest[:strings.Index(rest, `"`)]
}

func TestActionsUseTheAuthenticatedUserAndCSRF(t *testing.T) {
	b, h := newServer(t)
	tok := csrfFor(t, h, "derio")
	if w := post(h, "/act/hold", "derio", url.Values{"id": {"pr-4"}}); w.Code != http.StatusForbidden {
		t.Errorf("POST without csrf = %d", w.Code)
	}
	if w := post(h, "/act/hold", "mallory", url.Values{"id": {"pr-4"}, "csrf": {tok}}); w.Code != http.StatusForbidden {
		t.Errorf("csrf of another user = %d", w.Code)
	}
	cases := []struct {
		path string
		form url.Values
		want call
	}{
		{"/act/hold", url.Values{"id": {"pr-4"}}, call{"hold", "pr-4", "derio"}},
		{"/act/unhold", url.Values{"id": {"pr-4"}}, call{"unhold", "pr-4", "derio"}},
		{"/act/approve-now", url.Values{"id": {"pr-2"}}, call{"approve-now", "pr-2", "derio"}},
		{"/act/approve-batch", url.Values{"id": {"pr-3", "pr-9"}}, call{"approve-batch", "pr-3,pr-9", "derio"}},
		{"/act/retry-ci", url.Values{"id": {"pr-5"}}, call{"retry-ci", "pr-5", "derio"}},
		{"/act/revert", url.Values{"id": {"pr-1"}}, call{"revert", "pr-1", "derio"}},
		{"/act/end-session", url.Values{"id": {"pr-6"}}, call{"end-session", "pr-6", "derio"}},
	}
	for _, c := range cases {
		c.form.Set("csrf", tok)
		w := post(h, c.path, "derio", c.form)
		if w.Code != http.StatusSeeOther {
			t.Errorf("%s = %d", c.path, w.Code)
		}
		got := b.calls[len(b.calls)-1]
		if got != c.want {
			t.Errorf("%s called %+v, want %+v", c.path, got, c.want)
		}
	}
	// An action error is shown, not swallowed.
	post(h, "/act/merge-now", "derio", url.Values{"id": {"pr-4"}, "csrf": {tok}})
	if m := flash(h, "derio"); !strings.Contains(m, "CI has not passed") {
		t.Errorf("error not surfaced: %q", m)
	}
	if w := get(h, "/act/hold?id=pr-4", "derio"); w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET on an action = %d", w.Code)
	}
}

func TestStartSessionTwiceAttaches(t *testing.T) {
	b, h := newServer(t)
	tok := csrfFor(t, h, "derio")
	form := url.Values{"id": {"frank-os-talos-1.13.4"}, "csrf": {tok}}
	w1 := post(h, "/act/start-session", "derio", form)
	w2 := post(h, "/act/start-session", "derio", form)
	if w1.Code != http.StatusSeeOther || w2.Code != http.StatusSeeOther {
		t.Fatal(w1.Code, w2.Code)
	}
	for _, w := range []*httptest.ResponseRecorder{w1, w2} {
		if !strings.HasPrefix(w.Header().Get("Location"), "https://sessions.cluster.derio.net/#frank-os-talos-1.13.4") {
			t.Errorf("start must land on the attach page: %q", w.Header().Get("Location"))
		}
	}
	b.lockErr = &session.LockedError{Target: "os:frank", Holder: "frank-os-talos-1.13.4"}
	post(h, "/act/start-session", "derio", url.Values{"id": {"frank-os-k8s-1.36.2"}, "csrf": {tok}})
	if m := flash(h, "derio"); !strings.Contains(m, "frank-os-talos-1.13.4") {
		t.Errorf("lock conflict must name the holder: %q", m)
	}
}

func TestSessionAPIUsesTheStepToken(t *testing.T) {
	b, hs := newHandlers(t)
	h := hs.Session
	req := func(path, token, body string) int {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if c := req("/api/sessions/pr-6/step", "bad", `{"state":"start","name":"snapshot"}`); c != http.StatusForbidden {
		t.Errorf("bad token = %d", c)
	}
	if c := req("/api/sessions/pr-6/step", "good", `{"state":"start","name":"snapshot"}`); c != http.StatusNoContent {
		t.Errorf("step = %d", c)
	}
	if c := req("/api/sessions/pr-6/finish", "good", `{"outcome":"verified","transcript":"…"}`); c != http.StatusNoContent {
		t.Errorf("finish = %d", c)
	}
	if b.calls[len(b.calls)-1] != (call{"finished", "pr-6", "verified"}) {
		t.Errorf("calls = %+v", b.calls)
	}
	if c := req("/api/sessions/pr-6/step", "good", `not json`); c != http.StatusBadRequest {
		t.Errorf("bad body = %d", c)
	}
	_ = errors.New
}
