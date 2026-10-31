// Package web serves the console's pages (R13): Needs action (Security,
// Suggested batch, Auto-merge countdowns, Guided upgrades, Rollouts waiting
// for a decision, Held — CI), Inventory and History, plus the buttons. It
// trusts the X-authentik-username header that Traefik's forward-auth sets
// and overwrites (the Service is ClusterIP-only behind it); every POST
// carries a CSRF token bound to that user; every rendered byte is scrubbed.
package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/app"
	"github.com/derio-net/cluster-update-fr/internal/engine"
	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
	"github.com/derio-net/cluster-update-fr/internal/session"
)

// Backend is what the pages need from the app.
type Backend interface {
	View() app.View
	Metrics() string
	Hold(id, by string) error
	Unhold(id, by string) error
	MergeNow(ctx context.Context, id, by string) error
	ApproveNow(ctx context.Context, id, by string) error
	ApproveBatch(ctx context.Context, ids []string, by string) (engine.BatchResult, error)
	RetryCI(ctx context.Context, id, by string) error
	Revert(ctx context.Context, id, by string) (string, error)
	StartSession(ctx context.Context, id, by string) (session.Record, bool, error)
	EndSession(ctx context.Context, id, by string) error
	AttachURL(id string) string
	StepEvent(id, token string, start bool, name string) error
	SessionFinished(ctx context.Context, id, token, outcome, transcript string) error
}

// Options configures the handler.
type Options struct {
	AuthHeader string
	Secret     []byte // CSRF key (random per process)
}

//go:embed templates/*.html
var templates embed.FS

var funcs = template.FuncMap{
	"when": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.UTC().Format("2006-01-02 15:04 UTC")
	},
	"join":      strings.Join,
	"sevclass":  func(s string) string { return "sev-" + strings.ToLower(s) },
	"pathlabel": func(p string) string { return strings.ReplaceAll(p, "-", " ") },
	"btn": func(action, id, csrf, label, class string) map[string]string {
		return map[string]string{"Action": action, "ID": id, "CSRF": csrf, "Label": label, "Class": class}
	},
	"item": func(it engine.Item, csrf string) map[string]any { return map[string]any{"Item": it, "CSRF": csrf} },
}

var pages = template.Must(template.New("").Funcs(funcs).ParseFS(templates, "templates/*.html"))

type server struct {
	b    Backend
	opts Options
}

// New returns the console's HTTP handler.
func New(b Backend, opts Options) http.Handler {
	if opts.AuthHeader == "" {
		opts.AuthHeader = "X-authentik-username"
	}
	s := &server{b: b, opts: opts}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = io.WriteString(w, scrub.String(b.Metrics()))
	})
	mux.HandleFunc("POST /api/sessions/{id}/step", s.apiStep)
	mux.HandleFunc("POST /api/sessions/{id}/finish", s.apiFinish)
	mux.Handle("GET /{$}", s.auth(s.page("needs-action")))
	mux.Handle("GET /inventory", s.auth(s.page("inventory")))
	mux.Handle("GET /history", s.auth(s.page("history")))
	mux.Handle("GET /attach/{id}", s.auth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, s.b.AttachURL(r.PathValue("id")), http.StatusSeeOther)
	})))
	mux.Handle("POST /act/{action}", s.auth(http.HandlerFunc(s.act)))
	mux.Handle("/act/", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}))
	return headers(mux)
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https:; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

var userRe = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,128}$`)

func (s *server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := r.Header.Get(s.opts.AuthHeader)
		if !userRe.MatchString(user) {
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, user)))
	})
}

func userOf(r *http.Request) string { u, _ := r.Context().Value(ctxKey{}).(string); return u }

func (s *server) csrf(user string) string {
	m := hmac.New(sha256.New, s.opts.Secret)
	m.Write([]byte("csrf:" + user))
	return hex.EncodeToString(m.Sum(nil))
}

// pageData is what every template gets.
type pageData struct {
	app.View
	Page, User, CSRF, Msg string
	Security              []engine.Item
	Countdowns            []engine.Item
	SessionItems          []engine.Item
	HeldCI                []engine.Item
	Other                 []engine.Item
}

func (s *server) page(name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user := userOf(r)
		d := pageData{View: s.b.View(), Page: name, User: user, CSRF: s.csrf(user), Msg: r.URL.Query().Get("msg")}
		for _, it := range d.Items {
			switch {
			case it.Security:
				d.Security = append(d.Security, it)
			case it.State == engine.StateHeldCI || it.State == engine.StateFailedCI:
				d.HeldCI = append(d.HeldCI, it)
			case it.Path == frankrepo.PathAutoMerge:
				d.Countdowns = append(d.Countdowns, it)
			case it.Path == frankrepo.PathSession || it.Path == frankrepo.PathOperatorRunbook || it.Path == frankrepo.PathUnclassified:
				d.SessionItems = append(d.SessionItems, it)
			case it.State != engine.StateBatch:
				d.Other = append(d.Other, it)
			}
		}
		var buf bytes.Buffer
		if err := pages.ExecuteTemplate(&buf, name+".html", d); err != nil {
			http.Error(w, "render failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, scrub.String(buf.String()))
	})
}

func back(w http.ResponseWriter, r *http.Request, msg string) {
	to := "/"
	if ref := r.FormValue("back"); strings.HasPrefix(ref, "/") && !strings.HasPrefix(ref, "//") {
		to = ref
	}
	http.Redirect(w, r, to+"?msg="+url.QueryEscape(scrub.String(msg)), http.StatusSeeOther)
}

func (s *server) act(w http.ResponseWriter, r *http.Request) {
	user := userOf(r)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if !hmac.Equal([]byte(r.PostFormValue("csrf")), []byte(s.csrf(user))) {
		http.Error(w, "stale or missing form token; reload the page", http.StatusForbidden)
		return
	}
	id := r.PostFormValue("id")
	ctx := r.Context()
	var err error
	msg := "done"
	switch r.PathValue("action") {
	case "hold":
		err, msg = s.b.Hold(id, user), "held "+id
	case "unhold":
		err, msg = s.b.Unhold(id, user), "released "+id
	case "merge-now":
		err, msg = s.b.MergeNow(ctx, id, user), "merged "+id
	case "approve-now":
		err, msg = s.b.ApproveNow(ctx, id, user), "approved "+id+" (merges as soon as CI passes)"
	case "approve-batch":
		var res engine.BatchResult
		res, err = s.b.ApproveBatch(ctx, r.PostForm["id"], user)
		msg = "batch PR opened with " + strings.Join(res.Included, ", ")
		if len(res.Skipped) > 0 {
			msg += "; left out (conflict): " + strings.Join(res.Skipped, ", ")
		}
	case "retry-ci":
		err, msg = s.b.RetryCI(ctx, id, user), "CI retry requested for "+id
	case "revert":
		var u string
		u, err = s.b.Revert(ctx, id, user)
		msg = "revert PR opened: " + u
	case "start-session":
		var rec session.Record
		var created bool
		rec, created, err = s.b.StartSession(ctx, id, user)
		if err == nil {
			_ = created // created or attached: the operator lands on the attach page either way
			http.Redirect(w, r, s.b.AttachURL(rec.ID), http.StatusSeeOther)
			return
		}
	case "end-session":
		err, msg = s.b.EndSession(ctx, id, user), "session "+id+" ended and cleaned up"
	default:
		http.Error(w, "unknown action", http.StatusNotFound)
		return
	}
	if err != nil {
		var le *session.LockedError
		if errors.As(err, &le) {
			back(w, r, "refused: "+le.Target+" is held by session "+le.Holder)
			return
		}
		back(w, r, "failed: "+err.Error())
		return
	}
	back(w, r, msg)
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if t, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(t)
	}
	return ""
}

func (s *server) apiStep(w http.ResponseWriter, r *http.Request) {
	var in struct {
		State string `json:"state"` // start | finish
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil || (in.State != "start" && in.State != "finish") {
		http.Error(w, "body must be {\"state\":\"start|finish\",\"name\":...}", http.StatusBadRequest)
		return
	}
	if err := s.b.StepEvent(r.PathValue("id"), bearer(r), in.State == "start", in.Name); err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) apiFinish(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Outcome    string `json:"outcome"`
		Transcript string `json:"transcript"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8<<20)).Decode(&in); err != nil || in.Outcome == "" {
		http.Error(w, "body must be {\"outcome\":...,\"transcript\":...}", http.StatusBadRequest)
		return
	}
	if err := s.b.SessionFinished(r.Context(), r.PathValue("id"), bearer(r), in.Outcome, in.Transcript); err != nil {
		apiError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func apiError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, session.ErrBadToken):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, session.ErrNoSession):
		http.Error(w, "no such session", http.StatusNotFound)
	default:
		http.Error(w, scrub.String(err.Error()), http.StatusInternalServerError)
	}
}
