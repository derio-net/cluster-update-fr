// Package web serves the console's pages (R13): Needs action (Security,
// Suggested batch, Auto-merge countdowns, Guided upgrades, Rollouts waiting
// for a decision, Held — CI, untrusted PRs), Inventory and History, plus the
// buttons.
//
// Three separate handlers, served on separate listeners:
//
//	UI       pages and actions; every request needs a VERIFIED identity
//	         (internal/identity) in the operator group; client identity
//	         headers are stripped after verification
//	Ops      /healthz and /metrics only — no pages, no actions
//	Session  the session step/finish API only, authenticated by each
//	         session's step token; identity headers are never honoured
//
// Every POST carries a CSRF token bound to the verified user; status
// messages travel in a signed, user-bound flash cookie (never in the URL);
// every rendered byte is scrubbed.
package web

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/app"
	"github.com/derio-net/cluster-update-fr/internal/engine"
	"github.com/derio-net/cluster-update-fr/internal/frankrepo"
	"github.com/derio-net/cluster-update-fr/internal/identity"
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
	// Attach records operator activity on a running session and returns its
	// runs-fr URL. It mutates state, so it is only reached by a CSRF-checked
	// POST (c1s-r8).
	Attach(id, by string) (string, error)
	StepEvent(id, token string, start bool, name string) error
	SessionFinished(ctx context.Context, id, token, outcome, transcript string) error
}

// Options configures the handlers.
type Options struct {
	Auth   identity.Authenticator // nil = refuse everything
	Secret []byte                 // CSRF / flash key (random per process)
	// TranscriptMax is the session transcript cap in bytes (0 = 1 MiB).
	TranscriptMax int
}

func (o Options) transcriptMax() int {
	if o.TranscriptMax <= 0 {
		return 1 << 20
	}
	return o.TranscriptMax
}

// Handlers are the three listeners' handlers.
type Handlers struct {
	UI, Ops, Session http.Handler
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

// New returns the console's handlers.
func New(b Backend, opts Options) Handlers {
	if opts.Auth == nil {
		opts.Auth = identity.Refuse{}
	}
	s := &server{b: b, opts: opts}

	ops := http.NewServeMux()
	ops.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	ops.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = io.WriteString(w, scrub.String(b.Metrics()))
	})

	sess := http.NewServeMux()
	sess.HandleFunc("POST /api/sessions/{id}/step", s.apiStep)
	sess.HandleFunc("POST /api/sessions/{id}/finish", s.apiFinish)

	ui := http.NewServeMux()
	ui.Handle("GET /{$}", s.page("needs-action"))
	ui.Handle("GET /inventory", s.page("inventory"))
	ui.Handle("GET /history", s.page("history"))
	ui.HandleFunc("POST /act/{action}", s.act)
	ui.HandleFunc("/act/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	return Handlers{UI: headers(s.auth(ui)), Ops: headers(ops), Session: headers(stripIdentity(sess))}
}

func stripIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range identity.IdentityHeaders {
			r.Header.Del(h)
		}
		next.ServeHTTP(w, r)
	})
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

type ctxKey struct{}

var userRe = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,128}$`)

func (s *server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := s.opts.Auth.Authenticate(r)
		switch {
		case errors.Is(err, identity.ErrNotConfigured):
			http.Error(w, "identity verification is not configured", http.StatusServiceUnavailable)
			return
		case errors.Is(err, identity.ErrForbidden):
			http.Error(w, "not in the operator group", http.StatusForbidden)
			return
		case err != nil || !userRe.MatchString(id.User):
			http.Error(w, "not authenticated", http.StatusUnauthorized)
			return
		}
		for _, h := range identity.IdentityHeaders {
			r.Header.Del(h)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id.User)))
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
		d := pageData{View: s.b.View(), Page: name, User: user, CSRF: s.csrf(user), Msg: s.readFlash(w, r, user)}
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

const flashCookie = "cuf_flash"

func (s *server) flashMAC(user, msg string) string {
	m := hmac.New(sha256.New, s.opts.Secret)
	m.Write([]byte("flash:" + user + ":" + msg))
	return hex.EncodeToString(m.Sum(nil))
}

// back redirects to the page the form came from, carrying msg in a short
// signed cookie bound to the user — never in the URL, so no link can make
// the console display text of someone else's choosing.
func (s *server) back(w http.ResponseWriter, r *http.Request, msg string) {
	msg = scrub.String(msg)
	if len(msg) > 400 {
		msg = msg[:400]
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: base64.RawURLEncoding.EncodeToString([]byte(msg)) + "." + s.flashMAC(userOf(r), msg),
		Path: "/", MaxAge: 60, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	to := "/"
	if ref := r.FormValue("back"); ref == "/inventory" || ref == "/history" {
		to = ref
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func (s *server) readFlash(w http.ResponseWriter, r *http.Request, user string) string {
	c, err := r.Cookie(flashCookie)
	if err != nil {
		return ""
	}
	http.SetCookie(w, &http.Cookie{Name: flashCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	val, mac, ok := strings.Cut(c.Value, ".")
	if !ok {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(val)
	if err != nil || !hmac.Equal([]byte(mac), []byte(s.flashMAC(user, string(b)))) {
		return ""
	}
	return string(b)
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
			m := "Session " + rec.ID + " is running."
			if created {
				m = "Session " + rec.ID + " started."
			}
			s.attachPage(w, r, rec.ID, user, m)
			return
		}
	case "attach":
		s.attachPage(w, r, id, user, "Attaching to session "+id+".")
		return
	case "end-session":
		err, msg = s.b.EndSession(ctx, id, user), "session "+id+" ended and cleaned up"
	default:
		http.Error(w, "unknown action", http.StatusNotFound)
		return
	}
	if err != nil {
		var le *session.LockedError
		if errors.As(err, &le) {
			s.back(w, r, "refused: "+le.Target+" is held by session "+le.Holder)
			return
		}
		s.back(w, r, "failed: "+err.Error())
		return
	}
	s.back(w, r, msg)
}

// attachPage answers a POST with a same-origin page that sends the browser
// on to runs-fr (meta refresh + link) — never a redirect of the form
// submission to another origin, which CSP form-action 'self' forbids.
func (s *server) attachPage(w http.ResponseWriter, r *http.Request, id, user, msg string) {
	u, err := s.b.Attach(id, user)
	if err != nil {
		s.back(w, r, "failed: "+err.Error())
		return
	}
	var buf bytes.Buffer
	if err := pages.ExecuteTemplate(&buf, "attach.html", map[string]string{"URL": u, "ID": id, "Msg": msg}); err != nil {
		http.Error(w, "render failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, scrub.String(buf.String()))
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
	// The body is capped before it is decoded: JSON escaping can at most
	// ~6x a transcript, but a sane client sends near 1x; allow 2x + slack
	// and let the backend enforce the exact transcript cap (c1s-r11).
	limit := int64(2*s.opts.transcriptMax() + 16<<10)
	err := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit)).Decode(&in)
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		http.Error(w, "transcript too large", http.StatusRequestEntityTooLarge)
		return
	case err != nil || in.Outcome == "":
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
	case errors.Is(err, session.ErrTranscriptTooLarge), errors.Is(err, session.ErrFieldTooLarge):
		http.Error(w, scrub.String(err.Error()), http.StatusRequestEntityTooLarge)
	default:
		http.Error(w, scrub.String(err.Error()), http.StatusInternalServerError)
	}
}
