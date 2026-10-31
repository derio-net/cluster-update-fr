// Package forge holds the console's only write paths outside the session
// namespace: GitHub (merge, statuses, PR/issue bodies, revert, batch branch,
// webhook redelivery) and Gitea (read runs/statuses, re-run when the server
// offers it). R14: these are forge actions, never cluster writes.
package forge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/derio-net/cluster-update-fr/internal/scrub"
)

// ErrNoCredential is returned, without a request, for a write when no token
// is configured; the UI shows the action as unavailable.
var ErrNoCredential = errors.New("forge: no credential configured")

// ErrNotFound means the forge answered 404 or a lookup found nothing.
var ErrNotFound = errors.New("forge: not found")

// ErrUnsupported means the server does not offer the operation.
var ErrUnsupported = errors.New("forge: operation not supported by this server")

// Error is a non-2xx forge answer; the message is scrubbed.
type Error struct {
	Status  int
	Method  string
	Path    string
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("forge: %s %s: %d %s", e.Method, e.Path, e.Status, e.Message)
}

// Is lets errors.Is(err, ErrNotFound) match a 404.
func (e *Error) Is(target error) bool {
	return target == ErrNotFound && e.Status == http.StatusNotFound
}

// IsConflict reports a 409.
func IsConflict(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusConflict
}

type client struct {
	base   string
	auth   func() string
	http   *http.Client
	scheme string // "Bearer" (GitHub) or "token" (Gitea)
}

func (c client) tok() string {
	if c.auth == nil {
		return ""
	}
	return c.auth()
}

func (c client) do(ctx context.Context, method, path string, in, out any, write bool) error {
	t := c.tok()
	if write && t == "" {
		return ErrNoCredential
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "cluster-update-fr")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if t != "" {
		req.Header.Set("Authorization", c.scheme+" "+t)
	}
	hc := c.http
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("forge: %s %s: %s", method, path, scrub.String(err.Error()))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		var m struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(b, &m)
		if m.Message == "" {
			m.Message = strings.TrimSpace(string(b))
		}
		p := path
		if i := strings.Index(p, "?"); i >= 0 {
			p = p[:i]
		}
		return &Error{Status: resp.StatusCode, Method: method, Path: p, Message: scrub.String(m.Message)}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
