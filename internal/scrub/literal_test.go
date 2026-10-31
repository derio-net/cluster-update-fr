package scrub

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type literalCase struct {
	Name   string            `json:"name"`
	Kind   string            `json:"kind"`
	Secret []segment         `json:"secret"`
	In     []json.RawMessage `json:"in"`
}

// render assembles a literal case's input, resolving {"ref": F} segments
// against the secret.
func (c literalCase) render(t *testing.T, secret string) string {
	t.Helper()
	lines := strings.Split(secret, "\n")
	var b strings.Builder
	for _, raw := range c.In {
		var ref struct {
			Ref string `json:"ref"`
		}
		if json.Unmarshal(raw, &ref) == nil && ref.Ref != "" {
			b.WriteString(resolveRef(t, ref.Ref, secret, lines))
			continue
		}
		var s segment
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		b.WriteString(s.text())
	}
	return b.String()
}

func resolveRef(t *testing.T, ref, secret string, lines []string) string {
	t.Helper()
	line := func(spec string) string {
		n, err := strconv.Atoi(spec)
		if err != nil || n < 1 || n > len(lines) {
			t.Fatalf("bad line ref %q", ref)
		}
		return lines[n-1]
	}
	switch {
	case ref == "raw":
		return secret
	case ref == "base64":
		return base64.StdEncoding.EncodeToString([]byte(secret))
	case ref == "rawbase64url":
		return base64.RawURLEncoding.EncodeToString([]byte(secret))
	case ref == "query":
		return url.QueryEscape(secret)
	case strings.HasPrefix(ref, "line-base64:"):
		return base64.StdEncoding.EncodeToString([]byte(line(strings.TrimPrefix(ref, "line-base64:"))))
	case strings.HasPrefix(ref, "line:"):
		return line(strings.TrimPrefix(ref, "line:"))
	}
	t.Fatalf("unknown ref %q", ref)
	return ""
}

func TestLiteralSetRedactsShapesNoPatternMatches(t *testing.T) {
	b, err := os.ReadFile("../../testdata/scrub/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Literal []literalCase `json:"literal"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Literal) < 5 {
		t.Fatalf("literal fixtures missing: %d", len(f.Literal))
	}
	for _, c := range f.Literal {
		t.Run(c.Name, func(t *testing.T) {
			secret, _ := assemble(c.Secret)
			in := c.render(t, secret)
			// Precondition: the pattern layer alone leaves this input
			// untouched, so the case really exercises the literal layer.
			if got := NewSet(nil).String(in); got != in {
				t.Fatalf("fixture is caught by patterns (%q); pick a shape no pattern matches", got)
			}
			set := NewSet(nil)
			set.Add(c.Kind, secret)
			out := set.String(in)
			if !strings.Contains(out, "«redacted:"+c.Kind+"»") {
				t.Errorf("String(%q) = %q, want «redacted:%s»", in, out, c.Kind)
			}
			for _, form := range forms(secret) {
				if len(form) >= minLiteral && strings.Contains(out, form) {
					t.Errorf("form %q survived: %q", form, out)
				}
			}
			for _, l := range strings.Split(secret, "\n") {
				l = strings.TrimSpace(l)
				if len(l) >= minLiteral && strings.Contains(out, l) {
					t.Errorf("line %q survived: %q", l, out)
				}
			}
			found := false
			for _, k := range set.Find(in) {
				found = found || k == c.Kind
			}
			if !found {
				t.Errorf("Find missed %s", c.Kind)
			}
		})
	}
}

func TestSessionSetInheritsTheProcessSet(t *testing.T) {
	console := "console-" + strings.Repeat("Zq8", 5)
	session := "session-" + strings.Repeat("Wr4", 5)
	Register("github-token", console)
	s := NewSet(global)
	s.Add("omni-sa-key", session)
	out := s.String("c=" + console + " s=" + session)
	if strings.Contains(out, console) || strings.Contains(out, session) {
		t.Fatalf("leak: %q", out)
	}
	// Package-level String knows the console's own credentials …
	if strings.Contains(String("x "+console), console) {
		t.Error("package String must apply registered credentials")
	}
	// … but not a session's: those stay scoped to the session set.
	if !strings.Contains(String("x "+session), session) {
		t.Error("a session secret must not leak into the process-wide set")
	}
}

func TestShortValuesAreNotRegistered(t *testing.T) {
	s := NewSet(nil)
	s.Add("x", "abc")
	if got := s.String("abc abcabc"); got != "abc abcabc" {
		t.Errorf("a short value must not redact ordinary text: %q", got)
	}
}

func TestSetIsSafeForConcurrentUse(t *testing.T) {
	s := NewSet(nil)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			s.Add("k", fmt.Sprintf("value-%02d-%s", i, strings.Repeat("y", 8)))
		}(i)
		go func() {
			defer wg.Done()
			_ = s.String("value-01-yyyyyyyy")
		}()
	}
	wg.Wait()
	if strings.Contains(s.String("value-07-yyyyyyyy"), "value-07") {
		t.Error("registered value not redacted")
	}
}
