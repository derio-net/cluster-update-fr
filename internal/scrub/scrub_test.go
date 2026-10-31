package scrub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The fixtures live in testdata/scrub/cases.json, shared with derio-net/frank's
// scripts/life_scrub.py. They are stored as segments and assembled here, so
// this PUBLIC repository never carries a literal token.

type segment struct {
	lit     string
	repeat  string
	times   int
	base64  string
	isLit   bool
	isB64   bool
	isRepet bool
}

func (s *segment) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		s.isLit = true
		return json.Unmarshal(b, &s.lit)
	}
	var m struct {
		Repeat *string `json:"repeat"`
		Times  int     `json:"times"`
		Base64 *string `json:"base64"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	switch {
	case m.Repeat != nil:
		s.isRepet, s.repeat, s.times = true, *m.Repeat, m.Times
	case m.Base64 != nil:
		s.isB64, s.base64 = true, *m.Base64
	}
	return nil
}

func (s segment) text() string {
	switch {
	case s.isLit:
		return s.lit
	case s.isRepet:
		return strings.Repeat(s.repeat, s.times)
	case s.isB64:
		return base64.StdEncoding.EncodeToString([]byte(s.base64))
	}
	return ""
}

func assemble(segs []segment) (string, []string) {
	var b strings.Builder
	var secrets []string
	for _, s := range segs {
		t := s.text()
		b.WriteString(t)
		if (s.isRepet || s.isB64) && len(t) >= 16 {
			secrets = append(secrets, t)
		}
	}
	return b.String(), secrets
}

type fixtureFile struct {
	Cases []struct {
		Name  string    `json:"name"`
		Kinds []string  `json:"kinds"`
		In    []segment `json:"in"`
	} `json:"cases"`
	Benign [][]segment `json:"benign"`
}

func load(t *testing.T) fixtureFile {
	t.Helper()
	b, err := os.ReadFile("../../testdata/scrub/cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixtureFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) < 20 || len(f.Benign) < 5 {
		t.Fatalf("fixture file looks truncated: %d cases, %d benign", len(f.Cases), len(f.Benign))
	}
	return f
}

func TestStringRedactsEveryCase(t *testing.T) {
	for _, c := range load(t).Cases {
		t.Run(c.Name, func(t *testing.T) {
			in, secrets := assemble(c.In)
			out := String(in)
			for _, k := range c.Kinds {
				if !strings.Contains(out, "«redacted:"+k+"»") {
					t.Errorf("String(%q) = %q, missing «redacted:%s»", in, out, k)
				}
			}
			for _, s := range secrets {
				if strings.Contains(out, s) {
					t.Errorf("secret material %q survived: %q", s, out)
				}
			}
			if got := Find(out); len(got) != 0 {
				t.Errorf("scrubbed output still has tokens %v: %q", got, out)
			}
			if again := String(out); again != out {
				t.Errorf("String is not idempotent: %q -> %q", out, again)
			}
			found := map[string]bool{}
			for _, k := range Find(in) {
				found[k] = true
			}
			for _, k := range c.Kinds {
				if !found[k] {
					t.Errorf("Find(%q) = %v, want %s", in, Find(in), k)
				}
			}
		})
	}
}

func TestBenignTextIsUntouched(t *testing.T) {
	for _, segs := range load(t).Benign {
		b, _ := assemble(segs)
		if got := String(b); got != b {
			t.Errorf("String(%q) changed benign text to %q", b, got)
		}
		if f := Find(b); len(f) != 0 {
			t.Errorf("Find(%q) = %v, want none", b, f)
		}
	}
}

func TestWriterScrubs(t *testing.T) {
	var buf bytes.Buffer
	w := Writer(&buf)
	tok := "gh" + "s_" + strings.Repeat("A1b2", 9)
	line := "calling github with " + tok + "\n"
	n, err := w.Write([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if n != len(line) {
		t.Errorf("Write must report the caller's byte count, got %d", n)
	}
	if strings.Contains(buf.String(), tok) {
		t.Fatalf("token reached the log: %q", buf.String())
	}
}
