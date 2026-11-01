package scrub

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRepositoryHoldsNoTokens is R25's CI guard for this public repo: no
// tracked text file — code, fixtures, docs, workflows — may carry a
// token-shaped string.
func TestRepositoryHoldsNoTokens(t *testing.T) {
	root, err := moduleRoot()
	if err != nil {
		t.Fatal(err)
	}
	skipDirs := map[string]bool{".git": true, "bin": true, "node_modules": true}
	checked := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Name() == ".fr-isolation" {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if isBinary(b) {
			return nil
		}
		checked++
		found := Find(string(b))
		if strings.HasSuffix(path, ".go") {
			found = findInGoSource(string(b))
		}
		if rel, _ := filepath.Rel(root, path); rel == filepath.Join("testdata", "scrub", "cases.json") {
			// The shared fixture (byte-for-byte with frank) deliberately holds
			// a fake END-less PGP key header inside an Omni SA key's JSON; the
			// scrubber fails closed on it (scrub-limit), as it must. Only that
			// kind is excused, only in this file — a real token shape still fails.
			found = without(found, limitKind)
		}
		if rel, _ := filepath.Rel(root, path); filepath.Dir(rel) == filepath.Join("testdata", "podspec") {
			// Golden pod specs (generated from podSpec, copied by frank): their
			// Secret volume items name each credential file in a key field, which
			// the key/value pattern takes for a value. They carry key NAMES only
			// (internal/session renders them with empty data); every other kind
			// still fails.
			found = without(found, "yaml-secret")
		}
		if len(found) != 0 {
			rel, _ := filepath.Rel(root, path)
			t.Errorf("%s contains token-shaped strings: %v", rel, found)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked < 5 {
		t.Fatalf("walked only %d files from %s — wrong root?", checked, root)
	}
}

func moduleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}

func without(kinds []string, drop string) []string {
	var out []string
	for _, k := range kinds {
		if k != drop {
			out = append(out, k)
		}
	}
	return out
}

func isBinary(b []byte) bool {
	n := len(b)
	if n > 8000 {
		n = 8000
	}
	return strings.ContainsRune(string(b[:n]), 0)
}

// findInGoSource is Find without the unquoted key/value variant, which reads
// Go expressions as values; quoted literals and every token format still
// count.
func findInGoSource(text string) []string {
	var kinds []string
	seen := map[string]bool{}
	applyPatterns(global.literals(text, func(string) {}), func(k string) {
		if !seen[k] {
			seen[k] = true
			kinds = append(kinds, k)
		}
	}, true)
	return kinds
}
