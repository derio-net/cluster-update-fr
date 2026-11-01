package renovate

import "testing"

func TestDiffUpdateType(t *testing.T) {
	d64 := func(c string) string {
		s := "sha256:"
		for i := 0; i < 64; i++ {
			s += c
		}
		return s
	}
	cases := []struct {
		name    string
		patches []string
		want    string
	}{
		{"patch", []string{"@@ -1 +1 @@\n-  tag: v1.4.0\n+  tag: v1.4.1"}, "patch"},
		{"minor", []string{"-  targetRevision: 8.5.2\n+  targetRevision: 8.6.0"}, "minor"},
		{"major", []string{"-image: ghcr.io/x/y:1.9.3\n+image: ghcr.io/x/y:2.0.0"}, "major"},
		{"downgrade is major", []string{"-  tag: 1.4.1\n+  tag: 1.4.0"}, "major"},
		{"digest", []string{"-  image: x@" + d64("a") + "\n+  image: x@" + d64("b")}, "digest"},
		{"most severe wins", []string{"-  a: 1.0.0\n+  a: 1.0.1", "-  b: 3.1.0\n+  b: 4.0.0"}, "major"},
		{"no version change", []string{"-  replicas: 2\n+  replicas: 3"}, ""},
		{"unpaired", []string{"-  a: 1.0.0\n+  a: 1.0.1\n+  b: 2.0.0"}, ""},
		{"no patch", []string{""}, ""},
	}
	for _, c := range cases {
		if got, why := DiffUpdateType(c.patches); got != c.want {
			t.Errorf("%s: got %q (%s), want %q", c.name, got, why, c.want)
		}
	}
}
