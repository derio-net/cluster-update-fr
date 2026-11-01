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
		// the known shapes
		{"tag patch", []string{"@@ -1 +1 @@\n-  tag: v1.4.0\n+  tag: v1.4.1"}, "patch"},
		{"targetRevision minor", []string{"-    targetRevision: 8.5.2\n+    targetRevision: 8.6.0"}, "minor"},
		{"quoted targetRevision", []string{"-    targetRevision: \"8.5.2\"\n+    targetRevision: \"8.5.3\""}, "patch"},
		{"image tag major", []string{"-image: ghcr.io/x/y:1.9.3\n+image: ghcr.io/x/y:2.0.0"}, "major"},
		{"list image patch", []string{"-  - image: ghcr.io/x/y:1.9.3\n+  - image: ghcr.io/x/y:1.9.4"}, "patch"},
		{"image digest", []string{"-  image: ghcr.io/x/y:1.0.0@" + d64("a") + "\n+  image: ghcr.io/x/y:1.0.0@" + d64("b")}, "digest"},
		{"talos", []string{"-talos: 1.12.6\n+talos: 1.13.4"}, "minor"},
		{"omni env", []string{"-OMNI_VERSION=v1.5.0\n+OMNI_VERSION=v1.5.1"}, "patch"},
		{"downgrade is major", []string{"-  tag: 1.4.1\n+  tag: 1.4.0"}, "major"},
		{"integer tag is major", []string{"-  image: redis:2\n+  image: redis:3"}, "major"},
		{"integer targetRevision is major", []string{"-    targetRevision: 3\n+    targetRevision: 4"}, "major"},
		{"pre-release suffix is major", []string{"-  tag: 1.2.3\n+  tag: 1.2.4-rc1"}, "major"},
		{"the highest change wins", []string{"-  tag: 1.0.0\n+  tag: 1.0.1", "-  version: 3.1.0\n+  version: 4.0.0"}, "major"},
		// fail closed
		{"overflowing component", []string{"-  tag: 1.2.3\n+  tag: 1.2.99999999999999999999"}, ""},
		{"leading zero", []string{"-  tag: 1.2.3\n+  tag: 1.02.3"}, ""},
		{"respelled v prefix", []string{"-  tag: v1.2.3\n+  tag: 1.2.3"}, ""},
		{"URL host change", []string{"-  repoURL: https://charts.a.io\n+  repoURL: https://charts.evil.io"}, ""},
		{"IP change", []string{"-  loadBalancerIP: 192.168.55.200\n+  loadBalancerIP: 192.168.55.201"}, ""},
		{"version token in a comment", []string{"-  # pinned to 1.2.3\n+  # pinned to 1.2.4"}, ""},
		{"image repository change", []string{"-image: ghcr.io/x/y:1.4.0\n+image: ghcr.io/evil/y:1.4.1"}, ""},
		{"an extra added line", []string{"-  tag: 1.4.0\n+  tag: 1.4.1\n+  command: [sh, -c, curl evil]"}, ""},
		{"trailing text after the value", []string{"-  tag: 1.4.0\n+  tag: 1.4.1 # and more"}, ""},
		{"key changed", []string{"-  tag: 1.4.0\n+  version: 1.4.1"}, ""},
		{"no version change", []string{"-  replicas: 2\n+  replicas: 3"}, ""},
		{"no patch", []string{""}, ""},
	}
	for _, c := range cases {
		if got, why := DiffUpdateType(c.patches); got != c.want {
			t.Errorf("%s: got %q (%s), want %q", c.name, got, why, c.want)
		}
	}
}
