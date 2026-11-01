package scrub

import (
	"encoding/base64"
	"strings"
	"testing"
)

func noLeak(t *testing.T, out string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if strings.Contains(out, p) {
			t.Errorf("%q leaked in %q", p, out)
		}
	}
}

// A child (session) secret that overlaps a parent (console) secret must not
// break the parent's match and leave a remainder, whichever is registered
// first and whichever level holds which.
func TestOverlappingSecretsAcrossParentAndChild(t *testing.T) {
	left := "LEFTPART" + strings.Repeat("q", 6)  // 14
	mid := "MIDDLE" + strings.Repeat("w", 6)     // 12
	right := "RIGHTEND" + strings.Repeat("e", 6) // 14
	long := left + mid                           // parent secret
	overlap := mid + right                       // child secret overlapping the end of long
	text := "x " + left + mid + right + " y"

	for _, order := range []string{"parent-long", "child-long"} {
		t.Run(order, func(t *testing.T) {
			parent := NewSet(nil)
			child := NewSet(parent)
			if order == "parent-long" {
				parent.Add("github-token", long)
				child.Add("omni-sa-key", overlap)
			} else {
				parent.Add("github-token", overlap)
				child.Add("omni-sa-key", long)
			}
			out := child.String(text)
			noLeak(t, out, left, mid, right, "LEFT", "MIDDLE", "RIGHT")
			if strings.Count(out, "«redacted:") != 1 {
				t.Errorf("overlapping matches must merge into one span: %q", out)
			}
			if !strings.HasPrefix(out, "x «redacted:") || !strings.HasSuffix(out, "» y") {
				t.Errorf("surrounding text damaged: %q", out)
			}
		})
	}
}

func TestSecretThatIsASubstringOfAnother(t *testing.T) {
	inner := "innersecret-" + strings.Repeat("z", 6)
	outer := "pre-" + inner + "-post-" + strings.Repeat("m", 4)
	for _, swap := range []bool{false, true} {
		parent := NewSet(nil)
		child := NewSet(parent)
		if swap {
			parent.Add("a", outer)
			child.Add("b", inner)
		} else {
			parent.Add("b", inner)
			child.Add("a", outer)
		}
		out := child.String("v=" + outer + "; w=" + inner)
		noLeak(t, out, "pre-", "-post-", "innersecret")
		// The longest (most specific) form names the merged span.
		if !strings.HasPrefix(out, "v=«redacted:a»; w=«redacted:b»") {
			t.Errorf("swap=%v: %q", swap, out)
		}
	}
}

// A secret inside a larger base64 blob (a whole kubeconfig or talosconfig
// base64-encoded, as in client-key-data) encodes differently depending on its
// byte offset; all three alignments must be caught.
func TestSecretInsideABase64EncodedDocument(t *testing.T) {
	secret := "kube-session-" + strings.Repeat("Sx4", 6)
	for pad := 0; pad < 3; pad++ {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding} {
			doc := "apiVersion: v1\nkind: Config\nusers:\n- name: s\n  user:\n    token: " +
				strings.Repeat("#", pad) + secret + "\n    extra: yes\n"
			blob := enc.EncodeToString([]byte(doc))
			set := NewSet(nil)
			set.Add("kubeconfig", secret)
			text := "client-config-data " + blob + " end"
			out := set.String(text)
			if !strings.Contains(out, "«redacted:kubeconfig»") {
				t.Errorf("pad=%d: secret inside base64 not redacted: %q", pad, out)
			}
			// No stable base64 run of the secret may survive at any alignment.
			for k := 0; k < 3; k++ {
				f := alignedBase64(enc.WithPadding(base64.NoPadding), []byte(secret), k)
				if len(f) >= minLiteral && strings.Contains(out, f) {
					t.Errorf("pad=%d k=%d: aligned form survived: %q", pad, k, out)
				}
			}
		}
	}
}

// The aligned forms alone (without the decode pass) cover all offsets.
func TestAlignedFormsCoverEveryOffset(t *testing.T) {
	secret := []byte("aligned-" + strings.Repeat("Yz7", 5))
	for pre := 0; pre < 6; pre++ {
		blob := base64.StdEncoding.EncodeToString(append([]byte(strings.Repeat("P", pre)), append(secret, []byte("tail")...)...))
		found := false
		for k := 0; k < 3; k++ {
			f := alignedBase64(base64.RawStdEncoding, secret, k)
			if len(f) >= minLiteral && strings.Contains(blob, f) {
				found = true
			}
		}
		if !found {
			t.Errorf("prefix %d: no aligned form found in %q", pre, blob)
		}
	}
}
