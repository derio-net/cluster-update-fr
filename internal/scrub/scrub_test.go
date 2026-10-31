package scrub

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// Token-shaped fixtures are assembled at runtime so this repository (which is
// PUBLIC) never carries a literal that looks like a credential — the repo-wide
// test below would otherwise have to exempt this file.
func rep(s string, n int) string { return strings.Repeat(s, n) }

func cases() []struct {
	name, in, kind string
} {
	omniKey := base64.StdEncoding.EncodeToString([]byte(`{"name":"console-reader","pgp_key":"-----BEGIN PGP PRIVATE KEY BLOCK-----xyz"}`))
	return []struct{ name, in, kind string }{
		{"installation token", "auth " + "gh" + "s_" + rep("A1b2", 9) + " ok", "github-token"},
		{"classic pat", "gh" + "p_" + rep("Zz09", 9), "github-token"},
		{"oauth token", "gh" + "o_" + rep("Qq12", 9), "github-token"},
		{"fine-grained pat", "github" + "_pat_" + rep("11AB", 6) + "_" + rep("cd34", 12), "github-pat"},
		{"gitea token", "Authorization: token " + rep("0a1b2c3d4e", 4), "gitea-token"},
		{"telegram", "bot" + "123456789:" + "AA" + rep("Bc_-d", 6) + "xyz", "telegram-bot-token"},
		{"anthropic", "sk-" + "ant-api03-" + rep("Xy9_", 10), "api-key"},
		{"openai", "sk-" + "proj-" + rep("Ab12", 10), "api-key"},
		{"bearer", "Authorization: Bearer " + rep("abc.DEF_123-", 3), "bearer"},
		{"pem", "-----BEGIN RSA " + "PRIVATE KEY-----\nMIIEow" + rep("AB", 30) + "\n-----END RSA " + "PRIVATE KEY-----", "private-key"},
		{"kubeconfig token", "users:\n- user:\n    token: " + rep("kT9", 12), "yaml-secret"},
		{"kubeconfig client key", "    client-key-data: " + rep("LS0t", 12), "yaml-secret"},
		{"talosconfig key", "contexts:\n  frank:\n    key: " + rep("TFMw", 12), "yaml-secret"},
		{"omni sa key", "OMNI_SERVICE_ACCOUNT_KEY=" + omniKey, "omni-sa-key"},
		{"jwt", "id " + "eyJ" + "hbGciOiJSUzI1NiJ9." + rep("eyJzdWIi", 4) + "." + rep("sig_", 8), "jwt"},
	}
}

func TestStringRedactsEveryKind(t *testing.T) {
	for _, c := range cases() {
		t.Run(c.name, func(t *testing.T) {
			out := String(c.in)
			want := "«redacted:" + c.kind + "»"
			if !strings.Contains(out, want) {
				t.Fatalf("String(%q) = %q, want it to contain %q", c.in, out, want)
			}
			if got := Find(out); len(got) != 0 {
				t.Fatalf("scrubbed output still has tokens %v: %q", got, out)
			}
			if again := String(out); again != out {
				t.Fatalf("String is not idempotent: %q -> %q", out, again)
			}
		})
	}
}

func TestFindReportsKinds(t *testing.T) {
	for _, c := range cases() {
		got := Find(c.in)
		found := false
		for _, k := range got {
			if k == c.kind {
				found = true
			}
		}
		if !found {
			t.Errorf("Find(%s) = %v, want %s", c.name, got, c.kind)
		}
	}
}

func TestBenignTextIsUntouched(t *testing.T) {
	benign := []string{
		"commit " + rep("a1b2c3d4e5", 4),
		"merged 3f2a1b0 into main",
		"image: ghcr.io/derio-net/cluster-update-fr:0.1.0",
		"token: «redacted:yaml-secret»",
		"key: short",
		"the token expired",
		"sha256:" + rep("ab", 32),
	}
	for _, b := range benign {
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
	tok := "gh" + "s_" + rep("A1b2", 9)
	n, err := w.Write([]byte("calling github with " + tok + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	if n != len("calling github with "+tok+"\n") {
		t.Errorf("Write must report the caller's byte count, got %d", n)
	}
	if strings.Contains(buf.String(), tok) {
		t.Fatalf("token reached the log: %q", buf.String())
	}
}
