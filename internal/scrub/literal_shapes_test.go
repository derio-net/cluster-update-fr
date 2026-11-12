package scrub

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func wrap(s string, width int, eol, indent string) string {
	var b strings.Builder
	for len(s) > width {
		b.WriteString(indent + s[:width] + eol)
		s = s[width:]
	}
	b.WriteString(indent + s)
	return b.String()
}

// A base64 document wrapped at 64 or 76 columns (PEM bodies, `base64`
// output, kubeconfig dumps) must be joined and decoded as a whole.
func TestSecretInsideWrappedBase64(t *testing.T) {
	secret := "wrapped-session-" + strings.Repeat("Qv6", 6)
	for _, width := range []int{64, 76} {
		for pad := 0; pad < 3; pad++ {
			for _, style := range []struct{ name, eol, indent string }{
				{"lf", "\n", ""}, {"crlf", "\r\n", ""}, {"yaml-indent", "\n", "    "}, {"tab-indent", "\n", "\t"},
			} {
				doc := "apiVersion: v1\nclusters:\n- cluster:\n    server: https://hop-1:6443\nusers:\n- user:\n    token: " +
					strings.Repeat("#", pad) + secret + "\n" + strings.Repeat("padding line to make the blob long\n", 4)
				blob := wrap(base64.StdEncoding.EncodeToString([]byte(doc)), width, style.eol, style.indent)
				set := NewSet(nil)
				set.Add("kubeconfig", secret)
				text := "kubeconfig: |\n" + blob + "\nnext: value"
				out := set.String(text)
				if !strings.Contains(out, "«redacted:kubeconfig»") {
					t.Errorf("width=%d pad=%d %s: not redacted", width, pad, style.name)
					continue
				}
				// The whole multi-line span goes, not just the lines that
				// happen to carry the secret's bytes.
				for _, line := range strings.Split(blob, style.eol) {
					line = strings.TrimSpace(line)
					if len(line) >= 16 && strings.Contains(out, line) {
						t.Errorf("width=%d pad=%d %s: wrapped line survived: %q", width, pad, style.name, line)
					}
				}
				if !strings.HasSuffix(out, "\nnext: value") || !strings.HasPrefix(out, "kubeconfig: |\n") {
					t.Errorf("surrounding text damaged: %q", out)
				}
			}
		}
	}
}

func TestOtherEncodedShapes(t *testing.T) {
	secret := `pa"ss\word-` + strings.Repeat("Hx2", 5) + "&=/"
	jsonBody, _ := json.Marshal(map[string]string{"url": "https://x/?t=" + url.QueryEscape(secret)})
	cases := map[string]string{
		"hex lower":           "dump " + hex.EncodeToString([]byte(secret)) + " end",
		"hex upper":           "dump " + strings.ToUpper(hex.EncodeToString([]byte(secret))),
		"json escaped":        `{"note":"` + jsonEscaped(secret) + `"}`,
		"url encoded in json": string(jsonBody),
		"double base64": "x " + base64.StdEncoding.EncodeToString([]byte(
			base64.StdEncoding.EncodeToString([]byte(secret)))),
		"crlf multi-line": "first\r\n" + secret + "\r\nlast",
	}
	for name, text := range cases {
		set := NewSet(nil)
		set.Add("omni-sa-key", secret)
		out := set.String(text)
		if !strings.Contains(out, "«redacted:omni-sa-key»") {
			t.Errorf("%s: not redacted: %q", name, out)
		}
		for _, f := range []string{secret, hex.EncodeToString([]byte(secret)), url.QueryEscape(secret), jsonEscaped(secret)} {
			if strings.Contains(strings.ToLower(out), strings.ToLower(f)) {
				t.Errorf("%s: %q survived in %q", name, f, out)
			}
		}
	}
}

func TestMultiLineSecretWithCRLFAndTabs(t *testing.T) {
	line1 := "-----BEGIN-ish " + strings.Repeat("Ab3", 6)
	line2 := strings.Repeat("Cd4", 7)
	secret := line1 + "\r\n" + line2
	set := NewSet(nil)
	set.Add("talosconfig", secret)
	text := "ca:\n\t\t" + line1 + "\n\t\t" + line2 + "\n"
	out := set.String(text)
	noLeak(t, out, line1, line2)
}
