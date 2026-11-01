package scrub

import (
	"strings"
	"testing"
	"time"
)

func pemHeader() string { return "-----BEGIN RSA PRIVATE " + "KEY-----\n" }
func pemFooter() string { return "\n-----END RSA PRIVATE " + "KEY-----" }

// p5-relay-3b: a private-key header whose END is missing, or beyond the PEM
// window, fails closed — the body never survives.
func TestPEMWithoutEndFailsClosed(t *testing.T) {
	body := strings.Repeat("MIIEowIBAAKCAQEA"+"\n", 40) + "LASTBODYLINE"
	got := String("before\n" + pemHeader() + body + "\nafter")
	if strings.Contains(got, "MIIEow") || strings.Contains(got, "LASTBODYLINE") {
		t.Fatalf("END-less key body survived: %q", got)
	}
	if !strings.Contains(strings.Join(Find(pemHeader()+body), ","), limitKind) {
		t.Error("an END-less key is not reported as a limit")
	}
	if !strings.HasPrefix(got, "before\n") {
		t.Errorf("text before the header was redacted: %q", got)
	}
}

func TestPEMLongerThanTheWindowFailsClosed(t *testing.T) {
	line := strings.Repeat("Qk9EWQ", 10) + "\n"
	body := strings.Repeat(line, pemCap/len(line)+200) + "TAILBODY"
	got := String(pemHeader() + body + pemFooter() + "\nafter")
	if strings.Contains(got, "Qk9EWQ") || strings.Contains(got, "TAILBODY") {
		t.Fatal("a key longer than the PEM window leaked its body")
	}
	if !strings.Contains(got, "after") {
		t.Error("text after the END line was redacted")
	}
}

// The fail-closed path uses the pattern's own header — every header form the
// pattern recognises fails closed when its END is missing: JSON-escaped
// (a literal backslash-n), the body glued straight to the dashes, CRLF.
func TestEveryHeaderFormFailsClosed(t *testing.T) {
	h := "-----BEGIN PRIVATE " + "KEY-----"
	for name, in := range map[string]string{
		"json-escaped":  `{"k":"` + h + `\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\nTAILJSONBODY"}`,
		"glued base64":  h + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCTAILGLUEDBODY",
		"crlf":          h + "\r\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\r\nTAILCRLFBODY\r\n",
		"rsa, no space": "-----BEGIN RSA PRIVATE " + "KEY-----MIIEvQTAILRSABODY",
	} {
		got := String("x " + in)
		for _, leak := range []string{"MIIEvQ", "TAIL"} {
			if strings.Contains(got, leak) {
				t.Errorf("%s: %q survived in %q", name, leak, got)
			}
		}
		if !strings.Contains(strings.Join(Find(in), ","), limitKind) {
			t.Errorf("%s: not reported as fail-closed", name)
		}
	}
}

// An ordinary certificate (not a private key) is not fail-closed.
func TestCertificateIsNotFailClosed(t *testing.T) {
	cert := "-----BEGIN CERTIFICATE-----\n" + strings.Repeat("MIIC", 10) + "\n-----END CERTIFICATE-----"
	if got := String(cert); got != cert {
		t.Errorf("certificate changed: %q", got)
	}
}

// p5-relay-3b: line ends come from one index, not a rescan per start, so a
// 1 MiB SINGLE-LINE adversarial input stays fast; and if a cap trips on it,
// it ends fully redacted.
func singleLine(n int) (string, string) {
	r := strings.Repeat
	real := "gh" + "p_" + r("L3", 18)
	chunk := r("s"+"k-", 50) + " " + "to" + `ken: "` + r("q", 100) + " " + r("12345678:", 20) + " pass" + "word=" + r("x", 30) + " "
	var b strings.Builder
	for b.Len() < n/2 {
		b.WriteString(chunk)
	}
	b.WriteString(" " + real + " ")
	for b.Len() < n {
		b.WriteString(chunk)
	}
	return b.String(), real
}

func TestSingleLineAdversarialIsLinear(t *testing.T) {
	small, _ := singleLine(256 << 10)
	big, real := singleLine(1 << 20)
	ts := measure(func() { String(small) })
	var out string
	tb := measure(func() { out = String(big) })
	t.Logf("single line CPU: 256 KiB %v, 1 MiB %v", ts, tb)
	if strings.Contains(out, real[len(real)-12:]) {
		t.Error("the real token survived")
	}
	limit := 5 * time.Second
	if raceEnabled {
		limit = 30 * time.Second
	}
	if tb > limit {
		t.Errorf("1 MiB single line took %v", tb)
	}
	if ts < 20*time.Millisecond {
		ts = 20 * time.Millisecond
	}
	if tb > 10*ts {
		t.Errorf("not linear on one line: %v vs %v", ts, tb)
	}
}

func TestSingleLineCapEndsFullyRedacted(t *testing.T) {
	big, real := singleLine(1 << 20)
	for name, set := range map[string]func(*testing.T){
		"work": func(t *testing.T) { withLimits(t, maxRounds, timeLimit, func(int) int { return 1000 }) },
		"time": func(t *testing.T) { withLimits(t, maxRounds, 0, workBudget) },
	} {
		t.Run(name, func(t *testing.T) {
			set(t)
			var out string
			d := measure(func() { out = String(big) })
			if strings.Contains(out, real[len(real)-12:]) || strings.Contains(out, "qqqqqqqq") || strings.Contains(out, "xxxxxxxx") {
				t.Fatal("a secret survived a tripped cap")
			}
			limit := 5 * time.Second
			if raceEnabled {
				limit = 60 * time.Second // the race detector slows the literal layer ~15x
			}
			if d > limit {
				t.Errorf("fail-closed path took %v", d)
			}
		})
	}
}
