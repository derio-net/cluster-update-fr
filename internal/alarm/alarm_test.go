package alarm

import (
	"strings"
	"testing"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/live"
)

var t0 = time.Date(2026, 10, 31, 10, 0, 0, 0, time.UTC)

func finding(id, sev, fixed string) Finding {
	return Finding{Cluster: "frank", Component: "frank/caddy/image/docker.io/library/caddy", Image: "docker.io/library/caddy:2.10.0",
		Vuln: live.Vuln{ID: id, Severity: sev, Package: "golang.org/x/net", Fixed: fixed}}
}

func reasons(as []Alarm) []string {
	var out []string
	for _, a := range as {
		out = append(out, string(a.Reason))
	}
	return out
}

func TestAlarmOnlyOnStateChange(t *testing.T) {
	scanned := map[string]bool{"frank": true}
	recs, alarms := Evaluate(nil, []Finding{finding("CVE-1", "CRITICAL", "")}, scanned, t0)
	if len(alarms) != 1 || alarms[0].Reason != ReasonNew {
		t.Fatalf("first sighting: %v", reasons(alarms))
	}
	// Same finding on the next scan: silence.
	recs, alarms = Evaluate(recs, []Finding{finding("CVE-1", "CRITICAL", "")}, scanned, t0.Add(time.Hour))
	if len(alarms) != 0 {
		t.Fatalf("repeat alarm: %v", reasons(alarms))
	}
	// Fix released.
	recs, alarms = Evaluate(recs, []Finding{finding("CVE-1", "CRITICAL", "0.33.0")}, scanned, t0.Add(2*time.Hour))
	if len(alarms) != 1 || alarms[0].Reason != ReasonFixReleased {
		t.Fatalf("fix released: %v", reasons(alarms))
	}
	recs, alarms = Evaluate(recs, []Finding{finding("CVE-1", "CRITICAL", "0.33.0")}, scanned, t0.Add(3*time.Hour))
	if len(alarms) != 0 {
		t.Fatalf("repeat after fix: %v", reasons(alarms))
	}
	// Past the Critical deadline: once.
	recs, alarms = Evaluate(recs, []Finding{finding("CVE-1", "CRITICAL", "0.33.0")}, scanned, t0.Add(4*24*time.Hour))
	if len(alarms) != 1 || alarms[0].Reason != ReasonOverdue {
		t.Fatalf("overdue: %v", reasons(alarms))
	}
	recs, alarms = Evaluate(recs, []Finding{finding("CVE-1", "CRITICAL", "0.33.0")}, scanned, t0.Add(5*24*time.Hour))
	if len(alarms) != 0 {
		t.Fatalf("overdue repeated: %v", reasons(alarms))
	}
	// Resolved after ResolveAfter consecutive clean scans: silent.
	for i := 0; i < ResolveAfter; i++ {
		recs, alarms = Evaluate(recs, nil, scanned, t0.Add(6*24*time.Hour+time.Duration(i)*time.Hour))
	}
	if len(alarms) != 0 || recs[Key(finding("CVE-1", "", ""))].State != StateResolved {
		t.Fatalf("resolve: %v %+v", reasons(alarms), recs)
	}
}

// c1c-r13: a finding missing from one or two scans (a scanner hiccup, a
// pod restarting) is not resolved, so its return is not a "new" alarm.
func TestFlappingFindingDoesNotReAlarm(t *testing.T) {
	scanned := map[string]bool{"frank": true}
	f := []Finding{finding("CVE-2", "CRITICAL", "")}
	recs, _ := Evaluate(nil, f, scanned, t0)
	for i := 1; i < ResolveAfter; i++ {
		recs, _ = Evaluate(recs, nil, scanned, t0.Add(time.Duration(i)*time.Hour))
	}
	if recs[Key(f[0])].State == StateResolved {
		t.Fatal("resolved before ResolveAfter consecutive clean scans")
	}
	recs, alarms := Evaluate(recs, f, scanned, t0.Add(10*time.Hour))
	if len(alarms) != 0 {
		t.Fatalf("reappearance re-alarmed: %v", reasons(alarms))
	}
	if recs[Key(f[0])].Missed != 0 {
		t.Error("a sighting resets the clean-scan count")
	}
}

// c1c-r13: raising the severity resets the overdue alarm, so the NEW
// (shorter) deadline alarms when it passes.
func TestSeverityRaiseResetsOverdue(t *testing.T) {
	scanned := map[string]bool{"frank": true}
	recs, _ := Evaluate(nil, []Finding{finding("CVE-3", "HIGH", "1.0")}, scanned, t0)
	recs, alarms := Evaluate(recs, []Finding{finding("CVE-3", "HIGH", "1.0")}, scanned, t0.Add(15*24*time.Hour))
	if len(alarms) != 1 || alarms[0].Reason != ReasonOverdue {
		t.Fatalf("high overdue: %v", reasons(alarms))
	}
	recs, alarms = Evaluate(recs, []Finding{finding("CVE-3", "CRITICAL", "1.0")}, scanned, t0.Add(15*24*time.Hour+time.Hour))
	if len(alarms) != 1 || alarms[0].Reason != ReasonSeverityRaised {
		t.Fatalf("raise: %v", reasons(alarms))
	}
	if recs[Key(finding("CVE-3", "", ""))].OverdueAlarmed {
		t.Fatal("severity raise must reset the overdue alarm")
	}
	_, alarms = Evaluate(recs, []Finding{finding("CVE-3", "CRITICAL", "1.0")}, scanned, t0.Add(15*24*time.Hour+2*time.Hour))
	if len(alarms) != 1 || alarms[0].Reason != ReasonOverdue {
		t.Fatalf("overdue at the new severity: %v", reasons(alarms))
	}
}

func TestSeverityRaised(t *testing.T) {
	scanned := map[string]bool{"frank": true}
	recs, alarms := Evaluate(nil, []Finding{finding("CVE-2", "HIGH", "1.1")}, scanned, t0)
	if len(alarms) != 1 {
		t.Fatal("High with a fix alarms")
	}
	_, alarms = Evaluate(recs, []Finding{finding("CVE-2", "CRITICAL", "1.1")}, scanned, t0.Add(time.Hour))
	if len(alarms) != 1 || alarms[0].Reason != ReasonSeverityRaised {
		t.Fatalf("raised: %v", reasons(alarms))
	}
}

func TestBelowThresholdNeverAlarms(t *testing.T) {
	scanned := map[string]bool{"frank": true}
	_, alarms := Evaluate(nil, []Finding{finding("CVE-3", "HIGH", ""), finding("CVE-4", "MEDIUM", "2")}, scanned, t0)
	if len(alarms) != 0 {
		t.Fatalf("below threshold: %v", reasons(alarms))
	}
}

// A scan that failed must not resolve every record — the next good scan
// would then re-alarm all of them (anti-goal 1).
func TestUnscannedClusterKeepsItsRecords(t *testing.T) {
	recs, _ := Evaluate(nil, []Finding{finding("CVE-1", "CRITICAL", "")}, map[string]bool{"frank": true}, t0)
	recs, alarms := Evaluate(recs, nil, map[string]bool{"frank": false}, t0.Add(time.Hour))
	if len(alarms) != 0 || recs[Key(finding("CVE-1", "", ""))].State != StateOpen {
		t.Fatalf("records lost on a failed scan: %+v", recs)
	}
	_, alarms = Evaluate(recs, []Finding{finding("CVE-1", "CRITICAL", "")}, map[string]bool{"frank": true}, t0.Add(2*time.Hour))
	if len(alarms) != 0 {
		t.Fatalf("re-alarmed after a failed scan: %v", reasons(alarms))
	}
}

func TestCounts(t *testing.T) {
	recs, _ := Evaluate(nil, []Finding{finding("CVE-1", "CRITICAL", ""), finding("CVE-2", "HIGH", "1")}, map[string]bool{"frank": true}, t0)
	for i := 0; i < ResolveAfter; i++ { // CVE-1 absent from ResolveAfter clean scans
		recs, _ = Evaluate(recs, []Finding{finding("CVE-2", "HIGH", "1")}, map[string]bool{"frank": true}, t0.Add(time.Hour))
	}
	c := Counts(recs, t0.Add(time.Hour))
	if c[StateOpen] != 1 || c[StateResolved] != 1 || c[StateOverdue] != 0 {
		t.Errorf("counts = %v", c)
	}
	if c2 := Counts(recs, t0.Add(30*24*time.Hour)); c2[StateOverdue] != 1 {
		t.Errorf("overdue count = %v", c2)
	}
}

func TestMessageIsEscapedAndScrubbed(t *testing.T) {
	a := Alarm{Reason: ReasonNew, Record: Record{Cluster: "frank", Component: "frank/x/image/<img>", Image: "a&b", VulnID: "CVE-1", Severity: "CRITICAL",
		Package: "p", Title: "tok" + "en: " + strings.Repeat("Ab9", 6)}}
	msg := FormatAlarm(a, "https://updates.cluster.derio.net")
	if strings.Contains(msg, "<img>") || !strings.Contains(msg, "&lt;img&gt;") || !strings.Contains(msg, "a&amp;b") {
		t.Errorf("not escaped: %q", msg)
	}
	if strings.Contains(msg, "Ab9Ab9") {
		t.Errorf("not scrubbed: %q", msg)
	}
	if !strings.Contains(msg, `<a href="https://updates.cluster.derio.net">`) {
		t.Errorf("console link missing: %q", msg)
	}
}

func TestDailyReport(t *testing.T) {
	last := time.Date(2026, 10, 30, 8, 0, 0, 0, time.UTC)
	if Due(last, time.Date(2026, 10, 31, 7, 59, 0, 0, time.UTC), 8) {
		t.Error("not before the report hour")
	}
	if !Due(last, time.Date(2026, 10, 31, 8, 1, 0, 0, time.UTC), 8) {
		t.Error("due after the hour on a new day")
	}
	if Due(time.Date(2026, 10, 31, 8, 1, 0, 0, time.UTC), time.Date(2026, 10, 31, 20, 0, 0, 0, time.UTC), 8) {
		t.Error("once per day")
	}
	if !Due(time.Time{}, time.Date(2026, 10, 31, 9, 0, 0, 0, time.UTC), 8) {
		t.Error("first report")
	}
	quiet := FormatReport(Summary{Total: 3}, "https://u")
	if strings.Count(quiet, "\n") != 0 || !strings.Contains(quiet, "Nothing new") {
		t.Errorf("a day with nothing new is one short line: %q", quiet)
	}
	busy := FormatReport(Summary{Security: 1, Batch: 2, Countdowns: 1, Guided: 1, HeldCI: 1, NewSinceLast: 3, Total: 6, Lines: []string{"x <y>"}}, "https://u")
	for _, want := range []string{"Security", "batch", "countdown", "Guided", "CI", "https://u", "x &lt;y&gt;"} {
		if !strings.Contains(busy, want) {
			t.Errorf("report missing %q: %q", want, busy)
		}
	}
}
