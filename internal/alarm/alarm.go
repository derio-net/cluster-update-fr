// Package alarm owns the security alarm state (R10) and the daily report
// (R11). One record per vulnerability × component; a record alarms when it
// first appears at or above the threshold and again ONLY when its state
// changes — fix released, severity raised, still open past its deadline
// (once). Grafana alerts are dead-man's switches, never the alarm source,
// because they re-fire on their own schedule (anti-goal 1).
package alarm

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/derio-net/cluster-update-fr/internal/live"
	"github.com/derio-net/cluster-update-fr/internal/scrub"
)

// Record states (exported as cluster_update_alarms{state}).
const (
	StateOpen     = "open"
	StateOverdue  = "overdue"
	StateResolved = "resolved"
)

// Deadlines by severity (builder's numbers).
var Deadlines = map[string]time.Duration{"CRITICAL": 3 * 24 * time.Hour, "HIGH": 14 * 24 * time.Hour}

// Finding is one vulnerability seen in one running component.
type Finding struct {
	Cluster   string
	Component string // inventory dependency ID
	Image     string
	Vuln      live.Vuln
}

// Record is the persisted alarm state of one vulnerability × component.
type Record struct {
	Cluster         string    `json:"cluster"`
	Component       string    `json:"component"`
	Image           string    `json:"image"`
	VulnID          string    `json:"vuln_id"`
	Package         string    `json:"package"`
	Title           string    `json:"title,omitempty"`
	Severity        string    `json:"severity"`
	Fixed           string    `json:"fixed,omitempty"`
	State           string    `json:"state"`
	FirstSeen       time.Time `json:"first_seen"`
	LastSeen        time.Time `json:"last_seen"`
	Deadline        time.Time `json:"deadline"`
	LastAlarmed     time.Time `json:"last_alarmed"`
	OverdueAlarmed  bool      `json:"overdue_alarmed"`
	AlarmedSeverity string    `json:"alarmed_severity"`
}

// Reason is why an alarm fires.
type Reason string

// Reasons.
const (
	ReasonNew            Reason = "new"
	ReasonFixReleased    Reason = "fix released"
	ReasonSeverityRaised Reason = "severity raised"
	ReasonOverdue        Reason = "still unresolved past its deadline"
)

// Alarm is one message to send.
type Alarm struct {
	Reason Reason
	Record Record
}

// Key identifies a record.
func Key(f Finding) string { return f.Component + "|" + f.Vuln.ID + "|" + f.Vuln.Package }

func recordKey(r Record) string { return r.Component + "|" + r.VulnID + "|" + r.Package }

// Evaluate advances the records with this scan's findings. scanned names the
// clusters whose scan SUCCEEDED: records of other clusters are carried over
// untouched, so a failed scan never resolves (and later re-alarms) them.
func Evaluate(prev map[string]Record, findings []Finding, scanned map[string]bool, now time.Time) (map[string]Record, []Alarm) {
	next := map[string]Record{}
	for k, r := range prev {
		next[k] = r
	}
	var alarms []Alarm
	seen := map[string]bool{}
	for _, f := range findings {
		if !live.Alarming(f.Vuln) {
			continue
		}
		k := Key(f)
		seen[k] = true
		r, existed := next[k]
		if !existed || r.State == StateResolved {
			r = Record{Cluster: f.Cluster, Component: f.Component, Image: f.Image, VulnID: f.Vuln.ID, Package: f.Vuln.Package,
				Title: f.Vuln.Title, Severity: f.Vuln.Severity, Fixed: f.Vuln.Fixed, State: StateOpen, FirstSeen: now,
				Deadline: now.Add(Deadlines[f.Vuln.Severity]), AlarmedSeverity: f.Vuln.Severity, LastAlarmed: now}
			r.LastSeen = now
			next[k] = r
			alarms = append(alarms, Alarm{Reason: ReasonNew, Record: r})
			continue
		}
		reason := Reason("")
		if r.Fixed == "" && f.Vuln.Fixed != "" {
			reason = ReasonFixReleased
		}
		if live.SeverityRank(f.Vuln.Severity) > live.SeverityRank(r.AlarmedSeverity) {
			reason = ReasonSeverityRaised
			r.Deadline = r.FirstSeen.Add(Deadlines[f.Vuln.Severity])
			r.AlarmedSeverity = f.Vuln.Severity
		}
		r.Severity, r.Fixed, r.Image, r.LastSeen = f.Vuln.Severity, f.Vuln.Fixed, f.Image, now
		if reason == "" && !r.OverdueAlarmed && !r.Deadline.IsZero() && now.After(r.Deadline) {
			reason = ReasonOverdue
			r.OverdueAlarmed = true
		}
		if reason != "" {
			r.LastAlarmed = now
			alarms = append(alarms, Alarm{Reason: reason, Record: r})
		}
		next[k] = r
	}
	for k, r := range next {
		if !seen[k] && r.State != StateResolved && scanned[r.Cluster] {
			r.State = StateResolved
			r.LastSeen = now
			next[k] = r
		}
	}
	sort.SliceStable(alarms, func(i, j int) bool {
		a, b := alarms[i].Record, alarms[j].Record
		if live.SeverityRank(a.Severity) != live.SeverityRank(b.Severity) {
			return live.SeverityRank(a.Severity) > live.SeverityRank(b.Severity)
		}
		return recordKey(a) < recordKey(b)
	})
	return next, alarms
}

// Counts reports records by state at now (open past deadline = overdue).
func Counts(recs map[string]Record, now time.Time) map[string]int {
	c := map[string]int{StateOpen: 0, StateOverdue: 0, StateResolved: 0}
	for _, r := range recs {
		switch {
		case r.State == StateResolved:
			c[StateResolved]++
		case !r.Deadline.IsZero() && now.After(r.Deadline):
			c[StateOverdue]++
		default:
			c[StateOpen]++
		}
	}
	return c
}

var e = html.EscapeString

// FormatAlarm renders an alarm for Telegram (parse_mode HTML, every value
// escaped, the whole text scrubbed).
func FormatAlarm(a Alarm, consoleURL string) string {
	r := a.Record
	fix := "no fixed version yet"
	if r.Fixed != "" {
		fix = "fixed in " + e(r.Fixed)
	}
	msg := fmt.Sprintf("🔴 <b>%s %s</b> — %s\n%s in <code>%s</code> (%s)\n%s · %s\n<a href=\"%s\">Open the update console</a>",
		e(r.Severity), e(r.VulnID), e(string(a.Reason)), e(r.Package), e(r.Image), e(r.Component), fix, e(r.Title), e(consoleURL))
	return scrub.String(msg)
}

// Summary is what the daily report counts.
type Summary struct {
	Security, Batch, Countdowns, Guided, HeldCI, Rollouts int
	NewSinceLast                                          int
	Total                                                 int
	Lines                                                 []string // a few headline items
}

// Due reports whether the daily report should go out: once per UTC day,
// after hour.
func Due(last, now time.Time, hour int) bool {
	now = now.UTC()
	if now.Hour() < hour {
		return false
	}
	if last.IsZero() {
		return true
	}
	ly, lm, ld := last.UTC().Date()
	ny, nm, nd := now.Date()
	return ly != ny || lm != nm || ld != nd
}

// FormatReport renders the daily report; on a day with nothing new it is a
// single short line.
func FormatReport(s Summary, consoleURL string) string {
	link := fmt.Sprintf("<a href=\"%s\">console</a>", e(consoleURL))
	if s.NewSinceLast == 0 {
		if s.Total == 0 {
			return scrub.String("✅ Nothing new, nothing waiting — " + link)
		}
		return scrub.String(fmt.Sprintf("✅ Nothing new; %d item(s) still waiting — %s", s.Total, link))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "📋 <b>Daily update report</b> — %d new, %d need action\n", s.NewSinceLast, s.Total)
	add := func(n int, label string) {
		if n > 0 {
			fmt.Fprintf(&b, "• %d %s\n", n, label)
		}
	}
	add(s.Security, "🔴 Security")
	add(s.Batch, "📦 in the suggested batch")
	add(s.Countdowns, "⏱ auto-merge countdown(s)")
	add(s.Guided, "🧭 Guided upgrade(s)")
	add(s.HeldCI, "⚠️ held for CI")
	add(s.Rollouts, "🚦 rollout(s) waiting for a decision")
	for _, l := range s.Lines {
		fmt.Fprintf(&b, "  – %s\n", e(l))
	}
	b.WriteString(link)
	return scrub.String(b.String())
}
