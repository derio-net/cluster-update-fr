// Package renovate reads Renovate's PR bodies and Dependency Dashboard and
// edits their checkboxes — the console's only way of steering Renovate.
package renovate

import (
	"errors"
	"regexp"
	"strings"

	"github.com/derio-net/cluster-update-fr/internal/version"
)

// Dep is one update in a Renovate PR.
type Dep struct {
	Name       string
	From, To   string
	UpdateType string // patch | minor | major | digest | "" (unknown)
}

var (
	tableRow   = regexp.MustCompile("(?m)^\\|\\s*(?:\\[([^\\]]+)\\]\\([^)]*\\)|([^|\\s][^|]*?))\\s*\\|.*?`([^`]+)`\\s*(?:->|→)\\s*`([^`]+)`")
	rebaseBox  = regexp.MustCompile(`- \[( |x|X)\] <!-- rebase-check -->`)
	dashboxRe  = regexp.MustCompile(`(?m)^\s*- \[( |x|X)\] <!-- (approve-branch|approvePr-branch|unlimit-branch|rebase-branch)=([^ ]+?) -->(.*)$`)
	vulnHeader = regexp.MustCompile(`(?m)^#{2,4} (GitHub Vulnerability Alerts|Vulnerability Alerts)`)
)

// ParsePR extracts the updates from a Renovate PR body's table.
func ParsePR(body string) []Dep {
	var out []Dep
	for _, m := range tableRow.FindAllStringSubmatch(body, -1) {
		name := strings.TrimSpace(m[1])
		if name == "" {
			name = strings.TrimSpace(m[2])
		}
		if name == "" || name == "Package" || strings.HasPrefix(name, "---") {
			continue
		}
		d := Dep{Name: name, From: m[3], To: m[4]}
		if from, err := version.Parse(d.From); err == nil {
			if to, err := version.Parse(d.To); err == nil {
				d.UpdateType = version.UpdateType(from, to)
			}
		} else if len(d.From) >= 7 && len(d.To) >= 7 {
			d.UpdateType = "digest"
		}
		out = append(out, d)
	}
	return out
}

// IsSecurity reports a Renovate vulnerability-alert PR.
func IsSecurity(title, body string, labels []string) bool {
	for _, l := range labels {
		if strings.EqualFold(l, "security") {
			return true
		}
	}
	return strings.Contains(title, "[SECURITY]") || vulnHeader.MatchString(body)
}

// RebaseRequested reports whether the rebase/retry box is ticked.
func RebaseRequested(body string) bool {
	m := rebaseBox.FindStringSubmatch(body)
	return m != nil && m[1] != " "
}

// ErrNoCheckbox means the body lacks the expected Renovate checkbox.
var ErrNoCheckbox = errors.New("renovate: checkbox not found")

// TickRebase ticks the rebase/retry box (asks Renovate to rebase and so
// re-run CI). Idempotent.
func TickRebase(body string) (string, error) {
	loc := rebaseBox.FindStringSubmatchIndex(body)
	if loc == nil {
		return body, ErrNoCheckbox
	}
	return body[:loc[2]] + "x" + body[loc[3]:], nil
}

// Item is one dashboard checkbox line.
type Item struct {
	Kind    string // approve-branch | approvePr-branch | unlimit-branch | rebase-branch
	Branch  string
	Title   string
	Checked bool
}

// Dashboard is the parsed Dependency Dashboard.
type Dashboard struct {
	PendingApproval []Item
	RateLimited     []Item
	Open            []Item
}

// ParseDashboard reads the dashboard's checkbox sections.
func ParseDashboard(body string) Dashboard {
	var d Dashboard
	for _, m := range dashboxRe.FindAllStringSubmatch(body, -1) {
		it := Item{Kind: m[2], Branch: m[3], Title: strings.TrimSpace(m[4]), Checked: m[1] != " "}
		switch it.Kind {
		case "approve-branch", "approvePr-branch":
			d.PendingApproval = append(d.PendingApproval, it)
		case "unlimit-branch":
			d.RateLimited = append(d.RateLimited, it)
		case "rebase-branch":
			d.Open = append(d.Open, it)
		}
	}
	return d
}

func setApproval(body, branch string, checked bool) (string, error) {
	for _, loc := range dashboxRe.FindAllStringSubmatchIndex(body, -1) {
		kind := body[loc[4]:loc[5]]
		if (kind != "approve-branch" && kind != "approvePr-branch") || body[loc[6]:loc[7]] != branch {
			continue
		}
		mark := " "
		if checked {
			mark = "x"
		}
		return body[:loc[2]] + mark + body[loc[3]:], nil
	}
	return body, ErrNoCheckbox
}

// Approve ticks the approval box of branch. Idempotent.
func Approve(body, branch string) (string, error) { return setApproval(body, branch, true) }

// Unapprove clears the approval box of branch.
func Unapprove(body, branch string) (string, error) { return setApproval(body, branch, false) }
