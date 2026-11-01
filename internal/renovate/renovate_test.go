package renovate

import (
	"os"
	"strings"
	"testing"
)

func read(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../testdata/renovate/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParsePRBody(t *testing.T) {
	deps := ParsePR(read(t, "pr-single.md"))
	if len(deps) != 1 {
		t.Fatalf("deps = %+v", deps)
	}
	d := deps[0]
	if d.Name != "ghcr.io/berriai/litellm" || d.From != "v1.80.0" || d.To != "v1.80.3" || d.UpdateType != "patch" {
		t.Errorf("dep = %+v", d)
	}
	sec := ParsePR(read(t, "pr-security.md"))
	if len(sec) != 1 || sec[0].Name != "golang.org/x/net" || sec[0].To != "v0.33.0" || sec[0].UpdateType != "minor" {
		t.Errorf("security dep = %+v", sec)
	}
}

func TestSecurityDetection(t *testing.T) {
	if !IsSecurity("Update golang.org/x/net to v0.33.0 [SECURITY]", "", nil) {
		t.Error("title marker")
	}
	if !IsSecurity("x", "", []string{"security"}) {
		t.Error("label")
	}
	if !IsSecurity("x", read(t, "pr-security.md"), nil) {
		t.Error("vulnerability alerts section")
	}
	if IsSecurity("Update litellm", read(t, "pr-single.md"), []string{"dependencies"}) {
		t.Error("ordinary PR flagged as security")
	}
}

func TestRebaseCheckbox(t *testing.T) {
	body := read(t, "pr-single.md")
	if RebaseRequested(body) {
		t.Fatal("unticked box read as ticked")
	}
	ticked, err := TickRebase(body)
	if err != nil || !RebaseRequested(ticked) {
		t.Fatalf("TickRebase: %v", err)
	}
	again, _ := TickRebase(ticked)
	if again != ticked {
		t.Error("TickRebase must be idempotent")
	}
	if strings.Count(ticked, "rebase-check") != 1 {
		t.Error("checkbox duplicated")
	}
	if _, err := TickRebase("no checkbox here"); err == nil {
		t.Error("a PR without the checkbox (not a Renovate PR) must error")
	}
}

func TestDashboard(t *testing.T) {
	d := ParseDashboard(read(t, "dashboard.md"))
	if len(d.PendingApproval) != 2 || d.PendingApproval[0].Branch != "renovate/talos-1.x" || d.PendingApproval[0].Checked ||
		!strings.Contains(d.PendingApproval[0].Title, "siderolabs/talos to v1.13.4") {
		t.Fatalf("pending = %+v", d.PendingApproval)
	}
	if len(d.RateLimited) != 1 || len(d.Open) != 1 || d.Open[0].Branch != "renovate/litellm-1.x" {
		t.Errorf("dashboard = %+v", d)
	}
	body := read(t, "dashboard.md")
	b2, err := Approve(body, "renovate/talos-1.x")
	if err != nil {
		t.Fatal(err)
	}
	d2 := ParseDashboard(b2)
	if !d2.PendingApproval[0].Checked || d2.PendingApproval[1].Checked {
		t.Errorf("approve ticked the wrong boxes: %+v", d2.PendingApproval)
	}
	b3, _ := Approve(b2, "renovate/talos-1.x")
	if b3 != b2 {
		t.Error("Approve must be idempotent")
	}
	b4, err := Unapprove(b2, "renovate/talos-1.x")
	if err != nil || b4 != body {
		t.Error("Unapprove must restore the original body")
	}
	if _, err := Approve(body, "renovate/nope"); err == nil {
		t.Error("unknown branch must error")
	}
	// The "approve all" box is never a branch and is never ticked by the console.
	for _, it := range d.PendingApproval {
		if strings.Contains(it.Branch, "all-pending") {
			t.Error("approve-all leaked in as a branch")
		}
	}
}
