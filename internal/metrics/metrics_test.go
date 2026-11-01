package metrics

import (
	"strings"
	"testing"
	"time"
)

func TestExpositionCarriesFranksNames(t *testing.T) {
	s := Snapshot{
		VersionsBehind: []Behind{{Cluster: "frank", Component: "os/talos", Value: 2}, {Cluster: "hop", Component: `we"ird\name`, Value: 1}},
		VulnsOpen:      map[string]map[string]int{"frank": {"CRITICAL": 1, "HIGH": 3}},
		LastReport:     time.Unix(1700000000, 0),
		LastScan:       time.Unix(1700000500, 0),
		Updates:        map[string]int{"pending": 2, "verified": 5},
		Alarms:         map[string]int{"open": 1, "overdue": 0, "resolved": 4},
	}
	out := Render(s)
	for _, want := range []string{
		"# TYPE cluster_update_versions_behind gauge",
		`cluster_update_versions_behind{cluster="frank",component="os/talos"} 2`,
		`cluster_update_versions_behind{cluster="hop",component="we\"ird\\name"} 1`,
		"# TYPE cluster_update_vulns_open gauge",
		`cluster_update_vulns_open{cluster="frank",severity="CRITICAL"} 1`,
		"cluster_update_last_report_timestamp_seconds 1700000000",
		"cluster_update_last_scan_timestamp_seconds 1700000500",
		`cluster_update_updates{state="pending"} 2`,
		`cluster_update_alarms{state="overdue"} 0`,
		"# HELP cluster_update_alarms",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	// Deterministic order: same input, same output.
	if Render(s) != out {
		t.Error("output not deterministic")
	}
}

func TestZeroTimestampsExportZero(t *testing.T) {
	out := Render(Snapshot{})
	if !strings.Contains(out, "cluster_update_last_report_timestamp_seconds 0") {
		t.Errorf("never-sent report must export 0 so the dead-man rule fires:\n%s", out)
	}
}
