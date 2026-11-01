// Package metrics renders the Prometheus text exposition frank's Grafana
// dashboard and dead-man rules read (R12). The names are an interface
// contract with derio-net/frank — do not rename them.
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Behind is one versions-behind sample.
type Behind struct {
	Cluster, Component string
	Value              int
}

// Snapshot is everything exported.
type Snapshot struct {
	VersionsBehind []Behind
	VulnsOpen      map[string]map[string]int // cluster -> severity -> count
	LastReport     time.Time
	LastScan       time.Time
	Updates        map[string]int // state -> count
	Alarms         map[string]int // state -> count
	TelegramReady  bool
}

func esc(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

func ts(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Render returns the exposition text.
func Render(s Snapshot) string {
	var b strings.Builder
	head := func(name, help string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	}
	head("cluster_update_versions_behind", "How far a component is behind its latest version (in its most significant semver part).")
	behind := append([]Behind(nil), s.VersionsBehind...)
	sort.Slice(behind, func(i, j int) bool {
		if behind[i].Cluster != behind[j].Cluster {
			return behind[i].Cluster < behind[j].Cluster
		}
		return behind[i].Component < behind[j].Component
	})
	for _, v := range behind {
		fmt.Fprintf(&b, "cluster_update_versions_behind{cluster=\"%s\",component=\"%s\"} %d\n", esc(v.Cluster), esc(v.Component), v.Value)
	}
	head("cluster_update_vulns_open", "Open vulnerabilities in running images, by cluster and severity.")
	for _, c := range sortedKeys(s.VulnsOpen) {
		for _, sev := range sortedKeys(s.VulnsOpen[c]) {
			fmt.Fprintf(&b, "cluster_update_vulns_open{cluster=\"%s\",severity=\"%s\"} %d\n", esc(c), esc(sev), s.VulnsOpen[c][sev])
		}
	}
	head("cluster_update_last_report_timestamp_seconds", "Unix time the last daily report was sent (0 = never).")
	fmt.Fprintf(&b, "cluster_update_last_report_timestamp_seconds %d\n", ts(s.LastReport))
	head("cluster_update_last_scan_timestamp_seconds", "Unix time of the last successful inventory/vulnerability scan (0 = never).")
	fmt.Fprintf(&b, "cluster_update_last_scan_timestamp_seconds %d\n", ts(s.LastScan))
	head("cluster_update_updates", "Updates by lifecycle state.")
	for _, st := range sortedKeys(s.Updates) {
		fmt.Fprintf(&b, "cluster_update_updates{state=\"%s\"} %d\n", esc(st), s.Updates[st])
	}
	head("cluster_update_alarms", "Security alarm records by state.")
	for _, st := range sortedKeys(s.Alarms) {
		fmt.Fprintf(&b, "cluster_update_alarms{state=\"%s\"} %d\n", esc(st), s.Alarms[st])
	}
	head("cluster_update_telegram_configured", "1 when the #security topic bot is fully configured.")
	ready := 0
	if s.TelegramReady {
		ready = 1
	}
	fmt.Fprintf(&b, "cluster_update_telegram_configured %d\n", ready)
	return b.String()
}
