package live

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/derio-net/cluster-update-fr/internal/scrub"
)

// HopScanPrefix starts every result line the Frank hop-scan CronJob writes:
//
//	hop-scan result {"image": "...", "namespace": "...",
//	  "vulnerabilities": [{"id","severity","pkg","installed","fixed","title"}]}
//
// Hop has no Trivy Operator (4 GB node), so its findings arrive through
// VictoriaLogs rather than VulnerabilityReport objects.
const HopScanPrefix = "hop-scan result "

// HopScan queries VictoriaLogs for the latest day's hop-scan results. When an
// image appears more than once, the last line wins.
func HopScan(ctx context.Context, client *http.Client, base string) ([]Report, error) {
	q := url.Values{}
	q.Set("query", `_time:26h _msg:"hop-scan result"`)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/select/logsql/query?"+q.Encode(), nil)
	if err != nil {
		return nil, err
	}
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("live: hop-scan query: %s", scrub.String(err.Error()))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("live: hop-scan query: %d %s", resp.StatusCode, scrub.String(string(b)))
	}
	return ParseHopScan(resp.Body)
}

// ParseHopScan parses VictoriaLogs JSON lines.
func ParseHopScan(r io.Reader) ([]Report, error) {
	byImage := map[string]int{}
	var out []Report
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		var line struct {
			Msg string `json:"_msg"`
		}
		if json.Unmarshal(sc.Bytes(), &line) != nil {
			continue
		}
		i := strings.Index(line.Msg, HopScanPrefix)
		if i < 0 {
			continue
		}
		var res struct {
			Image     string `json:"image"`
			Namespace string `json:"namespace"`
			Vulns     []struct {
				ID, Severity, Pkg, Installed, Fixed, Title string
			} `json:"vulnerabilities"`
		}
		if json.Unmarshal([]byte(line.Msg[i+len(HopScanPrefix):]), &res) != nil || res.Image == "" {
			continue
		}
		rep := Report{Namespace: res.Namespace, Image: NormalizeImage(res.Image)}
		for _, v := range res.Vulns {
			rep.Vulns = append(rep.Vulns, Vuln{ID: v.ID, Severity: strings.ToUpper(v.Severity), Package: v.Pkg, Installed: v.Installed, Fixed: v.Fixed, Title: v.Title})
		}
		if j, ok := byImage[rep.Image]; ok {
			out[j] = rep
			continue
		}
		byImage[rep.Image] = len(out)
		out = append(out, rep)
	}
	return out, sc.Err()
}
