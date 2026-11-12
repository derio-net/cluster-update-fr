package live

// SeverityRank orders Trivy severities (higher is worse).
func SeverityRank(s string) int {
	switch s {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

// Alarming is the alarm threshold (spec "left to the builder", suggestion
// taken): every Critical, and High when a fixed version exists.
func Alarming(v Vuln) bool {
	switch v.Severity {
	case "CRITICAL":
		return true
	case "HIGH":
		return v.Fixed != ""
	}
	return false
}
