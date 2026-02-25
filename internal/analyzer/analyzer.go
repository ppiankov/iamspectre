package analyzer

import (
	"github.com/ppiankov/iamspectre/internal/iam"
)

// Analyze filters findings by severity and computes summary statistics.
func Analyze(result *iam.ScanResult, cfg AnalyzerConfig) *AnalysisResult {
	minRank := iam.SeverityRank(cfg.SeverityMin)

	var filtered []iam.Finding
	for _, f := range result.Findings {
		if iam.SeverityRank(f.Severity) >= minRank {
			filtered = append(filtered, f)
		}
	}

	summary := Summary{
		TotalPrincipalsScanned: result.PrincipalsScanned,
		TotalFindings:          len(filtered),
		BySeverity:             make(map[string]int),
		ByResourceType:         make(map[string]int),
		ByFindingID:            make(map[string]int),
	}

	for _, f := range filtered {
		summary.BySeverity[string(f.Severity)]++
		summary.ByResourceType[string(f.ResourceType)]++
		summary.ByFindingID[string(f.ID)]++
	}

	return &AnalysisResult{
		Findings: filtered,
		Summary:  summary,
		Errors:   result.Errors,
	}
}
