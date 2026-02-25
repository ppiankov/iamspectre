package analyzer

import (
	"github.com/ppiankov/iamspectre/internal/iam"
)

// Summary holds aggregated statistics about scan findings.
type Summary struct {
	TotalPrincipalsScanned int            `json:"total_principals_scanned"`
	TotalFindings          int            `json:"total_findings"`
	BySeverity             map[string]int `json:"by_severity"`
	ByResourceType         map[string]int `json:"by_resource_type"`
	ByFindingID            map[string]int `json:"by_finding_id"`
}

// AnalysisResult holds filtered findings and computed summary.
type AnalysisResult struct {
	Findings []iam.Finding `json:"findings"`
	Summary  Summary       `json:"summary"`
	Errors   []string      `json:"errors,omitempty"`
}

// AnalyzerConfig controls analysis behavior.
type AnalyzerConfig struct {
	SeverityMin iam.Severity
}
