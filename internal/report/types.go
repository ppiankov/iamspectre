package report

import (
	"io"
	"time"

	"github.com/ppiankov/iamspectre/internal/analyzer"
	"github.com/ppiankov/iamspectre/internal/iam"
)

// Reporter is the interface for output formatters.
type Reporter interface {
	Generate(data Data) error
}

// Data holds all information needed to generate a report.
type Data struct {
	Tool      string           `json:"tool"`
	Version   string           `json:"version"`
	Timestamp time.Time        `json:"timestamp"`
	Target    Target           `json:"target"`
	Config    ReportConfig     `json:"config"`
	Findings  []iam.Finding    `json:"findings"`
	Summary   analyzer.Summary `json:"summary"`
	Errors    []string         `json:"errors,omitempty"`
	Coverage  CoverageManifest `json:"coverage_manifest,omitempty"` // WO-70@v4: surface unevaluable checks outside the finding plane.
}

// WO-70@v4: CoverageManifest summarizes missing evidence without inventing alerts.
type CoverageManifest struct {
	Gaps                      []CoverageGap `json:"gaps,omitempty"`
	EvaluableOpportunities    int           `json:"evaluable_opportunities"`
	TotalOpportunities        int           `json:"total_opportunities"`
	UniqueMissingCapabilities int           `json:"unique_missing_capabilities"`
	OldestEvidence            *time.Time    `json:"oldest_evidence,omitempty"`
}

// WO-70@v4: CoverageGap is one deterministically merged causal gap and scope.
type CoverageGap struct {
	Capability        string                 `json:"capability"`
	Cause             string                 `json:"cause"`
	Scope             string                 `json:"scope"`
	AffectedFindings  []AffectedFindingClass `json:"affected_findings"`
	EvaluableCount    int                    `json:"evaluable_count"`
	TotalCount        int                    `json:"total_count"`
	OldestEvidence    *time.Time             `json:"oldest_evidence,omitempty"`
	ObservationWindow string                 `json:"observation_window,omitempty"`
	FeatureStage      string                 `json:"feature_stage,omitempty"`
	MaxConsequence    iam.Severity           `json:"max_consequence"`
}

// WO-70@v4: AffectedFindingClass retains the unresolved class count explicitly.
type AffectedFindingClass struct {
	FindingID iam.FindingID `json:"finding_id"`
	Count     int           `json:"count"`
}

// Target identifies the cloud account being audited.
type Target struct {
	Type    string `json:"type"`
	URIHash string `json:"uri_hash"`
}

// ReportConfig captures the scan configuration used.
type ReportConfig struct {
	StaleDays   int    `json:"stale_days"`
	SeverityMin string `json:"severity_min"`
	Cloud       string `json:"cloud"`
}

// TextReporter generates human-readable terminal output.
type TextReporter struct {
	Writer io.Writer
}

// JSONReporter generates spectre/v1 envelope JSON output.
type JSONReporter struct {
	Writer io.Writer
}

// SpectreHubReporter generates SpectreHub envelope JSON output.
type SpectreHubReporter struct {
	Writer io.Writer
}

// SARIFReporter generates SARIF v2.1.0 output.
type SARIFReporter struct {
	Writer io.Writer
}
