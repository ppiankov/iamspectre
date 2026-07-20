package report

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-74@v5: name the current consumer allowlist so producer validation cannot drift silently.
const (
	spectreHubInfoSeverity iam.Severity = "info"
	spectreHubTargetAWS    string       = "aws-account"
	spectreHubTargetGCP    string       = "gcp-project"
)

// WO-74@v5: mirror the current consumer schema's release-version requirement.
var spectreHubVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]`)

// WO-74@v5: spectrehubEnvelope maps supported native findings onto the stable spectre/v1 contract.
type spectrehubEnvelope struct {
	Schema    string              `json:"schema"`
	Tool      string              `json:"tool"`
	Version   string              `json:"version"`
	Timestamp time.Time           `json:"timestamp"`
	Target    Target              `json:"target"`
	Findings  []spectrehubFinding `json:"findings"`
	Summary   spectrehubSummary   `json:"summary"`
}

// WO-74@v5: spectrehubFinding preserves consumer identity and supported severity fields explicitly.
type spectrehubFinding struct {
	ID       iam.FindingID `json:"id"`
	Severity iam.Severity  `json:"severity"`
	Location string        `json:"location"`
	Message  string        `json:"message"`
}

// WO-74@v5: spectrehubSummary uses the canonical transport counter names.
type spectrehubSummary struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

// Generate produces spectre/v1 envelope JSON output.
func (r *SpectreHubReporter) Generate(data Data) error {
	// WO-74@v5: required envelope metadata must pass the consumer contract before any output.
	if data.Tool != "iamspectre" {
		return fmt.Errorf("spectre/v1 requires tool %q, got %q", "iamspectre", data.Tool)
	}
	if !spectreHubVersionPattern.MatchString(data.Version) {
		return fmt.Errorf("spectre/v1 requires a semantic version, got %q", data.Version)
	}
	if data.Timestamp.IsZero() {
		return fmt.Errorf("spectre/v1 requires a nonzero timestamp")
	}
	// WO-74@v5: fail closed until the consumer can represent diagnostics and coverage without loss.
	if len(data.Errors) > 0 {
		return fmt.Errorf("spectre/v1 does not support scan diagnostics; coordinated consumer support is required")
	}
	if len(data.Coverage.Gaps) > 0 || data.Coverage.EvaluableOpportunities != 0 ||
		data.Coverage.TotalOpportunities != 0 || data.Coverage.UniqueMissingCapabilities != 0 ||
		data.Coverage.OldestEvidence != nil {
		return fmt.Errorf("spectre/v1 does not support coverage_manifest; coordinated consumer support is required")
	}
	switch data.Target.Type {
	case spectreHubTargetAWS, spectreHubTargetGCP:
	default:
		return fmt.Errorf("spectre/v1 does not support target type %q", data.Target.Type)
	}
	// WO-74@v5: explicit validation and projection prevent invalid identity from reaching consumers.
	findings := make([]spectrehubFinding, 0, len(data.Findings))
	summary := spectrehubSummary{}
	for _, finding := range data.Findings {
		if finding.ID == "" {
			return fmt.Errorf("spectre/v1 finding id must not be empty")
		}
		if finding.ResourceID == "" {
			return fmt.Errorf("spectre/v1 finding location must not be empty for finding %s", finding.ID)
		}
		if finding.Message == "" {
			return fmt.Errorf("spectre/v1 finding message must not be empty for finding %s", finding.ID)
		}
		switch finding.Severity {
		case iam.SeverityHigh:
			summary.High++
		case iam.SeverityMedium:
			summary.Medium++
		case iam.SeverityLow:
			summary.Low++
		case spectreHubInfoSeverity:
			summary.Info++
		case iam.SeverityCritical:
			return fmt.Errorf("spectre/v1 does not support critical severity for finding %s", finding.ID)
		default:
			return fmt.Errorf("spectre/v1 does not support severity %q for finding %s", finding.Severity, finding.ID)
		}
		summary.Total++
		findings = append(findings, spectrehubFinding{
			ID: finding.ID, Severity: finding.Severity, Location: finding.ResourceID, Message: finding.Message,
		})
	}
	envelope := spectrehubEnvelope{
		Schema: "spectre/v1", Tool: data.Tool, Version: data.Version, Timestamp: data.Timestamp,
		Target: data.Target, Findings: findings,
		Summary: summary,
	}
	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}
