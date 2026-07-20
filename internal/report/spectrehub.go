package report

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-74@v3: spectre/v1 accepts info even though native scanners currently emit low and above.
const spectreHubInfoSeverity iam.Severity = "info"

// WO-74@v3: spectrehubEnvelope maps supported native findings onto the stable spectre/v1 contract.
type spectrehubEnvelope struct {
	Schema    string              `json:"schema"`
	Tool      string              `json:"tool"`
	Version   string              `json:"version"`
	Timestamp time.Time           `json:"timestamp"`
	Target    Target              `json:"target"`
	Findings  []spectrehubFinding `json:"findings"`
	Summary   spectrehubSummary   `json:"summary"`
}

// WO-74@v3: spectrehubFinding preserves consumer identity and supported severity fields explicitly.
type spectrehubFinding struct {
	ID       iam.FindingID `json:"id"`
	Severity iam.Severity  `json:"severity"`
	Location string        `json:"location"`
	Message  string        `json:"message"`
}

// WO-74@v3: spectrehubSummary uses the canonical transport counter names.
type spectrehubSummary struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

// Generate produces spectre/v1 envelope JSON output.
func (r *SpectreHubReporter) Generate(data Data) error {
	// WO-74@v3: fail closed until the consumer can represent coverage without dropping evidence.
	if len(data.Coverage.Gaps) > 0 || data.Coverage.EvaluableOpportunities != 0 ||
		data.Coverage.TotalOpportunities != 0 || data.Coverage.UniqueMissingCapabilities != 0 ||
		data.Coverage.OldestEvidence != nil {
		return fmt.Errorf("spectre/v1 does not support coverage_manifest; coordinated consumer support is required")
	}
	// WO-74@v3: explicit projection prevents native field names from leaking into spectre/v1.
	findings := make([]spectrehubFinding, 0, len(data.Findings))
	summary := spectrehubSummary{}
	for _, finding := range data.Findings {
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
