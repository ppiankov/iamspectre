package report

import (
	"encoding/json"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-74@v2: spectrehubEnvelope maps native findings onto the stable spectre/v1 transport contract.
type spectrehubEnvelope struct {
	Schema    string              `json:"schema"`
	Tool      string              `json:"tool"`
	Version   string              `json:"version"`
	Timestamp time.Time           `json:"timestamp"`
	Target    Target              `json:"target"`
	Findings  []spectrehubFinding `json:"findings"`
	Summary   spectrehubSummary   `json:"summary"`
	Coverage  CoverageManifest    `json:"coverage_manifest,omitempty"`
}

// WO-74@v2: spectrehubFinding preserves consumer identity and severity fields explicitly.
type spectrehubFinding struct {
	ID       iam.FindingID `json:"id"`
	Severity iam.Severity  `json:"severity"`
	Location string        `json:"location"`
	Message  string        `json:"message"`
}

// WO-74@v2: spectrehubSummary uses the canonical transport counter names.
type spectrehubSummary struct {
	Total  int `json:"total"`
	High   int `json:"high"`
	Medium int `json:"medium"`
	Low    int `json:"low"`
	Info   int `json:"info"`
}

// Generate produces spectre/v1 envelope JSON output.
func (r *SpectreHubReporter) Generate(data Data) error {
	// WO-74@v2: explicit projection prevents native field names from leaking into spectre/v1.
	findings := make([]spectrehubFinding, 0, len(data.Findings))
	for _, finding := range data.Findings {
		findings = append(findings, spectrehubFinding{
			ID: finding.ID, Severity: finding.Severity, Location: finding.ResourceID, Message: finding.Message,
		})
	}
	envelope := spectrehubEnvelope{
		Schema: "spectre/v1", Tool: data.Tool, Version: data.Version, Timestamp: data.Timestamp,
		Target: data.Target, Findings: findings,
		Summary: spectrehubSummary{
			Total: len(findings), High: data.Summary.BySeverity[string(iam.SeverityHigh)],
			Medium: data.Summary.BySeverity[string(iam.SeverityMedium)],
			Low:    data.Summary.BySeverity[string(iam.SeverityLow)],
			Info:   data.Summary.BySeverity["info"],
		},
		Coverage: data.Coverage,
	}
	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	return enc.Encode(envelope)
}
