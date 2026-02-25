package report

import (
	"encoding/json"

	"github.com/ppiankov/iamspectre/internal/iam"
)

type sarifReport struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	HelpURI          string       `json:"helpUri,omitempty"`
}

type sarifResult struct {
	RuleID  string         `json:"ruleId"`
	Level   string         `json:"level"`
	Message sarifMessage   `json:"message"`
	Props   map[string]any `json:"properties,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

// Generate produces SARIF v2.1.0 output.
func (r *SARIFReporter) Generate(data Data) error {
	results := make([]sarifResult, 0, len(data.Findings))
	for _, f := range data.Findings {
		props := map[string]any{
			"resource_type":  string(f.ResourceType),
			"resource_id":    f.ResourceID,
			"recommendation": f.Recommendation,
		}
		if f.ResourceName != "" {
			props["resource_name"] = f.ResourceName
		}
		for k, v := range f.Metadata {
			props[k] = v
		}

		results = append(results, sarifResult{
			RuleID:  string(f.ID),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Message},
			Props:   props,
		})
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "iamspectre",
						Version:        data.Version,
						InformationURI: "https://github.com/ppiankov/iamspectre",
						Rules:          buildSARIFRules(),
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func sarifLevel(s iam.Severity) string {
	switch s {
	case iam.SeverityCritical, iam.SeverityHigh:
		return "error"
	case iam.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}

func buildSARIFRules() []sarifRule {
	return []sarifRule{
		{ID: string(iam.FindingStaleUser), ShortDescription: sarifMessage{Text: "Stale IAM user"}},
		{ID: string(iam.FindingStaleAccessKey), ShortDescription: sarifMessage{Text: "Stale access key"}},
		{ID: string(iam.FindingNoMFA), ShortDescription: sarifMessage{Text: "Console user without MFA"}},
		{ID: string(iam.FindingUnusedRole), ShortDescription: sarifMessage{Text: "Unused IAM role"}},
		{ID: string(iam.FindingUnattachedPolicy), ShortDescription: sarifMessage{Text: "Unattached IAM policy"}},
		{ID: string(iam.FindingWildcardPolicy), ShortDescription: sarifMessage{Text: "Wildcard IAM policy"}},
		{ID: string(iam.FindingCrossAccountTrust), ShortDescription: sarifMessage{Text: "Cross-account trust without conditions"}},
		{ID: string(iam.FindingStaleSA), ShortDescription: sarifMessage{Text: "Stale service account"}},
		{ID: string(iam.FindingStaleSAKey), ShortDescription: sarifMessage{Text: "Stale service account key"}},
		{ID: string(iam.FindingOverprivilegedSA), ShortDescription: sarifMessage{Text: "Overprivileged service account"}},
	}
}
