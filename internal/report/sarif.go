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

// WO-32@v2: sarifRun carries execution notifications for partial scan failures.
type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Results     []sarifResult     `json:"results"`
	Invocations []sarifInvocation `json:"invocations,omitempty"` // WO-32@v2: expose partial scanner failures to SARIF consumers
	Properties  map[string]any    `json:"properties,omitempty"`  // WO-70@v4: coverage is run evidence, not a synthetic result.
}

// WO-32@v2: represent a failed scan execution without hiding the meaningful false value.
type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

// WO-32@v2: carry each scanner failure as a SARIF runtime notification.
type sarifNotification struct {
	Level   string       `json:"level"`
	Message sarifMessage `json:"message"`
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

// WO-30@v2: preserve report identity, failures, and canonical finding properties in SARIF.
func (r *SARIFReporter) Generate(data Data) error {
	results := make([]sarifResult, 0, len(data.Findings))
	for _, f := range data.Findings {
		f = iam.NormalizeSeverity(f) // WO-20@v3: direct reporter use must fail closed like analyzer output.
		props := make(map[string]any, len(f.Metadata)+4)
		for k, v := range f.Metadata {
			props[k] = v
		}
		// WO-39: canonical fields win over arbitrary provider metadata.
		props["resource_type"] = string(f.ResourceType)
		props["resource_id"] = f.ResourceID
		props["recommendation"] = f.Recommendation
		if f.ResourceName != "" {
			props["resource_name"] = f.ResourceName
		} else {
			delete(props, "resource_name")
		}
		// WO-20@v3: expose assessment inputs only when the finding carries assessment metadata.
		if iam.HasAssessment(f) {
			props["evidence_tier"] = f.EvidenceTier
			props["state"] = f.State
			props["reachability"] = f.Reachability
			props["impact"] = f.Impact
			props["blast_radius"] = f.BlastRadius
			props["rubric_version"] = f.RubricVersion
			props["evaluated_layers"] = f.EvaluatedLayers
			props["effective_severity"] = f.Severity
		}

		results = append(results, sarifResult{
			RuleID:  string(f.ID),
			Level:   sarifLevel(f.Severity),
			Message: sarifMessage{Text: f.Message},
			Props:   props,
		})
	}

	var invocations []sarifInvocation
	if len(data.Errors) > 0 {
		notifications := make([]sarifNotification, 0, len(data.Errors))
		for _, scanErr := range data.Errors {
			notifications = append(notifications, sarifNotification{
				Level:   "error",
				Message: sarifMessage{Text: scanErr},
			})
		}
		invocations = []sarifInvocation{{
			ExecutionSuccessful:        false,
			ToolExecutionNotifications: notifications,
		}}
	}

	report := sarifReport{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           data.Tool,
						Version:        data.Version,
						InformationURI: "https://github.com/ppiankov/iamspectre",
						Rules:          buildSARIFRules(),
					},
				},
				Results:     results,
				Invocations: invocations,
				Properties:  sarifCoverageProperties(data.Coverage),
			},
		},
	}

	enc := json.NewEncoder(r.Writer)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// WO-70@v4: omit an empty manifest while preserving the typed plane when present.
func sarifCoverageProperties(manifest CoverageManifest) map[string]any {
	if len(manifest.Gaps) == 0 {
		return nil
	}
	return map[string]any{"coverage_manifest": manifest}
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
		// WO-55@v4: register whole-principal dormancy as its own SARIF rule descriptor.
		{ID: string(iam.FindingInactiveIAMUser), ShortDescription: sarifMessage{Text: "Inactive IAM user"}},
		{ID: string(iam.FindingStaleAccessKey), ShortDescription: sarifMessage{Text: "Stale access key"}},
		{ID: string(iam.FindingNoMFA), ShortDescription: sarifMessage{Text: "Console user without MFA"}},
		{ID: string(iam.FindingUnusedRole), ShortDescription: sarifMessage{Text: "Unused IAM role"}},
		{ID: string(iam.FindingUnattachedPolicy), ShortDescription: sarifMessage{Text: "Unattached IAM policy"}},
		{ID: string(iam.FindingWildcardPolicy), ShortDescription: sarifMessage{Text: "Wildcard IAM policy"}},
		{ID: string(iam.FindingCrossAccountTrust), ShortDescription: sarifMessage{Text: "Cross-account trust without conditions"}},
		{ID: string(iam.FindingStaleSA), ShortDescription: sarifMessage{Text: "Stale service account"}},
		{ID: string(iam.FindingStaleSAKey), ShortDescription: sarifMessage{Text: "Stale service account key"}},
		// WO-69@v2: disabled is a reversible lifecycle fact, registered as its own informational rule.
		{ID: string(iam.FindingDisabledSA), ShortDescription: sarifMessage{Text: "Disabled service account"}},
		{ID: string(iam.FindingOverprivilegedSA), ShortDescription: sarifMessage{Text: "Overprivileged service account"}},
		{ID: string(iam.FindingStaleGuestUser), ShortDescription: sarifMessage{Text: "Stale Azure AD guest user"}},
		{ID: string(iam.FindingLegacyAuth), ShortDescription: sarifMessage{Text: "Legacy authentication not blocked"}},
		{ID: string(iam.FindingStaleApp), ShortDescription: sarifMessage{Text: "Stale app registration"}},
		{ID: string(iam.FindingExpiredSecret), ShortDescription: sarifMessage{Text: "Expired app credential"}},
		{ID: string(iam.FindingExpiringSecret), ShortDescription: sarifMessage{Text: "Expiring app credential"}},
		{ID: string(iam.FindingStaleSP), ShortDescription: sarifMessage{Text: "Stale service principal"}},
		{ID: string(iam.FindingOverprivilegedApp), ShortDescription: sarifMessage{Text: "Overprivileged app permission"}},
		{ID: string(iam.FindingRootAccessKey), ShortDescription: sarifMessage{Text: "Root access key present"}}, // WO-20@v3: register the rubric's direct-harm finding
	}
}
