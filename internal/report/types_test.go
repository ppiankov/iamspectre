package report

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ppiankov/iamspectre/internal/analyzer"
	"github.com/ppiankov/iamspectre/internal/iam"
)

func testData() Data {
	return Data{
		Tool:      "iamspectre",
		Version:   "0.1.0",
		Timestamp: time.Date(2026, 2, 25, 12, 0, 0, 0, time.UTC),
		Target: Target{
			Type:    "aws-account",
			URIHash: "sha256:abc123",
		},
		Config: ReportConfig{
			StaleDays:   90,
			SeverityMin: "low",
			Cloud:       "aws",
		},
		Findings: []iam.Finding{
			{
				ID:             iam.FindingNoMFA,
				Severity:       iam.SeverityCritical,
				ResourceType:   iam.ResourceIAMUser,
				ResourceID:     "arn:aws:iam::123456789012:user/admin",
				ResourceName:   "admin",
				Message:        "Console user without MFA",
				Recommendation: "Enable MFA",
			},
			{
				ID:             iam.FindingUnusedRole,
				Severity:       iam.SeverityMedium,
				ResourceType:   iam.ResourceIAMRole,
				ResourceID:     "arn:aws:iam::123456789012:role/old-role",
				Message:        "Role not assumed in 120 days",
				Recommendation: "Delete unused role",
			},
		},
		Summary: analyzer.Summary{
			TotalPrincipalsScanned: 50,
			TotalFindings:          2,
			BySeverity:             map[string]int{"critical": 1, "medium": 1},
			ByResourceType:         map[string]int{"iam_user": 1, "iam_role": 1},
			ByFindingID:            map[string]int{"NO_MFA": 1, "UNUSED_ROLE": 1},
		},
	}
}

// WO-31@v2: the primary fixture pins the text report's self-describing fields.
func TestTextReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}
	data := testData()

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "iamspectre") {
		t.Fatal("expected output to contain iamspectre")
	}
	if !strings.Contains(output, "CRIT") {
		t.Fatal("expected output to contain CRIT severity")
	}
	if !strings.Contains(output, "Enable MFA") {
		t.Fatal("expected output to contain recommendation")
	}
	for _, expected := range []string{"FINDING_ID", "NO_MFA", "Scanned at: 2026-02-25T12:00:00Z", "Severity filter: low"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected output to contain %q", expected)
		}
	}
}

// WO-38: zero findings must not hide summary or scanner failures.
func TestTextReporter_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}
	data := testData()
	data.Findings = nil
	data.Summary.TotalFindings = 0
	data.Errors = []string{"role scanner: denied", "policy scanner: timeout"}

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No findings") {
		t.Fatal("expected 'No findings' message")
	}
	for _, expected := range []string{"Principals scanned: 50", "Total findings: 0", "role scanner: denied", "policy scanner: timeout"} {
		if !strings.Contains(output, expected) {
			t.Fatalf("expected no-findings output to contain %q", expected)
		}
	}
	if strings.Index(output, data.Errors[0]) > strings.Index(output, data.Errors[1]) {
		t.Fatal("expected scan errors in input order")
	}
}

// WO-36@v2: distinguish an absent severity filter from a configured one.
func TestTextReporter_EmptySeverityFilter(t *testing.T) {
	var buf bytes.Buffer
	data := testData()
	data.Config.SeverityMin = ""

	if err := (&TextReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(buf.String(), "Severity filter:") {
		t.Fatal("expected empty severity filter to be omitted")
	}
}

// WO-35@v2: normalize non-UTC scan timestamps deterministically.
func TestTextReporter_TimestampUsesUTC(t *testing.T) {
	var buf bytes.Buffer
	data := testData()
	data.Timestamp = time.Date(2026, 2, 25, 20, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))

	if err := (&TextReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.Contains(buf.String(), "Scanned at: 2026-02-25T12:00:00Z") {
		t.Fatal("expected timestamp normalized to UTC")
	}
}

// WO-42@v2: equivalent finding sets and severity maps must produce identical text.
func TestTextReporter_DeterministicSeverityOrder(t *testing.T) {
	findings := []iam.Finding{
		{ID: "Z_LOW", Severity: iam.SeverityLow, ResourceType: iam.ResourceIAMRole, ResourceID: "z"},
		{ID: "B_HIGH", Severity: iam.SeverityHigh, ResourceType: iam.ResourceIAMRole, ResourceID: "b"},
		{ID: "A_HIGH", Severity: iam.SeverityHigh, ResourceType: iam.ResourceIAMRole, ResourceID: "a"},
		{ID: "C_CRIT", Severity: iam.SeverityCritical, ResourceType: iam.ResourceIAMRole, ResourceID: "c"},
		{ID: "M_MED", Severity: iam.SeverityMedium, ResourceType: iam.ResourceIAMRole, ResourceID: "m"},
		{ID: "ALPHA_UNKNOWN", Severity: iam.Severity("alpha"), ResourceType: iam.ResourceIAMRole, ResourceID: "a"},
		{ID: "OMEGA_UNKNOWN", Severity: iam.Severity("omega"), ResourceType: iam.ResourceIAMRole, ResourceID: "o"},
	}
	render := func(input []iam.Finding, bySeverity map[string]int) string {
		t.Helper()
		data := testData()
		data.Findings = input
		data.Summary.TotalFindings = len(input)
		data.Summary.BySeverity = bySeverity
		before := append([]iam.Finding(nil), input...)
		var buf bytes.Buffer
		if err := (&TextReporter{Writer: &buf}).Generate(data); err != nil {
			t.Fatalf("Generate: %v", err)
		}
		if !reflect.DeepEqual(input, before) {
			t.Fatal("Generate mutated caller-owned findings")
		}
		return buf.String()
	}

	reversed := append([]iam.Finding(nil), findings...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	first := render(findings, map[string]int{"omega": 1, "low": 1, "medium": 1, "alpha": 1, "high": 2, "critical": 1})
	second := render(reversed, map[string]int{"high": 2, "alpha": 1, "critical": 1, "omega": 1, "low": 1, "medium": 1})
	if first != second {
		t.Fatal("equivalent inputs produced different text reports")
	}
	for _, pair := range [][2]string{{"C_CRIT", "A_HIGH"}, {"A_HIGH", "B_HIGH"}, {"B_HIGH", "M_MED"}, {"M_MED", "Z_LOW"}, {"Z_LOW", "ALPHA_UNKNOWN"}, {"ALPHA_UNKNOWN", "OMEGA_UNKNOWN"}} {
		if strings.Index(first, pair[0]) >= strings.Index(first, pair[1]) {
			t.Fatalf("expected %s before %s", pair[0], pair[1])
		}
	}
	if !strings.Contains(first, "By severity: critical=1 high=2 medium=1 low=1 alpha=1 omega=1") {
		t.Fatal("expected canonical severity summary order")
	}
}

// WO-43@v2: long same-prefix resource identifiers must remain complete and distinct.
func TestTextReporter_PreservesFullResourceIDs(t *testing.T) {
	data := testData()
	first := "arn:aws:iam::123456789012:role/team/very-long-shared-prefix/production-reader"
	second := "arn:aws:iam::123456789012:role/team/very-long-shared-prefix/production-writer"
	data.Findings = []iam.Finding{
		{ID: iam.FindingUnusedRole, Severity: iam.SeverityMedium, ResourceType: iam.ResourceIAMRole, ResourceID: first},
		{ID: iam.FindingUnusedRole, Severity: iam.SeverityMedium, ResourceType: iam.ResourceIAMRole, ResourceID: second},
	}
	data.Summary.TotalFindings = 2
	var buf bytes.Buffer
	if err := (&TextReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	output := buf.String()
	if !strings.Contains(output, first) || !strings.Contains(output, second) {
		t.Fatal("expected complete distinct resource IDs")
	}
}

// WO-48: bounded text must never split a UTF-8 code point.
func TestTextReporter_TruncatesByRune(t *testing.T) {
	message := strings.Repeat("界", 60)
	data := testData()
	data.Findings[0].Message = message
	data.Findings[0].Recommendation = message
	var buf bytes.Buffer
	if err := (&TextReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !utf8.ValidString(buf.String()) {
		t.Fatal("text report contains invalid UTF-8")
	}
	if got, want := truncate(message, 50), strings.Repeat("界", 47)+"..."; got != want {
		t.Fatalf("truncate = %q, want %q", got, want)
	}
	if got := truncate("short", 50); got != "short" {
		t.Fatalf("short string changed: %q", got)
	}
	if got, want := truncate(strings.Repeat("a", 60), 50), strings.Repeat("a", 47)+"..."; got != want {
		t.Fatalf("ASCII truncate = %q, want %q", got, want)
	}
}

func TestJSONReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &JSONReporter{Writer: &buf}
	data := testData()

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"$schema": "spectre/v1"`) {
		t.Fatal("expected spectre/v1 schema")
	}
	if !strings.Contains(output, `"tool": "iamspectre"`) {
		t.Fatal("expected tool iamspectre")
	}
	if !strings.Contains(output, `"NO_MFA"`) {
		t.Fatal("expected NO_MFA finding")
	}
}

// WO-74@v3: pin canonical locations, stable IDs, supported severity, and summary field names.
func TestSpectreHubReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &SpectreHubReporter{Writer: &buf}
	data := testData()
	data.Findings[0].Severity = iam.SeverityHigh
	data.Summary.BySeverity = map[string]int{"high": 1, "medium": 1}

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"schema": "spectre/v1"`) {
		t.Fatal("expected spectre/v1 schema")
	}
	if strings.Contains(output, `"resource_id"`) || strings.Contains(output, `"total_findings"`) {
		t.Fatalf("native report fields leaked into spectre/v1: %s", output)
	}
	var envelope spectrehubEnvelope
	if err := json.Unmarshal(buf.Bytes(), &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Findings) != 2 || envelope.Findings[0].Location == envelope.Findings[1].Location || envelope.Findings[0].Location == "" {
		t.Fatalf("finding locations = %#v", envelope.Findings)
	}
	if envelope.Findings[0].ID != iam.FindingNoMFA || envelope.Findings[0].Severity != iam.SeverityHigh {
		t.Fatalf("finding identity/severity = %#v", envelope.Findings[0])
	}
	if envelope.Summary.Total != 2 || envelope.Summary.High != 1 || envelope.Summary.Medium != 1 {
		t.Fatalf("summary = %#v", envelope.Summary)
	}
}

// WO-74@v3: unsupported consumer capabilities fail before emitting partial or invalid JSON.
func TestSpectreHubReporterRejectsUnsupportedData(t *testing.T) {
	tests := []struct {
		name string
		data Data
		want string
	}{
		{name: "critical", data: testData(), want: "does not support critical severity"},
		{name: "coverage", data: Data{Coverage: CoverageManifest{Gaps: []CoverageGap{{Capability: "azure_activity"}}}}, want: "does not support coverage_manifest"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := (&SpectreHubReporter{Writer: &buf}).Generate(tt.data)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			if buf.Len() != 0 {
				t.Fatalf("partial output = %q", buf.String())
			}
		})
	}
}

func TestSARIFReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{Writer: &buf}
	data := testData()

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"version": "2.1.0"`) {
		t.Fatal("expected SARIF version 2.1.0")
	}
	if !strings.Contains(output, `"name": "iamspectre"`) {
		t.Fatal("expected tool name iamspectre")
	}
	if !strings.Contains(output, `"NO_MFA"`) {
		t.Fatal("expected NO_MFA rule")
	}
	// Critical should map to error level
	if !strings.Contains(output, `"level": "error"`) {
		t.Fatal("expected error level for critical severity")
	}
}

func TestSARIFReporter_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &SARIFReporter{Writer: &buf}
	data := testData()
	data.Findings = nil

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"results": []`) {
		t.Fatal("expected empty results array")
	}
}

// WO-32@v2: scanner errors must be structurally visible as a failed SARIF invocation.
func TestSARIFReporter_WithErrors(t *testing.T) {
	var buf bytes.Buffer
	data := testData()
	data.Errors = []string{"user scanner: denied", "role scanner: timeout"}

	if err := (&SARIFReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var got sarifReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	if len(got.Runs) != 1 || len(got.Runs[0].Invocations) != 1 {
		t.Fatalf("expected one invocation, got %#v", got.Runs)
	}
	invocation := got.Runs[0].Invocations[0]
	if invocation.ExecutionSuccessful {
		t.Fatal("expected failed execution")
	}
	var raw struct {
		Runs []struct {
			Invocations []struct {
				ExecutionSuccessful *bool `json:"executionSuccessful"`
			} `json:"invocations"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("decode raw SARIF: %v", err)
	}
	executionSuccessful := raw.Runs[0].Invocations[0].ExecutionSuccessful
	if executionSuccessful == nil || *executionSuccessful {
		t.Fatalf("executionSuccessful = %v, want present false", executionSuccessful)
	}
	if len(invocation.ToolExecutionNotifications) != len(data.Errors) {
		t.Fatalf("expected %d notifications, got %d", len(data.Errors), len(invocation.ToolExecutionNotifications))
	}
	for i, notification := range invocation.ToolExecutionNotifications {
		if notification.Level != "error" || notification.Message.Text != data.Errors[i] {
			t.Fatalf("notification %d = %#v", i, notification)
		}
	}
}

// WO-32@v2: successful reports need no synthetic invocation record.
func TestSARIFReporter_WithoutErrorsOmitsInvocations(t *testing.T) {
	var buf bytes.Buffer
	if err := (&SARIFReporter{Writer: &buf}).Generate(testData()); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if strings.Contains(buf.String(), `"invocations"`) {
		t.Fatal("expected invocations to be omitted without errors")
	}
}

// WO-33@v2: use the report envelope as the canonical SARIF driver identity.
func TestSARIFReporter_ToolName(t *testing.T) {
	var buf bytes.Buffer
	data := testData()
	data.Tool = "custom-tool"
	if err := (&SARIFReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var got sarifReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	if got.Runs[0].Tool.Driver.Name != data.Tool {
		t.Fatalf("driver name = %q, want %q", got.Runs[0].Tool.Driver.Name, data.Tool)
	}
}

// WO-20@v3: every emitted finding kind must have a matching SARIF rule descriptor.
func TestSARIFReporter_RegistersEmittedRules(t *testing.T) {
	var buf bytes.Buffer
	data := testData()
	data.Findings = append(data.Findings, iam.Finding{
		ID:             iam.FindingRootAccessKey,
		Severity:       iam.SeverityCritical,
		ResourceType:   iam.ResourceIAMUser,
		ResourceID:     "arn:aws:iam::123456789012:root",
		Message:        "Root access key present",
		Recommendation: "Remove the root access key",
	})
	if err := (&SARIFReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var got sarifReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	registered := make(map[string]bool, len(got.Runs[0].Tool.Driver.Rules))
	for _, rule := range got.Runs[0].Tool.Driver.Rules {
		registered[rule.ID] = true
	}
	for _, result := range got.Runs[0].Results {
		if !registered[result.RuleID] {
			t.Errorf("result rule %q has no driver descriptor", result.RuleID)
		}
	}
}

// WO-39: arbitrary metadata cannot rewrite canonical SARIF properties.
func TestSARIFReporter_CanonicalPropertiesWin(t *testing.T) {
	var buf bytes.Buffer
	data := testData()
	data.Findings[0].Metadata = map[string]any{
		"resource_type":   "spoofed-type",
		"resource_id":     "spoofed-id",
		"resource_name":   "spoofed-name",
		"recommendation":  "spoofed recommendation",
		"provider_detail": "preserved",
	}
	if err := (&SARIFReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var got sarifReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	props := got.Runs[0].Results[0].Props
	wants := map[string]any{
		"resource_type":   string(data.Findings[0].ResourceType),
		"resource_id":     data.Findings[0].ResourceID,
		"resource_name":   data.Findings[0].ResourceName,
		"recommendation":  data.Findings[0].Recommendation,
		"provider_detail": "preserved",
	}
	for key, want := range wants {
		if got := props[key]; got != want {
			t.Errorf("property %q = %#v, want %#v", key, got, want)
		}
	}

	data.Findings[0].ResourceName = ""
	buf.Reset()
	if err := (&SARIFReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate without resource name: %v", err)
	}
	got = sarifReport{}
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode SARIF without resource name: %v", err)
	}
	if _, exists := got.Runs[0].Results[0].Props["resource_name"]; exists {
		t.Fatal("expected resource_name omitted when canonical value is empty")
	}
}

// WO-20@v3: SARIF independently applies the severity rubric and exposes its evidence.
func TestSARIFReporter_AssessmentProperties(t *testing.T) {
	var buf bytes.Buffer
	data := testData()
	canonicalLayers := iam.CanonicalLayers()
	layers := make(map[iam.AuthorizationLayer]iam.LayerStatus, len(canonicalLayers))
	for _, layer := range canonicalLayers {
		layers[layer] = iam.LayerEvaluated
	}
	tier := iam.EvidenceTierContextualized
	data.Findings[0].Severity = iam.SeverityCritical
	data.Findings[0].EvidenceTier = &tier
	data.Findings[0].State = iam.FindingStateDeterminate
	data.Findings[0].Reachability = iam.ReachabilityUnknown
	data.Findings[0].Impact = iam.SeverityCritical
	data.Findings[0].BlastRadius = iam.BlastRadiusCritical
	data.Findings[0].RubricVersion = iam.RubricVersionV1
	data.Findings[0].EvaluatedLayers = layers

	if err := (&SARIFReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var got sarifReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	result := got.Runs[0].Results[0]
	if result.Level != "warning" {
		t.Fatalf("SARIF level = %q, want warning", result.Level)
	}
	wants := map[string]any{
		"evidence_tier":      float64(iam.EvidenceTierContextualized),
		"state":              string(iam.FindingStateDeterminate),
		"reachability":       string(iam.ReachabilityUnknown),
		"impact":             string(iam.SeverityCritical),
		"blast_radius":       string(iam.BlastRadiusCritical),
		"rubric_version":     string(iam.RubricVersionV1),
		"effective_severity": string(iam.SeverityMedium),
	}
	for key, want := range wants {
		if got := result.Props[key]; got != want {
			t.Errorf("property %q = %#v, want %#v", key, got, want)
		}
	}
	gotLayers, ok := result.Props["evaluated_layers"].(map[string]any)
	if !ok {
		t.Fatalf("evaluated_layers = %#v, want object", result.Props["evaluated_layers"])
	}
	if len(gotLayers) != len(canonicalLayers) {
		t.Fatalf("evaluated_layers has %d entries, want %d", len(gotLayers), len(canonicalLayers))
	}
	for _, layer := range canonicalLayers {
		if got := gotLayers[string(layer)]; got != string(iam.LayerEvaluated) {
			t.Errorf("evaluated_layers[%q] = %#v, want %q", layer, got, iam.LayerEvaluated)
		}
	}
}

// WO-20@v3: SARIF fails closed and exposes invalid partial assessment state without a rubric version.
func TestSARIFReporter_InvalidPartialAssessment(t *testing.T) {
	var buf bytes.Buffer
	data := testData()
	tier := iam.EvidenceTierPolicyShape
	data.Findings[0].Severity = iam.SeverityCritical
	data.Findings[0].EvidenceTier = &tier

	if err := (&SARIFReporter{Writer: &buf}).Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	var got sarifReport
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	result := got.Runs[0].Results[0]
	if result.Level != "warning" {
		t.Fatalf("SARIF level = %q, want warning", result.Level)
	}
	if got := result.Props["state"]; got != string(iam.FindingStateIndeterminate) {
		t.Fatalf("state = %#v, want indeterminate", got)
	}
	if got := result.Props["effective_severity"]; got != string(iam.SeverityMedium) {
		t.Fatalf("effective_severity = %#v, want medium", got)
	}
	if _, ok := result.Props["evidence_tier"]; !ok {
		t.Fatal("invalid partial assessment metadata was omitted")
	}
}

// WO-70@v4: native reporters preserve coverage; SpectreHub fails closed until its schema supports it.
func TestReporters_CoverageManifestPlane(t *testing.T) {
	data := testData()
	data.Findings = nil
	data.Summary.TotalFindings = 0
	data.Coverage = CoverageManifest{
		Gaps: []CoverageGap{{
			Capability: "azure_activity", Cause: "report unavailable", Scope: "tenant:a",
			AffectedFindings: []AffectedFindingClass{{FindingID: iam.FindingStaleSP, Count: 2}},
			TotalCount:       2, FeatureStage: "beta", MaxConsequence: iam.SeverityHigh,
		}},
		TotalOpportunities: 2, UniqueMissingCapabilities: 1,
	}

	var jsonBuffer bytes.Buffer
	if err := (&JSONReporter{Writer: &jsonBuffer}).Generate(data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jsonBuffer.String(), `"coverage_manifest"`) || strings.Contains(jsonBuffer.String(), `"id":"STALE_SP"`) {
		t.Fatalf("JSON mixed coverage with findings: %s", jsonBuffer.String())
	}
	var hubBuffer bytes.Buffer
	if err := (&SpectreHubReporter{Writer: &hubBuffer}).Generate(data); err == nil || !strings.Contains(err.Error(), "does not support coverage_manifest") {
		t.Fatalf("SpectreHub coverage error = %v", err)
	}
	if hubBuffer.Len() != 0 {
		t.Fatalf("SpectreHub emitted partial coverage output: %s", hubBuffer.String())
	}

	var textBuffer bytes.Buffer
	if err := (&TextReporter{Writer: &textBuffer}).Generate(data); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(textBuffer.String(), "Coverage gaps:") || !strings.Contains(textBuffer.String(), "azure_activity") {
		t.Fatalf("text missing coverage plane: %s", textBuffer.String())
	}

	var sarifBuffer bytes.Buffer
	if err := (&SARIFReporter{Writer: &sarifBuffer}).Generate(data); err != nil {
		t.Fatal(err)
	}
	var sarif sarifReport
	if err := json.Unmarshal(sarifBuffer.Bytes(), &sarif); err != nil {
		t.Fatal(err)
	}
	if len(sarif.Runs[0].Results) != 0 || sarif.Runs[0].Properties["coverage_manifest"] == nil {
		t.Fatalf("SARIF coverage plane = %#v", sarif.Runs[0])
	}
}
