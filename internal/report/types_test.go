package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

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
}

func TestTextReporter_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	r := &TextReporter{Writer: &buf}
	data := testData()
	data.Findings = nil

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "No findings") {
		t.Fatal("expected 'No findings' message")
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

func TestSpectreHubReporter(t *testing.T) {
	var buf bytes.Buffer
	r := &SpectreHubReporter{Writer: &buf}
	data := testData()

	if err := r.Generate(data); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"schema": "spectre/v1"`) {
		t.Fatal("expected spectre/v1 schema")
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
