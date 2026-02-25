package analyzer

import (
	"testing"

	"github.com/ppiankov/iamspectre/internal/iam"
)

func TestAnalyze_FiltersBySeverity(t *testing.T) {
	result := &iam.ScanResult{
		PrincipalsScanned: 10,
		Findings: []iam.Finding{
			{ID: iam.FindingNoMFA, Severity: iam.SeverityCritical, ResourceType: iam.ResourceIAMUser},
			{ID: iam.FindingStaleUser, Severity: iam.SeverityHigh, ResourceType: iam.ResourceIAMUser},
			{ID: iam.FindingUnusedRole, Severity: iam.SeverityMedium, ResourceType: iam.ResourceIAMRole},
			{ID: iam.FindingUnattachedPolicy, Severity: iam.SeverityLow, ResourceType: iam.ResourceIAMPolicy},
		},
	}

	analysis := Analyze(result, AnalyzerConfig{SeverityMin: iam.SeverityHigh})

	if len(analysis.Findings) != 2 {
		t.Fatalf("expected 2 findings (critical+high), got %d", len(analysis.Findings))
	}
	if analysis.Findings[0].ID != iam.FindingNoMFA {
		t.Fatalf("expected first finding NO_MFA, got %s", analysis.Findings[0].ID)
	}
	if analysis.Findings[1].ID != iam.FindingStaleUser {
		t.Fatalf("expected second finding STALE_USER, got %s", analysis.Findings[1].ID)
	}
}

func TestAnalyze_NoMinimum(t *testing.T) {
	result := &iam.ScanResult{
		PrincipalsScanned: 5,
		Findings: []iam.Finding{
			{ID: iam.FindingNoMFA, Severity: iam.SeverityCritical},
			{ID: iam.FindingUnusedRole, Severity: iam.SeverityMedium},
			{ID: iam.FindingUnattachedPolicy, Severity: iam.SeverityLow},
		},
	}

	// Empty severity maps to rank 0, so all findings pass
	analysis := Analyze(result, AnalyzerConfig{SeverityMin: ""})

	if len(analysis.Findings) != 3 {
		t.Fatalf("expected all 3 findings, got %d", len(analysis.Findings))
	}
}

func TestAnalyze_LowIncludesAll(t *testing.T) {
	result := &iam.ScanResult{
		Findings: []iam.Finding{
			{ID: iam.FindingNoMFA, Severity: iam.SeverityCritical},
			{ID: iam.FindingStaleUser, Severity: iam.SeverityHigh},
			{ID: iam.FindingUnusedRole, Severity: iam.SeverityMedium},
			{ID: iam.FindingUnattachedPolicy, Severity: iam.SeverityLow},
		},
	}

	analysis := Analyze(result, AnalyzerConfig{SeverityMin: iam.SeverityLow})

	if len(analysis.Findings) != 4 {
		t.Fatalf("expected all 4 findings with low minimum, got %d", len(analysis.Findings))
	}
}

func TestAnalyze_CriticalOnly(t *testing.T) {
	result := &iam.ScanResult{
		Findings: []iam.Finding{
			{ID: iam.FindingNoMFA, Severity: iam.SeverityCritical},
			{ID: iam.FindingStaleUser, Severity: iam.SeverityHigh},
			{ID: iam.FindingUnusedRole, Severity: iam.SeverityMedium},
		},
	}

	analysis := Analyze(result, AnalyzerConfig{SeverityMin: iam.SeverityCritical})

	if len(analysis.Findings) != 1 {
		t.Fatalf("expected 1 critical finding, got %d", len(analysis.Findings))
	}
	if analysis.Findings[0].Severity != iam.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", analysis.Findings[0].Severity)
	}
}

func TestAnalyze_NoFindings(t *testing.T) {
	result := &iam.ScanResult{
		PrincipalsScanned: 20,
	}

	analysis := Analyze(result, AnalyzerConfig{SeverityMin: iam.SeverityLow})

	if len(analysis.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(analysis.Findings))
	}
	if analysis.Summary.TotalPrincipalsScanned != 20 {
		t.Fatalf("expected 20 principals, got %d", analysis.Summary.TotalPrincipalsScanned)
	}
	if analysis.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 total findings, got %d", analysis.Summary.TotalFindings)
	}
}

func TestAnalyze_Summary(t *testing.T) {
	result := &iam.ScanResult{
		PrincipalsScanned: 15,
		Findings: []iam.Finding{
			{ID: iam.FindingNoMFA, Severity: iam.SeverityCritical, ResourceType: iam.ResourceIAMUser},
			{ID: iam.FindingStaleUser, Severity: iam.SeverityHigh, ResourceType: iam.ResourceIAMUser},
			{ID: iam.FindingStaleAccessKey, Severity: iam.SeverityHigh, ResourceType: iam.ResourceIAMUser},
			{ID: iam.FindingUnusedRole, Severity: iam.SeverityMedium, ResourceType: iam.ResourceIAMRole},
			{ID: iam.FindingUnattachedPolicy, Severity: iam.SeverityMedium, ResourceType: iam.ResourceIAMPolicy},
		},
		Errors: []string{"partial scan error"},
	}

	analysis := Analyze(result, AnalyzerConfig{SeverityMin: iam.SeverityLow})

	s := analysis.Summary
	if s.TotalPrincipalsScanned != 15 {
		t.Fatalf("expected 15 principals, got %d", s.TotalPrincipalsScanned)
	}
	if s.TotalFindings != 5 {
		t.Fatalf("expected 5 total findings, got %d", s.TotalFindings)
	}

	// by_severity
	if s.BySeverity["critical"] != 1 {
		t.Fatalf("expected 1 critical, got %d", s.BySeverity["critical"])
	}
	if s.BySeverity["high"] != 2 {
		t.Fatalf("expected 2 high, got %d", s.BySeverity["high"])
	}
	if s.BySeverity["medium"] != 2 {
		t.Fatalf("expected 2 medium, got %d", s.BySeverity["medium"])
	}

	// by_resource_type
	if s.ByResourceType["iam_user"] != 3 {
		t.Fatalf("expected 3 iam_user, got %d", s.ByResourceType["iam_user"])
	}
	if s.ByResourceType["iam_role"] != 1 {
		t.Fatalf("expected 1 iam_role, got %d", s.ByResourceType["iam_role"])
	}
	if s.ByResourceType["iam_policy"] != 1 {
		t.Fatalf("expected 1 iam_policy, got %d", s.ByResourceType["iam_policy"])
	}

	// by_finding_id
	if s.ByFindingID["NO_MFA"] != 1 {
		t.Fatalf("expected 1 NO_MFA, got %d", s.ByFindingID["NO_MFA"])
	}
	if s.ByFindingID["STALE_USER"] != 1 {
		t.Fatalf("expected 1 STALE_USER, got %d", s.ByFindingID["STALE_USER"])
	}
	if s.ByFindingID["STALE_ACCESS_KEY"] != 1 {
		t.Fatalf("expected 1 STALE_ACCESS_KEY, got %d", s.ByFindingID["STALE_ACCESS_KEY"])
	}

	// errors passed through
	if len(analysis.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(analysis.Errors))
	}
}

func TestAnalyze_ErrorsPassedThrough(t *testing.T) {
	result := &iam.ScanResult{
		Errors: []string{"error1", "error2"},
	}

	analysis := Analyze(result, AnalyzerConfig{})

	if len(analysis.Errors) != 2 {
		t.Fatalf("expected 2 errors, got %d", len(analysis.Errors))
	}
}

func TestAnalyze_AllFilteredOut(t *testing.T) {
	result := &iam.ScanResult{
		PrincipalsScanned: 5,
		Findings: []iam.Finding{
			{ID: iam.FindingUnattachedPolicy, Severity: iam.SeverityLow},
			{ID: iam.FindingUnusedRole, Severity: iam.SeverityMedium},
		},
	}

	analysis := Analyze(result, AnalyzerConfig{SeverityMin: iam.SeverityCritical})

	if len(analysis.Findings) != 0 {
		t.Fatalf("expected 0 findings after filter, got %d", len(analysis.Findings))
	}
	if analysis.Summary.TotalFindings != 0 {
		t.Fatalf("expected 0 total findings, got %d", analysis.Summary.TotalFindings)
	}
	if analysis.Summary.TotalPrincipalsScanned != 5 {
		t.Fatalf("expected 5 principals, got %d", analysis.Summary.TotalPrincipalsScanned)
	}
}
