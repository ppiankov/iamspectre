package gcp

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/ppiankov/iamspectre/internal/iam"
	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
)

type mockCRM struct {
	policy     *crmv1.Policy
	policyErr  error
	project    *crmv1.Project
	projectErr error
}

const testProjectNumber int64 = 123456789

func (m *mockCRM) GetIamPolicy(_ context.Context, _ string) (*crmv1.Policy, error) {
	if m.policyErr != nil {
		return nil, m.policyErr
	}
	return m.policy, nil
}

// WO-83: provide authoritative project-number evidence to binding tests.
func (m *mockCRM) GetProject(_ context.Context, _ string) (*crmv1.Project, error) {
	if m.projectErr != nil {
		return nil, m.projectErr
	}
	if m.project != nil {
		return m.project, nil
	}
	return &crmv1.Project{ProjectNumber: testProjectNumber}, nil
}

func TestBindingScanner_OverprivilegedSA(t *testing.T) {
	mock := &mockCRM{
		policy: &crmv1.Policy{
			Bindings: []*crmv1.Binding{
				{
					Role:    "roles/owner",
					Members: []string{"serviceAccount:sa1@test.iam.gserviceaccount.com"},
				},
			},
		},
	}

	scanner := NewBindingScanner(mock, "test-project")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.ID != iam.FindingOverprivilegedSA {
		t.Fatalf("expected OVERPRIVILEGED_SA, got %s", f.ID)
	}
	if f.Severity != iam.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", f.Severity)
	}
	if f.ResourceType != iam.ResourceIAMBinding {
		t.Fatalf("expected iam_binding, got %s", f.ResourceType)
	}
}

func TestBindingScanner_EditorRole(t *testing.T) {
	mock := &mockCRM{
		policy: &crmv1.Policy{
			Bindings: []*crmv1.Binding{
				{
					Role:    "roles/editor",
					Members: []string{"serviceAccount:sa1@test.iam.gserviceaccount.com"},
				},
			},
		},
	}

	scanner := NewBindingScanner(mock, "test-project")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding for editor role, got %d", len(result.Findings))
	}
	if result.Findings[0].ID != iam.FindingOverprivilegedSA {
		t.Fatalf("expected OVERPRIVILEGED_SA, got %s", result.Findings[0].ID)
	}
}

// WO-83: suppress only the exact local Google APIs Service Agent Editor grant.
func TestBindingScanner_LocalGoogleAPIsServiceAgentEditor(t *testing.T) {
	localAgent := fmt.Sprintf("%d@cloudservices.gserviceaccount.com", testProjectNumber)
	mock := &mockCRM{policy: &crmv1.Policy{Bindings: []*crmv1.Binding{{
		Role: "roles/editor", Members: []string{"serviceAccount:" + localAgent},
	}}}}

	result, err := NewBindingScanner(mock, "test-project").Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 || len(result.Errors) != 0 || len(result.CoverageGaps) != 0 {
		t.Fatalf("expected local managed Editor grant to be suppressed: %#v", result)
	}
}

// WO-83: customer-controlled and external identities remain actionable.
func TestBindingScanner_PreservesActionableEditorAndOwnerBindings(t *testing.T) {
	localAgent := fmt.Sprintf("%d@cloudservices.gserviceaccount.com", testProjectNumber)
	localDefaultCompute := fmt.Sprintf("%d-compute@developer.gserviceaccount.com", testProjectNumber)
	mock := &mockCRM{policy: &crmv1.Policy{Bindings: []*crmv1.Binding{
		{Role: "roles/editor", Members: []string{
			"serviceAccount:" + localDefaultCompute,
			"serviceAccount:custom@test-project.iam.gserviceaccount.com",
			"serviceAccount:999999999@cloudservices.gserviceaccount.com",
		}},
		{Role: "roles/owner", Members: []string{"serviceAccount:" + localAgent}},
	}}}

	result, err := NewBindingScanner(mock, "test-project").Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 4 {
		t.Fatalf("findings = %#v", result.Findings)
	}
	for _, finding := range result.Findings {
		if finding.ResourceName == localDefaultCompute && !strings.Contains(finding.Recommendation, "Policy Simulator") {
			t.Fatalf("default Compute remediation = %q", finding.Recommendation)
		}
	}
}

// WO-83: missing project identity fails closed and records the unevaluated classification.
func TestBindingScanner_ProjectMetadataFailurePreservesCandidates(t *testing.T) {
	mock := &mockCRM{
		policy: &crmv1.Policy{Bindings: []*crmv1.Binding{{
			Role: "roles/editor", Members: []string{
				"serviceAccount:123456789@cloudservices.gserviceaccount.com",
				"serviceAccount:custom@test-project.iam.gserviceaccount.com",
			},
		}}},
		projectErr: fmt.Errorf("metadata denied"),
	}

	result, err := NewBindingScanner(mock, "test-project").Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 2 || len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "metadata denied") {
		t.Fatalf("fail-closed result = %#v", result)
	}
	if len(result.CoverageGaps) != 1 {
		t.Fatalf("coverage gaps = %#v", result.CoverageGaps)
	}
	gap := result.CoverageGaps[0]
	if gap.Capability != "gcp_managed_service_agent_classification" || gap.Cause != "project_metadata_unavailable" || gap.AffectedCount != 1 || gap.TotalCount != 1 {
		t.Fatalf("coverage gap = %#v", gap)
	}
}

// WO-89@v4: safe-role observations still contribute to complete principal accounting.
func TestBindingScanner_SafeRole(t *testing.T) {
	mock := &mockCRM{
		policy: &crmv1.Policy{
			Bindings: []*crmv1.Binding{
				{
					Role:    "roles/viewer",
					Members: []string{"serviceAccount:sa1@test.iam.gserviceaccount.com"},
				},
			},
		},
	}

	scanner := NewBindingScanner(mock, "test-project")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for viewer role, got %d", len(result.Findings))
	}
	if result.PrincipalsScanned != 1 || !result.PrincipalIdentityAccountingComplete {
		t.Fatalf("principal accounting = %#v", result)
	}
	if _, ok := result.ObservedPrincipalIDs["serviceAccount:sa1@test.iam.gserviceaccount.com"]; !ok {
		t.Fatalf("observed principals = %#v", result.ObservedPrincipalIDs)
	}
}

func TestBindingScanner_NonServiceAccount(t *testing.T) {
	mock := &mockCRM{
		policy: &crmv1.Policy{
			Bindings: []*crmv1.Binding{
				{
					Role:    "roles/owner",
					Members: []string{"user:admin@example.com", "group:devs@example.com"},
				},
			},
		},
	}

	scanner := NewBindingScanner(mock, "test-project")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings (only users/groups), got %d", len(result.Findings))
	}
}

// WO-89@v4: a bare service-account member prefix cannot become a synthetic union identity.
func TestBindingScanner_BlankServiceAccountMemberUsesIncompleteFallback(t *testing.T) {
	mock := &mockCRM{policy: &crmv1.Policy{Bindings: []*crmv1.Binding{
		{Role: "roles/viewer", Members: []string{"serviceAccount:", "serviceAccount:   "}},
	}}}

	result, err := NewBindingScanner(mock, "test-project").Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if result.PrincipalIdentityAccountingComplete || len(result.ObservedPrincipalIDs) != 0 {
		t.Fatalf("blank identity carrier = %#v, complete=%v", result.ObservedPrincipalIDs, result.PrincipalIdentityAccountingComplete)
	}
	if result.PrincipalsScanned != 2 {
		t.Fatalf("additive principal count = %d, want prior raw-member count 2", result.PrincipalsScanned)
	}
}

// WO-89@v4: distinct policy members contribute distinct canonical principal identities.
func TestBindingScanner_MultipleSAs(t *testing.T) {
	mock := &mockCRM{
		policy: &crmv1.Policy{
			Bindings: []*crmv1.Binding{
				{
					Role: "roles/owner",
					Members: []string{
						"serviceAccount:sa1@test.iam.gserviceaccount.com",
						"serviceAccount:sa2@test.iam.gserviceaccount.com",
					},
				},
				{
					Role: "roles/editor",
					Members: []string{
						"serviceAccount: SA1@Test.Iam.Gserviceaccount.Com ",
					},
				},
			},
		},
	}

	scanner := NewBindingScanner(mock, "test-project")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// sa1 has owner + editor, sa2 has owner = 3 findings
	if len(result.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(result.Findings))
	}

	// PrincipalsScanned should count unique SAs
	if result.PrincipalsScanned != 2 {
		t.Fatalf("expected 2 unique principals, got %d", result.PrincipalsScanned)
	}
	if !result.PrincipalIdentityAccountingComplete || len(result.ObservedPrincipalIDs) != 2 {
		t.Fatalf("principal identities = %#v, complete=%v", result.ObservedPrincipalIDs, result.PrincipalIdentityAccountingComplete)
	}
}

// WO-89@v4: exclusion suppresses findings without erasing an observed principal.
func TestBindingScanner_Excluded(t *testing.T) {
	mock := &mockCRM{
		policy: &crmv1.Policy{
			Bindings: []*crmv1.Binding{
				{
					Role:    "roles/owner",
					Members: []string{"serviceAccount:sa1@test.iam.gserviceaccount.com"},
				},
			},
		},
	}

	scanner := NewBindingScanner(mock, "test-project")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{
		Exclude: iam.ExcludeConfig{
			Principals: map[string]bool{"sa1@test.iam.gserviceaccount.com": true},
		},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings (excluded), got %d", len(result.Findings))
	}
	if result.PrincipalsScanned != 1 || !result.PrincipalIdentityAccountingComplete {
		t.Fatalf("excluded principal accounting = %#v", result)
	}
}

func TestBindingScanner_GetPolicyError(t *testing.T) {
	mock := &mockCRM{
		policyErr: fmt.Errorf("permission denied"),
	}

	scanner := NewBindingScanner(mock, "test-project")
	_, err := scanner.Scan(context.Background(), iam.ScanConfig{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// WO-89@v4: an empty successful policy read proves a complete empty identity set.
func TestBindingScanner_EmptyPolicy(t *testing.T) {
	mock := &mockCRM{
		policy: &crmv1.Policy{},
	}

	scanner := NewBindingScanner(mock, "test-project")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.PrincipalsScanned != 0 || !result.PrincipalIdentityAccountingComplete || len(result.ObservedPrincipalIDs) != 0 {
		t.Fatalf("empty principal accounting = %#v", result)
	}
}

func TestBindingScanner_Type(t *testing.T) {
	scanner := NewBindingScanner(nil, "test")
	if scanner.Type() != iam.ResourceIAMBinding {
		t.Fatalf("expected iam_binding, got %s", scanner.Type())
	}
}
