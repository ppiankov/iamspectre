package gcp

import (
	"context"
	"fmt"
	"testing"

	"github.com/ppiankov/iamspectre/internal/iam"
	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
)

type mockCRM struct {
	policy    *crmv1.Policy
	policyErr error
}

func (m *mockCRM) GetIamPolicy(_ context.Context, _ string) (*crmv1.Policy, error) {
	if m.policyErr != nil {
		return nil, m.policyErr
	}
	return m.policy, nil
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
						"serviceAccount:sa1@test.iam.gserviceaccount.com",
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
}

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
}

func TestBindingScanner_Type(t *testing.T) {
	scanner := NewBindingScanner(nil, "test")
	if scanner.Type() != iam.ResourceIAMBinding {
		t.Fatalf("expected iam_binding, got %s", scanner.Type())
	}
}
