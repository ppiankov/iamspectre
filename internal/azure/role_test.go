package azure

import (
	"context"
	"fmt"
	"testing"

	"github.com/ppiankov/iamspectre/internal/iam"
)

func TestRoleScanner_Type(t *testing.T) {
	s := NewRoleScanner(&mockGraph{}, nil)
	if s.Type() != iam.ResourceAzureDirectoryRole {
		t.Fatalf("expected %s, got %s", iam.ResourceAzureDirectoryRole, s.Type())
	}
}

func TestRoleScanner_ListError(t *testing.T) {
	mock := &mockGraph{roleAssignsErr: fmt.Errorf("forbidden")}
	s := NewRoleScanner(mock, nil)
	_, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err == nil {
		t.Fatal("expected error from list failure")
	}
}

func TestRoleScanner_UnusedRole(t *testing.T) {
	mock := &mockGraph{
		roleAssigns: []DirectoryRoleAssignment{
			{
				ID:               "assign-1",
				RoleDefinitionID: "role-global-admin",
				PrincipalID:      "inactive-user",
			},
		},
	}

	// inactive-user is NOT in the activity map
	activity := map[string]bool{"active-user": true}
	s := NewRoleScanner(mock, activity)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingUnusedRole)
	if found == nil {
		t.Fatal("expected UNUSED_ROLE finding for inactive principal")
	}
	if found.Severity != iam.SeverityMedium {
		t.Fatalf("expected medium severity, got %s", found.Severity)
	}
}

func TestRoleScanner_ActiveRole(t *testing.T) {
	mock := &mockGraph{
		roleAssigns: []DirectoryRoleAssignment{
			{
				ID:               "assign-2",
				RoleDefinitionID: "role-reader",
				PrincipalID:      "active-user",
			},
		},
	}

	activity := map[string]bool{"active-user": true}
	s := NewRoleScanner(mock, activity)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if findFinding(result.Findings, iam.FindingUnusedRole) != nil {
		t.Fatal("should not emit UNUSED_ROLE for active principal")
	}
}

func TestRoleScanner_NilActivityMap(t *testing.T) {
	mock := &mockGraph{
		roleAssigns: []DirectoryRoleAssignment{
			{
				ID:               "assign-3",
				RoleDefinitionID: "role-admin",
				PrincipalID:      "some-user",
			},
		},
	}

	// nil activity map means all principals treated as inactive
	s := NewRoleScanner(mock, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if findFinding(result.Findings, iam.FindingUnusedRole) == nil {
		t.Fatal("expected UNUSED_ROLE when activity map is nil")
	}
}

func TestRoleScanner_Excluded(t *testing.T) {
	mock := &mockGraph{
		roleAssigns: []DirectoryRoleAssignment{
			{
				ID:               "assign-4",
				RoleDefinitionID: "role-admin",
				PrincipalID:      "excluded-principal",
			},
		},
	}

	s := NewRoleScanner(mock, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{
		StaleDays: 90,
		Exclude:   iam.ExcludeConfig{Principals: map[string]bool{"excluded-principal": true}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for excluded principal, got %d", len(result.Findings))
	}
}

func TestRoleScanner_PrincipalsScanned(t *testing.T) {
	mock := &mockGraph{
		roleAssigns: []DirectoryRoleAssignment{
			{ID: "a1", PrincipalID: "p1"},
			{ID: "a2", PrincipalID: "p2"},
		},
	}

	activity := map[string]bool{"p1": true, "p2": true}
	s := NewRoleScanner(mock, activity)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PrincipalsScanned != 2 {
		t.Fatalf("expected 2 principals scanned, got %d", result.PrincipalsScanned)
	}
}
