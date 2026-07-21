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

// WO-73@v1: known stale activity remains actionable.
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

	activity := map[string]PrincipalActivityState{"inactive-user": PrincipalActivityStale}
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

// WO-73@v1: known recent activity remains non-actionable.
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

	activity := map[string]PrincipalActivityState{"active-user": PrincipalActivityRecent}
	s := NewRoleScanner(mock, activity)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if findFinding(result.Findings, iam.FindingUnusedRole) != nil {
		t.Fatal("should not emit UNUSED_ROLE for active principal")
	}
}

// WO-73@v1: absent activity is unknown coverage, not evidence of an unused role.
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

	s := NewRoleScanner(mock, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if findFinding(result.Findings, iam.FindingUnusedRole) != nil {
		t.Fatal("unknown activity emitted UNUSED_ROLE")
	}
	if len(result.CoverageGaps) != 1 || result.CoverageGaps[0].AffectedCount != 1 {
		t.Fatalf("coverage gaps = %#v", result.CoverageGaps)
	}
}

// WO-81: source-wide user gating must not relabel unrelated principal evidence.
func TestRoleScanner_GroupsUnknownCoverageByPrincipalCause(t *testing.T) {
	mock := &mockGraph{roleAssigns: []DirectoryRoleAssignment{
		{ID: "user-assignment", PrincipalID: "user-1"},
		{ID: "sp-assignment", PrincipalID: "sp-1"},
	}}
	scanner := NewRoleScannerWithActivityCauses(mock, map[string]PrincipalActivityState{
		"user-1": PrincipalActivityUnknown,
		"sp-1":   PrincipalActivityUnknown,
	}, "azure-tenant:tenant-a", map[string]string{"user-1": userActivityPermissionDeniedCause})

	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.CoverageGaps) != 2 {
		t.Fatalf("coverage gaps = %#v", result.CoverageGaps)
	}
	causes := map[string]int{}
	for _, gap := range result.CoverageGaps {
		causes[gap.Cause] += gap.AffectedCount
	}
	if causes[userActivityPermissionDeniedCause] != 1 || causes["principal_activity_unknown"] != 1 {
		t.Fatalf("coverage causes = %#v", causes)
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

// WO-73@v1: tri-state evidence does not change scan accounting.
func TestRoleScanner_PrincipalsScanned(t *testing.T) {
	mock := &mockGraph{
		roleAssigns: []DirectoryRoleAssignment{
			{ID: "a1", PrincipalID: "p1"},
			{ID: "a2", PrincipalID: "p2"},
		},
	}

	activity := map[string]PrincipalActivityState{"p1": PrincipalActivityRecent, "p2": PrincipalActivityRecent}
	s := NewRoleScanner(mock, activity)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.PrincipalsScanned != 2 {
		t.Fatalf("expected 2 principals scanned, got %d", result.PrincipalsScanned)
	}
}
