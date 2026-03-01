package azure

import (
	"context"
	"fmt"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// RoleScanner detects unused directory role assignments.
type RoleScanner struct {
	api               GraphAPI
	principalActivity map[string]bool
}

// NewRoleScanner creates a scanner with a pre-built principal activity map.
func NewRoleScanner(api GraphAPI, principalActivity map[string]bool) *RoleScanner {
	return &RoleScanner{api: api, principalActivity: principalActivity}
}

// Type returns the resource type this scanner handles.
func (s *RoleScanner) Type() iam.ResourceType {
	return iam.ResourceAzureDirectoryRole
}

// Scan checks directory role assignments for inactive principals.
func (s *RoleScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	assignments, err := s.api.ListDirectoryRoleAssignments(ctx)
	if err != nil {
		return nil, fmt.Errorf("list role assignments: %w", err)
	}

	result := &iam.ScanResult{PrincipalsScanned: len(assignments)}

	for _, a := range assignments {
		if isExcluded(cfg, a.ID, a.PrincipalID) {
			continue
		}

		if !s.principalActivity[a.PrincipalID] {
			result.Findings = append(result.Findings, iam.Finding{
				ID:             iam.FindingUnusedRole,
				Severity:       iam.SeverityMedium,
				ResourceType:   iam.ResourceAzureDirectoryRole,
				ResourceID:     a.ID,
				ResourceName:   a.RoleDefinitionID,
				Message:        "Directory role assigned to an inactive principal",
				Recommendation: "Review the role assignment and remove if the principal is no longer active",
				Metadata: map[string]any{
					"principal_id":       a.PrincipalID,
					"role_definition_id": a.RoleDefinitionID,
				},
			})
		}
	}

	return result, nil
}
