package azure

import (
	"context"
	"fmt"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-73@v1: RoleScanner retains tri-state principal activity evidence and tenant coverage scope.
type RoleScanner struct {
	api               GraphAPI
	principalActivity map[string]PrincipalActivityState
	coverageScope     string
}

// WO-73@v1: NewRoleScanner preserves unknown evidence instead of treating absence as inactivity.
func NewRoleScanner(api GraphAPI, principalActivity map[string]PrincipalActivityState) *RoleScanner {
	return NewRoleScannerWithScope(api, principalActivity, "azure-tenant:unknown")
}

// WO-73@v1: NewRoleScannerWithScope binds a deduplicatable coverage gap to its tenant.
func NewRoleScannerWithScope(api GraphAPI, principalActivity map[string]PrincipalActivityState, coverageScope string) *RoleScanner {
	return &RoleScanner{api: api, principalActivity: principalActivity, coverageScope: coverageScope}
}

// Type returns the resource type this scanner handles.
func (s *RoleScanner) Type() iam.ResourceType {
	return iam.ResourceAzureDirectoryRole
}

// WO-73@v1: Scan emits UNUSED_ROLE only for known stale evidence and reports unknown coverage once.
func (s *RoleScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	assignments, err := s.api.ListDirectoryRoleAssignments(ctx)
	if err != nil {
		return nil, fmt.Errorf("list role assignments: %w", err)
	}

	result := &iam.ScanResult{PrincipalsScanned: len(assignments)}
	unknown := 0
	evaluable := 0

	for _, a := range assignments {
		if iam.IsExcluded(cfg, a.ID, a.PrincipalID) { // WO-14@v3: use the shared exclusion policy.
			continue
		}

		state := s.principalActivity[a.PrincipalID]
		if state == "" || state == PrincipalActivityUnknown {
			unknown++
			continue
		}
		evaluable++
		if state == PrincipalActivityStale {
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
	if unknown > 0 {
		result.CoverageGaps = append(result.CoverageGaps, iam.CoverageGapObservation{
			Capability: "azure_principal_sign_in_activity", Cause: "principal_activity_unknown",
			Scope: s.coverageScope, FindingID: iam.FindingUnusedRole, AffectedCount: unknown,
			EvaluableCount: evaluable, TotalCount: evaluable + unknown,
			FeatureStage: "mixed", MaxConsequence: iam.SeverityMedium,
		})
	}

	return result, nil
}
