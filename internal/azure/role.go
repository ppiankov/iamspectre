package azure

import (
	"context"
	"fmt"
	"sort"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-73@v1: RoleScanner retains tri-state principal activity evidence and tenant coverage scope.
type RoleScanner struct {
	api               GraphAPI
	principalActivity map[string]PrincipalActivityState
	coverageScope     string
	coverageCause     string            // WO-81@v4: preserve a default source-wide activity cause.
	coverageCauses    map[string]string // WO-81@v4: prevent one source failure from relabeling unrelated principals.
}

// WO-73@v1: NewRoleScanner preserves unknown evidence instead of treating absence as inactivity.
func NewRoleScanner(api GraphAPI, principalActivity map[string]PrincipalActivityState) *RoleScanner {
	return NewRoleScannerWithScope(api, principalActivity, "azure-tenant:unknown")
}

// WO-73@v1: NewRoleScannerWithScope binds a deduplicatable coverage gap to its tenant.
func NewRoleScannerWithScope(api GraphAPI, principalActivity map[string]PrincipalActivityState, coverageScope string) *RoleScanner {
	return NewRoleScannerWithActivityCause(api, principalActivity, coverageScope, "principal_activity_unknown")
}

// WO-81@v4: NewRoleScannerWithActivityCause carries a tenant-wide activity-source failure into coverage.
func NewRoleScannerWithActivityCause(api GraphAPI, principalActivity map[string]PrincipalActivityState, coverageScope, coverageCause string) *RoleScanner {
	if coverageCause == "" {
		coverageCause = "principal_activity_unknown"
	}
	return &RoleScanner{
		api: api, principalActivity: principalActivity,
		coverageScope: coverageScope, coverageCause: coverageCause,
	}
}

// WO-81@v4: NewRoleScannerWithActivityCauses carries exact source failures per principal.
func NewRoleScannerWithActivityCauses(api GraphAPI, principalActivity map[string]PrincipalActivityState, coverageScope string, coverageCauses map[string]string) *RoleScanner {
	return &RoleScanner{
		api: api, principalActivity: principalActivity, coverageScope: coverageScope,
		coverageCause: "principal_activity_unknown", coverageCauses: coverageCauses,
	}
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
	unknownByCause := make(map[string]int)
	evaluable := 0

	for _, a := range assignments {
		if iam.IsExcluded(cfg, a.ID, a.PrincipalID) { // WO-14@v3: use the shared exclusion policy.
			continue
		}

		state := s.principalActivity[a.PrincipalID]
		if state == "" || state == PrincipalActivityUnknown {
			unknown++
			cause := s.coverageCauses[a.PrincipalID]
			if cause == "" {
				cause = s.coverageCause
			}
			unknownByCause[cause]++
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
		causes := make([]string, 0, len(unknownByCause))
		for cause := range unknownByCause {
			causes = append(causes, cause)
		}
		sort.Strings(causes)
		for _, cause := range causes {
			result.CoverageGaps = append(result.CoverageGaps, iam.CoverageGapObservation{
				Capability: "azure_principal_sign_in_activity", Cause: cause,
				Scope: s.coverageScope, FindingID: iam.FindingUnusedRole, AffectedCount: unknownByCause[cause],
				EvaluableCount: evaluable, TotalCount: evaluable + unknown,
				FeatureStage: "mixed", MaxConsequence: iam.SeverityMedium,
			})
		}
	}

	return result, nil
}
