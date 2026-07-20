package azure

import (
	"context"
	"fmt"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// overprivilegedRoleIDs maps well-known Microsoft Graph app role GUIDs to their names.
// Resource app ID: 00000003-0000-0000-c000-000000000000 (Microsoft Graph).
var overprivilegedRoleIDs = map[string]string{
	"19dbc75e-c2e2-444c-a770-ec69d8559fc7": "Directory.ReadWrite.All",
	"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8": "RoleManagement.ReadWrite.Directory",
	"1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9": "Application.ReadWrite.All",
	"06b708a9-e830-4db3-a914-8e69da51d44f": "AppRoleAssignment.ReadWrite.All",
}

// WO-68@v3: ServicePrincipalScanner carries activity diagnostics and coverage alongside other checks.
type ServicePrincipalScanner struct {
	api         GraphAPI
	sps         []ServicePrincipal
	fetchErr    error
	coverage    *iam.CoverageGapObservation
	activityErr error
}

// NewServicePrincipalScanner creates a scanner with pre-fetched service principal data.
func NewServicePrincipalScanner(api GraphAPI, sps []ServicePrincipal, fetchErr error) *ServicePrincipalScanner {
	return &ServicePrincipalScanner{api: api, sps: sps, fetchErr: fetchErr}
}

// WO-68@v3: preserve the old constructor while production wiring supplies explicit activity coverage evidence.
func NewServicePrincipalScannerWithActivityCoverage(api GraphAPI, sps []ServicePrincipal, fetchErr, activityErr error, coverage *iam.CoverageGapObservation) *ServicePrincipalScanner {
	return &ServicePrincipalScanner{api: api, sps: sps, fetchErr: fetchErr, activityErr: activityErr, coverage: coverage}
}

// Type returns the resource type this scanner handles.
func (s *ServicePrincipalScanner) Type() iam.ResourceType {
	return iam.ResourceAzureServicePrincipal
}

// WO-68@v3: Scan preserves overprivileged checks when activity evidence is unavailable.
func (s *ServicePrincipalScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	if s.fetchErr != nil {
		return nil, fmt.Errorf("fetch service principals: %w", s.fetchErr)
	}

	result := &iam.ScanResult{PrincipalsScanned: len(s.sps)}
	if s.activityErr != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("service principal sign-in activity: %v", s.activityErr))
	}
	if s.coverage != nil {
		result.CoverageGaps = append(result.CoverageGaps, *s.coverage)
	}

	for _, sp := range s.sps {
		if iam.IsExcluded(cfg, sp.ID, sp.DisplayName) { // WO-14@v3: use the shared exclusion policy.
			continue
		}

		// WO-68@v3: SP sign-in activity is available only on the Graph beta reports surface, so it
		// is reported as a coverage gap (see joinServicePrincipalActivity) — never as a severity
		// finding built on beta data, which is not a supportable production signal. The beta
		// enrichment survives only to feed the role-activity coverage map.
		s.checkOverprivileged(sp, result)
	}

	return result, nil
}

func (s *ServicePrincipalScanner) checkOverprivileged(sp ServicePrincipal, result *iam.ScanResult) {
	for _, assignment := range sp.AppRoleAssignments {
		roleName, dangerous := overprivilegedRoleIDs[assignment.AppRoleID]
		if !dangerous {
			continue
		}

		result.Findings = append(result.Findings, iam.Finding{
			ID:             iam.FindingOverprivilegedApp,
			Severity:       iam.SeverityCritical,
			ResourceType:   iam.ResourceAzureServicePrincipal,
			ResourceID:     sp.ID,
			ResourceName:   sp.DisplayName,
			Message:        fmt.Sprintf("Service principal has dangerous permission: %s", roleName),
			Recommendation: "Review and reduce permissions to least-privilege",
			Metadata: map[string]any{
				"app_id":        sp.AppID,
				"role_id":       assignment.AppRoleID,
				"role_name":     roleName,
				"resource_name": assignment.ResourceDisplayName,
			},
		})
	}
}
