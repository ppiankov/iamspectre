package azure

import (
	"context"
	"fmt"
	"time"

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

// ServicePrincipalScanner detects stale service principals and overprivileged apps.
type ServicePrincipalScanner struct {
	api      GraphAPI
	sps      []ServicePrincipal
	fetchErr error
}

// NewServicePrincipalScanner creates a scanner with pre-fetched service principal data.
func NewServicePrincipalScanner(api GraphAPI, sps []ServicePrincipal, fetchErr error) *ServicePrincipalScanner {
	return &ServicePrincipalScanner{api: api, sps: sps, fetchErr: fetchErr}
}

// Type returns the resource type this scanner handles.
func (s *ServicePrincipalScanner) Type() iam.ResourceType {
	return iam.ResourceAzureServicePrincipal
}

// Scan checks Azure AD service principals for staleness and overprivileged permissions.
func (s *ServicePrincipalScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	if s.fetchErr != nil {
		return nil, fmt.Errorf("fetch service principals: %w", s.fetchErr)
	}

	result := &iam.ScanResult{PrincipalsScanned: len(s.sps)}
	cutoff := daysAgo(cfg.StaleDays)

	for _, sp := range s.sps {
		if isExcluded(cfg, sp.ID, sp.DisplayName) {
			continue
		}

		s.checkStale(sp, cutoff, result)
		s.checkOverprivileged(sp, result)
	}

	return result, nil
}

func (s *ServicePrincipalScanner) checkStale(sp ServicePrincipal, cutoff time.Time, result *iam.ScanResult) {
	if sp.SignInActivity == nil || sp.SignInActivity.LastSignInDateTime == nil {
		return
	}

	lastSignIn := *sp.SignInActivity.LastSignInDateTime
	if lastSignIn.After(cutoff) {
		return
	}

	daysSince := int(time.Since(lastSignIn).Hours() / 24)
	result.Findings = append(result.Findings, iam.Finding{
		ID:             iam.FindingStaleSP,
		Severity:       iam.SeverityHigh,
		ResourceType:   iam.ResourceAzureServicePrincipal,
		ResourceID:     sp.ID,
		ResourceName:   sp.DisplayName,
		Message:        fmt.Sprintf("Service principal has not signed in for %d days", daysSince),
		Recommendation: "Review the service principal and remove if no longer needed",
		Metadata: map[string]any{
			"app_id":       sp.AppID,
			"last_sign_in": lastSignIn.Format(time.RFC3339),
			"days_since":   daysSince,
		},
	})
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
