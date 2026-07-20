package azure

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// AzureScanner orchestrates all Azure AD IAM scanners.
type AzureScanner struct {
	client  *Client
	scanCfg iam.ScanConfig
}

// NewAzureScanner creates an orchestrator for Azure AD IAM scanning.
func NewAzureScanner(client *Client, scanCfg iam.ScanConfig) *AzureScanner {
	return &AzureScanner{
		client:  client,
		scanCfg: scanCfg,
	}
}

// ScanAll runs all Azure AD IAM scanners and returns combined results.
func (s *AzureScanner) ScanAll(ctx context.Context) (*iam.ScanResult, error) {
	slog.Info("Scanning Azure AD tenant", "tenant_id", s.client.TenantID)

	// Pre-fetch shared data (like AWS credential report).
	users, usersErr := s.client.Graph.ListUsers(ctx)
	sps, spsErr := s.client.Graph.ListServicePrincipals(ctx)
	spActivities, spActivityErr := s.client.Graph.ListServicePrincipalSignInActivities(ctx) // WO-68@v3: fetch the separate beta report.
	sps, spCoverage := joinServicePrincipalActivity(sps, spActivities, spActivityErr, s.client.TenantID, s.scanCfg)

	// Build principal activity map for role scanner.
	principalActivity := buildPrincipalActivityMap(users, sps, s.scanCfg.StaleDays)

	scanners := []iam.Scanner{
		NewUserScannerWithScope(s.client.Graph, users, usersErr, "azure-tenant:"+s.client.TenantID), // WO-77: scope missing user activity evidence to this tenant.
		NewAppScanner(s.client.Graph),
		NewServicePrincipalScannerWithActivityCoverage(s.client.Graph, sps, spsErr, spActivityErr, spCoverage),
		NewRoleScannerWithScope(s.client.Graph, principalActivity, "azure-tenant:"+s.client.TenantID), // WO-73@v1: bind unknown role evidence to tenant scope.
	}

	// WO-26@v2: provider setup stays local while orchestration policy is shared.
	return iam.RunScanners(ctx, scanners, s.scanCfg)
}

// WO-68@v3: join authoritative report rows by appId and report unknown evidence once per tenant.
func joinServicePrincipalActivity(servicePrincipals []ServicePrincipal, activities []ServicePrincipalSignInActivity, activityErr error, tenantID string, scanCfg iam.ScanConfig) ([]ServicePrincipal, *iam.CoverageGapObservation) {
	joined := append([]ServicePrincipal(nil), servicePrincipals...)
	for index := range joined {
		joined[index].SignInActivity = nil
	}
	byAppID := make(map[string]*SignInActivity, len(activities))
	if activityErr == nil {
		for _, activity := range activities {
			if activity.AppID != "" && activity.LastSignInActivity != nil && activity.LastSignInActivity.LastSignInDateTime != nil {
				byAppID[activity.AppID] = activity.LastSignInActivity
			}
		}
	}
	missing, evaluable, eligible := 0, 0, 0
	for index := range joined {
		excluded := iam.IsExcluded(scanCfg, joined[index].ID, joined[index].DisplayName) // WO-75@v1: coverage counts only in-scope principals.
		if activity := byAppID[joined[index].AppID]; activity != nil {
			joined[index].SignInActivity = activity
			if !excluded {
				evaluable++
				eligible++
			}
			continue
		}
		if !excluded {
			missing++
			eligible++
		}
	}
	if missing == 0 {
		return joined, nil
	}
	cause := "missing_report_rows"
	if activityErr != nil {
		cause = "report_unavailable"
	}
	return joined, &iam.CoverageGapObservation{
		Capability: "azure_service_principal_sign_in_activity",
		Cause:      cause, Scope: "azure-tenant:" + tenantID, FindingID: iam.FindingStaleSP,
		AffectedCount: missing, EvaluableCount: evaluable, TotalCount: eligible,
		ObservationWindow: fmt.Sprintf("stale-threshold:%dd", scanCfg.StaleDays), FeatureStage: "beta",
		MaxConsequence: iam.SeverityHigh,
	}
}

// ScannerCount returns the number of scanners used.
func ScannerCount() int {
	return 4
}

// WO-73@v1: buildPrincipalActivityMap preserves recent, stale, and unknown evidence states.
func buildPrincipalActivityMap(users []User, sps []ServicePrincipal, staleDays int) map[string]PrincipalActivityState {
	activity := make(map[string]PrincipalActivityState, len(users)+len(sps))
	cutoff := iam.StaleThreshold(time.Now(), staleDays) // WO-24@v2: preserve the local clock sample.

	for _, u := range users {
		activity[u.ID] = PrincipalActivityUnknown
		if latestActivity := latestUserActivity(u.SignInActivity); latestActivity != nil { // WO-77: role activity shares the complete user evidence rule.
			if latestActivity.After(cutoff) {
				activity[u.ID] = PrincipalActivityRecent
			} else {
				activity[u.ID] = PrincipalActivityStale
			}
		}
	}

	for _, sp := range sps {
		activity[sp.ID] = PrincipalActivityUnknown
		if sp.SignInActivity != nil && sp.SignInActivity.LastSignInDateTime != nil {
			if sp.SignInActivity.LastSignInDateTime.After(cutoff) {
				activity[sp.ID] = PrincipalActivityRecent
			} else {
				activity[sp.ID] = PrincipalActivityStale
			}
		}
	}

	return activity
}
