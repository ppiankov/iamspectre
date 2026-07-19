package azure

import (
	"context"
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

	// Build principal activity map for role scanner.
	principalActivity := buildPrincipalActivityMap(users, sps, s.scanCfg.StaleDays)

	scanners := []iam.Scanner{
		NewUserScanner(s.client.Graph, users, usersErr),
		NewAppScanner(s.client.Graph),
		NewServicePrincipalScanner(s.client.Graph, sps, spsErr),
		NewRoleScanner(s.client.Graph, principalActivity),
	}

	// WO-26@v2: provider setup stays local while orchestration policy is shared.
	return iam.RunScanners(ctx, scanners, s.scanCfg)
}

// ScannerCount returns the number of scanners used.
func ScannerCount() int {
	return 4
}

// buildPrincipalActivityMap returns a map of principal IDs that have recent sign-in activity.
func buildPrincipalActivityMap(users []User, sps []ServicePrincipal, staleDays int) map[string]bool {
	active := make(map[string]bool)
	cutoff := iam.StaleThreshold(time.Now(), staleDays) // WO-24@v2: preserve the local clock sample.

	for _, u := range users {
		if u.SignInActivity != nil && u.SignInActivity.LastSignInDateTime != nil {
			if u.SignInActivity.LastSignInDateTime.After(cutoff) {
				active[u.ID] = true
			}
		}
	}

	for _, sp := range sps {
		if sp.SignInActivity != nil && sp.SignInActivity.LastSignInDateTime != nil {
			if sp.SignInActivity.LastSignInDateTime.After(cutoff) {
				active[sp.ID] = true
			}
		}
	}

	return active
}
