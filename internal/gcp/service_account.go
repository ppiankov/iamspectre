package gcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
	iamv1 "google.golang.org/api/iam/v1"
)

// ServiceAccountScanner detects stale service accounts and stale service account keys.
type ServiceAccountScanner struct {
	api     IAMAPI
	project string
}

// NewServiceAccountScanner creates a scanner for GCP service accounts.
func NewServiceAccountScanner(api IAMAPI, project string) *ServiceAccountScanner {
	return &ServiceAccountScanner{api: api, project: project}
}

// Type returns the resource type this scanner handles.
func (s *ServiceAccountScanner) Type() iam.ResourceType {
	return iam.ResourceServiceAccount
}

// Scan examines service accounts and their keys for staleness.
func (s *ServiceAccountScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	accounts, err := s.api.ListServiceAccounts(ctx, s.project)
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}

	result := &iam.ScanResult{PrincipalsScanned: len(accounts)}

	for _, sa := range accounts {
		if iam.IsExcluded(cfg, sa.UniqueId, sa.Email) { // WO-14@v3: use the shared exclusion policy.
			continue
		}

		// WO-69@v2: disabled is a reversible lifecycle state, not staleness. Report it as an
		// informational fact (no delete advice); staleness is driven only by key evidence.
		if sa.Disabled {
			result.Findings = append(result.Findings, iam.Finding{
				ID:           iam.FindingDisabledSA,
				Severity:     iam.SeverityLow,
				ResourceType: iam.ResourceServiceAccount,
				ResourceID:   sa.UniqueId,
				ResourceName: sa.Email,
				Message:      "Service account is disabled (reversible lifecycle state)",
				Recommendation: "No action required. Disabling is the recommended reversible state before deletion; " +
					"confirm the account is no longer needed before deleting it.",
				Metadata: map[string]any{
					"project":  s.project,
					"disabled": true,
				},
			})
		}

		keys, err := s.api.ListServiceAccountKeys(ctx, sa.Name)
		if err != nil {
			slog.Warn("Failed to list keys", "service_account", sa.Email, "error", err)
			result.Errors = append(result.Errors, fmt.Sprintf("list keys for %s: %v", sa.Email, err))
			continue
		}

		result.Findings = append(result.Findings, s.checkKeys(sa, keys, cfg)...)
	}

	return result, nil
}

func (s *ServiceAccountScanner) checkKeys(sa *iamv1.ServiceAccount, keys []*iamv1.ServiceAccountKey, cfg iam.ScanConfig) []iam.Finding {
	var findings []iam.Finding
	now := time.Now().UTC()
	threshold := iam.StaleThreshold(now, cfg.StaleDays) // WO-24@v2: use the shared calendar cutoff.

	for _, key := range keys {
		created, err := time.Parse(time.RFC3339, key.ValidAfterTime)
		if err != nil {
			slog.Warn("Failed to parse key time", "key", key.Name, "error", err)
			continue
		}

		if created.Before(threshold) {
			daysOld := int(now.Sub(created).Hours() / 24)
			findings = append(findings, iam.Finding{
				ID:             iam.FindingStaleSAKey,
				Severity:       iam.SeverityCritical,
				ResourceType:   iam.ResourceServiceAccountKey,
				ResourceID:     key.Name,
				ResourceName:   sa.Email,
				Message:        fmt.Sprintf("Service account key created %d days ago (threshold: %d days)", daysOld, cfg.StaleDays),
				Recommendation: "Rotate or delete the stale service account key",
				Metadata: map[string]any{
					"service_account": sa.Email,
					"key_created":     key.ValidAfterTime,
					"days_old":        daysOld,
				},
			})
		}
	}

	return findings
}
