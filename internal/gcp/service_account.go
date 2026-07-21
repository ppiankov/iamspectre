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
	now     func() time.Time // WO-88: inject the assessment clock so threshold evidence is reproducible.
}

// NewServiceAccountScanner creates a scanner for GCP service accounts.
func NewServiceAccountScanner(api IAMAPI, project string) *ServiceAccountScanner {
	return &ServiceAccountScanner{api: api, project: project, now: time.Now}
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

	// WO-89: a successful account list makes even an empty observed identity set complete.
	result := &iam.ScanResult{
		ObservedPrincipalIDs:                make(map[string]struct{}, len(accounts)),
		PrincipalIdentityAccountingComplete: true,
	}
	scanNow := s.now().UTC() // WO-88: one scan-wide instant prevents account-order boundary drift.

	for _, sa := range accounts {
		principalID := canonicalServiceAccountPrincipalID(sa.Email)
		if principalID == "" {
			result.PrincipalIdentityAccountingComplete = false // WO-89: preserve fallback without inventing a namespace-only identity.
		} else {
			result.ObservedPrincipalIDs[principalID] = struct{}{} // WO-89: count provider observations independently of finding filters.
		}
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
			// WO-92: a failed key inventory is an explicit unevaluable stale-key opportunity.
			result.CoverageGaps = append(result.CoverageGaps, iam.CoverageGapObservation{
				Capability:        "gcp_service_account_key_inventory",
				Cause:             "list_keys_failed",
				Scope:             "gcp-project:" + s.project,
				FindingID:         iam.FindingStaleSAKey,
				AffectedCount:     1,
				EvaluableCount:    0,
				TotalCount:        1,
				ObservationWindow: fmt.Sprintf("%dd", cfg.StaleDays),
				MaxConsequence:    iam.SeverityMedium,
			})
			continue
		}

		keyResult := s.checkKeys(sa, keys, cfg, scanNow)
		result.Findings = append(result.Findings, keyResult.Findings...)
		result.Errors = append(result.Errors, keyResult.Errors...)
		result.CoverageGaps = append(result.CoverageGaps, keyResult.CoverageGaps...)
	}

	if result.PrincipalIdentityAccountingComplete {
		result.PrincipalsScanned = len(result.ObservedPrincipalIDs)
	} else {
		result.PrincipalsScanned = len(accounts)
	}
	return result, nil
}

// WO-76: stale-key findings apply only to credentials that can still authenticate.
func (s *ServiceAccountScanner) checkKeys(sa *iamv1.ServiceAccount, keys []*iamv1.ServiceAccountKey, cfg iam.ScanConfig, now time.Time) *iam.ScanResult {
	result := &iam.ScanResult{}
	threshold := iam.StaleThreshold(now, cfg.StaleDays) // WO-24@v2: use the shared calendar cutoff.

	for _, key := range keys {
		if key.Disabled { // WO-76: an inactive key cannot present stale-credential exposure.
			continue
		}

		created, err := time.Parse(time.RFC3339, key.ValidAfterTime)
		if err != nil {
			// WO-90: report incomplete evidence without echoing the malformed timestamp or parser text.
			result.Errors = append(result.Errors, fmt.Sprintf(
				"service account key age unavailable for %s: invalid validAfterTime", key.Name,
			))
			result.CoverageGaps = append(result.CoverageGaps, iam.CoverageGapObservation{
				Capability:        "gcp_service_account_key_age",
				Cause:             "invalid_valid_after_time",
				Scope:             "gcp-project:" + s.project,
				FindingID:         iam.FindingStaleSAKey,
				AffectedCount:     1,
				EvaluableCount:    0,
				TotalCount:        1,
				ObservationWindow: fmt.Sprintf("%dd", cfg.StaleDays),
				MaxConsequence:    iam.SeverityMedium,
			})
			continue
		}

		if created.Before(threshold) {
			daysOld := int(now.Sub(created).Hours() / 24)
			evidenceTier := iam.EvidenceTierFact
			evaluatedLayers := make(map[iam.AuthorizationLayer]iam.LayerStatus, len(iam.CanonicalLayers()))
			for _, layer := range iam.CanonicalLayers() {
				evaluatedLayers[layer] = iam.LayerUnresolved
			}
			result.Findings = append(result.Findings, iam.Finding{
				ID:              iam.FindingStaleSAKey,
				Severity:        iam.SeverityMedium,
				ResourceType:    iam.ResourceServiceAccountKey,
				ResourceID:      key.Name,
				ResourceName:    sa.Email,
				Message:         fmt.Sprintf("Service account key created %d days ago (threshold: %d days)", daysOld, cfg.StaleDays),
				Recommendation:  "Rotate or delete the stale service account key",
				EvidenceTier:    &evidenceTier,               // WO-88: age is a directly observed hygiene fact.
				State:           iam.FindingStateDeterminate, // WO-88: the timestamp comparison itself is conclusive.
				Reachability:    iam.ReachabilityUnknown,     // WO-88: age does not prove whether the credential is reachable.
				Impact:          iam.SeverityMedium,          // WO-88: unsupported compromise claims cannot raise impact.
				BlastRadius:     iam.BlastRadiusMedium,       // WO-88: no narrower or broader authorization scope was evaluated.
				RubricVersion:   iam.RubricVersionV1,         // WO-88: bind the complete assessment to rubric v1.
				EvaluatedLayers: evaluatedLayers,             // WO-88: all authorization layers remain unresolved.
				Metadata: map[string]any{
					"service_account": sa.Email,
					"key_created":     key.ValidAfterTime,
					"days_old":        daysOld,
					"stale_days":      cfg.StaleDays,
					"enabled":         true,
				},
			})
		}
	}

	return result
}
