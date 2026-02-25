package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// UserScanner detects stale users, stale access keys, and users without MFA.
type UserScanner struct {
	entries []CredentialEntry
}

// NewUserScanner creates a scanner that operates on pre-fetched credential report entries.
func NewUserScanner(entries []CredentialEntry) *UserScanner {
	return &UserScanner{entries: entries}
}

// Type returns the resource type this scanner handles.
func (s *UserScanner) Type() iam.ResourceType {
	return iam.ResourceIAMUser
}

// Scan examines credential report entries for user-level findings.
func (s *UserScanner) Scan(_ context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	result := &iam.ScanResult{PrincipalsScanned: len(s.entries)}
	now := time.Now().UTC()
	threshold := now.AddDate(0, 0, -cfg.StaleDays)

	for _, entry := range s.entries {
		if isExcluded(cfg, entry.ARN, entry.User) {
			continue
		}

		// Check stale user (password enabled but not used)
		if entry.PasswordEnabled && entry.PasswordLastUsed != nil {
			if entry.PasswordLastUsed.Before(threshold) {
				daysSince := int(now.Sub(*entry.PasswordLastUsed).Hours() / 24)
				result.Findings = append(result.Findings, iam.Finding{
					ID:             iam.FindingStaleUser,
					Severity:       iam.SeverityHigh,
					ResourceType:   iam.ResourceIAMUser,
					ResourceID:     entry.ARN,
					ResourceName:   entry.User,
					Message:        fmt.Sprintf("No console login in %d days", daysSince),
					Recommendation: "Disable console access or delete the user if no longer needed",
					Metadata: map[string]any{
						"password_last_used": entry.PasswordLastUsed.Format(time.RFC3339),
						"days_since_login":   daysSince,
					},
				})
			}
		}

		// Check stale access key 1
		if entry.AccessKey1Active {
			s.checkStaleKey(entry, 1, entry.AccessKey1LastUsedDate, threshold, now, result)
		}

		// Check stale access key 2
		if entry.AccessKey2Active {
			s.checkStaleKey(entry, 2, entry.AccessKey2LastUsedDate, threshold, now, result)
		}

		// Check missing MFA
		if entry.PasswordEnabled && !entry.MFAActive {
			result.Findings = append(result.Findings, iam.Finding{
				ID:             iam.FindingNoMFA,
				Severity:       iam.SeverityCritical,
				ResourceType:   iam.ResourceIAMUser,
				ResourceID:     entry.ARN,
				ResourceName:   entry.User,
				Message:        "Console user without MFA enabled",
				Recommendation: "Enable MFA for this user immediately",
				Metadata: map[string]any{
					"password_enabled": true,
					"mfa_active":       false,
				},
			})
		}
	}

	return result, nil
}

func (s *UserScanner) checkStaleKey(entry CredentialEntry, keyNum int, lastUsed *time.Time, threshold, now time.Time, result *iam.ScanResult) {
	// If the key has never been used, lastUsed is nil — flag it
	if lastUsed == nil || lastUsed.Before(threshold) {
		var daysSince int
		msg := fmt.Sprintf("Access key %d never used", keyNum)
		if lastUsed != nil {
			daysSince = int(now.Sub(*lastUsed).Hours() / 24)
			msg = fmt.Sprintf("Access key %d unused for %d days", keyNum, daysSince)
		}

		meta := map[string]any{
			"key_number": keyNum,
		}
		if lastUsed != nil {
			meta["last_used"] = lastUsed.Format(time.RFC3339)
			meta["days_since_use"] = daysSince
		}

		result.Findings = append(result.Findings, iam.Finding{
			ID:             iam.FindingStaleAccessKey,
			Severity:       iam.SeverityHigh,
			ResourceType:   iam.ResourceIAMUser,
			ResourceID:     entry.ARN,
			ResourceName:   entry.User,
			Message:        msg,
			Recommendation: "Rotate or deactivate the unused access key",
			Metadata:       meta,
		})
	}
}

// isExcluded checks if a resource should be excluded from scanning.
func isExcluded(cfg iam.ScanConfig, resourceID, principalName string) bool {
	if cfg.Exclude.ResourceIDs != nil && cfg.Exclude.ResourceIDs[resourceID] {
		return true
	}
	if cfg.Exclude.Principals != nil && cfg.Exclude.Principals[principalName] {
		return true
	}
	return false
}
