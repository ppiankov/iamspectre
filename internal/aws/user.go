package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-57@v5: AWS IAM access-key last-used tracking began on this documented date.
var accessKeyLastUseTrackingStartedAt = time.Date(2015, time.April, 22, 0, 0, 0, 0, time.UTC)

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
// WO-55@v3: aggregate only applicable and determinate user-activity evidence.
func (s *UserScanner) Scan(_ context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	result := &iam.ScanResult{PrincipalsScanned: len(s.entries)}
	scanNow := time.Now().UTC()

	for _, entry := range s.entries {
		if iam.IsExcluded(cfg, entry.ARN, entry.User) { // WO-14@v3: use the shared exclusion policy.
			continue
		}
		evidenceNow := scanNow
		if entry.CredentialReportGeneratedAt != nil {
			evidenceNow = entry.CredentialReportGeneratedAt.UTC() // WO-61@v2: compare observations at report generation, not later scan time.
		}
		threshold := iam.StaleThreshold(evidenceNow, cfg.StaleDays) // WO-24@v2: use the shared calendar cutoff.

		// WO-55@v3: use the latest applicable console or active-key evidence for user activity.
		lastActivity, passwordBlocks, passwordUnavailable, keyIndeterminate := latestUserActivity(entry)
		if passwordUnavailable {
			result.Errors = append(result.Errors, fmt.Sprintf("evaluate stale user %s: console last-used evidence is unavailable", entry.User))
		}
		if lastActivity != nil && lastActivity.Before(threshold) && !passwordBlocks && !keyIndeterminate {
			daysSince := int(evidenceNow.Sub(*lastActivity).Hours() / 24)
			metadata := map[string]any{
				"last_activity":       lastActivity.Format(time.RFC3339),
				"days_since_activity": daysSince,
			}
			addCredentialReportGeneratedAt(metadata, entry)
			result.Findings = append(result.Findings, iam.Finding{
				ID:             iam.FindingStaleUser,
				Severity:       iam.SeverityHigh,
				ResourceType:   iam.ResourceIAMUser,
				ResourceID:     entry.ARN,
				ResourceName:   entry.User,
				Message:        fmt.Sprintf("No IAM user activity in %d days", daysSince),
				Recommendation: staleUserRecommendation(entry),
				Metadata:       metadata,
			})
		}

		// Check stale access key 1
		if entry.AccessKey1Active {
			s.checkStaleKey(entry, 1, entry.AccessKey1LastUsedDate, entry.AccessKey1LastRotated, entry.AccessKey1UseState, threshold, evidenceNow, result)
		}

		// Check stale access key 2
		if entry.AccessKey2Active {
			s.checkStaleKey(entry, 2, entry.AccessKey2LastUsedDate, entry.AccessKey2LastRotated, entry.AccessKey2UseState, threshold, evidenceNow, result)
		}

		// Check missing MFA
		if entry.PasswordEnabled && !entry.MFAActive {
			metadata := map[string]any{
				"password_enabled": true,
				"mfa_active":       false,
			}
			addCredentialReportGeneratedAt(metadata, entry)
			result.Findings = append(result.Findings, iam.Finding{
				ID:             iam.FindingNoMFA,
				Severity:       iam.SeverityCritical,
				ResourceType:   iam.ResourceIAMUser,
				ResourceID:     entry.ARN,
				ResourceName:   entry.User,
				Message:        "Console user without MFA enabled",
				Recommendation: "Enable MFA for this user immediately",
				Metadata:       metadata,
			})
		}
	}

	return result, nil
}

// WO-55@v3: inactive credential slots cannot mask stale applicable activity.
func latestUserActivity(entry CredentialEntry) (*time.Time, bool, bool, bool) {
	var latest *time.Time
	consider := func(active bool, candidate *time.Time) {
		if active && candidate != nil && (latest == nil || candidate.After(*latest)) {
			latest = candidate
		}
	}

	consider(entry.PasswordEnabled, entry.PasswordLastUsed)
	consider(entry.AccessKey1Active, entry.AccessKey1LastUsedDate)
	consider(entry.AccessKey2Active, entry.AccessKey2LastUsedDate)
	passwordBlocks := entry.PasswordEnabled && entry.PasswordLastUsed == nil &&
		(entry.PasswordUseState == PasswordUseUnknown || entry.PasswordUseState == PasswordUseNoRecordedUse)
	passwordUnavailable := entry.PasswordEnabled && entry.PasswordLastUsed == nil && entry.PasswordUseState == PasswordUseUnknown
	keyIndeterminate := entry.AccessKey1Active && entry.AccessKey1LastUsedDate == nil && entry.AccessKey1UseState == CredentialUseUnknown
	keyIndeterminate = keyIndeterminate || entry.AccessKey2Active && entry.AccessKey2LastUsedDate == nil && entry.AccessKey2UseState == CredentialUseUnknown
	return latest, passwordBlocks, passwordUnavailable, keyIndeterminate
}

// WO-55@v3: stale guidance must match the credential channels that actually apply.
func staleUserRecommendation(entry CredentialEntry) string {
	if entry.PasswordEnabled {
		return "Review console and credential activity; disable access or delete the user if no longer needed"
	}
	return "Review active credentials; deactivate credentials or delete the user if no longer needed"
}

// WO-61@v2: attach source freshness without inventing a timestamp when AWS omits it.
func addCredentialReportGeneratedAt(metadata map[string]any, entry CredentialEntry) {
	if entry.CredentialReportGeneratedAt != nil {
		metadata["credential_report_generated_at"] = entry.CredentialReportGeneratedAt.UTC().Format(time.RFC3339)
	}
}

// WO-57@v5: require both global tracking coverage and per-key age evidence.
func (s *UserScanner) checkStaleKey(entry CredentialEntry, keyNum int, lastUsed, lastRotated *time.Time, state CredentialUseState, threshold, now time.Time, result *iam.ScanResult) {
	if lastUsed != nil {
		state = CredentialUseUsed
	}
	if state != CredentialUseNoRecordedUse && state != CredentialUseUsed {
		result.Errors = append(result.Errors, fmt.Sprintf("evaluate access key %d for %s: last-used evidence is unavailable", keyNum, entry.User))
		return
	}
	if state == CredentialUseUsed && lastUsed == nil {
		result.Errors = append(result.Errors, fmt.Sprintf("evaluate access key %d for %s: used evidence has no timestamp", keyNum, entry.User))
		return
	}

	if state == CredentialUseNoRecordedUse && threshold.Before(accessKeyLastUseTrackingStartedAt) {
		result.Errors = append(result.Errors, fmt.Sprintf("evaluate access key %d for %s: stale cutoff predates access-key last-used tracking", keyNum, entry.User))
		return
	}
	if state == CredentialUseNoRecordedUse && lastRotated == nil {
		result.Errors = append(result.Errors, fmt.Sprintf("evaluate access key %d for %s: key rotation age evidence is unavailable", keyNum, entry.User))
		return
	}
	if state == CredentialUseNoRecordedUse && !lastRotated.Before(threshold) {
		return
	}

	if state == CredentialUseNoRecordedUse || lastUsed.Before(threshold) {
		var daysSince int
		msg := fmt.Sprintf("Access key %d has no recorded use", keyNum)
		if lastUsed != nil {
			daysSince = int(now.Sub(*lastUsed).Hours() / 24)
			msg = fmt.Sprintf("Access key %d unused for %d days", keyNum, daysSince)
		}

		meta := map[string]any{
			"key_number": keyNum,
		}
		if state == CredentialUseNoRecordedUse {
			meta["no_recorded_use"] = true
		} else {
			meta["last_used"] = lastUsed.Format(time.RFC3339)
			meta["days_since_use"] = daysSince
		}
		addCredentialReportGeneratedAt(meta, entry)

		recommendation := "Rotate or deactivate the unused access key"
		if state == CredentialUseNoRecordedUse {
			recommendation = "Verify whether the key is needed and review activity before changing credentials"
		}
		result.Findings = append(result.Findings, iam.Finding{
			ID:             iam.FindingStaleAccessKey,
			Severity:       iam.SeverityHigh,
			ResourceType:   iam.ResourceIAMUser,
			ResourceID:     entry.ARN,
			ResourceName:   entry.User,
			Message:        msg,
			Recommendation: recommendation,
			Metadata:       meta,
		})
	}
}
