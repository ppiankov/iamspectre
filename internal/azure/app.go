package azure

import (
	"context"
	"fmt"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// expiryWarningDays is the number of days before expiry to emit an EXPIRING_SECRET finding.
const expiryWarningDays = 30

// AppScanner detects stale app registrations, expired secrets, and expiring secrets.
type AppScanner struct {
	api GraphAPI
}

// NewAppScanner creates a scanner for Azure AD app registrations.
func NewAppScanner(api GraphAPI) *AppScanner {
	return &AppScanner{api: api}
}

// Type returns the resource type this scanner handles.
func (s *AppScanner) Type() iam.ResourceType {
	return iam.ResourceAzureAppRegistration
}

// Scan checks Azure AD app registrations for credential issues.
func (s *AppScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	apps, err := s.api.ListApplications(ctx)
	if err != nil {
		return nil, fmt.Errorf("list applications: %w", err)
	}

	result := &iam.ScanResult{PrincipalsScanned: len(apps)}
	now := time.Now().UTC()
	warningCutoff := now.AddDate(0, 0, expiryWarningDays)

	for _, app := range apps {
		if isExcluded(cfg, app.ID, app.DisplayName) {
			continue
		}

		allCreds := append(app.PasswordCredentials, app.KeyCredentials...)
		allExpired := len(allCreds) > 0
		hasAnyCred := len(allCreds) > 0

		for _, cred := range allCreds {
			if cred.EndDateTime == nil {
				allExpired = false
				continue
			}

			if cred.EndDateTime.Before(now) {
				result.Findings = append(result.Findings, iam.Finding{
					ID:             iam.FindingExpiredSecret,
					Severity:       iam.SeverityCritical,
					ResourceType:   iam.ResourceAzureAppRegistration,
					ResourceID:     app.ID,
					ResourceName:   app.DisplayName,
					Message:        fmt.Sprintf("Credential %q expired on %s", credName(cred), cred.EndDateTime.Format("2006-01-02")),
					Recommendation: "Rotate or remove the expired credential",
					Metadata: map[string]any{
						"app_id":     app.AppID,
						"key_id":     cred.KeyID,
						"expired_at": cred.EndDateTime.Format(time.RFC3339),
					},
				})
			} else {
				allExpired = false
				if cred.EndDateTime.Before(warningCutoff) {
					daysUntil := int(time.Until(*cred.EndDateTime).Hours() / 24)
					result.Findings = append(result.Findings, iam.Finding{
						ID:             iam.FindingExpiringSecret,
						Severity:       iam.SeverityMedium,
						ResourceType:   iam.ResourceAzureAppRegistration,
						ResourceID:     app.ID,
						ResourceName:   app.DisplayName,
						Message:        fmt.Sprintf("Credential %q expires in %d days", credName(cred), daysUntil),
						Recommendation: "Rotate the credential before it expires",
						Metadata: map[string]any{
							"app_id":     app.AppID,
							"key_id":     cred.KeyID,
							"expires_at": cred.EndDateTime.Format(time.RFC3339),
							"days_until": daysUntil,
						},
					})
				}
			}
		}

		if hasAnyCred && allExpired {
			result.Findings = append(result.Findings, iam.Finding{
				ID:             iam.FindingStaleApp,
				Severity:       iam.SeverityHigh,
				ResourceType:   iam.ResourceAzureAppRegistration,
				ResourceID:     app.ID,
				ResourceName:   app.DisplayName,
				Message:        "All credentials for this app registration have expired",
				Recommendation: "Review the app registration and remove it if no longer needed, or rotate credentials",
				Metadata: map[string]any{
					"app_id":           app.AppID,
					"credential_count": len(allCreds),
				},
			})
		}
	}

	return result, nil
}

func credName(c Credential) string {
	if c.DisplayName != "" {
		return c.DisplayName
	}
	return c.KeyID
}
