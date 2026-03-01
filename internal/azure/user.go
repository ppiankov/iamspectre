package azure

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// passwordMethodType is the OData type for password-only authentication.
const passwordMethodType = "#microsoft.graph.passwordAuthenticationMethod"

// UserScanner detects stale users, stale guest users, missing MFA, and legacy auth risk.
type UserScanner struct {
	api      GraphAPI
	users    []User
	fetchErr error
}

// NewUserScanner creates a scanner with pre-fetched user data.
func NewUserScanner(api GraphAPI, users []User, fetchErr error) *UserScanner {
	return &UserScanner{api: api, users: users, fetchErr: fetchErr}
}

// Type returns the resource type this scanner handles.
func (s *UserScanner) Type() iam.ResourceType {
	return iam.ResourceAzureUser
}

// Scan checks Azure AD users for stale accounts, missing MFA, and legacy auth risk.
func (s *UserScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	if s.fetchErr != nil {
		return nil, fmt.Errorf("fetch users: %w", s.fetchErr)
	}

	result := &iam.ScanResult{PrincipalsScanned: len(s.users)}
	cutoff := daysAgo(cfg.StaleDays)
	hasSignInData := false

	for _, user := range s.users {
		if isExcluded(cfg, user.ID, user.UserPrincipalName) {
			continue
		}

		if user.SignInActivity != nil && user.SignInActivity.LastSignInDateTime != nil {
			hasSignInData = true
		}

		s.checkStale(user, cutoff, result)
		s.checkMFA(ctx, user, result)
	}

	if !hasSignInData && len(s.users) > 0 {
		slog.Warn("signInActivity unavailable — Azure AD Premium P1 required for stale user detection")
	}

	s.checkLegacyAuth(ctx, result)

	return result, nil
}

func (s *UserScanner) checkStale(user User, cutoff time.Time, result *iam.ScanResult) {
	if user.SignInActivity == nil || user.SignInActivity.LastSignInDateTime == nil {
		return
	}

	lastSignIn := *user.SignInActivity.LastSignInDateTime
	if lastSignIn.After(cutoff) {
		return
	}

	daysSince := int(time.Since(lastSignIn).Hours() / 24)

	if user.UserType == "Guest" {
		result.Findings = append(result.Findings, iam.Finding{
			ID:             iam.FindingStaleGuestUser,
			Severity:       iam.SeverityHigh,
			ResourceType:   iam.ResourceAzureGuestUser,
			ResourceID:     user.ID,
			ResourceName:   user.UserPrincipalName,
			Message:        fmt.Sprintf("Guest user has not signed in for %d days", daysSince),
			Recommendation: "Review guest access and remove if no longer needed",
			Metadata: map[string]any{
				"last_sign_in": lastSignIn.Format(time.RFC3339),
				"days_since":   daysSince,
				"display_name": user.DisplayName,
			},
		})
		return
	}

	result.Findings = append(result.Findings, iam.Finding{
		ID:             iam.FindingStaleUser,
		Severity:       iam.SeverityHigh,
		ResourceType:   iam.ResourceAzureUser,
		ResourceID:     user.ID,
		ResourceName:   user.UserPrincipalName,
		Message:        fmt.Sprintf("User has not signed in for %d days", daysSince),
		Recommendation: "Disable or delete the user account if no longer needed",
		Metadata: map[string]any{
			"last_sign_in": lastSignIn.Format(time.RFC3339),
			"days_since":   daysSince,
			"display_name": user.DisplayName,
		},
	})
}

func (s *UserScanner) checkMFA(ctx context.Context, user User, result *iam.ScanResult) {
	methods, err := s.api.ListAuthenticationMethods(ctx, user.ID)
	if err != nil {
		slog.Warn("Failed to check MFA", "user", user.UserPrincipalName, "error", err)
		result.Errors = append(result.Errors, fmt.Sprintf("check MFA for %s: %v", user.UserPrincipalName, err))
		return
	}

	hasMFA := false
	for _, m := range methods {
		if m.ODataType != passwordMethodType {
			hasMFA = true
			break
		}
	}

	if !hasMFA {
		result.Findings = append(result.Findings, iam.Finding{
			ID:             iam.FindingNoMFA,
			Severity:       iam.SeverityCritical,
			ResourceType:   iam.ResourceAzureUser,
			ResourceID:     user.ID,
			ResourceName:   user.UserPrincipalName,
			Message:        "User has no multi-factor authentication methods registered",
			Recommendation: "Register an MFA method (authenticator app, phone, or security key)",
			Metadata: map[string]any{
				"display_name": user.DisplayName,
				"user_type":    user.UserType,
			},
		})
	}
}

func (s *UserScanner) checkLegacyAuth(ctx context.Context, result *iam.ScanResult) {
	policy, err := s.api.GetSecurityDefaults(ctx)
	if err != nil {
		slog.Warn("Failed to check security defaults", "error", err)
		result.Errors = append(result.Errors, fmt.Sprintf("check security defaults: %v", err))
		return
	}

	if !policy.IsEnabled {
		result.Findings = append(result.Findings, iam.Finding{
			ID:             iam.FindingLegacyAuth,
			Severity:       iam.SeverityHigh,
			ResourceType:   iam.ResourceAzureUser,
			ResourceID:     "tenant-security-defaults",
			ResourceName:   "Security Defaults",
			Message:        "Security defaults are disabled — legacy authentication protocols may be permitted",
			Recommendation: "Enable security defaults or configure Conditional Access policies to block legacy authentication",
		})
	}
}
