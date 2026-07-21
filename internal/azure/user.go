package azure

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-78: only method families that can satisfy MFA belong in this explicit allowlist.
const (
	passwordMethodType            = "#microsoft.graph.passwordAuthenticationMethod"
	emailMethodType               = "#microsoft.graph.emailAuthenticationMethod"
	authenticatorMethodType       = "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"
	fido2MethodType               = "#microsoft.graph.fido2AuthenticationMethod"
	phoneMethodType               = "#microsoft.graph.phoneAuthenticationMethod"
	softwareOATHMethodType        = "#microsoft.graph.softwareOathAuthenticationMethod"
	temporaryAccessPassMethodType = "#microsoft.graph.temporaryAccessPassAuthenticationMethod"
	windowsHelloMethodType        = "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"
	platformCredentialMethodType  = "#microsoft.graph.platformCredentialAuthenticationMethod"
)

// WO-77: UserScanner carries tenant-scoped user activity evidence through each check.
type UserScanner struct {
	api           GraphAPI
	users         []User
	fetchErr      error
	coverageScope string // WO-77: bind missing user activity evidence to one Azure tenant.
}

// WO-77: NewUserScanner preserves the legacy constructor with an explicit unknown scope.
func NewUserScanner(api GraphAPI, users []User, fetchErr error) *UserScanner {
	return NewUserScannerWithScope(api, users, fetchErr, "azure-tenant:unknown")
}

// WO-77: NewUserScannerWithScope binds missing activity observations to one Azure tenant.
func NewUserScannerWithScope(api GraphAPI, users []User, fetchErr error, coverageScope string) *UserScanner {
	return &UserScanner{api: api, users: users, fetchErr: fetchErr, coverageScope: coverageScope}
}

// Type returns the resource type this scanner handles.
func (s *UserScanner) Type() iam.ResourceType {
	return iam.ResourceAzureUser
}

// WO-77: Scan keeps stale findings and missing-evidence coverage on one clock and evidence rule.
func (s *UserScanner) Scan(ctx context.Context, cfg iam.ScanConfig) (*iam.ScanResult, error) {
	result := &iam.ScanResult{}
	if s.fetchErr != nil {
		// WO-87: tenant policy is independent evidence and survives user enumeration failure.
		s.checkLegacyAuth(ctx, result)
		return result, fmt.Errorf("fetch users: %w", s.fetchErr)
	}

	// WO-15: count only principals admitted by the guest filter.
	evidenceNow := time.Now().UTC() // WO-77: one clock sample governs cutoff and days-since metadata.
	cutoff := iam.StaleThreshold(evidenceNow, cfg.StaleDays)
	hasSignInData := false
	// WO-77: keep member and guest coverage independently actionable.
	memberMissing, memberEvaluable := 0, 0
	guestMissing, guestEvaluable := 0, 0

	for _, user := range s.users {
		// WO-15: skip excluded guests before any per-user evaluation or API call.
		if cfg.ExcludeGuests && user.UserType == "Guest" {
			continue
		}
		result.PrincipalsScanned++

		if iam.IsExcluded(cfg, user.ID, user.UserPrincipalName) { // WO-14@v3: use the shared exclusion policy.
			continue
		}

		latestActivity := latestUserActivity(user.SignInActivity)
		if latestActivity != nil {
			hasSignInData = true
		}
		if user.UserType == "Guest" {
			if latestActivity == nil {
				guestMissing++
			} else {
				guestEvaluable++
			}
		} else if latestActivity == nil {
			memberMissing++
		} else {
			memberEvaluable++
		}

		s.checkStale(user, cutoff, evidenceNow, result)
		s.checkMFA(ctx, user, result)
	}
	s.appendActivityCoverage(result, iam.FindingStaleUser, memberMissing, memberEvaluable, cfg.StaleDays)
	s.appendActivityCoverage(result, iam.FindingStaleGuestUser, guestMissing, guestEvaluable, cfg.StaleDays)

	if !hasSignInData && len(s.users) > 0 {
		slog.Warn("signInActivity unavailable — Azure AD Premium P1 required for stale user detection")
	}

	s.checkLegacyAuth(ctx, result)

	return result, nil
}

// WO-77: latestUserActivity keeps stale-user and role decisions on one evidence rule.
func latestUserActivity(activity *SignInActivity) *time.Time {
	if activity == nil {
		return nil
	}

	var latest *time.Time
	for _, candidate := range []*time.Time{
		activity.LastSuccessfulSignInDateTime,
		activity.LastNonInteractiveSignInDateTime,
		activity.LastSignInDateTime,
	} {
		if candidate != nil && (latest == nil || candidate.After(*latest)) {
			latest = candidate
		}
	}
	return latest
}

// WO-77: appendActivityCoverage exposes unevaluable stale checks without fabricating findings.
func (s *UserScanner) appendActivityCoverage(result *iam.ScanResult, findingID iam.FindingID, missing, evaluable, staleDays int) {
	if missing == 0 {
		return
	}
	result.CoverageGaps = append(result.CoverageGaps, iam.CoverageGapObservation{
		Capability: "azure_user_sign_in_activity", Cause: "user_activity_unknown",
		Scope: s.coverageScope, FindingID: findingID, AffectedCount: missing,
		EvaluableCount: evaluable, TotalCount: missing + evaluable,
		ObservationWindow: fmt.Sprintf("stale-threshold:%dd", staleDays),
		FeatureStage:      "v1.0", MaxConsequence: iam.SeverityHigh,
	})
}

// WO-77: checkStale uses the newest evidence across all Graph user activity timestamps.
func (s *UserScanner) checkStale(user User, cutoff, evidenceNow time.Time, result *iam.ScanResult) {
	lastSignIn := latestUserActivity(user.SignInActivity)
	if lastSignIn == nil {
		return
	}

	if lastSignIn.After(cutoff) {
		return
	}

	daysSince := int(evidenceNow.Sub(*lastSignIn).Hours() / 24)

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

// WO-78: checkMFA classifies only explicit MFA-capable methods and preserves evidence scope.
func (s *UserScanner) checkMFA(ctx context.Context, user User, result *iam.ScanResult) {
	methods, err := s.api.ListAuthenticationMethods(ctx, user.ID)
	if err != nil {
		slog.Warn("Failed to check MFA", "user", user.UserPrincipalName, "error", err)
		result.Errors = append(result.Errors, fmt.Sprintf("check MFA for %s: %v", user.UserPrincipalName, err))
		return
	}

	hasMFA := false
	for _, m := range methods {
		if isMFACapableMethodType(m.ODataType) {
			hasMFA = true
			break
		}
	}

	if !hasMFA {
		severity := iam.SeverityHigh
		message := "User has no MFA-capable authentication methods visible"
		recommendation := "Register an MFA-capable method and verify that policy requires MFA"
		metadata := map[string]any{
			"display_name": user.DisplayName,
			"user_type":    user.UserType,
		}
		if user.UserType == "Guest" { // WO-78: resource-tenant method absence cannot establish home-tenant MFA posture.
			severity = iam.SeverityLow
			message = "No MFA-capable method is visible for guest user in this resource tenant; home-tenant MFA evidence is unavailable"
			recommendation = "Verify MFA requirements in the guest user's home tenant before changing access"
			metadata["home_tenant_mfa_evidence"] = "unavailable"
			metadata["evidence_scope"] = "resource_tenant"
		}
		result.Findings = append(result.Findings, iam.Finding{
			ID:             iam.FindingNoMFA,
			Severity:       severity,
			ResourceType:   iam.ResourceAzureUser,
			ResourceID:     user.ID,
			ResourceName:   user.UserPrincipalName,
			Message:        message,
			Recommendation: recommendation,
			Metadata:       metadata,
		})
	}
}

// WO-78: isMFACapableMethodType fails closed for SSPR-only and unknown Graph method types.
func isMFACapableMethodType(methodType string) bool {
	switch methodType {
	case authenticatorMethodType,
		fido2MethodType,
		phoneMethodType,
		softwareOATHMethodType,
		temporaryAccessPassMethodType,
		windowsHelloMethodType,
		platformCredentialMethodType:
		return true
	default:
		return false
	}
}

// WO-79: checkLegacyAuth distinguishes disabled defaults from proven legacy-auth exposure.
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
			Severity:       iam.SeverityLow, // WO-79: disabled defaults alone leave effective policy evidence indeterminate.
			ResourceType:   iam.ResourceAzureUser,
			ResourceID:     "tenant-security-defaults",
			ResourceName:   "Security Defaults",
			Message:        "Security defaults are disabled; Conditional Access was not evaluated, so effective legacy-auth coverage is unknown",
			Recommendation: "Verify that an effective Conditional Access policy blocks legacy authentication",
			Metadata: map[string]any{
				"evidence_state":               "indeterminate",
				"security_defaults_enabled":    false,
				"conditional_access_evaluated": false,
			},
		})
	}
}
