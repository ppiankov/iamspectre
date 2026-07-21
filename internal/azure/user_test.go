package azure

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

func TestUserScanner_Type(t *testing.T) {
	s := NewUserScanner(&mockGraph{}, nil, nil)
	if s.Type() != iam.ResourceAzureUser {
		t.Fatalf("expected %s, got %s", iam.ResourceAzureUser, s.Type())
	}
}

// WO-87: observe calls to evidence sources that remain independent of user enumeration.
type observedUserGraph struct {
	*mockGraph
	authMethodCalls      int
	securityDefaultCalls int
}

// WO-87: user-derived checks must not run without an enumerated user.
func (g *observedUserGraph) ListAuthenticationMethods(ctx context.Context, userID string) ([]AuthenticationMethod, error) {
	g.authMethodCalls++
	return g.mockGraph.ListAuthenticationMethods(ctx, userID)
}

// WO-87: tenant policy remains evaluable when user enumeration fails.
func (g *observedUserGraph) GetSecurityDefaults(ctx context.Context) (*SecurityDefaultsPolicy, error) {
	g.securityDefaultCalls++
	return g.mockGraph.GetSecurityDefaults(ctx)
}

// WO-87: retain tenant-policy evidence alongside the user-fetch error.
func TestUserScanner_FetchError(t *testing.T) {
	graph := &observedUserGraph{mockGraph: &mockGraph{secDefaults: &SecurityDefaultsPolicy{IsEnabled: false}}}
	s := NewUserScanner(graph, nil, fmt.Errorf("network error"))
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err == nil {
		t.Fatal("expected error from fetch failure")
	}
	if graph.securityDefaultCalls != 1 || graph.authMethodCalls != 0 {
		t.Fatalf("calls: security defaults=%d auth methods=%d", graph.securityDefaultCalls, graph.authMethodCalls)
	}
	if findFinding(result.Findings, iam.FindingLegacyAuth) == nil || result.PrincipalsScanned != 0 {
		t.Fatalf("independent tenant evidence was lost: %#v", result)
	}
}

// WO-87: preserve both independent source failures without duplicating the fetch wrapper.
func TestUserScanner_FetchAndSecurityDefaultsErrors(t *testing.T) {
	graph := &observedUserGraph{mockGraph: &mockGraph{secDefaultsErr: fmt.Errorf("policy denied")}}
	result, err := NewUserScanner(graph, nil, fmt.Errorf("users denied")).Scan(
		context.Background(), iam.ScanConfig{StaleDays: 90},
	)
	if err == nil || strings.Count(err.Error(), "users denied") != 1 {
		t.Fatalf("fetch error = %v", err)
	}
	if graph.securityDefaultCalls != 1 || graph.authMethodCalls != 0 {
		t.Fatalf("calls: security defaults=%d auth methods=%d", graph.securityDefaultCalls, graph.authMethodCalls)
	}
	if got := strings.Join(result.Errors, "|"); strings.Count(got, "policy denied") != 1 {
		t.Fatalf("result errors = %q", got)
	}
}

func TestUserScanner_StaleUser(t *testing.T) {
	lastSignIn := time.Now().AddDate(0, 0, -100)
	users := []User{
		{
			ID:                "user-1",
			DisplayName:       "Alice",
			UserPrincipalName: "alice@example.com",
			UserType:          "Member",
			SignInActivity: &SignInActivity{
				LastSignInDateTime: &lastSignIn,
			},
		},
	}

	mock := &mockGraph{
		authMethods: map[string][]AuthenticationMethod{
			"user-1": {{ODataType: "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"}},
		},
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	s := NewUserScanner(mock, users, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingStaleUser)
	if found == nil {
		t.Fatal("expected STALE_USER finding")
	}
	if found.ResourceName != "alice@example.com" {
		t.Fatalf("expected alice@example.com, got %s", found.ResourceName)
	}
}

// WO-77: the newest user activity timestamp prevents false stale-user findings.
func TestUserScanner_LatestActivityPreventsStaleUser(t *testing.T) {
	oldInteractive := time.Now().AddDate(0, 0, -200)
	recentNonInteractive := time.Now().AddDate(0, 0, -5)
	users := []User{{
		ID: "user-active", UserPrincipalName: "active@example.com", UserType: "Member",
		SignInActivity: &SignInActivity{
			LastSignInDateTime:               &oldInteractive,
			LastNonInteractiveSignInDateTime: &recentNonInteractive,
		},
	}}
	mock := &mockGraph{
		authMethods: map[string][]AuthenticationMethod{
			"user-active": {{ODataType: "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"}},
		},
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}

	result, err := NewUserScanner(mock, users, nil).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatal(err)
	}
	if findFinding(result.Findings, iam.FindingStaleUser) != nil {
		t.Fatalf("newer non-interactive activity emitted STALE_USER: %#v", result.Findings)
	}
}

// WO-77: stale metadata identifies the newest usable evidence, not only interactive activity.
func TestUserScanner_LatestActivityDrivesStaleMetadata(t *testing.T) {
	evidenceNow := time.Date(2026, time.July, 20, 12, 0, 0, 0, time.UTC)
	oldInteractive := evidenceNow.AddDate(0, 0, -220)
	oldNonInteractive := evidenceNow.AddDate(0, 0, -180)
	latestSuccessful := evidenceNow.AddDate(0, 0, -120)
	user := User{
		ID: "user-stale", UserPrincipalName: "stale@example.com", UserType: "Member",
		SignInActivity: &SignInActivity{
			LastSignInDateTime:               &oldInteractive,
			LastNonInteractiveSignInDateTime: &oldNonInteractive,
			LastSuccessfulSignInDateTime:     &latestSuccessful,
		},
	}
	result := &iam.ScanResult{}
	NewUserScanner(&mockGraph{}, nil, nil).checkStale(
		user, iam.StaleThreshold(evidenceNow, 90), evidenceNow, result,
	)
	finding := findFinding(result.Findings, iam.FindingStaleUser)
	if finding == nil || finding.Metadata["last_sign_in"] != latestSuccessful.Format(time.RFC3339) {
		t.Fatalf("stale finding did not use latest activity: %#v", finding)
	}
	if finding.Metadata["days_since"] != 120 {
		t.Fatalf("days_since = %v, want 120", finding.Metadata["days_since"])
	}
}

func TestUserScanner_StaleGuestUser(t *testing.T) {
	lastSignIn := time.Now().AddDate(0, 0, -200)
	users := []User{
		{
			ID:                "guest-1",
			DisplayName:       "External Bob",
			UserPrincipalName: "bob_partner.com#EXT#@example.com",
			UserType:          "Guest",
			SignInActivity: &SignInActivity{
				LastSignInDateTime: &lastSignIn,
			},
		},
	}

	mock := &mockGraph{
		authMethods: map[string][]AuthenticationMethod{
			"guest-1": {{ODataType: "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"}},
		},
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	s := NewUserScanner(mock, users, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingStaleGuestUser)
	if found == nil {
		t.Fatal("expected STALE_GUEST_USER finding")
	}
	if found.ResourceType != iam.ResourceAzureGuestUser {
		t.Fatalf("expected %s, got %s", iam.ResourceAzureGuestUser, found.ResourceType)
	}
}

// WO-15: pin guest exclusion before per-user API calls.
func TestUserScanner_ExcludeGuests(t *testing.T) {
	users := []User{
		{ID: "member-1", UserPrincipalName: "member@example.com", UserType: "Member"},
		{ID: "guest-1", UserPrincipalName: "guest@example.com", UserType: "Guest"},
	}
	mock := &mockGraph{
		authMethods: map[string][]AuthenticationMethod{
			"member-1": {{ODataType: "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"}},
		},
		authMethodsErr: map[string]error{"guest-1": fmt.Errorf("guest MFA must not be queried")},
		secDefaults:    &SecurityDefaultsPolicy{IsEnabled: true},
	}
	s := NewUserScanner(mock, users, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90, ExcludeGuests: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.PrincipalsScanned != 1 {
		t.Fatalf("principals scanned = %d, want 1", result.PrincipalsScanned)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("guest processing produced errors: %v", result.Errors)
	}
}

func TestUserScanner_HealthyUser(t *testing.T) {
	recentSignIn := time.Now().AddDate(0, 0, -5)
	users := []User{
		{
			ID:                "user-2",
			DisplayName:       "Charlie",
			UserPrincipalName: "charlie@example.com",
			UserType:          "Member",
			SignInActivity: &SignInActivity{
				LastSignInDateTime: &recentSignIn,
			},
		},
	}

	mock := &mockGraph{
		authMethods: map[string][]AuthenticationMethod{
			"user-2": {{ODataType: "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"}},
		},
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	s := NewUserScanner(mock, users, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for healthy user, got %d", len(result.Findings))
	}
}

func TestUserScanner_NoMFA(t *testing.T) {
	recentSignIn := time.Now().AddDate(0, 0, -5)
	users := []User{
		{
			ID:                "user-3",
			DisplayName:       "Dave",
			UserPrincipalName: "dave@example.com",
			UserType:          "Member",
			SignInActivity: &SignInActivity{
				LastSignInDateTime: &recentSignIn,
			},
		},
	}

	mock := &mockGraph{
		authMethods: map[string][]AuthenticationMethod{
			// WO-78: email is SSPR-only and must not upgrade password-only evidence to MFA.
			"user-3": {{ODataType: passwordMethodType}, {ODataType: emailMethodType}},
		},
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	s := NewUserScanner(mock, users, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingNoMFA)
	if found == nil {
		t.Fatal("expected NO_MFA finding")
	}
	if found.Severity != iam.SeverityHigh {
		t.Fatalf("expected high severity, got %s", found.Severity)
	}
}

// WO-78: every supported Graph method family is classified explicitly and unknown types fail closed.
func TestIsMFACapableMethodType(t *testing.T) {
	tests := []struct {
		name       string
		methodType string
		want       bool
	}{
		{name: "password", methodType: passwordMethodType},
		{name: "email SSPR", methodType: emailMethodType},
		{name: "unknown", methodType: "#microsoft.graph.futureAuthenticationMethod"},
		{name: "authenticator", methodType: authenticatorMethodType, want: true},
		{name: "FIDO2 passkey", methodType: fido2MethodType, want: true},
		{name: "phone", methodType: phoneMethodType, want: true},
		{name: "software OATH", methodType: softwareOATHMethodType, want: true},
		{name: "temporary access pass", methodType: temporaryAccessPassMethodType, want: true},
		{name: "Windows Hello", methodType: windowsHelloMethodType, want: true},
		{name: "platform credential", methodType: platformCredentialMethodType, want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isMFACapableMethodType(test.methodType); got != test.want {
				t.Fatalf("isMFACapableMethodType(%q) = %t, want %t", test.methodType, got, test.want)
			}
		})
	}
}

// WO-78: guest method absence remains visible without claiming knowledge of the home tenant.
func TestUserScanner_GuestNoMFAUsesEvidenceAwareGrading(t *testing.T) {
	recentSignIn := time.Now().AddDate(0, 0, -5)
	users := []User{{
		ID: "guest-no-mfa", UserPrincipalName: "guest@example.com", UserType: "Guest",
		SignInActivity: &SignInActivity{LastSuccessfulSignInDateTime: &recentSignIn},
	}}
	mock := &mockGraph{
		authMethods: map[string][]AuthenticationMethod{
			"guest-no-mfa": {{ODataType: passwordMethodType}, {ODataType: emailMethodType}},
		},
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}

	result, err := NewUserScanner(mock, users, nil).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatal(err)
	}
	finding := findFinding(result.Findings, iam.FindingNoMFA)
	if finding == nil || finding.Severity != iam.SeverityLow {
		t.Fatalf("guest NO_MFA grading = %#v", finding)
	}
	if finding.Metadata["home_tenant_mfa_evidence"] != "unavailable" || finding.Metadata["evidence_scope"] != "resource_tenant" {
		t.Fatalf("guest NO_MFA metadata = %#v", finding.Metadata)
	}
	if !strings.Contains(finding.Message, "home-tenant MFA evidence is unavailable") || !strings.Contains(finding.Recommendation, "home tenant") {
		t.Fatalf("guest NO_MFA guidance = %#v", finding)
	}
}

func TestUserScanner_HasMFA(t *testing.T) {
	recentSignIn := time.Now().AddDate(0, 0, -5)
	users := []User{
		{
			ID:                "user-4",
			DisplayName:       "Eve",
			UserPrincipalName: "eve@example.com",
			UserType:          "Member",
			SignInActivity: &SignInActivity{
				LastSignInDateTime: &recentSignIn,
			},
		},
	}

	mock := &mockGraph{
		authMethods: map[string][]AuthenticationMethod{
			"user-4": {
				{ODataType: passwordMethodType},
				{ODataType: "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"},
			},
		},
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	s := NewUserScanner(mock, users, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if findFinding(result.Findings, iam.FindingNoMFA) != nil {
		t.Fatal("should not emit NO_MFA when user has authenticator app")
	}
}

// WO-79: disabled defaults remain visible without claiming effective policy exposure.
func TestUserScanner_LegacyAuth_SecurityDefaultsDisabled(t *testing.T) {
	users := []User{}
	mock := &mockGraph{
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: false},
	}
	s := NewUserScanner(mock, users, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingLegacyAuth)
	if found == nil {
		t.Fatal("expected LEGACY_AUTH finding when security defaults disabled")
	}
	if found.Severity != iam.SeverityLow || found.Metadata["evidence_state"] != "indeterminate" {
		t.Fatalf("legacy-auth evidence grading = %#v", found)
	}
	if found.Metadata["conditional_access_evaluated"] != false || !strings.Contains(found.Message, "Conditional Access was not evaluated") {
		t.Fatalf("legacy-auth evidence context = %#v", found)
	}
	if !strings.Contains(found.Recommendation, "Verify") || !strings.Contains(found.Recommendation, "Conditional Access") {
		t.Fatalf("legacy-auth recommendation = %q", found.Recommendation)
	}
}

func TestUserScanner_LegacyAuth_SecurityDefaultsEnabled(t *testing.T) {
	users := []User{}
	mock := &mockGraph{
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	s := NewUserScanner(mock, users, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if findFinding(result.Findings, iam.FindingLegacyAuth) != nil {
		t.Fatal("should not emit LEGACY_AUTH when security defaults are enabled")
	}
}

// WO-79: a Security Defaults fetch error stays diagnostic and emits no unsupported verdict.
func TestUserScanner_LegacyAuth_SecurityDefaultsError(t *testing.T) {
	mock := &mockGraph{secDefaultsErr: fmt.Errorf("security defaults unavailable")}
	result, err := NewUserScanner(mock, nil, nil).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected scanner error: %v", err)
	}
	if findFinding(result.Findings, iam.FindingLegacyAuth) != nil {
		t.Fatalf("fetch error emitted LEGACY_AUTH: %#v", result.Findings)
	}
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "security defaults unavailable") {
		t.Fatalf("fetch errors = %#v", result.Errors)
	}
}

func TestUserScanner_NoSignInActivity(t *testing.T) {
	users := []User{
		{
			ID:                "user-5",
			DisplayName:       "Frank",
			UserPrincipalName: "frank@example.com",
			UserType:          "Member",
			// No SignInActivity (P1 not available)
		},
	}

	mock := &mockGraph{
		authMethods: map[string][]AuthenticationMethod{
			"user-5": {{ODataType: passwordMethodType}},
		},
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	s := NewUserScanner(mock, users, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should not emit STALE_USER without sign-in data
	if findFinding(result.Findings, iam.FindingStaleUser) != nil {
		t.Fatal("should not emit STALE_USER without signInActivity")
	}
	// Should still check MFA
	if findFinding(result.Findings, iam.FindingNoMFA) == nil {
		t.Fatal("should still emit NO_MFA even without signInActivity")
	}
}

// WO-77: missing member and guest evidence produce separate tenant-scoped coverage observations.
func TestUserScanner_MissingActivityCoverageByUserType(t *testing.T) {
	recent := time.Now().AddDate(0, 0, -5)
	users := []User{
		{ID: "member-missing", UserPrincipalName: "member-missing@example.com", UserType: "Member"},
		{ID: "member-present", UserPrincipalName: "member-present@example.com", UserType: "Member", SignInActivity: &SignInActivity{LastSuccessfulSignInDateTime: &recent}},
		{ID: "guest-missing", UserPrincipalName: "guest-missing@example.com", UserType: "Guest"},
		{ID: "guest-present", UserPrincipalName: "guest-present@example.com", UserType: "Guest", SignInActivity: &SignInActivity{LastNonInteractiveSignInDateTime: &recent}},
	}
	authMethods := make(map[string][]AuthenticationMethod, len(users))
	for _, user := range users {
		authMethods[user.ID] = []AuthenticationMethod{{ODataType: "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"}}
	}
	mock := &mockGraph{authMethods: authMethods, secDefaults: &SecurityDefaultsPolicy{IsEnabled: true}}

	result, err := NewUserScannerWithScope(mock, users, nil, "azure-tenant:tenant-a").Scan(
		context.Background(), iam.ScanConfig{StaleDays: 90},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, findingID := range []iam.FindingID{iam.FindingStaleUser, iam.FindingStaleGuestUser} {
		gap := findCoverageGap(result.CoverageGaps, findingID)
		if gap == nil || gap.Scope != "azure-tenant:tenant-a" || gap.AffectedCount != 1 || gap.EvaluableCount != 1 || gap.TotalCount != 2 {
			t.Fatalf("coverage for %s = %#v", findingID, gap)
		}
	}
}

// WO-77: explicit principal and guest exclusions do not become coverage opportunities.
func TestUserScanner_MissingActivityCoverageExcludesOutOfScopeUsers(t *testing.T) {
	users := []User{
		{ID: "excluded-member", UserPrincipalName: "excluded@example.com", UserType: "Member"},
		{ID: "excluded-guest", UserPrincipalName: "guest@example.com", UserType: "Guest"},
	}
	mock := &mockGraph{secDefaults: &SecurityDefaultsPolicy{IsEnabled: true}}
	result, err := NewUserScannerWithScope(mock, users, nil, "azure-tenant:tenant-a").Scan(context.Background(), iam.ScanConfig{
		StaleDays: 90, ExcludeGuests: true,
		Exclude: iam.ExcludeConfig{Principals: map[string]bool{"excluded@example.com": true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.CoverageGaps) != 0 {
		t.Fatalf("excluded users produced coverage: %#v", result.CoverageGaps)
	}
}

func TestUserScanner_Excluded(t *testing.T) {
	lastSignIn := time.Now().AddDate(0, 0, -100)
	users := []User{
		{
			ID:                "user-6",
			DisplayName:       "Excluded User",
			UserPrincipalName: "excluded@example.com",
			UserType:          "Member",
			SignInActivity:    &SignInActivity{LastSignInDateTime: &lastSignIn},
		},
	}

	mock := &mockGraph{secDefaults: &SecurityDefaultsPolicy{IsEnabled: true}}
	s := NewUserScanner(mock, users, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{
		StaleDays: 90,
		Exclude:   iam.ExcludeConfig{Principals: map[string]bool{"excluded@example.com": true}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for excluded user, got %d", len(result.Findings))
	}
}

func TestUserScanner_PrincipalsScanned(t *testing.T) {
	users := []User{
		{ID: "u1", UserPrincipalName: "a@x.com", UserType: "Member"},
		{ID: "u2", UserPrincipalName: "b@x.com", UserType: "Member"},
	}
	mock := &mockGraph{secDefaults: &SecurityDefaultsPolicy{IsEnabled: true}}
	s := NewUserScanner(mock, users, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.PrincipalsScanned != 2 {
		t.Fatalf("expected 2 principals scanned, got %d", result.PrincipalsScanned)
	}
}

func findFinding(findings []iam.Finding, id iam.FindingID) *iam.Finding {
	for _, f := range findings {
		if f.ID == id {
			return &f
		}
	}
	return nil
}

// WO-77: findCoverageGap keeps coverage assertions focused on the affected finding class.
func findCoverageGap(gaps []iam.CoverageGapObservation, id iam.FindingID) *iam.CoverageGapObservation {
	for index := range gaps {
		if gaps[index].FindingID == id {
			return &gaps[index]
		}
	}
	return nil
}
