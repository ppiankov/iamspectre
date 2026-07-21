package azure

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
	"github.com/ppiankov/iamspectre/internal/testutil"
)

func TestScannerCount(t *testing.T) {
	if ScannerCount() != 4 {
		t.Fatalf("expected 4 scanners, got %d", ScannerCount())
	}
}

func TestAzureScanner_ScanAll_Empty(t *testing.T) {
	mock := &mockGraph{
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	client := NewClientWith("test-tenant", mock)
	scanner := NewAzureScanner(client, iam.ScanConfig{StaleDays: 90})

	result, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
}

// WO-77: production orchestration binds user activity coverage to the scanned tenant.
func TestAzureScanner_UserActivityCoverageUsesTenantScope(t *testing.T) {
	mock := &mockGraph{
		users: []User{{ID: "user-missing", UserPrincipalName: "missing@example.com", UserType: "Member"}},
		authMethods: map[string][]AuthenticationMethod{
			"user-missing": {{ODataType: "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod"}},
		},
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	result, err := NewAzureScanner(NewClientWith("tenant-a", mock), iam.ScanConfig{StaleDays: 90}).ScanAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	gap := findCoverageGap(result.CoverageGaps, iam.FindingStaleUser)
	if gap == nil || gap.Scope != "azure-tenant:tenant-a" || gap.AffectedCount != 1 {
		t.Fatalf("user activity coverage = %#v", gap)
	}
}

// WO-81: protected activity failures retain base checks and expose an exact coverage cause.
func TestAzureScanner_UserActivityAuthorizationDegradesWithoutErasingBaseUsers(t *testing.T) {
	tests := []struct {
		name      string
		status    int
		code      string
		wantCause string
	}{
		{name: "permission or role denied", status: http.StatusForbidden, code: "Authorization_RequestDenied", wantCause: "permission_or_role_denied"},
		{name: "premium license required", status: http.StatusForbidden, code: "Authentication_RequestFromNonPremiumTenantOrB2CTenant", wantCause: "premium_license_required"},
		{name: "non-gating server failure", status: http.StatusInternalServerError, code: "InternalServerError", wantCause: "activity_source_unavailable"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mock := &mockGraph{
				users: []User{
					{ID: "member-1", UserPrincipalName: "member@example.com", UserType: "Member"},
					{ID: "guest-1", UserPrincipalName: "guest@example.com", UserType: "Guest"},
				},
				userActivityErr: &GraphHTTPError{StatusCode: test.status, Code: test.code, Message: "activity unavailable"},
				roleAssigns:     []DirectoryRoleAssignment{{ID: "assignment-1", PrincipalID: "member-1"}},
				secDefaults:     &SecurityDefaultsPolicy{IsEnabled: false},
			}

			result, err := NewAzureScanner(NewClientWith("tenant-a", mock), iam.ScanConfig{StaleDays: 90}).ScanAll(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if findFinding(result.Findings, iam.FindingNoMFA) == nil || findFinding(result.Findings, iam.FindingLegacyAuth) == nil {
				t.Fatalf("base checks did not run: %#v", result.Findings)
			}
			for _, findingID := range []iam.FindingID{iam.FindingStaleUser, iam.FindingStaleGuestUser, iam.FindingUnusedRole} {
				gap := findCoverageGap(result.CoverageGaps, findingID)
				if gap == nil || gap.Cause != test.wantCause || gap.Scope != "azure-tenant:tenant-a" {
					t.Fatalf("coverage for %s = %#v", findingID, gap)
				}
			}
			if findFinding(result.Findings, iam.FindingStaleUser) != nil || findFinding(result.Findings, iam.FindingStaleGuestUser) != nil || findFinding(result.Findings, iam.FindingUnusedRole) != nil {
				t.Fatalf("unavailable activity emitted activity-derived finding: %#v", result.Findings)
			}
			if got := strings.Join(result.Errors, "|"); !strings.Contains(got, test.code) {
				t.Fatalf("activity diagnostic missing from errors: %q", got)
			}
		})
	}
}

// WO-81: authorized activity rows enrich every timestamp consumer without a gap.
func TestAzureScanner_UserActivityJoinUsesCompleteEvidence(t *testing.T) {
	oldInteractive := time.Now().AddDate(0, 0, -120)
	recentSuccessful := time.Now().AddDate(0, 0, -2)
	mock := &mockGraph{
		users: []User{{ID: "user-1", UserPrincipalName: "member@example.com", UserType: "Member"}},
		userActivities: []UserSignInActivity{{ID: "user-1", SignInActivity: &SignInActivity{
			LastSignInDateTime: &oldInteractive, LastSuccessfulSignInDateTime: &recentSuccessful,
		}}},
		authMethods: map[string][]AuthenticationMethod{"user-1": {{ODataType: authenticatorMethodType}}},
		roleAssigns: []DirectoryRoleAssignment{{ID: "assignment-1", PrincipalID: "user-1"}},
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}

	result, err := NewAzureScanner(NewClientWith("tenant-a", mock), iam.ScanConfig{StaleDays: 90}).ScanAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 0 || len(result.Errors) != 0 || len(result.CoverageGaps) != 0 {
		t.Fatalf("complete activity evidence produced diagnostics: %#v", result)
	}
}

// WO-68@v3: unavailable beta evidence clears legacy activity without blocking other Azure checks.
func TestAzureScanner_ServicePrincipalActivityUnavailable(t *testing.T) {
	legacySignIn := time.Now().AddDate(0, 0, -200)
	mock := &mockGraph{
		sps:           []ServicePrincipal{{ID: "sp-1", AppID: "app-1", DisplayName: "SP", SignInActivity: &SignInActivity{LastSignInDateTime: &legacySignIn}}},
		spActivityErr: fmt.Errorf("license unavailable"),
		secDefaults:   &SecurityDefaultsPolicy{IsEnabled: true},
	}
	result, err := NewAzureScanner(NewClientWith("tenant-a", mock), iam.ScanConfig{StaleDays: 90}).ScanAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if findFinding(result.Findings, iam.FindingStaleSP) != nil {
		t.Fatal("missing activity evidence emitted STALE_SP")
	}
	if len(result.CoverageGaps) != 1 || result.CoverageGaps[0].AffectedCount != 1 || result.CoverageGaps[0].Cause != "report_unavailable" {
		t.Fatalf("coverage gaps = %#v", result.CoverageGaps)
	}
	if len(result.Errors) == 0 || !strings.Contains(strings.Join(result.Errors, "|"), "license unavailable") {
		t.Fatalf("errors = %#v", result.Errors)
	}
}

// WO-68@v3: report rows join by appId to enrich the role-activity map, but a stale sign-in
// derived from the beta report never becomes a severity STALE_SP finding. Present rows also
// mean no coverage gap. Beta stays enrichment-only; it never drives a severity verdict.
func TestAzureScanner_ServicePrincipalActivityJoin(t *testing.T) {
	lastSignIn := time.Now().AddDate(0, 0, -100)
	mock := &mockGraph{
		sps:          []ServicePrincipal{{ID: "sp-1", AppID: "app-1", DisplayName: "SP"}},
		spActivities: []ServicePrincipalSignInActivity{{AppID: "app-1", LastSignInActivity: &SignInActivity{LastSignInDateTime: &lastSignIn}}},
		secDefaults:  &SecurityDefaultsPolicy{IsEnabled: true},
	}
	result, err := NewAzureScanner(NewClientWith("tenant-a", mock), iam.ScanConfig{StaleDays: 90}).ScanAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if findFinding(result.Findings, iam.FindingStaleSP) != nil {
		t.Fatalf("beta-derived stale sign-in must not emit STALE_SP: %#v", result.Findings)
	}
	if len(result.CoverageGaps) != 0 {
		t.Fatalf("present report rows should leave no coverage gap: %#v", result.CoverageGaps)
	}
}

func TestAzureScanner_ScanAll_UserFetchError(t *testing.T) {
	// WO-28@v2: share exact non-fatal error assertions across provider packages.
	mock := &mockGraph{
		usersErr:    fmt.Errorf("permission denied"),
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	client := NewClientWith("test-tenant", mock)
	scanner := NewAzureScanner(client, iam.ScanConfig{StaleDays: 90})

	testutil.AssertNonFatalScannerErrors(t, scanner.ScanAll, 1, "permission denied")
}

func TestAzureScanner_ScanAll_SPFetchError(t *testing.T) {
	// WO-28@v2: share exact non-fatal error assertions across provider packages.
	mock := &mockGraph{
		spsErr:      fmt.Errorf("access denied"),
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	client := NewClientWith("test-tenant", mock)
	scanner := NewAzureScanner(client, iam.ScanConfig{StaleDays: 90})

	testutil.AssertNonFatalScannerErrors(t, scanner.ScanAll, 1, "access denied")
}

// WO-68@v3, WO-73@v1: joined activity drives both SP and role decisions through orchestration.
func TestAzureScanner_ScanAll_Integration(t *testing.T) {
	// WO-73@v1: a known-stale principal keeps the integration assertion evidence-backed.
	lastSignIn := time.Now().AddDate(0, 0, -100)
	expired := time.Now().AddDate(0, -1, 0)

	mock := &mockGraph{
		users: []User{
			{
				ID:                "user-1",
				UserPrincipalName: "stale@example.com",
				DisplayName:       "Stale User",
				UserType:          "Member",
			},
			{
				ID: "inactive-principal", UserPrincipalName: "inactive@example.com", DisplayName: "Inactive",
				UserType: "Member",
			},
		},
		// WO-81: integration activity arrives through the separately authorized query.
		userActivities: []UserSignInActivity{
			{ID: "user-1", SignInActivity: &SignInActivity{LastSignInDateTime: &lastSignIn}},
			{ID: "inactive-principal", SignInActivity: &SignInActivity{LastSignInDateTime: &lastSignIn}},
		},
		apps: []Application{
			{
				ID:          "app-1",
				AppID:       "app-id-1",
				DisplayName: "Expired App",
				PasswordCredentials: []Credential{
					{KeyID: "k1", EndDateTime: &expired},
				},
			},
		},
		sps: []ServicePrincipal{
			// WO-80@v2: integration findings require the tenant-local Graph resource identity.
			{ID: "graph-resource-sp", AppID: microsoftGraphAppID, DisplayName: "Microsoft Graph"},
			{
				ID:          "sp-1",
				DisplayName: "Overprivileged SP",
				AppRoleAssignments: []AppRoleAssignment{
					{AppRoleID: "19dbc75e-c2e2-444c-a770-ec69d8559fc7", ResourceID: "graph-resource-sp"},
				},
			},
		},
		roleAssigns: []DirectoryRoleAssignment{
			{ID: "ra-1", RoleDefinitionID: "role-admin", PrincipalID: "inactive-principal"},
		},
		authMethods: map[string][]AuthenticationMethod{
			"user-1": {{ODataType: passwordMethodType}},
		},
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: false},
	}

	client := NewClientWith("test-tenant", mock)
	scanner := NewAzureScanner(client, iam.ScanConfig{StaleDays: 90})

	result, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have findings from all scanners
	if result.PrincipalsScanned == 0 {
		t.Fatal("expected principals scanned > 0")
	}

	findingTypes := make(map[iam.FindingID]bool)
	for _, f := range result.Findings {
		findingTypes[f.ID] = true
	}

	expectedTypes := []iam.FindingID{
		iam.FindingStaleUser,
		iam.FindingNoMFA,
		iam.FindingLegacyAuth,
		iam.FindingExpiredSecret,
		iam.FindingStaleApp,
		iam.FindingOverprivilegedApp,
		iam.FindingUnusedRole,
	}

	for _, expected := range expectedTypes {
		if !findingTypes[expected] {
			t.Errorf("expected finding type %s not found", expected)
		}
	}
}

// WO-73@v1: the activity map preserves every evidence state.
func TestBuildPrincipalActivityMap(t *testing.T) {
	recentSignIn := time.Now().AddDate(0, 0, -10)
	oldSignIn := time.Now().AddDate(0, 0, -200)

	users := []User{
		// WO-77: recent successful activity overrides stale interactive activity for roles too.
		{ID: "active-user", SignInActivity: &SignInActivity{LastSignInDateTime: &oldSignIn, LastSuccessfulSignInDateTime: &recentSignIn}},
		{ID: "stale-user", SignInActivity: &SignInActivity{LastSignInDateTime: &oldSignIn}},
		{ID: "no-data-user"},
	}
	sps := []ServicePrincipal{
		{ID: "active-sp", SignInActivity: &SignInActivity{LastSignInDateTime: &recentSignIn}},
	}

	activity := buildPrincipalActivityMap(users, sps, 90)

	if activity["active-user"] != PrincipalActivityRecent {
		t.Fatalf("active-user = %q", activity["active-user"])
	}
	if activity["stale-user"] != PrincipalActivityStale {
		t.Fatalf("stale-user = %q", activity["stale-user"])
	}
	if activity["no-data-user"] != PrincipalActivityUnknown {
		t.Fatalf("no-data-user = %q", activity["no-data-user"])
	}
	if activity["active-sp"] != PrincipalActivityRecent {
		t.Fatalf("active-sp = %q", activity["active-sp"])
	}
}

// WO-68@v3: missing authoritative rows erase stale compatibility data before role decisions.
func TestJoinServicePrincipalActivityClearsEmbeddedEvidence(t *testing.T) {
	legacySignIn := time.Now().AddDate(0, 0, -200)
	joined, coverage := joinServicePrincipalActivity(
		[]ServicePrincipal{{ID: "sp-1", AppID: "app-1", DisplayName: "SP", SignInActivity: &SignInActivity{LastSignInDateTime: &legacySignIn}}},
		nil, nil, "tenant-a", iam.ScanConfig{StaleDays: 90},
	)
	if joined[0].SignInActivity != nil || buildPrincipalActivityMap(nil, joined, 90)["sp-1"] != PrincipalActivityUnknown {
		t.Fatalf("joined principals retained non-authoritative evidence: %#v", joined)
	}
	if coverage == nil || coverage.Cause != "missing_report_rows" || coverage.AffectedCount != 1 {
		t.Fatalf("coverage = %#v", coverage)
	}
}

// WO-75@v1: excluded principals do not inflate missing-evidence opportunity counts.
func TestJoinServicePrincipalActivityExcludesCoverageOpportunities(t *testing.T) {
	recent := time.Now().AddDate(0, 0, -10)
	principals := []ServicePrincipal{
		{ID: "excluded-id", AppID: "excluded-app", DisplayName: "Excluded"},
		{ID: "eligible-id", AppID: "eligible-app", DisplayName: "Eligible"},
	}
	activities := []ServicePrincipalSignInActivity{{AppID: "excluded-app", LastSignInActivity: &SignInActivity{LastSignInDateTime: &recent}}}
	_, coverage := joinServicePrincipalActivity(principals, activities, nil, "tenant-a", iam.ScanConfig{
		StaleDays: 90, Exclude: iam.ExcludeConfig{ResourceIDs: map[string]bool{"excluded-id": true}},
	})
	if coverage == nil || coverage.AffectedCount != 1 || coverage.EvaluableCount != 0 || coverage.TotalCount != 1 {
		t.Fatalf("coverage = %#v", coverage)
	}

	_, coverage = joinServicePrincipalActivity(principals[:1], nil, nil, "tenant-a", iam.ScanConfig{
		StaleDays: 90, Exclude: iam.ExcludeConfig{Principals: map[string]bool{"Excluded": true}},
	})
	if coverage != nil {
		t.Fatalf("all-excluded coverage = %#v", coverage)
	}
}
