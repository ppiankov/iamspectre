package azure

import (
	"context"
	"fmt"
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

// WO-68@v2: unavailable beta evidence remains visible without blocking other Azure checks.
func TestAzureScanner_ServicePrincipalActivityUnavailable(t *testing.T) {
	mock := &mockGraph{
		sps:           []ServicePrincipal{{ID: "sp-1", AppID: "app-1", DisplayName: "SP"}},
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

// WO-68@v2: report rows join by appId and drive the production STALE_SP path.
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
	if findFinding(result.Findings, iam.FindingStaleSP) == nil || len(result.CoverageGaps) != 0 {
		t.Fatalf("findings=%#v coverage=%#v", result.Findings, result.CoverageGaps)
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

// WO-68@v2, WO-73@v1: joined activity drives both SP and role decisions through orchestration.
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
				SignInActivity:    &SignInActivity{LastSignInDateTime: &lastSignIn},
			},
			{
				ID: "inactive-principal", UserPrincipalName: "inactive@example.com", DisplayName: "Inactive",
				UserType: "Member", SignInActivity: &SignInActivity{LastSignInDateTime: &lastSignIn},
			},
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
			{
				ID:          "sp-1",
				DisplayName: "Overprivileged SP",
				AppRoleAssignments: []AppRoleAssignment{
					{AppRoleID: "19dbc75e-c2e2-444c-a770-ec69d8559fc7"},
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
		{ID: "active-user", SignInActivity: &SignInActivity{LastSignInDateTime: &recentSignIn}},
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
