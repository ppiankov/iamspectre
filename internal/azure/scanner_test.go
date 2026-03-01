package azure

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
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

func TestAzureScanner_ScanAll_UserFetchError(t *testing.T) {
	mock := &mockGraph{
		usersErr:    fmt.Errorf("permission denied"),
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	client := NewClientWith("test-tenant", mock)
	scanner := NewAzureScanner(client, iam.ScanConfig{StaleDays: 90})

	result, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Errors) == 0 {
		t.Fatal("expected errors from user scanner failure")
	}
}

func TestAzureScanner_ScanAll_SPFetchError(t *testing.T) {
	mock := &mockGraph{
		spsErr:      fmt.Errorf("access denied"),
		secDefaults: &SecurityDefaultsPolicy{IsEnabled: true},
	}
	client := NewClientWith("test-tenant", mock)
	scanner := NewAzureScanner(client, iam.ScanConfig{StaleDays: 90})

	result, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// SP scanner should report error but not abort other scanners
	if len(result.Errors) == 0 {
		t.Fatal("expected errors from SP scanner failure")
	}
}

func TestAzureScanner_ScanAll_Integration(t *testing.T) {
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

	if !activity["active-user"] {
		t.Fatal("expected active-user to be active")
	}
	if activity["stale-user"] {
		t.Fatal("expected stale-user to be inactive")
	}
	if activity["no-data-user"] {
		t.Fatal("expected no-data-user to be inactive")
	}
	if !activity["active-sp"] {
		t.Fatal("expected active-sp to be active")
	}
}
