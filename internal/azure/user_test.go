package azure

import (
	"context"
	"fmt"
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

func TestUserScanner_FetchError(t *testing.T) {
	s := NewUserScanner(&mockGraph{}, nil, fmt.Errorf("network error"))
	_, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err == nil {
		t.Fatal("expected error from fetch failure")
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
			"user-3": {{ODataType: passwordMethodType}},
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
	if found.Severity != iam.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", found.Severity)
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
