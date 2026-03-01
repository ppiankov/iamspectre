package azure

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

func TestServicePrincipalScanner_Type(t *testing.T) {
	s := NewServicePrincipalScanner(&mockGraph{}, nil, nil)
	if s.Type() != iam.ResourceAzureServicePrincipal {
		t.Fatalf("expected %s, got %s", iam.ResourceAzureServicePrincipal, s.Type())
	}
}

func TestServicePrincipalScanner_FetchError(t *testing.T) {
	s := NewServicePrincipalScanner(&mockGraph{}, nil, fmt.Errorf("access denied"))
	_, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err == nil {
		t.Fatal("expected error from fetch failure")
	}
}

func TestServicePrincipalScanner_OverprivilegedApp(t *testing.T) {
	sps := []ServicePrincipal{
		{
			ID:          "sp-1",
			AppID:       "app-id-1",
			DisplayName: "Dangerous App",
			AppRoleAssignments: []AppRoleAssignment{
				{
					AppRoleID:           "19dbc75e-c2e2-444c-a770-ec69d8559fc7", // Directory.ReadWrite.All
					ResourceDisplayName: "Microsoft Graph",
				},
			},
		},
	}

	s := NewServicePrincipalScanner(&mockGraph{}, sps, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingOverprivilegedApp)
	if found == nil {
		t.Fatal("expected OVERPRIVILEGED_APP finding")
	}
	if found.Severity != iam.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", found.Severity)
	}
	if found.Metadata["role_name"] != "Directory.ReadWrite.All" {
		t.Fatalf("expected Directory.ReadWrite.All, got %v", found.Metadata["role_name"])
	}
}

func TestServicePrincipalScanner_SafePermissions(t *testing.T) {
	sps := []ServicePrincipal{
		{
			ID:          "sp-2",
			AppID:       "app-id-2",
			DisplayName: "Safe App",
			AppRoleAssignments: []AppRoleAssignment{
				{
					AppRoleID:           "e1fe6dd8-ba31-4d61-89e7-88639da4683d", // User.Read
					ResourceDisplayName: "Microsoft Graph",
				},
			},
		},
	}

	s := NewServicePrincipalScanner(&mockGraph{}, sps, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if findFinding(result.Findings, iam.FindingOverprivilegedApp) != nil {
		t.Fatal("should not emit OVERPRIVILEGED_APP for safe permissions")
	}
}

func TestServicePrincipalScanner_StaleSP(t *testing.T) {
	lastSignIn := time.Now().AddDate(0, 0, -120)
	sps := []ServicePrincipal{
		{
			ID:          "sp-3",
			AppID:       "app-id-3",
			DisplayName: "Stale SP",
			SignInActivity: &SignInActivity{
				LastSignInDateTime: &lastSignIn,
			},
		},
	}

	s := NewServicePrincipalScanner(&mockGraph{}, sps, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingStaleSP)
	if found == nil {
		t.Fatal("expected STALE_SP finding")
	}
}

func TestServicePrincipalScanner_HealthySP(t *testing.T) {
	recentSignIn := time.Now().AddDate(0, 0, -5)
	sps := []ServicePrincipal{
		{
			ID:          "sp-4",
			AppID:       "app-id-4",
			DisplayName: "Active SP",
			SignInActivity: &SignInActivity{
				LastSignInDateTime: &recentSignIn,
			},
		},
	}

	s := NewServicePrincipalScanner(&mockGraph{}, sps, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if findFinding(result.Findings, iam.FindingStaleSP) != nil {
		t.Fatal("should not emit STALE_SP for active service principal")
	}
}

func TestServicePrincipalScanner_NoSignInData(t *testing.T) {
	sps := []ServicePrincipal{
		{
			ID:          "sp-5",
			AppID:       "app-id-5",
			DisplayName: "No Data SP",
		},
	}

	s := NewServicePrincipalScanner(&mockGraph{}, sps, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if findFinding(result.Findings, iam.FindingStaleSP) != nil {
		t.Fatal("should not emit STALE_SP without sign-in data")
	}
}

func TestServicePrincipalScanner_Excluded(t *testing.T) {
	sps := []ServicePrincipal{
		{
			ID:          "sp-6",
			DisplayName: "Excluded SP",
			AppRoleAssignments: []AppRoleAssignment{
				{AppRoleID: "19dbc75e-c2e2-444c-a770-ec69d8559fc7"},
			},
		},
	}

	s := NewServicePrincipalScanner(&mockGraph{}, sps, nil)
	result, err := s.Scan(context.Background(), iam.ScanConfig{
		StaleDays: 90,
		Exclude:   iam.ExcludeConfig{Principals: map[string]bool{"Excluded SP": true}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for excluded SP, got %d", len(result.Findings))
	}
}
