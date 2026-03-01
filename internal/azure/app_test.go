package azure

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

func TestAppScanner_Type(t *testing.T) {
	s := NewAppScanner(&mockGraph{})
	if s.Type() != iam.ResourceAzureAppRegistration {
		t.Fatalf("expected %s, got %s", iam.ResourceAzureAppRegistration, s.Type())
	}
}

func TestAppScanner_ListError(t *testing.T) {
	mock := &mockGraph{appsErr: fmt.Errorf("forbidden")}
	s := NewAppScanner(mock)
	_, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err == nil {
		t.Fatal("expected error from list failure")
	}
}

func TestAppScanner_ExpiredSecret(t *testing.T) {
	expired := time.Now().AddDate(0, 0, -10)
	mock := &mockGraph{
		apps: []Application{
			{
				ID:          "app-1",
				AppID:       "app-id-1",
				DisplayName: "My App",
				PasswordCredentials: []Credential{
					{KeyID: "key-1", DisplayName: "secret1", EndDateTime: &expired},
				},
			},
		},
	}

	s := NewAppScanner(mock)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingExpiredSecret)
	if found == nil {
		t.Fatal("expected EXPIRED_SECRET finding")
	}
	if found.Severity != iam.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", found.Severity)
	}
}

func TestAppScanner_ExpiringSecret(t *testing.T) {
	expiring := time.Now().AddDate(0, 0, 15)
	mock := &mockGraph{
		apps: []Application{
			{
				ID:          "app-2",
				AppID:       "app-id-2",
				DisplayName: "Expiring App",
				PasswordCredentials: []Credential{
					{KeyID: "key-2", DisplayName: "secret2", EndDateTime: &expiring},
				},
			},
		},
	}

	s := NewAppScanner(mock)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingExpiringSecret)
	if found == nil {
		t.Fatal("expected EXPIRING_SECRET finding")
	}
	if found.Severity != iam.SeverityMedium {
		t.Fatalf("expected medium severity, got %s", found.Severity)
	}
}

func TestAppScanner_HealthySecret(t *testing.T) {
	farFuture := time.Now().AddDate(1, 0, 0)
	mock := &mockGraph{
		apps: []Application{
			{
				ID:          "app-3",
				AppID:       "app-id-3",
				DisplayName: "Healthy App",
				PasswordCredentials: []Credential{
					{KeyID: "key-3", EndDateTime: &farFuture},
				},
			},
		},
	}

	s := NewAppScanner(mock)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for healthy app, got %d", len(result.Findings))
	}
}

func TestAppScanner_StaleApp_AllCredentialsExpired(t *testing.T) {
	expired1 := time.Now().AddDate(0, -2, 0)
	expired2 := time.Now().AddDate(0, -1, 0)
	mock := &mockGraph{
		apps: []Application{
			{
				ID:          "app-4",
				AppID:       "app-id-4",
				DisplayName: "Stale App",
				PasswordCredentials: []Credential{
					{KeyID: "key-4a", EndDateTime: &expired1},
				},
				KeyCredentials: []Credential{
					{KeyID: "key-4b", EndDateTime: &expired2},
				},
			},
		},
	}

	s := NewAppScanner(mock)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingStaleApp)
	if found == nil {
		t.Fatal("expected STALE_APP finding when all credentials expired")
	}
	if found.Severity != iam.SeverityHigh {
		t.Fatalf("expected high severity, got %s", found.Severity)
	}

	// Should also have individual EXPIRED_SECRET findings
	expiredCount := 0
	for _, f := range result.Findings {
		if f.ID == iam.FindingExpiredSecret {
			expiredCount++
		}
	}
	if expiredCount != 2 {
		t.Fatalf("expected 2 EXPIRED_SECRET findings, got %d", expiredCount)
	}
}

func TestAppScanner_MixedCredentials(t *testing.T) {
	expired := time.Now().AddDate(0, -1, 0)
	valid := time.Now().AddDate(1, 0, 0)
	mock := &mockGraph{
		apps: []Application{
			{
				ID:          "app-5",
				AppID:       "app-id-5",
				DisplayName: "Mixed App",
				PasswordCredentials: []Credential{
					{KeyID: "key-5a", EndDateTime: &expired},
					{KeyID: "key-5b", EndDateTime: &valid},
				},
			},
		},
	}

	s := NewAppScanner(mock)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have EXPIRED_SECRET but NOT STALE_APP (still has valid credential)
	if findFinding(result.Findings, iam.FindingExpiredSecret) == nil {
		t.Fatal("expected EXPIRED_SECRET for the expired credential")
	}
	if findFinding(result.Findings, iam.FindingStaleApp) != nil {
		t.Fatal("should not emit STALE_APP when some credentials are still valid")
	}
}

func TestAppScanner_NoCredentials(t *testing.T) {
	mock := &mockGraph{
		apps: []Application{
			{
				ID:          "app-6",
				AppID:       "app-id-6",
				DisplayName: "No Creds App",
			},
		},
	}

	s := NewAppScanner(mock)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for app with no credentials, got %d", len(result.Findings))
	}
}

func TestAppScanner_Excluded(t *testing.T) {
	expired := time.Now().AddDate(0, -1, 0)
	mock := &mockGraph{
		apps: []Application{
			{
				ID:          "app-7",
				AppID:       "app-id-7",
				DisplayName: "Excluded App",
				PasswordCredentials: []Credential{
					{KeyID: "key-7", EndDateTime: &expired},
				},
			},
		},
	}

	s := NewAppScanner(mock)
	result, err := s.Scan(context.Background(), iam.ScanConfig{
		StaleDays: 90,
		Exclude:   iam.ExcludeConfig{Principals: map[string]bool{"Excluded App": true}},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for excluded app, got %d", len(result.Findings))
	}
}

func TestAppScanner_PrincipalsScanned(t *testing.T) {
	mock := &mockGraph{
		apps: []Application{
			{ID: "a1", DisplayName: "App1"},
			{ID: "a2", DisplayName: "App2"},
			{ID: "a3", DisplayName: "App3"},
		},
	}

	s := NewAppScanner(mock)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.PrincipalsScanned != 3 {
		t.Fatalf("expected 3 principals scanned, got %d", result.PrincipalsScanned)
	}
}

func TestAppScanner_CredentialWithNoExpiry(t *testing.T) {
	mock := &mockGraph{
		apps: []Application{
			{
				ID:          "app-8",
				DisplayName: "No Expiry App",
				PasswordCredentials: []Credential{
					{KeyID: "key-8"}, // nil EndDateTime
				},
			},
		},
	}

	s := NewAppScanner(mock)
	result, err := s.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for credential without expiry, got %d", len(result.Findings))
	}
}
