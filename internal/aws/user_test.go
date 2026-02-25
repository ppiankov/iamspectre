package aws

import (
	"context"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

func TestUserScanner_StaleUser(t *testing.T) {
	staleDate := time.Now().UTC().AddDate(0, 0, -120)
	entries := []CredentialEntry{
		{
			User:             "stale-admin",
			ARN:              "arn:aws:iam::123456789012:user/stale-admin",
			PasswordEnabled:  true,
			PasswordLastUsed: &staleDate,
			MFAActive:        true,
		},
	}

	scanner := NewUserScanner(entries)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if result.PrincipalsScanned != 1 {
		t.Fatalf("expected 1 principal scanned, got %d", result.PrincipalsScanned)
	}

	found := findFinding(result.Findings, iam.FindingStaleUser)
	if found == nil {
		t.Fatal("expected STALE_USER finding")
	}
	if found.Severity != iam.SeverityHigh {
		t.Fatalf("expected high severity, got %s", found.Severity)
	}
	if found.ResourceName != "stale-admin" {
		t.Fatalf("expected stale-admin, got %s", found.ResourceName)
	}
}

func TestUserScanner_StaleAccessKey(t *testing.T) {
	staleDate := time.Now().UTC().AddDate(0, 0, -120)
	entries := []CredentialEntry{
		{
			User:                   "key-user",
			ARN:                    "arn:aws:iam::123456789012:user/key-user",
			PasswordEnabled:        false,
			MFAActive:              false,
			AccessKey1Active:       true,
			AccessKey1LastUsedDate: &staleDate,
		},
	}

	scanner := NewUserScanner(entries)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingStaleAccessKey)
	if found == nil {
		t.Fatal("expected STALE_ACCESS_KEY finding")
	}
	if found.Severity != iam.SeverityHigh {
		t.Fatalf("expected high severity, got %s", found.Severity)
	}
}

func TestUserScanner_NeverUsedAccessKey(t *testing.T) {
	entries := []CredentialEntry{
		{
			User:                   "new-key-user",
			ARN:                    "arn:aws:iam::123456789012:user/new-key-user",
			PasswordEnabled:        false,
			AccessKey1Active:       true,
			AccessKey1LastUsedDate: nil, // never used
		},
	}

	scanner := NewUserScanner(entries)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingStaleAccessKey)
	if found == nil {
		t.Fatal("expected STALE_ACCESS_KEY finding for never-used key")
	}
	if found.Message != "Access key 1 never used" {
		t.Fatalf("unexpected message: %s", found.Message)
	}
}

func TestUserScanner_NoMFA(t *testing.T) {
	recentDate := time.Now().UTC().AddDate(0, 0, -1)
	entries := []CredentialEntry{
		{
			User:             "no-mfa-user",
			ARN:              "arn:aws:iam::123456789012:user/no-mfa-user",
			PasswordEnabled:  true,
			PasswordLastUsed: &recentDate,
			MFAActive:        false,
		},
	}

	scanner := NewUserScanner(entries)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingNoMFA)
	if found == nil {
		t.Fatal("expected NO_MFA finding")
	}
	if found.Severity != iam.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", found.Severity)
	}
}

func TestUserScanner_HealthyUser(t *testing.T) {
	recentDate := time.Now().UTC().AddDate(0, 0, -1)
	entries := []CredentialEntry{
		{
			User:                   "healthy-user",
			ARN:                    "arn:aws:iam::123456789012:user/healthy-user",
			PasswordEnabled:        true,
			PasswordLastUsed:       &recentDate,
			MFAActive:              true,
			AccessKey1Active:       true,
			AccessKey1LastUsedDate: &recentDate,
		},
	}

	scanner := NewUserScanner(entries)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for healthy user, got %d", len(result.Findings))
	}
}

func TestUserScanner_Excluded(t *testing.T) {
	staleDate := time.Now().UTC().AddDate(0, 0, -120)
	entries := []CredentialEntry{
		{
			User:             "excluded-user",
			ARN:              "arn:aws:iam::123456789012:user/excluded-user",
			PasswordEnabled:  true,
			PasswordLastUsed: &staleDate,
			MFAActive:        false,
		},
	}

	cfg := iam.ScanConfig{
		StaleDays: 90,
		Exclude: iam.ExcludeConfig{
			Principals: map[string]bool{"excluded-user": true},
		},
	}

	scanner := NewUserScanner(entries)
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded user, got %d", len(result.Findings))
	}
}

func TestUserScanner_Type(t *testing.T) {
	scanner := NewUserScanner(nil)
	if scanner.Type() != iam.ResourceIAMUser {
		t.Fatalf("expected %s, got %s", iam.ResourceIAMUser, scanner.Type())
	}
}

func TestUserScanner_NoPasswordNoFindings(t *testing.T) {
	recentDate := time.Now().UTC().AddDate(0, 0, -1)
	entries := []CredentialEntry{
		{
			User:                   "api-only",
			ARN:                    "arn:aws:iam::123456789012:user/api-only",
			PasswordEnabled:        false,
			MFAActive:              false,
			AccessKey1Active:       true,
			AccessKey1LastUsedDate: &recentDate,
		},
	}

	scanner := NewUserScanner(entries)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Should not get NO_MFA (no password), should not get STALE_USER (no password)
	for _, f := range result.Findings {
		if f.ID == iam.FindingNoMFA {
			t.Fatal("unexpected NO_MFA for user without password")
		}
		if f.ID == iam.FindingStaleUser {
			t.Fatal("unexpected STALE_USER for user without password")
		}
	}
}

func TestUserScanner_BothKeysStale(t *testing.T) {
	staleDate := time.Now().UTC().AddDate(0, 0, -120)
	entries := []CredentialEntry{
		{
			User:                   "two-key-user",
			ARN:                    "arn:aws:iam::123456789012:user/two-key-user",
			PasswordEnabled:        false,
			AccessKey1Active:       true,
			AccessKey1LastUsedDate: &staleDate,
			AccessKey2Active:       true,
			AccessKey2LastUsedDate: &staleDate,
		},
	}

	scanner := NewUserScanner(entries)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	staleKeyCount := 0
	for _, f := range result.Findings {
		if f.ID == iam.FindingStaleAccessKey {
			staleKeyCount++
		}
	}
	if staleKeyCount != 2 {
		t.Fatalf("expected 2 STALE_ACCESS_KEY findings, got %d", staleKeyCount)
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
