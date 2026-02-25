package gcp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
	iamv1 "google.golang.org/api/iam/v1"
)

type mockIAM struct {
	accounts    []*iamv1.ServiceAccount
	accountsErr error
	keys        map[string][]*iamv1.ServiceAccountKey
	keysErr     map[string]error
}

func (m *mockIAM) ListServiceAccounts(_ context.Context, _ string) ([]*iamv1.ServiceAccount, error) {
	if m.accountsErr != nil {
		return nil, m.accountsErr
	}
	return m.accounts, nil
}

func (m *mockIAM) ListServiceAccountKeys(_ context.Context, name string) ([]*iamv1.ServiceAccountKey, error) {
	if m.keysErr != nil {
		if err, ok := m.keysErr[name]; ok {
			return nil, err
		}
	}
	if m.keys != nil {
		return m.keys[name], nil
	}
	return nil, nil
}

func TestServiceAccountScanner_StaleSAKey(t *testing.T) {
	staleTime := time.Now().AddDate(0, 0, -100).Format(time.RFC3339)
	mock := &mockIAM{
		accounts: []*iamv1.ServiceAccount{
			{Name: "projects/test/serviceAccounts/sa1", Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123"},
		},
		keys: map[string][]*iamv1.ServiceAccountKey{
			"projects/test/serviceAccounts/sa1": {
				{Name: "projects/test/serviceAccounts/sa1/keys/key1", ValidAfterTime: staleTime},
			},
		},
	}

	scanner := NewServiceAccountScanner(mock, "test")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.ID != iam.FindingStaleSAKey {
		t.Fatalf("expected STALE_SA_KEY, got %s", f.ID)
	}
	if f.Severity != iam.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", f.Severity)
	}
	if f.ResourceType != iam.ResourceServiceAccountKey {
		t.Fatalf("expected service_account_key, got %s", f.ResourceType)
	}
}

func TestServiceAccountScanner_RecentKey(t *testing.T) {
	recentTime := time.Now().AddDate(0, 0, -10).Format(time.RFC3339)
	mock := &mockIAM{
		accounts: []*iamv1.ServiceAccount{
			{Name: "projects/test/serviceAccounts/sa1", Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123"},
		},
		keys: map[string][]*iamv1.ServiceAccountKey{
			"projects/test/serviceAccounts/sa1": {
				{Name: "projects/test/serviceAccounts/sa1/keys/key1", ValidAfterTime: recentTime},
			},
		},
	}

	scanner := NewServiceAccountScanner(mock, "test")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings for recent key, got %d", len(result.Findings))
	}
}

func TestServiceAccountScanner_DisabledSA(t *testing.T) {
	mock := &mockIAM{
		accounts: []*iamv1.ServiceAccount{
			{Name: "projects/test/serviceAccounts/sa1", Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123", Disabled: true},
		},
		keys: map[string][]*iamv1.ServiceAccountKey{
			"projects/test/serviceAccounts/sa1": {},
		},
	}

	scanner := NewServiceAccountScanner(mock, "test")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding (disabled SA), got %d", len(result.Findings))
	}
	f := result.Findings[0]
	if f.ID != iam.FindingStaleSA {
		t.Fatalf("expected STALE_SA, got %s", f.ID)
	}
	if f.Severity != iam.SeverityHigh {
		t.Fatalf("expected high severity, got %s", f.Severity)
	}
}

func TestServiceAccountScanner_DisabledWithStaleKey(t *testing.T) {
	staleTime := time.Now().AddDate(0, 0, -100).Format(time.RFC3339)
	mock := &mockIAM{
		accounts: []*iamv1.ServiceAccount{
			{Name: "projects/test/serviceAccounts/sa1", Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123", Disabled: true},
		},
		keys: map[string][]*iamv1.ServiceAccountKey{
			"projects/test/serviceAccounts/sa1": {
				{Name: "projects/test/serviceAccounts/sa1/keys/key1", ValidAfterTime: staleTime},
			},
		},
	}

	scanner := NewServiceAccountScanner(mock, "test")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Should have both STALE_SA and STALE_SA_KEY
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings (disabled SA + stale key), got %d", len(result.Findings))
	}
}

func TestServiceAccountScanner_NoAccounts(t *testing.T) {
	mock := &mockIAM{
		accounts: []*iamv1.ServiceAccount{},
	}

	scanner := NewServiceAccountScanner(mock, "test")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
	if result.PrincipalsScanned != 0 {
		t.Fatalf("expected 0 principals, got %d", result.PrincipalsScanned)
	}
}

func TestServiceAccountScanner_ListError(t *testing.T) {
	mock := &mockIAM{
		accountsErr: fmt.Errorf("permission denied"),
	}

	scanner := NewServiceAccountScanner(mock, "test")
	_, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestServiceAccountScanner_KeyListError(t *testing.T) {
	mock := &mockIAM{
		accounts: []*iamv1.ServiceAccount{
			{Name: "projects/test/serviceAccounts/sa1", Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123"},
		},
		keysErr: map[string]error{
			"projects/test/serviceAccounts/sa1": fmt.Errorf("key list error"),
		},
	}

	scanner := NewServiceAccountScanner(mock, "test")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan should not fail for key list error: %v", err)
	}

	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
}

func TestServiceAccountScanner_Excluded(t *testing.T) {
	staleTime := time.Now().AddDate(0, 0, -100).Format(time.RFC3339)
	mock := &mockIAM{
		accounts: []*iamv1.ServiceAccount{
			{Name: "projects/test/serviceAccounts/sa1", Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123"},
		},
		keys: map[string][]*iamv1.ServiceAccountKey{
			"projects/test/serviceAccounts/sa1": {
				{Name: "projects/test/serviceAccounts/sa1/keys/key1", ValidAfterTime: staleTime},
			},
		},
	}

	scanner := NewServiceAccountScanner(mock, "test")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{
		StaleDays: 90,
		Exclude: iam.ExcludeConfig{
			Principals: map[string]bool{"sa1@test.iam.gserviceaccount.com": true},
		},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings (excluded), got %d", len(result.Findings))
	}
}

func TestServiceAccountScanner_MultipleKeys(t *testing.T) {
	staleTime := time.Now().AddDate(0, 0, -100).Format(time.RFC3339)
	recentTime := time.Now().AddDate(0, 0, -10).Format(time.RFC3339)
	mock := &mockIAM{
		accounts: []*iamv1.ServiceAccount{
			{Name: "projects/test/serviceAccounts/sa1", Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123"},
		},
		keys: map[string][]*iamv1.ServiceAccountKey{
			"projects/test/serviceAccounts/sa1": {
				{Name: "projects/test/serviceAccounts/sa1/keys/key1", ValidAfterTime: staleTime},
				{Name: "projects/test/serviceAccounts/sa1/keys/key2", ValidAfterTime: recentTime},
			},
		},
	}

	scanner := NewServiceAccountScanner(mock, "test")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Only the stale key should be flagged
	if len(result.Findings) != 1 {
		t.Fatalf("expected 1 finding (one stale key), got %d", len(result.Findings))
	}
}

func TestServiceAccountScanner_Type(t *testing.T) {
	scanner := NewServiceAccountScanner(nil, "test")
	if scanner.Type() != iam.ResourceServiceAccount {
		t.Fatalf("expected service_account, got %s", scanner.Type())
	}
}
