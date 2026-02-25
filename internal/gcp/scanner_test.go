package gcp

import (
	"context"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
	crmv1 "google.golang.org/api/cloudresourcemanager/v1"
	iamv1 "google.golang.org/api/iam/v1"
)

func TestScannerCount(t *testing.T) {
	if ScannerCount() != 2 {
		t.Fatalf("expected 2 scanners, got %d", ScannerCount())
	}
}

func TestGCPScanner_ScanAll(t *testing.T) {
	staleTime := time.Now().AddDate(0, 0, -100).Format(time.RFC3339)

	mockIAMAPI := &mockIAM{
		accounts: []*iamv1.ServiceAccount{
			{Name: "projects/test/serviceAccounts/sa1", Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123"},
		},
		keys: map[string][]*iamv1.ServiceAccountKey{
			"projects/test/serviceAccounts/sa1": {
				{Name: "projects/test/serviceAccounts/sa1/keys/key1", ValidAfterTime: staleTime},
			},
		},
	}

	mockCRMAPI := &mockCRM{
		policy: &crmv1.Policy{
			Bindings: []*crmv1.Binding{
				{
					Role:    "roles/owner",
					Members: []string{"serviceAccount:sa1@test.iam.gserviceaccount.com"},
				},
			},
		},
	}

	client := NewClientWith("test-project", mockIAMAPI, mockCRMAPI)
	scanner := NewGCPScanner(client, iam.ScanConfig{StaleDays: 90})

	result, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Should have STALE_SA_KEY + OVERPRIVILEGED_SA
	if len(result.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(result.Findings))
	}

	hasStaleKey := false
	hasOverpriv := false
	for _, f := range result.Findings {
		switch f.ID {
		case iam.FindingStaleSAKey:
			hasStaleKey = true
		case iam.FindingOverprivilegedSA:
			hasOverpriv = true
		}
	}

	if !hasStaleKey {
		t.Fatal("expected STALE_SA_KEY finding")
	}
	if !hasOverpriv {
		t.Fatal("expected OVERPRIVILEGED_SA finding")
	}
}

func TestGCPScanner_ScanAll_ScannerError(t *testing.T) {
	mockIAMAPI := &mockIAM{
		accounts: []*iamv1.ServiceAccount{},
	}

	mockCRMAPI := &mockCRM{
		policyErr: context.DeadlineExceeded,
	}

	client := NewClientWith("test-project", mockIAMAPI, mockCRMAPI)
	scanner := NewGCPScanner(client, iam.ScanConfig{StaleDays: 90})

	result, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("scan should not return error for individual scanner failure: %v", err)
	}

	// Binding scanner error should be recorded
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d", len(result.Errors))
	}
}

func TestGCPScanner_ScanAll_NoFindings(t *testing.T) {
	mockIAMAPI := &mockIAM{
		accounts: []*iamv1.ServiceAccount{},
	}

	mockCRMAPI := &mockCRM{
		policy: &crmv1.Policy{},
	}

	client := NewClientWith("test-project", mockIAMAPI, mockCRMAPI)
	scanner := NewGCPScanner(client, iam.ScanConfig{StaleDays: 90})

	result, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(result.Findings))
	}
}
