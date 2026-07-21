package gcp

import (
	"context"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
	"github.com/ppiankov/iamspectre/internal/testutil"
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
	if result.PrincipalsScanned != 1 {
		t.Fatalf("principals scanned = %d, want one cross-scanner identity", result.PrincipalsScanned)
	}
}

// WO-89: the aggregate count is the union of listed accounts and policy members.
func TestGCPScanner_ScanAll_DeduplicatesPrincipalUnion(t *testing.T) {
	mockIAMAPI := &mockIAM{
		accounts: []*iamv1.ServiceAccount{
			{Name: "projects/test/serviceAccounts/sa1", Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "1"},
			{Name: "projects/test/serviceAccounts/sa2", Email: "sa2@test.iam.gserviceaccount.com", UniqueId: "2"},
		},
		keys: map[string][]*iamv1.ServiceAccountKey{},
	}
	mockCRMAPI := &mockCRM{policy: &crmv1.Policy{Bindings: []*crmv1.Binding{
		{
			Role: "roles/viewer",
			Members: []string{
				"serviceAccount: SA2@Test.Iam.Gserviceaccount.Com ",
				"serviceAccount:sa3@test.iam.gserviceaccount.com",
				"serviceAccount:sa4@test.iam.gserviceaccount.com",
			},
		},
	}}}

	client := NewClientWith("test-project", mockIAMAPI, mockCRMAPI)
	result, err := NewGCPScanner(client, iam.ScanConfig{StaleDays: 90}).ScanAll(context.Background())
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if result.PrincipalsScanned != 4 {
		t.Fatalf("principals scanned = %d, want union cardinality 4", result.PrincipalsScanned)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("viewer-only fixture emitted findings: %#v", result.Findings)
	}
}

func TestGCPScanner_ScanAll_ScannerError(t *testing.T) {
	// WO-28@v2: share exact non-fatal error assertions across provider packages.
	mockIAMAPI := &mockIAM{
		accounts: []*iamv1.ServiceAccount{},
	}

	mockCRMAPI := &mockCRM{
		policyErr: context.DeadlineExceeded,
	}

	client := NewClientWith("test-project", mockIAMAPI, mockCRMAPI)
	scanner := NewGCPScanner(client, iam.ScanConfig{StaleDays: 90})

	testutil.AssertNonFatalScannerErrors(t, scanner.ScanAll, 1, "deadline exceeded")
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
