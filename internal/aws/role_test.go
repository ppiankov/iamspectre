package aws

import (
	"context"
	"net/url"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/ppiankov/iamspectre/internal/iam"
)

func TestRoleScanner_UnusedRole(t *testing.T) {
	staleDate := time.Now().UTC().AddDate(0, 0, -120)
	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:   awssdk.String("old-role"),
				Arn:        awssdk.String("arn:aws:iam::123456789012:role/old-role"),
				Path:       awssdk.String("/"),
				CreateDate: awssdk.Time(time.Now().UTC().AddDate(-1, 0, 0)),
				RoleLastUsed: &iamtypes.RoleLastUsed{
					LastUsedDate: &staleDate,
				},
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if result.PrincipalsScanned != 1 {
		t.Fatalf("expected 1 principal scanned, got %d", result.PrincipalsScanned)
	}

	found := findFinding(result.Findings, iam.FindingUnusedRole)
	if found == nil {
		t.Fatal("expected UNUSED_ROLE finding")
	}
	if found.Severity != iam.SeverityMedium {
		t.Fatalf("expected medium severity, got %s", found.Severity)
	}
}

func TestRoleScanner_NeverUsedRole(t *testing.T) {
	oldCreateDate := time.Now().UTC().AddDate(-1, 0, 0)
	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:     awssdk.String("never-used"),
				Arn:          awssdk.String("arn:aws:iam::123456789012:role/never-used"),
				Path:         awssdk.String("/"),
				CreateDate:   &oldCreateDate,
				RoleLastUsed: nil,
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingUnusedRole)
	if found == nil {
		t.Fatal("expected UNUSED_ROLE finding for never-used role")
	}
	if found.Metadata["never_used"] != true {
		t.Fatal("expected never_used metadata")
	}
}

func TestRoleScanner_RecentlyUsedRole(t *testing.T) {
	recentDate := time.Now().UTC().AddDate(0, 0, -5)
	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:   awssdk.String("active-role"),
				Arn:        awssdk.String("arn:aws:iam::123456789012:role/active-role"),
				Path:       awssdk.String("/"),
				CreateDate: awssdk.Time(time.Now().UTC().AddDate(-1, 0, 0)),
				RoleLastUsed: &iamtypes.RoleLastUsed{
					LastUsedDate: &recentDate,
				},
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for active role, got %d", len(result.Findings))
	}
}

func TestRoleScanner_ServiceLinkedRoleSkipped(t *testing.T) {
	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:     awssdk.String("AWSServiceRoleForECS"),
				Arn:          awssdk.String("arn:aws:iam::123456789012:role/aws-service-role/ecs.amazonaws.com/AWSServiceRoleForECS"),
				Path:         awssdk.String("/aws-service-role/ecs.amazonaws.com/"),
				CreateDate:   awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)),
				RoleLastUsed: nil,
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for service-linked role, got %d", len(result.Findings))
	}
}

func TestRoleScanner_CrossAccountTrust(t *testing.T) {
	trustPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}`
	encodedTrust := url.QueryEscape(trustPolicy)

	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:                 awssdk.String("cross-acct-role"),
				Arn:                      awssdk.String("arn:aws:iam::123456789012:role/cross-acct-role"),
				Path:                     awssdk.String("/"),
				CreateDate:               awssdk.Time(time.Now().UTC().AddDate(0, 0, -10)),
				RoleLastUsed:             &iamtypes.RoleLastUsed{LastUsedDate: awssdk.Time(time.Now().UTC().AddDate(0, 0, -1))},
				AssumeRolePolicyDocument: awssdk.String(encodedTrust),
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingCrossAccountTrust)
	if found == nil {
		t.Fatal("expected CROSS_ACCOUNT_TRUST finding")
	}
	if found.Severity != iam.SeverityCritical {
		t.Fatalf("expected critical severity, got %s", found.Severity)
	}
}

func TestRoleScanner_CrossAccountTrustWithCondition(t *testing.T) {
	trustPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"secret123"}}}]}`
	encodedTrust := url.QueryEscape(trustPolicy)

	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:                 awssdk.String("safe-cross-acct"),
				Arn:                      awssdk.String("arn:aws:iam::123456789012:role/safe-cross-acct"),
				Path:                     awssdk.String("/"),
				CreateDate:               awssdk.Time(time.Now().UTC().AddDate(0, 0, -10)),
				RoleLastUsed:             &iamtypes.RoleLastUsed{LastUsedDate: awssdk.Time(time.Now().UTC().AddDate(0, 0, -1))},
				AssumeRolePolicyDocument: awssdk.String(encodedTrust),
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Should NOT have cross-account finding since it has a condition
	found := findFinding(result.Findings, iam.FindingCrossAccountTrust)
	if found != nil {
		t.Fatal("expected no CROSS_ACCOUNT_TRUST finding when conditions present")
	}
}

func TestRoleScanner_SameAccountTrust(t *testing.T) {
	trustPolicy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"sts:AssumeRole"}]}`
	encodedTrust := url.QueryEscape(trustPolicy)

	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:                 awssdk.String("same-acct-role"),
				Arn:                      awssdk.String("arn:aws:iam::123456789012:role/same-acct-role"),
				Path:                     awssdk.String("/"),
				CreateDate:               awssdk.Time(time.Now().UTC().AddDate(0, 0, -10)),
				RoleLastUsed:             &iamtypes.RoleLastUsed{LastUsedDate: awssdk.Time(time.Now().UTC().AddDate(0, 0, -1))},
				AssumeRolePolicyDocument: awssdk.String(encodedTrust),
			},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingCrossAccountTrust)
	if found != nil {
		t.Fatal("expected no CROSS_ACCOUNT_TRUST for same-account trust")
	}
}

func TestRoleScanner_Excluded(t *testing.T) {
	mock := &mockIAM{
		roles: []iamtypes.Role{
			{
				RoleName:     awssdk.String("excluded-role"),
				Arn:          awssdk.String("arn:aws:iam::123456789012:role/excluded-role"),
				Path:         awssdk.String("/"),
				CreateDate:   awssdk.Time(time.Now().UTC().AddDate(-2, 0, 0)),
				RoleLastUsed: nil,
			},
		},
	}

	cfg := iam.ScanConfig{
		StaleDays: 90,
		Exclude: iam.ExcludeConfig{
			Principals: map[string]bool{"excluded-role": true},
		},
	}

	scanner := NewRoleScanner(mock, "123456789012")
	result, err := scanner.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no findings for excluded role, got %d", len(result.Findings))
	}
}

func TestRoleScanner_Type(t *testing.T) {
	scanner := NewRoleScanner(nil, "")
	if scanner.Type() != iam.ResourceIAMRole {
		t.Fatalf("expected %s, got %s", iam.ResourceIAMRole, scanner.Type())
	}
}

func TestRoleScanner_ListError(t *testing.T) {
	mock := &mockIAM{
		rolesErr: context.DeadlineExceeded,
	}

	scanner := NewRoleScanner(mock, "123456789012")
	_, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestIsExternalAccount(t *testing.T) {
	scanner := &RoleScanner{accountID: "123456789012"}

	tests := []struct {
		principal string
		external  bool
	}{
		{"*", true},
		{"arn:aws:iam::123456789012:root", false},
		{"arn:aws:iam::999999999999:root", true},
		{"arn:aws:iam::999999999999:role/some-role", true},
		{"not-an-arn", false},
	}

	for _, tt := range tests {
		t.Run(tt.principal, func(t *testing.T) {
			got := scanner.isExternalAccount(tt.principal)
			if got != tt.external {
				t.Fatalf("isExternalAccount(%q) = %v, want %v", tt.principal, got, tt.external)
			}
		})
	}
}
