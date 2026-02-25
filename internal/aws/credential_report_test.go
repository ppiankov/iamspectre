package aws

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

type mockIAM struct {
	generateState    iamtypes.ReportStateType
	generateErr      error
	reportContent    []byte
	reportErr        error
	roles            []iamtypes.Role
	rolesErr         error
	policies         []iamtypes.Policy
	policiesErr      error
	policyVersion    *iam.GetPolicyVersionOutput
	policyVersionErr error
}

func (m *mockIAM) GenerateCredentialReport(_ context.Context, _ *iam.GenerateCredentialReportInput, _ ...func(*iam.Options)) (*iam.GenerateCredentialReportOutput, error) {
	if m.generateErr != nil {
		return nil, m.generateErr
	}
	return &iam.GenerateCredentialReportOutput{State: m.generateState}, nil
}

func (m *mockIAM) GetCredentialReport(_ context.Context, _ *iam.GetCredentialReportInput, _ ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	if m.reportErr != nil {
		return nil, m.reportErr
	}
	return &iam.GetCredentialReportOutput{Content: m.reportContent}, nil
}

func (m *mockIAM) ListRoles(_ context.Context, _ *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if m.rolesErr != nil {
		return nil, m.rolesErr
	}
	return &iam.ListRolesOutput{Roles: m.roles, IsTruncated: false}, nil
}

func (m *mockIAM) ListPolicies(_ context.Context, _ *iam.ListPoliciesInput, _ ...func(*iam.Options)) (*iam.ListPoliciesOutput, error) {
	if m.policiesErr != nil {
		return nil, m.policiesErr
	}
	return &iam.ListPoliciesOutput{Policies: m.policies, IsTruncated: false}, nil
}

func (m *mockIAM) GetPolicyVersion(_ context.Context, _ *iam.GetPolicyVersionInput, _ ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error) {
	if m.policyVersionErr != nil {
		return nil, m.policyVersionErr
	}
	return m.policyVersion, nil
}

const testCredentialReportCSV = `user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::123456789012:root,2020-01-01T00:00:00+00:00,true,2026-02-20T10:00:00+00:00,N/A,N/A,true,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
admin,arn:aws:iam::123456789012:user/admin,2020-01-01T00:00:00+00:00,true,2025-10-01T10:00:00+00:00,2020-01-01T00:00:00+00:00,N/A,false,true,2020-01-01T00:00:00+00:00,2025-09-01T10:00:00+00:00,us-east-1,iam,true,2020-01-01T00:00:00+00:00,N/A,N/A,N/A,false,N/A,false,N/A
developer,arn:aws:iam::123456789012:user/developer,2024-01-01T00:00:00+00:00,true,2026-02-20T10:00:00+00:00,2024-01-01T00:00:00+00:00,N/A,true,true,2024-01-01T00:00:00+00:00,2026-02-20T10:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
cibot,arn:aws:iam::123456789012:user/cibot,2023-01-01T00:00:00+00:00,false,N/A,N/A,N/A,false,true,2023-01-01T00:00:00+00:00,2025-06-01T10:00:00+00:00,us-east-1,s3,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A
`

func TestParseCredentialReport(t *testing.T) {
	entries, err := parseCredentialReport([]byte(testCredentialReportCSV))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	// root account should be skipped
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries (root excluded), got %d", len(entries))
	}

	// Check admin entry
	admin := entries[0]
	if admin.User != "admin" {
		t.Fatalf("expected admin, got %s", admin.User)
	}
	if !admin.PasswordEnabled {
		t.Fatal("expected admin password_enabled=true")
	}
	if admin.MFAActive {
		t.Fatal("expected admin mfa_active=false")
	}
	if !admin.AccessKey1Active {
		t.Fatal("expected admin access_key_1_active=true")
	}
	if admin.AccessKey1LastUsedDate == nil {
		t.Fatal("expected admin access_key_1_last_used_date to be set")
	}
	if admin.AccessKey2Active != true {
		t.Fatal("expected admin access_key_2_active=true")
	}
	// Key 2 has N/A for last used
	if admin.AccessKey2LastUsedDate != nil {
		t.Fatal("expected admin access_key_2_last_used_date to be nil (N/A)")
	}

	// Check developer entry
	dev := entries[1]
	if !dev.MFAActive {
		t.Fatal("expected developer mfa_active=true")
	}

	// Check cibot entry (no password)
	cibot := entries[2]
	if cibot.PasswordEnabled {
		t.Fatal("expected cibot password_enabled=false")
	}
	if cibot.PasswordLastUsed != nil {
		t.Fatal("expected cibot password_last_used to be nil")
	}
}

func TestParseCredentialReport_Empty(t *testing.T) {
	csv := `user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
`
	entries, err := parseCredentialReport([]byte(csv))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries, got %d", len(entries))
	}
}

func TestParseCredentialReport_MissingColumn(t *testing.T) {
	csv := `user,arn
admin,arn:aws:iam::123456789012:user/admin
`
	_, err := parseCredentialReport([]byte(csv))
	if err == nil {
		t.Fatal("expected error for missing columns")
	}
}

func TestParseCredentialTime(t *testing.T) {
	tests := []struct {
		input string
		isNil bool
	}{
		{"", true},
		{"N/A", true},
		{"not_supported", true},
		{"no_information", true},
		{"2026-02-25T12:00:00Z", false},
		{"2026-02-25T12:00:00+00:00", false},
		{"invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := parseCredentialTime(tt.input)
			if tt.isNil && result != nil {
				t.Fatalf("expected nil for %q, got %v", tt.input, result)
			}
			if !tt.isNil && result == nil {
				t.Fatalf("expected non-nil for %q", tt.input)
			}
		})
	}
}

func TestFetchCredentialReport(t *testing.T) {
	mock := &mockIAM{
		generateState: iamtypes.ReportStateTypeComplete,
		reportContent: []byte(testCredentialReportCSV),
	}

	entries, err := FetchCredentialReport(context.Background(), mock)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
}

func TestFetchCredentialReport_GenerateError(t *testing.T) {
	mock := &mockIAM{
		generateErr: context.DeadlineExceeded,
	}

	_, err := FetchCredentialReport(context.Background(), mock)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFetchCredentialReport_GetError(t *testing.T) {
	mock := &mockIAM{
		generateState: iamtypes.ReportStateTypeComplete,
		reportErr:     context.DeadlineExceeded,
	}

	_, err := FetchCredentialReport(context.Background(), mock)
	if err == nil {
		t.Fatal("expected error")
	}
}
