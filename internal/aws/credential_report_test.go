package aws

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

// WO-61@v2: retain credential-report envelope provenance in the shared AWS mock.
type mockIAM struct {
	generateState    iamtypes.ReportStateType
	generateErr      error
	reportContent    []byte
	reportGenerated  *time.Time
	reportErr        error
	roles            []iamtypes.Role
	rolesErr         error
	getRoleFn        func(context.Context, *iam.GetRoleInput) (*iam.GetRoleOutput, error) // WO-107@v2: inject per-role evidence outcomes.
	getRoleCalls     []string                                                             // WO-107@v2: prove enrichment request bounds.
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

// WO-61@v2: return report content and generation time through the real SDK shape.
func (m *mockIAM) GetCredentialReport(_ context.Context, _ *iam.GetCredentialReportInput, _ ...func(*iam.Options)) (*iam.GetCredentialReportOutput, error) {
	if m.reportErr != nil {
		return nil, m.reportErr
	}
	return &iam.GetCredentialReportOutput{Content: m.reportContent, GeneratedTime: m.reportGenerated}, nil
}

func (m *mockIAM) ListRoles(_ context.Context, _ *iam.ListRolesInput, _ ...func(*iam.Options)) (*iam.ListRolesOutput, error) {
	if m.rolesErr != nil {
		return nil, m.rolesErr
	}
	return &iam.ListRolesOutput{Roles: m.roles, IsTruncated: false}, nil
}

// WO-107@v2: mirror GetRole evidence while allowing focused failure injection.
func (m *mockIAM) GetRole(ctx context.Context, input *iam.GetRoleInput, _ ...func(*iam.Options)) (*iam.GetRoleOutput, error) {
	roleName := ""
	if input != nil && input.RoleName != nil {
		roleName = *input.RoleName
	}
	m.getRoleCalls = append(m.getRoleCalls, roleName)
	if m.getRoleFn != nil {
		return m.getRoleFn(ctx, input)
	}
	for i := range m.roles {
		if m.roles[i].RoleName != nil && *m.roles[i].RoleName == roleName {
			return &iam.GetRoleOutput{Role: &m.roles[i]}, nil
		}
	}
	return &iam.GetRoleOutput{}, nil
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

// WO-57@v5: parse both access-key slots into typed usage and rotation evidence.
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
	if admin.AccessKey1UseState != CredentialUseUsed || admin.AccessKey2UseState != CredentialUseNoRecordedUse {
		t.Fatalf("unexpected admin key states: key1=%v key2=%v", admin.AccessKey1UseState, admin.AccessKey2UseState)
	}
	if admin.AccessKey1LastRotated == nil || admin.AccessKey2LastRotated == nil {
		t.Fatal("expected both active-key rotation timestamps")
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

// WO-63: booleans crossing critical finding boundaries accept only exact credential-report values.
func TestParseCredentialBool(t *testing.T) {
	tests := []struct {
		value     string
		want      bool
		wantError bool
	}{
		{value: "true", want: true},
		{value: "false"},
		{value: "TRUE", wantError: true},
		{value: "", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			got, err := parseCredentialBool("mfa_active", tt.value)
			if got != tt.want || (err != nil) != tt.wantError {
				t.Fatalf("got value/error %v/%v, want %v/%v", got, err, tt.want, tt.wantError)
			}
		})
	}
}

// WO-57@v5: key-rotation evidence preserves timestamps and bounds unavailable sentinels.
func TestParseCredentialTimestamp(t *testing.T) {
	tests := []struct {
		name, value string
		wantTime    bool
		wantError   bool
	}{
		{name: "timestamp", value: "2020-01-01T00:00:00Z", wantTime: true},
		{name: "N/A", value: "N/A"},
		{name: "empty"},
		{name: "not supported", value: "not_supported"},
		{name: "no information", value: "no_information"},
		{name: "malformed", value: "yesterday", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCredentialTimestamp("access_key_1_last_rotated", tt.value)
			if (got != nil) != tt.wantTime || (err != nil) != tt.wantError {
				t.Fatalf("got timestamp/error %v/%v", got, err)
			}
		})
	}
}

// WO-57@v5: malformed rotation evidence identifies the user and affected key slot.
func TestParseCredentialReport_MalformedRotationTimestamps(t *testing.T) {
	tests := []struct {
		field, key1Rotated, key2Rotated string
	}{
		{field: "access_key_1_last_rotated", key1Rotated: "yesterday", key2Rotated: "N/A"},
		{field: "access_key_2_last_rotated", key1Rotated: "N/A", key2Rotated: "yesterday"},
	}
	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			csv := fmt.Sprintf("user,arn,password_enabled,password_last_used,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\nbroken,arn:broken,false,N/A,false,true,%s,N/A,true,%s,N/A\n", tt.key1Rotated, tt.key2Rotated)
			_, err := parseCredentialReport([]byte(csv))
			if err == nil || !strings.Contains(err.Error(), "broken") || !strings.Contains(err.Error(), tt.field) {
				t.Fatalf("expected user+field error, got %v", err)
			}
		})
	}
}

// WO-63: password-use sentinels retain applicability and uncertainty.
func TestParsePasswordUse(t *testing.T) {
	tests := []struct {
		name      string
		enabled   bool
		value     string
		wantState PasswordUseState
		wantTime  bool
		wantError bool
	}{
		{name: "used", enabled: true, value: "2026-02-25T12:00:00Z", wantState: PasswordUseUsed, wantTime: true},
		{name: "no recorded use", enabled: true, value: "no_information", wantState: PasswordUseNoRecordedUse},
		{name: "disabled N/A", value: "N/A", wantState: PasswordUseNotApplicable},
		{name: "enabled N/A inconsistent", enabled: true, value: "N/A", wantState: PasswordUseUnknown, wantError: true},
		{name: "empty unknown", enabled: true, value: "", wantState: PasswordUseUnknown},
		{name: "unsupported unknown", enabled: true, value: "not_supported", wantState: PasswordUseUnknown},
		{name: "malformed", enabled: true, value: "yesterday", wantState: PasswordUseUnknown, wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTime, gotState, err := parsePasswordUse(tt.enabled, tt.value)
			if gotState != tt.wantState || (gotTime != nil) != tt.wantTime || (err != nil) != tt.wantError {
				t.Fatalf("got time/state/error %v/%v/%v", gotTime, gotState, err)
			}
		})
	}
}

// WO-63: invalid rows identify both their user and exact evidence field.
func TestParseCredentialReport_StrictEvidenceErrors(t *testing.T) {
	tests := []struct {
		name, passwordEnabled, passwordLastUsed, mfaActive, key1Active, key1LastUsed, key2Active, key2LastUsed, wantField string
	}{
		{name: "password boolean", passwordEnabled: "yes", passwordLastUsed: "N/A", mfaActive: "false", key1Active: "false", key1LastUsed: "N/A", key2Active: "false", key2LastUsed: "N/A", wantField: "password_enabled"},
		{name: "MFA boolean", passwordEnabled: "false", passwordLastUsed: "N/A", mfaActive: "no", key1Active: "false", key1LastUsed: "N/A", key2Active: "false", key2LastUsed: "N/A", wantField: "mfa_active"},
		{name: "key one boolean", passwordEnabled: "false", passwordLastUsed: "N/A", mfaActive: "false", key1Active: "1", key1LastUsed: "N/A", key2Active: "false", key2LastUsed: "N/A", wantField: "access_key_1_active"},
		{name: "key two boolean", passwordEnabled: "false", passwordLastUsed: "N/A", mfaActive: "false", key1Active: "false", key1LastUsed: "N/A", key2Active: "TRUE", key2LastUsed: "N/A", wantField: "access_key_2_active"},
		{name: "enabled N/A", passwordEnabled: "true", passwordLastUsed: "N/A", mfaActive: "false", key1Active: "false", key1LastUsed: "N/A", key2Active: "false", key2LastUsed: "N/A", wantField: "password_last_used"},
		{name: "password timestamp", passwordEnabled: "true", passwordLastUsed: "yesterday", mfaActive: "false", key1Active: "false", key1LastUsed: "N/A", key2Active: "false", key2LastUsed: "N/A", wantField: "password_last_used"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			csv := fmt.Sprintf("user,arn,password_enabled,password_last_used,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date\nbroken,arn:broken,%s,%s,%s,%s,2020-01-01T00:00:00Z,%s,%s,2020-01-01T00:00:00Z,%s\n", tt.passwordEnabled, tt.passwordLastUsed, tt.mfaActive, tt.key1Active, tt.key1LastUsed, tt.key2Active, tt.key2LastUsed)
			_, err := parseCredentialReport([]byte(csv))
			if err == nil || !strings.Contains(err.Error(), "broken") || !strings.Contains(err.Error(), tt.wantField) {
				t.Fatalf("expected user+field error for %s, got %v", tt.wantField, err)
			}
		})
	}
}

// WO-57@v5: credential-report sentinels must retain their evidence meaning.
func TestParseAccessKeyUse(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantState CredentialUseState
		wantTime  bool
		wantError bool
	}{
		{name: "no recorded use", value: "N/A", wantState: CredentialUseNoRecordedUse},
		{name: "used RFC3339", value: "2026-02-25T12:00:00Z", wantState: CredentialUseUsed, wantTime: true},
		{name: "used AWS offset", value: "2026-02-25T12:00:00+00:00", wantState: CredentialUseUsed, wantTime: true},
		{name: "empty unavailable", value: "", wantState: CredentialUseUnknown},
		{name: "not supported", value: "not_supported", wantState: CredentialUseUnknown},
		{name: "no information", value: "no_information", wantState: CredentialUseUnknown},
		{name: "malformed", value: "yesterday", wantState: CredentialUseUnknown, wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTime, gotState, err := parseAccessKeyUse("access_key_1_last_used_date", tt.value)
			if (err != nil) != tt.wantError {
				t.Fatalf("expected error=%v, got %v", tt.wantError, err)
			}
			if gotState != tt.wantState {
				t.Fatalf("expected state %v, got %v", tt.wantState, gotState)
			}
			if (gotTime != nil) != tt.wantTime {
				t.Fatalf("expected timestamp=%v, got %v", tt.wantTime, gotTime)
			}
		})
	}
}

// WO-57@v5: malformed access-key evidence fails with the source field named.
func TestParseCredentialReport_MalformedAccessKeyTimestamp(t *testing.T) {
	csv := `user,arn,password_enabled,password_last_used,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date
broken,arn:aws:iam::123456789012:user/broken,false,N/A,false,true,2020-01-01T00:00:00Z,yesterday,false,N/A,N/A
`
	_, err := parseCredentialReport([]byte(csv))
	if err == nil {
		t.Fatal("expected malformed access-key timestamp error")
	}
	if !strings.Contains(err.Error(), "access_key_1_last_used_date") {
		t.Fatalf("expected field-qualified error, got %v", err)
	}
}

// WO-61@v2: propagate exact generation time without pointer aliasing.
func TestFetchCredentialReport(t *testing.T) {
	generatedAt := time.Date(2026, 7, 19, 3, 4, 5, 0, time.FixedZone("cached", 8*60*60))
	mock := &mockIAM{
		generateState:   iamtypes.ReportStateTypeComplete,
		reportContent:   []byte(testCredentialReportCSV),
		reportGenerated: &generatedAt,
	}

	entries, err := FetchCredentialReport(context.Background(), mock)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	for i := range entries {
		if entries[i].CredentialReportGeneratedAt == nil || !entries[i].CredentialReportGeneratedAt.Equal(generatedAt) {
			t.Fatalf("entry %d missing exact report generation time", i)
		}
	}
	if entries[0].CredentialReportGeneratedAt == entries[1].CredentialReportGeneratedAt {
		t.Fatal("entries must not alias the same timestamp pointer")
	}
}

// WO-61@v2: absent envelope provenance remains absent on direct findings.
func TestFetchCredentialReport_NilGeneratedTime(t *testing.T) {
	mock := &mockIAM{generateState: iamtypes.ReportStateTypeComplete, reportContent: []byte(testCredentialReportCSV)}
	entries, err := FetchCredentialReport(context.Background(), mock)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	for i := range entries {
		if entries[i].CredentialReportGeneratedAt != nil {
			t.Fatalf("entry %d fabricated report generation time", i)
		}
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
