package aws

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-55@v4: STALE_USER reports console-credential staleness by itself.
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
	if found.Metadata["last_console_activity"] != staleDate.Format(time.RFC3339) {
		t.Fatalf("expected console activity metadata, got %v", found.Metadata["last_console_activity"])
	}
	if _, ok := found.Metadata["days_since_console_activity"]; !ok {
		t.Fatal("expected days_since_console_activity metadata")
	}
	if !strings.Contains(strings.ToLower(found.Recommendation), "console") {
		t.Fatalf("console guidance omits console review: %q", found.Recommendation)
	}
}

// WO-55@v4: a dormant console password with an active key yields STALE_USER (console dormant)
// and NOT INACTIVE_IAM_USER (keys active) — the console credential is no longer masked.
func TestUserScanner_DormantConsoleActiveKey(t *testing.T) {
	dormantConsole := time.Now().UTC().AddDate(0, 0, -120)
	activeKey := time.Now().UTC().AddDate(0, 0, -1)
	entries := []CredentialEntry{
		{
			User:                   "masked-console",
			ARN:                    "arn:aws:iam::123456789012:user/masked-console",
			PasswordEnabled:        true,
			PasswordLastUsed:       &dormantConsole,
			MFAActive:              true,
			AccessKey1Active:       true,
			AccessKey1LastUsedDate: &activeKey,
			AccessKey1UseState:     CredentialUseUsed,
		},
	}
	result, err := NewUserScanner(entries).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if findFinding(result.Findings, iam.FindingStaleUser) == nil {
		t.Fatal("expected STALE_USER for dormant console credential")
	}
	if findFinding(result.Findings, iam.FindingInactiveIAMUser) != nil {
		t.Fatal("INACTIVE_IAM_USER must not fire while a key is active — user is not dormant")
	}
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
}

// WO-55@v4: a fully dormant user (console and keys both stale) yields INACTIVE_IAM_USER.
func TestUserScanner_FullyDormantUser(t *testing.T) {
	stale := time.Now().UTC().AddDate(0, 0, -120)
	entries := []CredentialEntry{
		{
			User:                   "fully-dormant",
			ARN:                    "arn:aws:iam::123456789012:user/fully-dormant",
			PasswordEnabled:        true,
			PasswordLastUsed:       &stale,
			MFAActive:              true,
			AccessKey1Active:       true,
			AccessKey1LastUsedDate: &stale,
			AccessKey1UseState:     CredentialUseUsed,
		},
	}
	result, err := NewUserScanner(entries).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := findFinding(result.Findings, iam.FindingInactiveIAMUser)
	if found == nil {
		t.Fatal("expected INACTIVE_IAM_USER for fully dormant user")
	}
	if found.Severity != iam.SeverityHigh {
		t.Fatalf("expected high severity, got %s", found.Severity)
	}
	if found.Metadata["last_activity"] != stale.Format(time.RFC3339) {
		t.Fatalf("expected last_activity metadata, got %v", found.Metadata["last_activity"])
	}
	// Console is also dormant, so STALE_USER fires too — both axes are independent.
	if findFinding(result.Findings, iam.FindingStaleUser) == nil {
		t.Fatal("expected STALE_USER for dormant console on a fully dormant user")
	}
}

// WO-55@v4: an active-console user triggers neither console staleness nor whole-user inactivity.
func TestUserScanner_ActiveConsoleUser(t *testing.T) {
	recent := time.Now().UTC().AddDate(0, 0, -1)
	entries := []CredentialEntry{
		{
			User:             "active-console",
			ARN:              "arn:aws:iam::123456789012:user/active-console",
			PasswordEnabled:  true,
			PasswordLastUsed: &recent,
			MFAActive:        true,
		},
	}
	result, err := NewUserScanner(entries).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if findFinding(result.Findings, iam.FindingStaleUser) != nil {
		t.Fatal("STALE_USER must not fire for an active console credential")
	}
	if findFinding(result.Findings, iam.FindingInactiveIAMUser) != nil {
		t.Fatal("INACTIVE_IAM_USER must not fire for an active user")
	}
}

// WO-55@v4: select the newest applicable activity without allowing inactive keys to mask dormancy.
func TestLatestUserActivity(t *testing.T) {
	oldest := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	middle := oldest.Add(24 * time.Hour)
	newest := middle.Add(24 * time.Hour)

	tests := []struct {
		name                      string
		entry                     CredentialEntry
		want                      *time.Time
		wantPasswordIndeterminate bool
		wantKeyIndeterminate      bool
	}{
		{name: "no applicable timestamps", entry: CredentialEntry{}},
		{
			name:  "active key newer than console",
			entry: CredentialEntry{PasswordEnabled: true, PasswordLastUsed: &oldest, AccessKey1Active: true, AccessKey1LastUsedDate: &newest},
			want:  &newest,
		},
		{
			name:  "second key newest",
			entry: CredentialEntry{PasswordEnabled: true, PasswordLastUsed: &oldest, AccessKey1Active: true, AccessKey1LastUsedDate: &middle, AccessKey2Active: true, AccessKey2LastUsedDate: &newest},
			want:  &newest,
		},
		{
			name:  "inactive key ignored",
			entry: CredentialEntry{PasswordEnabled: true, PasswordLastUsed: &oldest, AccessKey1Active: false, AccessKey1LastUsedDate: &newest},
			want:  &oldest,
		},
		{
			name:                 "active unknown key",
			entry:                CredentialEntry{PasswordEnabled: true, PasswordLastUsed: &oldest, AccessKey1Active: true, AccessKey1UseState: CredentialUseUnknown},
			want:                 &oldest,
			wantKeyIndeterminate: true,
		},
		{
			name:                      "never-used console blocks",
			entry:                     CredentialEntry{PasswordEnabled: true, PasswordUseState: PasswordUseNoRecordedUse},
			wantPasswordIndeterminate: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, passwordIndeterminate, keyIndeterminate := latestUserActivity(tt.entry)
			if tt.want == nil && got != nil {
				t.Fatalf("expected no activity, got %v", got)
			}
			if tt.want != nil && (got == nil || !got.Equal(*tt.want)) {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
			if passwordIndeterminate != tt.wantPasswordIndeterminate || keyIndeterminate != tt.wantKeyIndeterminate {
				t.Fatalf("expected password/key indeterminate=%v/%v, got %v/%v", tt.wantPasswordIndeterminate, tt.wantKeyIndeterminate, passwordIndeterminate, keyIndeterminate)
			}
		})
	}
}

// WO-55@v4: whole-user dormancy is cleared by activity on any applicable credential; active
// key use prevents INACTIVE_IAM_USER even when the console credential is itself dormant.
func TestUserScanner_WholeUserInactivity(t *testing.T) {
	recent := time.Now().UTC().AddDate(0, 0, -1)
	stale := time.Now().UTC().AddDate(0, 0, -120)
	tests := []struct {
		name         string
		entry        CredentialEntry
		wantInactive bool
		wantErrors   int
	}{
		{
			name:  "stale console recent key one",
			entry: CredentialEntry{User: "active-key-one", ARN: "arn:active-key-one", PasswordEnabled: true, PasswordLastUsed: &stale, MFAActive: true, AccessKey1Active: true, AccessKey1LastUsedDate: &recent},
		},
		{
			name:  "stale console recent key two",
			entry: CredentialEntry{User: "active-key-two", ARN: "arn:active-key-two", PasswordEnabled: true, PasswordLastUsed: &stale, MFAActive: true, AccessKey2Active: true, AccessKey2LastUsedDate: &recent},
		},
		{
			name:         "fully stale",
			entry:        CredentialEntry{User: "fully-stale", ARN: "arn:fully-stale", PasswordEnabled: true, PasswordLastUsed: &stale, MFAActive: true, AccessKey1Active: true, AccessKey1LastUsedDate: &stale},
			wantInactive: true,
		},
		{
			name:  "key only recent",
			entry: CredentialEntry{User: "key-only", ARN: "arn:key-only", AccessKey1Active: true, AccessKey1LastUsedDate: &recent},
		},
		{
			name:         "inactive recent key",
			entry:        CredentialEntry{User: "inactive-key", ARN: "arn:inactive-key", PasswordEnabled: true, PasswordLastUsed: &stale, MFAActive: true, AccessKey1LastUsedDate: &recent},
			wantInactive: true,
		},
		{
			name:       "no applicable timestamps",
			entry:      CredentialEntry{User: "no-evidence", ARN: "arn:no-evidence", PasswordEnabled: true, MFAActive: true},
			wantErrors: 1,
		},
		{
			name:       "stale console unknown active key",
			entry:      CredentialEntry{User: "stale-unknown", ARN: "arn:stale-unknown", PasswordEnabled: true, PasswordLastUsed: &stale, MFAActive: true, AccessKey1Active: true, AccessKey1UseState: CredentialUseUnknown},
			wantErrors: 1,
		},
		{
			name:       "no timestamp unknown active key",
			entry:      CredentialEntry{User: "only-unknown", ARN: "arn:only-unknown", AccessKey1Active: true, AccessKey1UseState: CredentialUseUnknown},
			wantErrors: 1,
		},
		{
			name:       "recent console unknown active key",
			entry:      CredentialEntry{User: "recent-unknown", ARN: "arn:recent-unknown", PasswordEnabled: true, PasswordLastUsed: &recent, MFAActive: true, AccessKey1Active: true, AccessKey1UseState: CredentialUseUnknown},
			wantErrors: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := NewUserScanner([]CredentialEntry{tt.entry}).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			gotInactive := findFinding(result.Findings, iam.FindingInactiveIAMUser) != nil
			if gotInactive != tt.wantInactive {
				t.Fatalf("expected inactive=%v, got %v", tt.wantInactive, gotInactive)
			}
			if len(result.Errors) != tt.wantErrors {
				t.Fatalf("expected %d errors, got %v", tt.wantErrors, result.Errors)
			}
			if tt.wantErrors > 0 && !strings.Contains(result.Errors[0], tt.entry.User) {
				t.Fatalf("expected user-qualified error, got %v", result.Errors)
			}
		})
	}
}

// WO-63: indeterminate console evidence blocks stale-user conclusions unless recent activity is known.
// WO-55@v4: the console axis owns this block; STALE_USER stays suppressed on unknown console evidence.
func TestUserScanner_PasswordEvidenceAggregation(t *testing.T) {
	stale := time.Now().UTC().AddDate(0, 0, -120)
	recent := time.Now().UTC().AddDate(0, 0, -1)
	tests := []struct {
		name          string
		passwordState PasswordUseState
		keyUsed       *time.Time
		wantErrors    int
	}{
		{name: "unknown console stale key", passwordState: PasswordUseUnknown, keyUsed: &stale, wantErrors: 1},
		{name: "no recorded console stale key", passwordState: PasswordUseNoRecordedUse, keyUsed: &stale},
		{name: "unknown console recent key", passwordState: PasswordUseUnknown, keyUsed: &recent, wantErrors: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := CredentialEntry{
				User:                   "password-evidence-user",
				ARN:                    "arn:password-evidence-user",
				PasswordEnabled:        true,
				PasswordUseState:       tt.passwordState,
				MFAActive:              true,
				AccessKey1Active:       true,
				AccessKey1LastUsedDate: tt.keyUsed,
				AccessKey1UseState:     CredentialUseUsed,
			}
			result, err := NewUserScanner([]CredentialEntry{entry}).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if findFinding(result.Findings, iam.FindingStaleUser) != nil {
				t.Fatal("indeterminate console evidence must not emit STALE_USER")
			}
			if len(result.Errors) != tt.wantErrors {
				t.Fatalf("expected %d console evidence errors, got %v", tt.wantErrors, result.Errors)
			}
			if tt.wantErrors > 0 && !strings.Contains(result.Errors[0], entry.User) {
				t.Fatalf("expected user-qualified console evidence error, got %v", result.Errors)
			}
		})
	}
}

// WO-55@v4: an API-only dormant user is INACTIVE_IAM_USER (not STALE_USER, no console credential),
// and its guidance must not imply console access exists.
func TestUserScanner_APIOnlyInactiveGuidance(t *testing.T) {
	stale := time.Now().UTC().AddDate(0, 0, -120)
	entry := CredentialEntry{User: "api-only-stale", ARN: "arn:api-only-stale", AccessKey1Active: true, AccessKey1LastUsedDate: &stale}
	result, err := NewUserScanner([]CredentialEntry{entry}).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if findFinding(result.Findings, iam.FindingStaleUser) != nil {
		t.Fatal("STALE_USER must not fire for an API-only user with no console credential")
	}
	found := findFinding(result.Findings, iam.FindingInactiveIAMUser)
	if found == nil {
		t.Fatal("expected INACTIVE_IAM_USER")
	}
	if strings.Contains(strings.ToLower(found.Recommendation), "console") {
		t.Fatalf("API-only guidance mentions console: %q", found.Recommendation)
	}
}

// WO-57@v5: known stale key use retains the timestamp-based finding contract.
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
	if found.Metadata["last_used"] != staleDate.Format(time.RFC3339) {
		t.Fatalf("expected last_used metadata, got %v", found.Metadata)
	}
	if _, ok := found.Metadata["days_since_use"]; !ok {
		t.Fatal("expected days_since_use metadata")
	}
	if _, ok := found.Metadata["never_used"]; ok {
		t.Fatal("used key must not include never_used")
	}
}

// WO-57@v5: require tracking coverage and key age before reporting no recorded use.
func TestUserScanner_NoRecordedUseAccessKey(t *testing.T) {
	rotated := time.Now().UTC().AddDate(0, 0, -120)
	entries := []CredentialEntry{
		{
			User:                   "new-key-user",
			ARN:                    "arn:aws:iam::123456789012:user/new-key-user",
			PasswordEnabled:        false,
			AccessKey1Active:       true,
			AccessKey1LastUsedDate: nil,
			AccessKey1LastRotated:  &rotated,
			AccessKey1UseState:     CredentialUseNoRecordedUse,
		},
	}

	scanner := NewUserScanner(entries)
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	found := findFinding(result.Findings, iam.FindingStaleAccessKey)
	if found == nil {
		t.Fatal("expected STALE_ACCESS_KEY finding for key with no recorded use")
	}
	if found.Message != "Access key 1 has no recorded use" {
		t.Fatalf("unexpected message: %s", found.Message)
	}
	if found.Metadata["no_recorded_use"] != true {
		t.Fatalf("expected no_recorded_use metadata, got %v", found.Metadata)
	}
	if _, ok := found.Metadata["last_used"]; ok {
		t.Fatal("no-recorded-use key must not include last_used")
	}
	if _, ok := found.Metadata["days_since_use"]; ok {
		t.Fatal("no-recorded-use key must not include days_since_use")
	}
	if _, ok := found.Metadata["never_used"]; ok {
		t.Fatal("no-recorded-use key must not include never_used")
	}
}

// WO-57@v5: no-recorded-use evidence is usable only within AWS's tracking window.
func TestUserScanner_NoRecordedUseTrackingBoundary(t *testing.T) {
	now := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		threshold   time.Time
		wantFinding bool
		wantError   bool
	}{
		{name: "before tracking", threshold: accessKeyLastUseTrackingStartedAt.AddDate(0, 0, -1), wantError: true},
		{name: "tracking start", threshold: accessKeyLastUseTrackingStartedAt, wantFinding: true},
		{name: "after tracking", threshold: accessKeyLastUseTrackingStartedAt.AddDate(0, 0, 1), wantFinding: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rotated := time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)
			entry := CredentialEntry{User: "boundary-user", ARN: "arn:boundary-user"}
			result := &iam.ScanResult{}
			NewUserScanner(nil).checkStaleKey(entry, 1, nil, &rotated, CredentialUseNoRecordedUse, tt.threshold, now, result)
			found := findFinding(result.Findings, iam.FindingStaleAccessKey)
			if (found != nil) != tt.wantFinding || (len(result.Errors) > 0) != tt.wantError {
				t.Fatalf("finding/errors=%v/%v", found, result.Errors)
			}
			if tt.wantError && (!strings.Contains(result.Errors[0], "boundary-user") || !strings.Contains(result.Errors[0], "key 1")) {
				t.Fatalf("expected slot-qualified error, got %v", result.Errors)
			}
			if found != nil {
				if strings.Contains(strings.ToLower(found.Recommendation), "unused") {
					t.Fatalf("no-recorded-use guidance overclaims: %q", found.Recommendation)
				}
				if !strings.Contains(strings.ToLower(found.Recommendation), "verify") {
					t.Fatalf("expected verification-first guidance: %q", found.Recommendation)
				}
			}
		})
	}
}

// WO-57@v5: an individual key must be old enough before no-recorded-use proves staleness.
func TestUserScanner_NoRecordedUseRotationBoundary(t *testing.T) {
	now := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	threshold := time.Date(2026, 4, 21, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name        string
		rotated     *time.Time
		wantFinding bool
		wantError   bool
	}{
		{name: "missing age", wantError: true},
		{name: "newer than cutoff", rotated: timePointer(threshold.AddDate(0, 0, 1))},
		{name: "equal to cutoff", rotated: timePointer(threshold)},
		{name: "older than cutoff", rotated: timePointer(threshold.AddDate(0, 0, -1)), wantFinding: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := CredentialEntry{User: "rotation-boundary", ARN: "arn:rotation-boundary"}
			result := &iam.ScanResult{}
			NewUserScanner(nil).checkStaleKey(entry, 1, nil, tt.rotated, CredentialUseNoRecordedUse, threshold, now, result)
			if (findFinding(result.Findings, iam.FindingStaleAccessKey) != nil) != tt.wantFinding || (len(result.Errors) > 0) != tt.wantError {
				t.Fatalf("findings/errors=%v/%v", result.Findings, result.Errors)
			}
			if tt.wantError && (!strings.Contains(result.Errors[0], "rotation-boundary") || !strings.Contains(result.Errors[0], "key 1")) {
				t.Fatalf("expected slot-qualified age error, got %v", result.Errors)
			}
		})
	}
}

// WO-57@v5: construct fixed key-evidence boundaries without shared mutation.
func timePointer(value time.Time) *time.Time {
	return &value
}

// WO-57@v5: unavailable key evidence is reportable uncertainty, not a lifetime-use claim.
func TestUserScanner_UnknownAccessKeyUse(t *testing.T) {
	entries := []CredentialEntry{
		{
			User:               "unknown-key-user",
			ARN:                "arn:aws:iam::123456789012:user/unknown-key-user",
			AccessKey1Active:   true,
			AccessKey1UseState: CredentialUseUnknown,
		},
	}

	result, err := NewUserScanner(entries).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if findFinding(result.Findings, iam.FindingStaleAccessKey) != nil {
		t.Fatal("unknown key evidence must not emit STALE_ACCESS_KEY")
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected one scanner error, got %v", result.Errors)
	}
}

// WO-57@v5: each unknown active-key slot owns one diagnostic; aggregation adds none.
func TestUserScanner_UnknownAccessKeySlots(t *testing.T) {
	entry := CredentialEntry{
		User:               "two-unknown-keys",
		ARN:                "arn:two-unknown-keys",
		AccessKey1Active:   true,
		AccessKey1UseState: CredentialUseUnknown,
		AccessKey2Active:   true,
		AccessKey2UseState: CredentialUseUnknown,
	}
	result, err := NewUserScanner([]CredentialEntry{entry}).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Errors) != 2 {
		t.Fatalf("expected one error per key slot, got %v", result.Errors)
	}
	if !strings.Contains(result.Errors[0], "key 1") || !strings.Contains(result.Errors[1], "key 2") {
		t.Fatalf("expected key-number-qualified errors, got %v", result.Errors)
	}
}

// WO-57@v5: the second access-key slot uses the same no-recorded-use evidence contract.
func TestUserScanner_NoRecordedUseAccessKeyTwo(t *testing.T) {
	rotated := time.Now().UTC().AddDate(0, 0, -120)
	entries := []CredentialEntry{
		{
			User:                  "second-key-user",
			ARN:                   "arn:aws:iam::123456789012:user/second-key-user",
			AccessKey2Active:      true,
			AccessKey2LastRotated: &rotated,
			AccessKey2UseState:    CredentialUseNoRecordedUse,
		},
	}

	result, err := NewUserScanner(entries).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	found := findFinding(result.Findings, iam.FindingStaleAccessKey)
	if found == nil {
		t.Fatal("expected STALE_ACCESS_KEY for second key with no recorded use")
	}
	if found.Metadata["key_number"] != 2 || found.Metadata["no_recorded_use"] != true {
		t.Fatalf("unexpected second-key metadata: %v", found.Metadata)
	}
}

// WO-56@v2: console-capable users without an MFA device retain one finding.
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
	if found.Metadata["password_enabled"] != true || found.Metadata["mfa_active"] != false {
		t.Fatalf("unexpected NO_MFA metadata: %v", found.Metadata)
	}
	count := 0
	for _, finding := range result.Findings {
		if finding.ID == iam.FindingNoMFA {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly one NO_MFA finding, got %d", count)
	}
}

// WO-61@v2: every credential-report finding carries the shared evidence timestamp when available.
func TestUserScanner_CredentialReportGeneratedAtMetadata(t *testing.T) {
	generatedAt := time.Date(2026, 7, 19, 3, 4, 5, 0, time.FixedZone("cached", 8*60*60))
	stale := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	want := generatedAt.UTC().Format(time.RFC3339)

	tests := []struct {
		name        string
		generatedAt *time.Time
		wantPresent bool
	}{
		{name: "cached report time", generatedAt: &generatedAt, wantPresent: true},
		{name: "missing report time"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := CredentialEntry{
				User:                        "all-findings",
				ARN:                         "arn:all-findings",
				CredentialReportGeneratedAt: tt.generatedAt,
				PasswordEnabled:             true,
				PasswordLastUsed:            &stale,
				MFAActive:                   false,
				AccessKey1Active:            true,
				AccessKey1LastUsedDate:      &stale,
				AccessKey1UseState:          CredentialUseUsed,
			}
			result, err := NewUserScanner([]CredentialEntry{entry}).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			for _, id := range []iam.FindingID{iam.FindingStaleUser, iam.FindingStaleAccessKey, iam.FindingNoMFA} {
				found := findFinding(result.Findings, id)
				if found == nil {
					t.Fatalf("expected %s", id)
				}
				got, present := found.Metadata["credential_report_generated_at"]
				if present != tt.wantPresent {
					t.Fatalf("%s: expected generated_at present=%v, metadata=%v", id, tt.wantPresent, found.Metadata)
				}
				if tt.wantPresent && got != want {
					t.Fatalf("%s: expected %q, got %v", id, want, got)
				}
			}
		})
	}
}

// WO-61@v2: cached observations use report time for cutoffs and age metadata.
func TestUserScanner_UsesCredentialReportTimeForStaleness(t *testing.T) {
	generatedAt := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	insideCutoff := generatedAt.AddDate(0, 0, -89)
	stale := generatedAt.AddDate(0, 0, -100)
	entries := []CredentialEntry{
		{
			User:                        "inside-at-report-time",
			ARN:                         "arn:inside-at-report-time",
			CredentialReportGeneratedAt: &generatedAt,
			PasswordEnabled:             true,
			PasswordLastUsed:            &insideCutoff,
			PasswordUseState:            PasswordUseUsed,
			MFAActive:                   true,
			AccessKey1Active:            true,
			AccessKey1LastRotated:       timePointer(generatedAt.AddDate(-1, 0, 0)),
			AccessKey1LastUsedDate:      &insideCutoff,
			AccessKey1UseState:          CredentialUseUsed,
		},
		{
			User:                        "stale-at-report-time",
			ARN:                         "arn:stale-at-report-time",
			CredentialReportGeneratedAt: &generatedAt,
			PasswordEnabled:             true,
			PasswordLastUsed:            &stale,
			PasswordUseState:            PasswordUseUsed,
			MFAActive:                   true,
			AccessKey1Active:            true,
			AccessKey1LastRotated:       timePointer(generatedAt.AddDate(-1, 0, 0)),
			AccessKey1LastUsedDate:      &stale,
			AccessKey1UseState:          CredentialUseUsed,
		},
	}
	result, err := NewUserScanner(entries).Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, finding := range result.Findings {
		if finding.ResourceName == "inside-at-report-time" {
			t.Fatalf("cached evidence crossed cutoff at scan time: %+v", finding)
		}
		if finding.ResourceName == "stale-at-report-time" {
			// WO-55@v4: each axis reports its own age metadata key.
			key := "days_since_activity"
			switch finding.ID {
			case iam.FindingStaleAccessKey:
				key = "days_since_use"
			case iam.FindingStaleUser:
				key = "days_since_console_activity"
			}
			if finding.Metadata[key] != 100 {
				t.Fatalf("%s uses wrong evidence age: %v", finding.ID, finding.Metadata)
			}
		}
	}
	// WO-55@v4: the dormant user surfaces console staleness, whole-user inactivity, and the stale key.
	if len(result.Findings) != 3 {
		t.Fatalf("expected stale user, inactive user, and stale key, got %+v", result.Findings)
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

// WO-56@v2: console MFA findings do not apply to API-only users.
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

	noMFACount := 0
	for _, f := range result.Findings {
		if f.ID == iam.FindingNoMFA {
			noMFACount++
		}
	}
	if noMFACount != 0 {
		t.Fatalf("expected no NO_MFA findings for API-only user, got %d", noMFACount)
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
