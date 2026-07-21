package gcp

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/analyzer"
	"github.com/ppiankov/iamspectre/internal/iam"
	"github.com/ppiankov/iamspectre/internal/report"
	iamv1 "google.golang.org/api/iam/v1"
)

var serviceAccountTestNow = time.Date(2026, time.July, 21, 0, 0, 0, 0, time.UTC) // WO-88: pin all new key-age evidence.

// WO-88: construct scanners with a deterministic assessment clock.
func fixedServiceAccountScanner(api IAMAPI, project string) *ServiceAccountScanner {
	scanner := NewServiceAccountScanner(api, project)
	scanner.now = func() time.Time { return serviceAccountTestNow }
	return scanner
}

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

// WO-88: enabled stale keys carry a complete evidence-limited Medium assessment.
func TestServiceAccountScanner_StaleSAKey(t *testing.T) {
	staleTime := serviceAccountTestNow.AddDate(0, 0, -91).Format(time.RFC3339)
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

	scanner := fixedServiceAccountScanner(mock, "test")
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
	if f.Severity != iam.SeverityMedium || iam.EffectiveSeverity(f) != iam.SeverityMedium {
		t.Fatalf("severity = %s, effective = %s; want medium", f.Severity, iam.EffectiveSeverity(f))
	}
	if f.ResourceType != iam.ResourceServiceAccountKey {
		t.Fatalf("expected service_account_key, got %s", f.ResourceType)
	}
	if f.EvidenceTier == nil || *f.EvidenceTier != iam.EvidenceTierFact || f.State != iam.FindingStateDeterminate ||
		f.Reachability != iam.ReachabilityUnknown || f.Impact != iam.SeverityMedium ||
		f.BlastRadius != iam.BlastRadiusMedium || f.RubricVersion != iam.RubricVersionV1 {
		t.Fatalf("assessment = %#v", f)
	}
	for _, layer := range iam.CanonicalLayers() {
		if f.EvaluatedLayers[layer] != iam.LayerUnresolved {
			t.Fatalf("layer %s = %s, want unresolved", layer, f.EvaluatedLayers[layer])
		}
	}
	for key, want := range map[string]any{
		"service_account": "sa1@test.iam.gserviceaccount.com",
		"key_created":     staleTime,
		"days_old":        91,
		"stale_days":      90,
		"enabled":         true,
	} {
		if got := f.Metadata[key]; got != want {
			t.Fatalf("metadata[%q] = %#v, want %#v", key, got, want)
		}
	}
	analysis := analyzer.Analyze(result, analyzer.AnalyzerConfig{SeverityMin: iam.SeverityMedium})
	if len(analysis.Findings) != 1 || analysis.Findings[0].Severity != iam.SeverityMedium {
		t.Fatalf("analyzer findings = %#v", analysis.Findings)
	}
	if len(analyzer.Analyze(result, analyzer.AnalyzerConfig{SeverityMin: iam.SeverityHigh}).Findings) != 0 {
		t.Fatal("medium stale-key assessment passed a high severity filter")
	}
	if result.PrincipalsScanned != 1 || !result.PrincipalIdentityAccountingComplete {
		t.Fatalf("principal accounting = %#v", result)
	}
}

// WO-88: the shared cutoff is strict; equality is not stale.
func TestServiceAccountScanner_StaleKeyThresholdBoundary(t *testing.T) {
	threshold := serviceAccountTestNow.AddDate(0, 0, -90)
	tests := []struct {
		name    string
		created time.Time
		stale   bool
	}{
		{name: "exact threshold", created: threshold},
		{name: "one nanosecond older", created: threshold.Add(-time.Nanosecond), stale: true},
		{name: "recent", created: threshold.Add(time.Nanosecond)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accountName := "projects/test/serviceAccounts/sa1"
			mock := &mockIAM{
				accounts: []*iamv1.ServiceAccount{{Name: accountName, Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123"}},
				keys: map[string][]*iamv1.ServiceAccountKey{
					accountName: {{Name: accountName + "/keys/key1", ValidAfterTime: tt.created.Format(time.RFC3339Nano)}},
				},
			}
			result, err := fixedServiceAccountScanner(mock, "test").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			if got := len(result.Findings) == 1; got != tt.stale {
				t.Fatalf("stale = %v, want %v; findings=%#v", got, tt.stale, result.Findings)
			}
		})
	}
}

// WO-88: every account in one scan must share a single evidence timestamp.
func TestServiceAccountScanner_UsesSingleScanClock(t *testing.T) {
	threshold := serviceAccountTestNow.AddDate(0, 0, -90)
	accounts := []*iamv1.ServiceAccount{
		{Name: "projects/test/serviceAccounts/one", Email: "one@test.iam.gserviceaccount.com", UniqueId: "1"},
		{Name: "projects/test/serviceAccounts/two", Email: "two@test.iam.gserviceaccount.com", UniqueId: "2"},
	}
	mock := &mockIAM{
		accounts: accounts,
		keys: map[string][]*iamv1.ServiceAccountKey{
			accounts[0].Name: {{Name: accounts[0].Name + "/keys/key", ValidAfterTime: threshold.Format(time.RFC3339)}},
			accounts[1].Name: {{Name: accounts[1].Name + "/keys/key", ValidAfterTime: threshold.Format(time.RFC3339)}},
		},
	}
	scanner := NewServiceAccountScanner(mock, "test")
	clockCalls := 0
	scanner.now = func() time.Time {
		clockCalls++
		return serviceAccountTestNow.Add(time.Duration(clockCalls-1) * time.Second)
	}

	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if clockCalls != 1 {
		t.Fatalf("clock calls = %d, want one per scan", clockCalls)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("identical threshold evidence diverged across accounts: %#v", result.Findings)
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

// WO-76: disabled keys are already inactive and must not be reported as stale credentials.
func TestServiceAccountScanner_DisabledStaleKey(t *testing.T) {
	mock := &mockIAM{
		accounts: []*iamv1.ServiceAccount{
			{Name: "projects/test/serviceAccounts/sa1", Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123"},
		},
		keys: map[string][]*iamv1.ServiceAccountKey{
			"projects/test/serviceAccounts/sa1": {
				{
					Name:           "projects/test/serviceAccounts/sa1/keys/disabled",
					ValidAfterTime: "2000-01-01T00:00:00Z",
					Disabled:       true,
				},
			},
		},
	}

	scanner := NewServiceAccountScanner(mock, "test")
	result, err := scanner.Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if len(result.Findings) != 0 {
		t.Fatalf("expected no finding for disabled key, got %#v", result.Findings)
	}
}

// WO-76: disabled-key state takes precedence even when the credential is still recent.
func TestServiceAccountScanner_DisabledRecentKey(t *testing.T) {
	recentTime := time.Now().UTC().AddDate(0, 0, -10).Format(time.RFC3339)
	mock := &mockIAM{
		accounts: []*iamv1.ServiceAccount{
			{Name: "projects/test/serviceAccounts/sa1", Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123"},
		},
		keys: map[string][]*iamv1.ServiceAccountKey{
			"projects/test/serviceAccounts/sa1": {
				{
					Name:           "projects/test/serviceAccounts/sa1/keys/disabled-recent",
					ValidAfterTime: recentTime,
					Disabled:       true,
				},
			},
		},
	}

	result, err := NewServiceAccountScanner(mock, "test").Scan(
		context.Background(), iam.ScanConfig{StaleDays: 90},
	)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(result.Findings) != 0 {
		t.Fatalf("expected no finding for recent disabled key, got %#v", result.Findings)
	}
}

func TestServiceAccountScanner_DisabledSA(t *testing.T) {
	// WO-69@v2: disabled state alone is not staleness, but the fact is preserved as an
	// informational DISABLED_SA finding (no delete advice), never suppressed to nothing.
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
		t.Fatalf("expected exactly one informational finding, got %#v", result.Findings)
	}
	f := result.Findings[0]
	if f.ID != iam.FindingDisabledSA {
		t.Fatalf("expected DISABLED_SA, got %s", f.ID)
	}
	if f.Severity != iam.SeverityLow {
		t.Fatalf("expected low severity for disabled fact, got %s", f.Severity)
	}
	if f.ID == iam.FindingStaleSA {
		t.Fatalf("disabled must not be reported as STALE_SA")
	}
}

func TestServiceAccountScanner_DisabledWithStaleKey(t *testing.T) {
	// WO-69@v2: disabled accounts remain in key scanning and retain stale-key evidence.
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

	// WO-69@v2: disabled fact and stale-key evidence are independent axes; both are reported.
	ids := map[iam.FindingID]bool{}
	for _, f := range result.Findings {
		ids[f.ID] = true
	}
	if !ids[iam.FindingStaleSAKey] {
		t.Fatalf("expected STALE_SA_KEY, got %#v", result.Findings)
	}
	if !ids[iam.FindingDisabledSA] {
		t.Fatalf("expected DISABLED_SA preserved alongside stale key, got %#v", result.Findings)
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
	if !result.PrincipalIdentityAccountingComplete || len(result.ObservedPrincipalIDs) != 0 {
		t.Fatalf("empty principal accounting = %#v", result)
	}
}

// WO-89: missing provider identity data cannot become a synthetic union member.
func TestServiceAccountScanner_BlankEmailUsesIncompleteFallback(t *testing.T) {
	accountName := "projects/test/serviceAccounts/blank"
	mock := &mockIAM{
		accounts: []*iamv1.ServiceAccount{{Name: accountName, Email: "  ", UniqueId: "blank"}},
		keys:     map[string][]*iamv1.ServiceAccountKey{accountName: {}},
	}

	result, err := fixedServiceAccountScanner(mock, "test").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if result.PrincipalIdentityAccountingComplete || len(result.ObservedPrincipalIDs) != 0 {
		t.Fatalf("blank identity carrier = %#v, complete=%v", result.ObservedPrincipalIDs, result.PrincipalIdentityAccountingComplete)
	}
	if result.PrincipalsScanned != 1 {
		t.Fatalf("additive principal count = %d, want 1", result.PrincipalsScanned)
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
	if len(result.CoverageGaps) != 1 {
		t.Fatalf("coverage gaps = %#v, want one", result.CoverageGaps)
	}
	gap := result.CoverageGaps[0]
	if gap.Capability != "gcp_service_account_key_inventory" || gap.Cause != "list_keys_failed" ||
		gap.Scope != "gcp-project:test" || gap.FindingID != iam.FindingStaleSAKey ||
		gap.AffectedCount != 1 || gap.EvaluableCount != 0 || gap.TotalCount != 1 ||
		gap.OldestEvidence != nil || gap.ObservationWindow != "90d" || gap.FeatureStage != "" ||
		gap.MaxConsequence != iam.SeverityMedium {
		t.Fatalf("coverage gap = %#v", gap)
	}
}

// WO-92: account-order changes cannot alter merged key-inventory coverage totals.
func TestServiceAccountScanner_KeyListErrorsAggregateDeterministically(t *testing.T) {
	account := func(id string) *iamv1.ServiceAccount {
		return &iamv1.ServiceAccount{
			Name: "projects/test/serviceAccounts/" + id, Email: id + "@test.iam.gserviceaccount.com", UniqueId: id,
		}
	}
	scan := func(accounts []*iamv1.ServiceAccount) report.CoverageManifest {
		mock := &mockIAM{
			accounts: accounts,
			keysErr: map[string]error{
				accounts[0].Name: fmt.Errorf("first key list error"),
				accounts[1].Name: fmt.Errorf("second key list error"),
			},
		}
		result, err := fixedServiceAccountScanner(mock, "test").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		return report.BuildCoverageManifest(result.CoverageGaps)
	}

	forward := scan([]*iamv1.ServiceAccount{account("one"), account("two")})
	reverse := scan([]*iamv1.ServiceAccount{account("two"), account("one")})
	for _, manifest := range []report.CoverageManifest{forward, reverse} {
		if len(manifest.Gaps) != 1 || manifest.TotalOpportunities != 2 || manifest.EvaluableOpportunities != 0 {
			t.Fatalf("manifest = %#v", manifest)
		}
		gap := manifest.Gaps[0]
		if len(gap.AffectedFindings) != 1 || gap.AffectedFindings[0].FindingID != iam.FindingStaleSAKey ||
			gap.AffectedFindings[0].Count != 2 || gap.TotalCount != 2 {
			t.Fatalf("merged gap = %#v", gap)
		}
	}
}

// WO-90: malformed enabled-key timestamps are explicit gaps and never leak raw evidence.
func TestServiceAccountScanner_MalformedKeyTimestamp(t *testing.T) {
	const malformed = "malformed-private-timestamp"
	accountName := "projects/test/serviceAccounts/sa1"
	malformedKeyName := accountName + "/keys/malformed"
	mock := &mockIAM{
		accounts: []*iamv1.ServiceAccount{{Name: accountName, Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123"}},
		keys: map[string][]*iamv1.ServiceAccountKey{
			accountName: {
				{Name: malformedKeyName, ValidAfterTime: malformed},
				{Name: accountName + "/keys/disabled", ValidAfterTime: malformed, Disabled: true},
				{Name: accountName + "/keys/stale", ValidAfterTime: serviceAccountTestNow.AddDate(0, 0, -91).Format(time.RFC3339)},
			},
		},
	}

	var logs bytes.Buffer
	previousLogger := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	result, err := fixedServiceAccountScanner(mock, "test").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	wantError := "service account key age unavailable for " + malformedKeyName + ": invalid validAfterTime"
	if len(result.Errors) != 1 || result.Errors[0] != wantError {
		t.Fatalf("errors = %#v, want %q", result.Errors, wantError)
	}
	if strings.Contains(strings.Join(result.Errors, "\n")+logs.String(), malformed) || strings.Contains(logs.String(), "cannot parse") {
		t.Fatalf("malformed timestamp leaked in diagnostics: errors=%#v logs=%q", result.Errors, logs.String())
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != iam.FindingStaleSAKey {
		t.Fatalf("valid sibling findings = %#v", result.Findings)
	}
	if len(result.CoverageGaps) != 1 {
		t.Fatalf("coverage gaps = %#v, want one", result.CoverageGaps)
	}
	gap := result.CoverageGaps[0]
	if gap.Capability != "gcp_service_account_key_age" || gap.Cause != "invalid_valid_after_time" ||
		gap.Scope != "gcp-project:test" || gap.FindingID != iam.FindingStaleSAKey ||
		gap.AffectedCount != 1 || gap.EvaluableCount != 0 || gap.TotalCount != 1 ||
		gap.OldestEvidence != nil || gap.ObservationWindow != "90d" || gap.FeatureStage != "" ||
		gap.MaxConsequence != iam.SeverityMedium {
		t.Fatalf("coverage gap = %#v", gap)
	}
}

// WO-90: repeated malformed timestamps retain denominators independent of input order.
func TestServiceAccountScanner_MalformedKeyTimestampsAggregateDeterministically(t *testing.T) {
	accountName := "projects/test/serviceAccounts/sa1"
	key := func(name string) *iamv1.ServiceAccountKey {
		return &iamv1.ServiceAccountKey{Name: accountName + "/keys/" + name, ValidAfterTime: "invalid-" + name}
	}
	scan := func(keys []*iamv1.ServiceAccountKey) report.CoverageManifest {
		mock := &mockIAM{
			accounts: []*iamv1.ServiceAccount{{Name: accountName, Email: "sa1@test.iam.gserviceaccount.com", UniqueId: "123"}},
			keys:     map[string][]*iamv1.ServiceAccountKey{accountName: keys},
		}
		result, err := fixedServiceAccountScanner(mock, "test").Scan(context.Background(), iam.ScanConfig{StaleDays: 90})
		if err != nil {
			t.Fatalf("scan: %v", err)
		}
		return report.BuildCoverageManifest(result.CoverageGaps)
	}

	for _, manifest := range []report.CoverageManifest{scan([]*iamv1.ServiceAccountKey{key("one"), key("two")}), scan([]*iamv1.ServiceAccountKey{key("two"), key("one")})} {
		if len(manifest.Gaps) != 1 || manifest.TotalOpportunities != 2 || manifest.EvaluableOpportunities != 0 {
			t.Fatalf("manifest = %#v", manifest)
		}
		gap := manifest.Gaps[0]
		if len(gap.AffectedFindings) != 1 || gap.AffectedFindings[0].Count != 2 || gap.MaxConsequence != iam.SeverityMedium {
			t.Fatalf("merged gap = %#v", gap)
		}
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
	if result.PrincipalsScanned != 1 || !result.PrincipalIdentityAccountingComplete {
		t.Fatalf("excluded principal accounting = %#v", result)
	}
	if _, ok := result.ObservedPrincipalIDs["serviceAccount:sa1@test.iam.gserviceaccount.com"]; !ok {
		t.Fatalf("observed principal IDs = %#v", result.ObservedPrincipalIDs)
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
