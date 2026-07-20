package iam

import (
	"encoding/json"
	"testing"
)

func TestFinding_JSON(t *testing.T) {
	f := Finding{
		ID:             FindingNoMFA,
		Severity:       SeverityCritical,
		ResourceType:   ResourceIAMUser,
		ResourceID:     "arn:aws:iam::123456789012:user/admin",
		ResourceName:   "admin",
		Message:        "Console user without MFA enabled",
		Recommendation: "Enable MFA for this user",
		Metadata: map[string]any{
			"password_enabled": true,
			"mfa_active":       false,
		},
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.ID != FindingNoMFA {
		t.Fatalf("expected ID %s, got %s", FindingNoMFA, decoded.ID)
	}
	if decoded.Severity != SeverityCritical {
		t.Fatalf("expected severity %s, got %s", SeverityCritical, decoded.Severity)
	}
	if decoded.Recommendation != "Enable MFA for this user" {
		t.Fatalf("expected recommendation, got %q", decoded.Recommendation)
	}
}

// WO-20@v3: assessment metadata has a stable snake_case JSON round trip.
func TestFinding_AssessmentJSON(t *testing.T) {
	f := assessedFinding()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, field := range []string{"evidence_tier", "state", "reachability", "impact", "blast_radius", "rubric_version", "evaluated_layers"} {
		if !contains(string(data), `"`+field+`"`) {
			t.Fatalf("assessment JSON missing %q", field)
		}
	}
	var decoded Finding
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.RubricVersion != RubricVersionV1 || len(decoded.EvaluatedLayers) != len(CanonicalLayers()) {
		t.Fatalf("assessment round trip = %#v", decoded)
	}
	tierZero := EvidenceTierFact
	f.EvidenceTier = &tierZero
	data, err = json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal tier zero: %v", err)
	}
	if !contains(string(data), `"evidence_tier":0`) {
		t.Fatalf("tier-zero assessment omitted evidence tier: %s", data)
	}
	legacy, err := json.Marshal(Finding{Severity: SeverityHigh})
	if err != nil {
		t.Fatalf("marshal legacy: %v", err)
	}
	if contains(string(legacy), "evidence_tier") {
		t.Fatalf("legacy finding gained assessment metadata: %s", legacy)
	}
}

// WO-70@v3: coverage observations have a stable ScanResult JSON round trip.
func TestScanResult_JSON(t *testing.T) {
	r := ScanResult{
		Findings: []Finding{
			{
				ID:             FindingUnusedRole,
				Severity:       SeverityMedium,
				ResourceType:   ResourceIAMRole,
				ResourceID:     "arn:aws:iam::123456789012:role/old-role",
				Message:        "Role not assumed in 120 days",
				Recommendation: "Delete unused role",
			},
		},
		CoverageGaps: []CoverageGapObservation{{
			Capability: "activity", Scope: "account:a", FindingID: FindingUnusedRole, AffectedCount: 1,
		}},
		PrincipalsScanned: 25,
	}

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded ScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(decoded.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(decoded.Findings))
	}
	if decoded.PrincipalsScanned != 25 {
		t.Fatalf("expected 25 principals scanned, got %d", decoded.PrincipalsScanned)
	}
	if len(decoded.CoverageGaps) != 1 || decoded.CoverageGaps[0].Capability != "activity" {
		t.Fatalf("coverage gaps = %#v", decoded.CoverageGaps)
	}
}

// WO-15: pin historical guest inclusion on zero-value ScanConfig.
func TestScanConfig_ExcludeGuestsZeroValue(t *testing.T) {
	var cfg ScanConfig
	if cfg.ExcludeGuests {
		t.Fatal("zero-value ScanConfig must continue to include Azure guests")
	}
}

// WO-14@v3: pin resource and principal exclusion semantics, including false entries.
func TestIsExcluded(t *testing.T) {
	tests := []struct {
		name      string
		cfg       ScanConfig
		resource  string
		principal string
		want      bool
	}{
		{name: "nil maps"},
		{name: "resource", cfg: ScanConfig{Exclude: ExcludeConfig{ResourceIDs: map[string]bool{"r": true}}}, resource: "r", want: true},
		{name: "principal", cfg: ScanConfig{Exclude: ExcludeConfig{Principals: map[string]bool{"p": true}}}, principal: "p", want: true},
		{name: "absent", cfg: ScanConfig{Exclude: ExcludeConfig{ResourceIDs: map[string]bool{"other": true}, Principals: map[string]bool{"other": true}}}, resource: "r", principal: "p"},
		{name: "explicit false", cfg: ScanConfig{Exclude: ExcludeConfig{ResourceIDs: map[string]bool{"r": false}, Principals: map[string]bool{"p": false}}}, resource: "r", principal: "p"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsExcluded(tt.cfg, tt.resource, tt.principal); got != tt.want {
				t.Fatalf("IsExcluded() = %v, want %v", got, tt.want)
			}
		})
	}
}

// WO-44@v2: the zero value preserves default service-linked UNUSED_ROLE suppression.
func TestScanConfig_ServiceLinkedRoleDefault(t *testing.T) {
	if (ScanConfig{}).IncludeServiceLinkedRoles {
		t.Fatal("expected service-linked role inclusion to default false")
	}
}

func TestFinding_NoMetadata(t *testing.T) {
	f := Finding{
		ID:             FindingUnattachedPolicy,
		Severity:       SeverityMedium,
		ResourceType:   ResourceIAMPolicy,
		ResourceID:     "arn:aws:iam::123456789012:policy/old-policy",
		Message:        "Policy attached to nothing",
		Recommendation: "Delete unattached policy",
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// metadata should be omitted when nil
	str := string(data)
	if contains(str, "metadata") {
		t.Fatal("expected metadata to be omitted when nil")
	}
}

func TestSeverityRank(t *testing.T) {
	tests := []struct {
		severity Severity
		wantRank int
	}{
		{SeverityCritical, 4},
		{SeverityHigh, 3},
		{SeverityMedium, 2},
		{SeverityLow, 1},
		{Severity("unknown"), 0},
	}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := SeverityRank(tt.severity)
			if got != tt.wantRank {
				t.Fatalf("SeverityRank(%s) = %d, want %d", tt.severity, got, tt.wantRank)
			}
		})
	}
}

func TestSeverityRank_Ordering(t *testing.T) {
	if SeverityRank(SeverityCritical) <= SeverityRank(SeverityHigh) {
		t.Fatal("critical should rank higher than high")
	}
	if SeverityRank(SeverityHigh) <= SeverityRank(SeverityMedium) {
		t.Fatal("high should rank higher than medium")
	}
	if SeverityRank(SeverityMedium) <= SeverityRank(SeverityLow) {
		t.Fatal("medium should rank higher than low")
	}
}

func TestFindingIDs(t *testing.T) {
	ids := []FindingID{
		FindingStaleUser,
		FindingStaleAccessKey,
		FindingNoMFA,
		FindingUnusedRole,
		FindingUnattachedPolicy,
		FindingWildcardPolicy,
		FindingCrossAccountTrust,
		FindingStaleSA,
		FindingStaleSAKey,
		FindingOverprivilegedSA,
	}

	seen := make(map[FindingID]bool)
	for _, id := range ids {
		if seen[id] {
			t.Fatalf("duplicate finding ID: %s", id)
		}
		seen[id] = true
		if id == "" {
			t.Fatal("empty finding ID")
		}
	}

	if len(ids) != 10 {
		t.Fatalf("expected 10 finding IDs, got %d", len(ids))
	}
}

func TestResourceTypes(t *testing.T) {
	types := []ResourceType{
		ResourceIAMUser,
		ResourceIAMRole,
		ResourceIAMPolicy,
		ResourceServiceAccount,
		ResourceServiceAccountKey,
		ResourceIAMBinding,
	}

	seen := make(map[ResourceType]bool)
	for _, rt := range types {
		if seen[rt] {
			t.Fatalf("duplicate resource type: %s", rt)
		}
		seen[rt] = true
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
