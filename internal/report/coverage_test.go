package report

import (
	"reflect"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-70@v3: pin order-independent deduplication, counts, freshness, and consequence merging.
func TestBuildCoverageManifest(t *testing.T) {
	newer := time.Date(2026, 7, 20, 0, 0, 0, 0, time.UTC)
	older := newer.Add(-24 * time.Hour)
	observations := []iam.CoverageGapObservation{
		{Capability: "azure_activity", Cause: "report unavailable", Scope: "tenant:a", FindingID: iam.FindingStaleSP, AffectedCount: 2, TotalCount: 2, OldestEvidence: &newer, FeatureStage: "beta", MaxConsequence: iam.SeverityHigh},
		{Capability: "azure_activity", Cause: "report unavailable", Scope: "tenant:a", FindingID: iam.FindingUnusedRole, AffectedCount: 1, TotalCount: 1, OldestEvidence: &older, FeatureStage: "beta", MaxConsequence: iam.SeverityMedium},
		{Capability: "azure_activity", Cause: "missing row", Scope: "tenant:a", FindingID: iam.FindingStaleSP, AffectedCount: 3, EvaluableCount: 1, TotalCount: 4, OldestEvidence: &newer, FeatureStage: "beta", MaxConsequence: iam.SeverityHigh},
		{Capability: "", Scope: "tenant:a", FindingID: iam.FindingStaleSP, AffectedCount: 99},
	}

	manifest := BuildCoverageManifest(observations)
	if len(manifest.Gaps) != 1 || manifest.UniqueMissingCapabilities != 1 {
		t.Fatalf("manifest identity = %#v", manifest)
	}
	gap := manifest.Gaps[0]
	wantAffected := []AffectedFindingClass{{FindingID: iam.FindingStaleSP, Count: 5}, {FindingID: iam.FindingUnusedRole, Count: 1}}
	if !reflect.DeepEqual(gap.AffectedFindings, wantAffected) {
		t.Fatalf("affected findings = %#v, want %#v", gap.AffectedFindings, wantAffected)
	}
	if gap.EvaluableCount != 1 || gap.TotalCount != 7 || manifest.EvaluableOpportunities != 1 || manifest.TotalOpportunities != 7 {
		t.Fatalf("coverage counts = %#v", manifest)
	}
	if gap.OldestEvidence == nil || !gap.OldestEvidence.Equal(older) || manifest.OldestEvidence == nil || !manifest.OldestEvidence.Equal(older) {
		t.Fatalf("oldest evidence = gap:%v manifest:%v", gap.OldestEvidence, manifest.OldestEvidence)
	}
	if gap.MaxConsequence != iam.SeverityHigh {
		t.Fatalf("max consequence = %s", gap.MaxConsequence)
	}

	reversed := append([]iam.CoverageGapObservation(nil), observations...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	if got := BuildCoverageManifest(reversed); !reflect.DeepEqual(got, manifest) {
		t.Fatalf("aggregation depends on input order:\nforward=%#v\nreverse=%#v", manifest, got)
	}
}

// WO-70@v3: malformed and empty input remain zero-value safe.
func TestBuildCoverageManifestEmpty(t *testing.T) {
	manifest := BuildCoverageManifest([]iam.CoverageGapObservation{{Capability: "missing-fields"}})
	if len(manifest.Gaps) != 0 || manifest.TotalOpportunities != 0 {
		t.Fatalf("empty manifest = %#v", manifest)
	}
}
