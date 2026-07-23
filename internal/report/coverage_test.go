package report

import (
	"reflect"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-70@v4: pin order-independent causal deduplication, counts, freshness, and consequence merging.
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
	if len(manifest.Gaps) != 2 || manifest.UniqueMissingCapabilities != 1 {
		t.Fatalf("manifest identity = %#v", manifest)
	}
	missingRow, unavailable := manifest.Gaps[0], manifest.Gaps[1]
	if missingRow.Cause != "missing row" || unavailable.Cause != "report unavailable" {
		t.Fatalf("causal gaps = %#v", manifest.Gaps)
	}
	if want := []AffectedFindingClass{{FindingID: iam.FindingStaleSP, Count: 3}}; !reflect.DeepEqual(missingRow.AffectedFindings, want) {
		t.Fatalf("missing-row findings = %#v, want %#v", missingRow.AffectedFindings, want)
	}
	wantUnavailable := []AffectedFindingClass{{FindingID: iam.FindingStaleSP, Count: 2}, {FindingID: iam.FindingUnusedRole, Count: 1}}
	if !reflect.DeepEqual(unavailable.AffectedFindings, wantUnavailable) {
		t.Fatalf("unavailable findings = %#v, want %#v", unavailable.AffectedFindings, wantUnavailable)
	}
	if missingRow.EvaluableCount != 1 || missingRow.TotalCount != 4 || unavailable.TotalCount != 3 || manifest.EvaluableOpportunities != 1 || manifest.TotalOpportunities != 7 {
		t.Fatalf("coverage counts = %#v", manifest)
	}
	if unavailable.OldestEvidence == nil || !unavailable.OldestEvidence.Equal(older) || manifest.OldestEvidence == nil || !manifest.OldestEvidence.Equal(older) {
		t.Fatalf("oldest evidence = gap:%v manifest:%v", unavailable.OldestEvidence, manifest.OldestEvidence)
	}
	if unavailable.MaxConsequence != iam.SeverityHigh {
		t.Fatalf("max consequence = %s", unavailable.MaxConsequence)
	}

	reversed := append([]iam.CoverageGapObservation(nil), observations...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	if got := BuildCoverageManifest(reversed); !reflect.DeepEqual(got, manifest) {
		t.Fatalf("aggregation depends on input order:\nforward=%#v\nreverse=%#v", manifest, got)
	}
}

// WO-70@v4: malformed and empty input remain zero-value safe.
func TestBuildCoverageManifestEmpty(t *testing.T) {
	manifest := BuildCoverageManifest([]iam.CoverageGapObservation{
		{Capability: "missing-fields"},
		{Capability: "azure_activity", Scope: "tenant:a", FindingID: iam.FindingStaleSP},
	})
	if len(manifest.Gaps) != 0 || manifest.TotalOpportunities != 0 {
		t.Fatalf("empty manifest = %#v", manifest)
	}
}

// WO-128@v2: source-level gaps must remain representable without inventing a finding class.
func TestBuildCoverageManifestSourceGap(t *testing.T) {
	manifest := BuildCoverageManifest([]iam.CoverageGapObservation{{
		Capability: "aws_eks_pod_identity_associations",
		Cause:      "access_denied",
		Scope:      "aws-region:us-east-1",
	}})

	if len(manifest.Gaps) != 1 || manifest.UniqueMissingCapabilities != 1 {
		t.Fatalf("source manifest = %#v", manifest)
	}
	gap := manifest.Gaps[0]
	if gap.Capability != "aws_eks_pod_identity_associations" || gap.Cause != "access_denied" ||
		gap.Scope != "aws-region:us-east-1" {
		t.Fatalf("source gap identity = %#v", gap)
	}
	if len(gap.AffectedFindings) != 0 {
		t.Fatalf("source gap fabricated affected findings: %#v", gap.AffectedFindings)
	}
	if gap.MaxConsequence != "" {
		t.Fatalf("source gap fabricated max consequence: %q", gap.MaxConsequence)
	}
}
