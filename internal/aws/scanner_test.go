package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-126@v2: pin the production AWS source count after Pod Identity wiring.
func TestScannerCount(t *testing.T) {
	if ScannerCount() != 4 {
		t.Fatalf("expected 4 scanners, got %d", ScannerCount())
	}
}

// WO-126@v2: the production orchestrator must construct the regional EKS source.
func TestNewAWSScannerConstructsRegionalPodIdentitySource(t *testing.T) {
	client := NewClientWithSTS(awssdk.Config{Region: "us-west-2"}, nil)

	scanner := NewAWSScanner(client, iam.ScanConfig{})

	source, ok := scanner.podIdentitySource.(*PodIdentitySource)
	if !ok {
		t.Fatalf("pod identity source = %T, want *PodIdentitySource", scanner.podIdentitySource)
	}
	if source.region != "us-west-2" {
		t.Fatalf("pod identity source region = %q, want us-west-2", source.region)
	}
	if source.client == nil {
		t.Fatal("pod identity source EKS client is nil")
	}
}

// WO-126@v2: positive Pod Identity evidence remains private but reaches the scan pipeline.
func TestCollectPodIdentityAppendsPipelineEvidence(t *testing.T) {
	edge := iam.NewPodIdentityAssociationObservedEdge(iam.PodIdentityAssociationDetails{
		AssociationARN: "arn:aws:eks:us-west-2:123456789012:podidentityassociation/cluster-a/assoc-a",
		AssociationID:  "assoc-a",
		ClusterARN:     "arn:aws:eks:us-west-2:123456789012:cluster/cluster-a",
		ClusterName:    "cluster-a",
		Namespace:      "default",
		ServiceAccount: "reader",
		SourceRoleARN:  "arn:aws:iam::123456789012:role/reader",
	}, time.Unix(1_700_000_000, 0).UTC())
	sourceResult := &PodIdentitySourceResult{
		Edges: []iam.IAMPositiveEdge{edge},
		Completeness: iam.SourceCompleteness{
			Source: "eks_pod_identity", Region: "us-west-2", Complete: true,
			ListedClusters: 1, ListedAssociations: 1, DescribedAssociations: 1,
		},
	}
	scanner := &AWSScanner{podIdentitySource: &stubPodIdentityCollector{result: sourceResult}}
	existingEdge := iam.NewRoleActivityObservedEdge(
		"arn:aws:iam::123456789012:role/existing", "existing",
		time.Unix(1_699_999_000, 0).UTC(), "us-west-2", time.Unix(1_700_000_000, 0).UTC(),
	)
	result := &iam.ScanResult{
		IAMPositiveEdges:   []iam.IAMPositiveEdge{existingEdge},
		SourceCompleteness: []iam.SourceCompleteness{{Source: "existing", Complete: true}},
	}

	if err := scanner.collectPodIdentity(context.Background(), result); err != nil {
		t.Fatalf("collect pod identity: %v", err)
	}
	if len(result.IAMPositiveEdges) != 2 || result.IAMPositiveEdges[0].Type() != iam.RoleActivityObserved ||
		result.IAMPositiveEdges[1].Type() != iam.PodIdentityAssociationObserved {
		t.Fatalf("positive edges = %#v", result.IAMPositiveEdges)
	}
	if len(result.SourceCompleteness) != 2 || result.SourceCompleteness[0].Source != "existing" ||
		!result.SourceCompleteness[1].Complete {
		t.Fatalf("source completeness = %#v", result.SourceCompleteness)
	}
	if len(result.CoverageGaps) != 0 {
		t.Fatalf("coverage gaps = %#v, want none", result.CoverageGaps)
	}
}

// WO-126@v2: incomplete EKS collection becomes bounded coverage evidence, not a scan error.
func TestCollectPodIdentitySurfacesIncompleteCoverage(t *testing.T) {
	sourceResult := &PodIdentitySourceResult{Completeness: iam.SourceCompleteness{
		Source: "eks_pod_identity", Region: "us-east-1", Complete: false, Cause: "access_denied",
		ListedClusters: 2, ListedAssociations: 3, DescribedAssociations: 1,
	}}
	scanner := &AWSScanner{podIdentitySource: &stubPodIdentityCollector{result: sourceResult}}
	result := &iam.ScanResult{}

	if err := scanner.collectPodIdentity(context.Background(), result); err != nil {
		t.Fatalf("collect pod identity: %v", err)
	}
	if len(result.SourceCompleteness) != 1 || result.SourceCompleteness[0].Complete {
		t.Fatalf("source completeness = %#v", result.SourceCompleteness)
	}
	if len(result.CoverageGaps) != 1 {
		t.Fatalf("coverage gaps = %#v", result.CoverageGaps)
	}
	gap := result.CoverageGaps[0]
	if gap.Capability != podIdentityCapability || gap.Cause != "access_denied" ||
		gap.Scope != "aws-region:us-east-1" || gap.FindingID != "" || gap.MaxConsequence != "" {
		t.Fatalf("coverage gap identity = %#v", gap)
	}
	if gap.AffectedCount != 0 || gap.EvaluableCount != 1 || gap.TotalCount != 3 {
		t.Fatalf("coverage gap counts = %#v", gap)
	}
}

// WO-126@v2: nil source output is an invariant violation, never a silent complete scan.
func TestCollectPodIdentityRejectsNilResult(t *testing.T) {
	scanner := &AWSScanner{podIdentitySource: &stubPodIdentityCollector{}}

	err := scanner.collectPodIdentity(context.Background(), &iam.ScanResult{})
	if err == nil || err.Error() != "pod identity source returned no result" {
		t.Fatalf("collect pod identity error = %v", err)
	}
}

// WO-126@v2: a missing resolved region fails before any regional collection attempt.
func TestCollectPodIdentityReturnsSourceConstructionErrorAsCoverageGap(t *testing.T) {
	scanner := NewAWSScanner(NewClientWithSTS(awssdk.Config{}, nil), iam.ScanConfig{})
	result := &iam.ScanResult{}

	err := scanner.collectPodIdentity(context.Background(), result)
	if err != nil {
		t.Fatalf("collect pod identity error = %v", err)
	}
	if len(result.CoverageGaps) != 1 {
		t.Fatalf("coverage gaps = %#v", result.CoverageGaps)
	}
	gap := result.CoverageGaps[0]
	if gap.Capability != podIdentityCapability || gap.Cause != podIdentitySourceUnconstructable ||
		gap.Scope != awsRegionScopePrefix+podIdentityRegionUnknown {
		t.Fatalf("coverage gap identity = %#v", gap)
	}
	if len(result.SourceCompleteness) != 1 {
		t.Fatalf("source completeness = %#v", result.SourceCompleteness)
	}
	completeness := result.SourceCompleteness[0]
	if completeness.Cause != podIdentitySourceUnconstructable || completeness.Region != podIdentityRegionUnknown ||
		completeness.Source != "eks_pod_identity" || completeness.Complete {
		t.Fatalf("source completeness = %#v", completeness)
	}
}

// WO-126@v2: cancellation and structural source failures must remain explicit errors.
func TestCollectPodIdentityReturnsSourceError(t *testing.T) {
	want := errors.New("context canceled")
	scanner := &AWSScanner{podIdentitySource: &stubPodIdentityCollector{err: want}}

	err := scanner.collectPodIdentity(context.Background(), &iam.ScanResult{})
	if !errors.Is(err, want) {
		t.Fatalf("collect pod identity error = %v, want %v", err, want)
	}
}

// WO-132@v3: source construction failure degrades the AWS scan to coverage-only state.
func TestAWSScannerScanAllDegradesOnPodIdentitySourceConstructionFailure(t *testing.T) {
	iamClient := &mockIAM{
		generateState:   iamtypes.ReportStateTypeComplete,
		reportContent:   []byte(testCredentialReportCSV),
		reportGenerated: awssdk.Time(time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC)),
		roles: []iamtypes.Role{{
			RoleName: awssdk.String("stale-role"),
			Arn:      awssdk.String("arn:aws:iam::123456789012:role/stale-role"),
			RoleLastUsed: &iamtypes.RoleLastUsed{
				LastUsedDate: awssdk.Time(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
				Region:       awssdk.String("us-east-1"),
			},
		}},
	}
	client := NewClientWithSTS(awssdk.Config{}, &mockSTS{accountID: "123456789012"})
	scanner := NewAWSScannerWithSources(client, iamClient, &stubPodIdentityCollector{}, iam.ScanConfig{StaleDays: 90})
	scanner.podIdentitySourceError = errors.New("pod identity region is required")

	result, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Fatalf("findings = %#v", result.Findings)
	}
	if len(result.CoverageGaps) != 1 {
		t.Fatalf("coverage gaps = %#v", result.CoverageGaps)
	}
	if gap := result.CoverageGaps[0]; gap.Capability != podIdentityCapability || gap.Cause != podIdentitySourceUnconstructable ||
		gap.Scope != awsRegionScopePrefix+podIdentityRegionUnknown {
		t.Fatalf("coverage gap identity = %#v", gap)
	}
}

// WO-130@v2: the exported orchestration seam proves role and Pod Identity evidence coexist end to end.
func TestAWSScannerScanAllPreservesRoleAndPodIdentityEdges(t *testing.T) {
	observedAt := time.Unix(1_700_000_000, 0).UTC()
	roleARN := "arn:aws:iam::123456789012:role/workload"
	iamClient := &mockIAM{
		generateState:   iamtypes.ReportStateTypeComplete,
		reportContent:   []byte(testCredentialReportCSV),
		reportGenerated: awssdk.Time(observedAt),
		roles: []iamtypes.Role{{
			Arn:      awssdk.String(roleARN),
			RoleName: awssdk.String("workload"),
			RoleLastUsed: &iamtypes.RoleLastUsed{
				LastUsedDate: awssdk.Time(observedAt.Add(-time.Hour)),
				Region:       awssdk.String("us-west-2"),
			},
		}},
	}
	podEdge := iam.NewPodIdentityAssociationObservedEdge(iam.PodIdentityAssociationDetails{
		AssociationARN: "arn:aws:eks:us-west-2:123456789012:podidentityassociation/cluster-a/assoc-a",
		AssociationID:  "assoc-a",
		ClusterARN:     "arn:aws:eks:us-west-2:123456789012:cluster/cluster-a",
		ClusterName:    "cluster-a",
		Namespace:      "default",
		ServiceAccount: "reader",
		SourceRoleARN:  roleARN,
	}, observedAt)
	podSource := &stubPodIdentityCollector{result: &PodIdentitySourceResult{
		Edges: []iam.IAMPositiveEdge{podEdge},
		Completeness: iam.SourceCompleteness{
			Source: "eks_pod_identity", Region: "us-west-2", Complete: true,
			ListedClusters: 1, ListedAssociations: 1, DescribedAssociations: 1,
		},
	}}
	client := NewClientWithSTS(awssdk.Config{Region: "us-west-2"}, &mockSTS{accountID: "123456789012"})
	scanner := NewAWSScannerWithSources(client, iamClient, podSource, iam.ScanConfig{StaleDays: 90})

	result, err := scanner.ScanAll(context.Background())
	if err != nil {
		t.Fatalf("ScanAll: %v", err)
	}
	edgeTypes := map[iam.IAMPositiveEdgeType]bool{}
	for _, edge := range result.IAMPositiveEdges {
		edgeTypes[edge.Type()] = true
	}
	if !edgeTypes[iam.RoleActivityObserved] || !edgeTypes[iam.PodIdentityAssociationObserved] {
		t.Fatalf("positive edge types = %#v", edgeTypes)
	}
	if len(result.SourceCompleteness) != 1 || !result.SourceCompleteness[0].Complete {
		t.Fatalf("source completeness = %#v", result.SourceCompleteness)
	}
}

// WO-126@v2: stubPodIdentityCollector isolates orchestration from live EKS calls.
type stubPodIdentityCollector struct {
	result *PodIdentitySourceResult // WO-126@v2: inject one bounded source artifact.
	err    error                    // WO-126@v2: inject cancellation or structural failures.
}

// WO-126@v2: Collect returns only test-owned Pod Identity state.
func (s *stubPodIdentityCollector) Collect(context.Context) (*PodIdentitySourceResult, error) {
	return s.result, s.err
}
