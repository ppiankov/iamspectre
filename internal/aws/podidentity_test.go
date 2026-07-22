package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	ekstypes "github.com/aws/aws-sdk-go-v2/service/eks/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-120@v3: fakePodIdentityEKS records provider calls and effective retry options deterministically.
type fakePodIdentityEKS struct {
	listClustersFn     func(*eks.ListClustersInput) (*eks.ListClustersOutput, error)
	listAssociationsFn func(*eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error)
	describeFn         func(*eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error)
	listClusterTokens  []string
	listAssocKeys      []string
	describeKeys       []string
	noRetryOptions     []bool
}

// WO-120@v3: ListClusters records pagination and applies the production option functions.
func (f *fakePodIdentityEKS) ListClusters(
	_ context.Context,
	input *eks.ListClustersInput,
	optFns ...func(*eks.Options),
) (*eks.ListClustersOutput, error) {
	f.listClusterTokens = append(f.listClusterTokens, awssdk.ToString(input.NextToken))
	f.noRetryOptions = append(f.noRetryOptions, usesNopRetryer(optFns))
	return f.listClustersFn(input)
}

// WO-120@v3: ListPodIdentityAssociations records the complete cluster-token request identity.
func (f *fakePodIdentityEKS) ListPodIdentityAssociations(
	_ context.Context,
	input *eks.ListPodIdentityAssociationsInput,
	optFns ...func(*eks.Options),
) (*eks.ListPodIdentityAssociationsOutput, error) {
	key := awssdk.ToString(input.ClusterName) + ":" + awssdk.ToString(input.NextToken)
	f.listAssocKeys = append(f.listAssocKeys, key)
	f.noRetryOptions = append(f.noRetryOptions, usesNopRetryer(optFns))
	return f.listAssociationsFn(input)
}

// WO-120@v3: DescribePodIdentityAssociation records each source-owned attempt.
func (f *fakePodIdentityEKS) DescribePodIdentityAssociation(
	_ context.Context,
	input *eks.DescribePodIdentityAssociationInput,
	optFns ...func(*eks.Options),
) (*eks.DescribePodIdentityAssociationOutput, error) {
	key := awssdk.ToString(input.ClusterName) + ":" + awssdk.ToString(input.AssociationId)
	f.describeKeys = append(f.describeKeys, key)
	f.noRetryOptions = append(f.noRetryOptions, usesNopRetryer(optFns))
	return f.describeFn(input)
}

// WO-120@v3: usesNopRetryer proves nested SDK retry is disabled on every provider call.
func usesNopRetryer(optFns []func(*eks.Options)) bool {
	options := eks.Options{}
	for _, optFn := range optFns {
		optFn(&options)
	}
	_, ok := options.Retryer.(awssdk.NopRetryer)
	return ok && options.RetryMaxAttempts == 1
}

// WO-120@v3: fakePodIdentityAPIError supplies deterministic Smithy error classification.
type fakePodIdentityAPIError struct {
	code  string
	fault smithy.ErrorFault
}

// WO-120@v3: Error implements the deterministic fake provider error.
func (e fakePodIdentityAPIError) Error() string { return e.code }

// WO-120@v3: ErrorCode exposes the fake Smithy classification code.
func (e fakePodIdentityAPIError) ErrorCode() string { return e.code }

// WO-120@v3: ErrorMessage keeps the fake Smithy message deterministic.
func (e fakePodIdentityAPIError) ErrorMessage() string { return e.code }

// WO-120@v3: ErrorFault exposes the configured fake Smithy fault class.
func (e fakePodIdentityAPIError) ErrorFault() smithy.ErrorFault { return e.fault }

// WO-120@v3: fakePodIdentityHTTPError exercises narrow HTTP status classification.
type fakePodIdentityHTTPError struct{ status int }

// WO-120@v3: Error renders the synthetic HTTP status without response data.
func (e fakePodIdentityHTTPError) Error() string { return fmt.Sprintf("HTTP %d", e.status) }

// WO-120@v3: HTTPStatusCode exposes the synthetic list or describe status.
func (e fakePodIdentityHTTPError) HTTPStatusCode() int { return e.status }

// WO-120@v3: fakePodIdentityAPIHTTPError proves API throttles outrank a generic HTTP envelope.
type fakePodIdentityAPIHTTPError struct {
	fakePodIdentityAPIError
	status int
}

// WO-120@v3: HTTPStatusCode adds an envelope status to the fake API error.
func (e fakePodIdentityAPIHTTPError) HTTPStatusCode() int { return e.status }

// WO-120@v3: fakePodIdentityNetError exercises bounded transient transport retry.
type fakePodIdentityNetError struct{}

// WO-120@v3: Error identifies the deterministic transport failure.
func (fakePodIdentityNetError) Error() string { return "temporary transport failure" }

// WO-120@v3: Timeout marks the fake transport failure retryable.
func (fakePodIdentityNetError) Timeout() bool { return true }

// WO-120@v3: Temporary marks the fake transport failure transient.
func (fakePodIdentityNetError) Temporary() bool { return true }

// WO-120@v3: prove full pagination, deduplication, positive coexistence, ordering, and privacy.
func TestPodIdentitySourceCollect_PaginatesAndEmitsPositiveEdges(t *testing.T) {
	fixedNow := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	fake := &fakePodIdentityEKS{}
	fake.listClustersFn = func(input *eks.ListClustersInput) (*eks.ListClustersOutput, error) {
		if awssdk.ToString(input.NextToken) == "" {
			return &eks.ListClustersOutput{Clusters: []string{"cluster-z"}, NextToken: awssdk.String("clusters-2")}, nil
		}
		return &eks.ListClustersOutput{Clusters: []string{"cluster-a", "cluster-z"}}, nil
	}
	fake.listAssociationsFn = func(input *eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
		cluster, token := awssdk.ToString(input.ClusterName), awssdk.ToString(input.NextToken)
		switch cluster + ":" + token {
		case "cluster-a:":
			return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
				podIdentitySummary(cluster, "a-first"),
			}}, nil
		case "cluster-z:":
			return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
				podIdentitySummary(cluster, "a-chain"),
			}, NextToken: awssdk.String("associations-2")}, nil
		case "cluster-z:associations-2":
			return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
				podIdentitySummary(cluster, "a-chain"),
				podIdentitySummary(cluster, "a-plain"),
			}}, nil
		default:
			return nil, fmt.Errorf("unexpected association page %s:%s", cluster, token)
		}
	}
	fake.describeFn = func(input *eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
		cluster, associationID := awssdk.ToString(input.ClusterName), awssdk.ToString(input.AssociationId)
		roleARN := "arn:aws:iam::123456789012:role/" + associationID
		association := podIdentityAssociation("aws", "us-west-2", "123456789012", cluster, associationID, roleARN)
		if associationID == "a-chain" {
			association.TargetRoleArn = awssdk.String("arn:aws:iam::999999999999:role/target-role")
		}
		return &eks.DescribePodIdentityAssociationOutput{Association: &association}, nil
	}

	source, err := NewPodIdentitySource(fake, "us-west-2")
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	source.now = func() time.Time { return fixedNow }
	result, err := source.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if !result.Completeness.Complete || result.Completeness.ListedClusters != 2 ||
		result.Completeness.ListedAssociations != 3 || result.Completeness.DescribedAssociations != 3 {
		t.Fatalf("completeness = %#v", result.Completeness)
	}
	if len(result.Edges) != 4 {
		t.Fatalf("edges = %#v, want three associations plus one chain target", result.Edges)
	}
	wantOrder := []string{
		"POD_IDENTITY_ASSOCIATION_OBSERVED:arn:aws:eks:us-west-2:123456789012:podidentityassociation/cluster-a/a-first",
		"POD_IDENTITY_ASSOCIATION_OBSERVED:arn:aws:eks:us-west-2:123456789012:podidentityassociation/cluster-z/a-chain",
		"POD_IDENTITY_CHAIN_TARGET_OBSERVED:arn:aws:eks:us-west-2:123456789012:podidentityassociation/cluster-z/a-chain",
		"POD_IDENTITY_ASSOCIATION_OBSERVED:arn:aws:eks:us-west-2:123456789012:podidentityassociation/cluster-z/a-plain",
	}
	gotOrder := make([]string, 0, len(result.Edges))
	for _, edge := range result.Edges {
		details, ok := iam.PodIdentityAssociationEvidence(edge)
		if !ok {
			t.Fatalf("edge %T has no Pod Identity evidence", edge)
		}
		gotOrder = append(gotOrder, string(edge.Type())+":"+details.AssociationARN)
		if !edge.ObservedAt().Equal(fixedNow) {
			t.Fatalf("observed_at = %s, want %s", edge.ObservedAt(), fixedNow)
		}
		if details.ClusterARN != "arn:aws:eks:us-west-2:123456789012:cluster/"+details.ClusterName {
			t.Fatalf("cluster ARN = %q for %#v", details.ClusterARN, details)
		}
	}
	if !reflect.DeepEqual(gotOrder, wantOrder) {
		t.Fatalf("edge order = %#v, want %#v", gotOrder, wantOrder)
	}
	if got := countStrings(fake.describeKeys); !reflect.DeepEqual(got, map[string]int{
		"cluster-a:a-first": 1, "cluster-z:a-chain": 1, "cluster-z:a-plain": 1,
	}) {
		t.Fatalf("describe calls = %#v", got)
	}
	for i, noRetry := range fake.noRetryOptions {
		if !noRetry {
			t.Fatalf("call %d did not disable nested SDK retries", i)
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("private result JSON = %s, err=%v", encoded, err)
	}
	details, _ := iam.PodIdentityAssociationEvidence(result.Edges[0])
	for name, value := range map[string]any{
		"details": details, "completeness": result.Completeness,
	} {
		encoded, err = json.Marshal(value)
		if err != nil || string(encoded) != "{}" {
			t.Fatalf("private %s JSON = %s, err=%v", name, encoded, err)
		}
	}
	baseline := iam.ScanResult{Findings: []iam.Finding{}, PrincipalsScanned: 1}
	baselineJSON, err := json.Marshal(baseline)
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	baseline.IAMPositiveEdges = result.Edges
	baseline.SourceCompleteness = []iam.SourceCompleteness{result.Completeness}
	withPrivateEvidence, err := json.Marshal(baseline)
	if err != nil || !reflect.DeepEqual(withPrivateEvidence, baselineJSON) {
		t.Fatalf("default ScanResult JSON changed: before=%s after=%s err=%v", baselineJSON, withPrivateEvidence, err)
	}
}

// WO-120@v3: retryable Describe failures use bounded deterministic backoff and preserve coverage truth.
func TestPodIdentitySourceCollect_DescribeRetryAndCoverage(t *testing.T) {
	tests := []struct {
		name          string
		errors        []error
		wantComplete  bool
		wantCause     string
		wantCalls     int
		wantDelays    []time.Duration
		wantEdgeCount int
		wantDescribed int
	}{
		{
			name: "throttle then success",
			errors: []error{
				fakePodIdentityAPIError{code: "ThrottlingException", fault: smithy.FaultClient},
				fakePodIdentityAPIError{code: "TooManyRequestsException", fault: smithy.FaultClient},
				nil,
			},
			wantComplete: true, wantCalls: 3, wantDelays: []time.Duration{podIdentityRetryBaseDelay, 2 * podIdentityRetryBaseDelay}, wantEdgeCount: 1, wantDescribed: 1,
		},
		{
			name: "terminal throttle",
			errors: []error{
				fakePodIdentityAPIError{code: "ThrottlingException", fault: smithy.FaultClient},
				fakePodIdentityAPIError{code: "ThrottlingException", fault: smithy.FaultClient},
				fakePodIdentityAPIError{code: "ThrottlingException", fault: smithy.FaultClient},
			},
			wantCause: "describe_throttled", wantCalls: 3, wantDelays: []time.Duration{podIdentityRetryBaseDelay, 2 * podIdentityRetryBaseDelay},
		},
		{
			name: "API throttle retries despite HTTP 400 envelope",
			errors: []error{
				fakePodIdentityAPIHTTPError{
					fakePodIdentityAPIError: fakePodIdentityAPIError{code: "ThrottlingException", fault: smithy.FaultClient},
					status:                  400,
				},
				nil,
			},
			wantComplete: true, wantCalls: 2, wantDelays: []time.Duration{podIdentityRetryBaseDelay}, wantEdgeCount: 1, wantDescribed: 1,
		},
		{
			name: "EKS ServerException retries through HTTP 500 envelope",
			errors: []error{
				fakePodIdentityAPIHTTPError{
					fakePodIdentityAPIError: fakePodIdentityAPIError{code: "ServerException", fault: smithy.FaultServer}, status: 500,
				},
				fakePodIdentityAPIHTTPError{
					fakePodIdentityAPIError: fakePodIdentityAPIError{code: "ServerException", fault: smithy.FaultServer}, status: 500,
				},
				fakePodIdentityAPIHTTPError{
					fakePodIdentityAPIError: fakePodIdentityAPIError{code: "ServerException", fault: smithy.FaultServer}, status: 500,
				},
			},
			wantCause: "describe_failed", wantCalls: 3, wantDelays: []time.Duration{podIdentityRetryBaseDelay, 2 * podIdentityRetryBaseDelay},
		},
		{
			name: "access denied is not retried",
			errors: []error{
				fakePodIdentityAPIError{code: "AccessDeniedException", fault: smithy.FaultClient},
			},
			wantCause: "describe_access_denied", wantCalls: 1,
		},
		{
			name: "wrapped HTTP 500 then success",
			errors: []error{
				fmt.Errorf("wrapped: %w", fakePodIdentityHTTPError{status: 500}), nil,
			},
			wantComplete: true, wantCalls: 2, wantDelays: []time.Duration{podIdentityRetryBaseDelay}, wantEdgeCount: 1, wantDescribed: 1,
		},
		{
			name: "HTTP 400 is terminal",
			errors: []error{
				fakePodIdentityHTTPError{status: 400},
			},
			wantCause: "describe_failed", wantCalls: 1,
		},
		{
			name: "temporary transport then success",
			errors: []error{
				fakePodIdentityNetError{}, nil,
			},
			wantComplete: true, wantCalls: 2, wantDelays: []time.Duration{podIdentityRetryBaseDelay}, wantEdgeCount: 1, wantDescribed: 1,
		},
		{
			name: "non-timeout Smithy connection error then success",
			errors: []error{
				fmt.Errorf("wrapped: %w", &smithyhttp.RequestSendError{Err: errors.New("connection reset")}), nil,
			},
			wantComplete: true, wantCalls: 2, wantDelays: []time.Duration{podIdentityRetryBaseDelay}, wantEdgeCount: 1, wantDescribed: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := singleAssociationFake("cluster-a", "a-one")
			call := 0
			fake.describeFn = func(input *eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
				err := tt.errors[call]
				call++
				if err != nil {
					return nil, err
				}
				association := podIdentityAssociation("aws", "us-west-2", "123456789012", "cluster-a", "a-one", "arn:aws:iam::123456789012:role/source")
				return &eks.DescribePodIdentityAssociationOutput{Association: &association}, nil
			}
			source, err := NewPodIdentitySource(fake, "us-west-2")
			if err != nil {
				t.Fatalf("new source: %v", err)
			}
			var delays []time.Duration
			source.jitter = func(max time.Duration) time.Duration { return max }
			source.sleep = func(_ context.Context, delay time.Duration) error {
				delays = append(delays, delay)
				return nil
			}
			result, err := source.Collect(context.Background())
			if err != nil {
				t.Fatalf("collect: %v", err)
			}
			if result.Completeness.Complete != tt.wantComplete || result.Completeness.Cause != tt.wantCause ||
				result.Completeness.ListedAssociations != 1 || result.Completeness.DescribedAssociations != tt.wantDescribed ||
				len(fake.describeKeys) != tt.wantCalls || !reflect.DeepEqual(delays, tt.wantDelays) || len(result.Edges) != tt.wantEdgeCount {
				t.Fatalf("result=%#v calls=%d delays=%v edges=%d", result.Completeness, len(fake.describeKeys), delays, len(result.Edges))
			}
		})
	}
}

// WO-120@v3: an expired list token restarts once and never leaks partial evidence across attempts.
func TestPodIdentitySourceCollect_RestartsExpiredListToken(t *testing.T) {
	fake := &fakePodIdentityEKS{}
	clusterCall := 0
	fake.listClustersFn = func(*eks.ListClustersInput) (*eks.ListClustersOutput, error) {
		clusterCall++
		if clusterCall == 1 {
			return &eks.ListClustersOutput{Clusters: []string{"cluster-z", "cluster-a"}}, nil
		}
		return &eks.ListClustersOutput{Clusters: []string{"cluster-b"}}, nil
	}
	fake.listAssociationsFn = func(input *eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
		cluster := awssdk.ToString(input.ClusterName)
		switch cluster {
		case "cluster-a":
			return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
				podIdentitySummary(cluster, "a-stale"),
			}}, nil
		case "cluster-z":
			return nil, fakePodIdentityHTTPError{status: 410}
		case "cluster-b":
			return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
				podIdentitySummary(cluster, "a-fresh"),
			}}, nil
		default:
			return nil, fmt.Errorf("unexpected cluster %q", cluster)
		}
	}
	fake.describeFn = func(input *eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
		cluster, associationID := awssdk.ToString(input.ClusterName), awssdk.ToString(input.AssociationId)
		association := podIdentityAssociation(
			"aws", "us-west-2", "123456789012", cluster, associationID,
			"arn:aws:iam::123456789012:role/"+associationID,
		)
		return &eks.DescribePodIdentityAssociationOutput{Association: &association}, nil
	}
	source, err := NewPodIdentitySource(fake, "us-west-2")
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	result, err := source.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(result.Edges) != 1 {
		t.Fatalf("edges=%#v, want one clean second-attempt edge", result.Edges)
	}
	details, ok := iam.PodIdentityAssociationEvidence(result.Edges[0])
	if !result.Completeness.Complete || !ok || details.AssociationID != "a-fresh" ||
		result.Completeness.ListedClusters != 1 || result.Completeness.ListedAssociations != 1 ||
		result.Completeness.DescribedAssociations != 1 || clusterCall != 2 ||
		!reflect.DeepEqual(fake.describeKeys, []string{"cluster-a:a-stale", "cluster-b:a-fresh"}) {
		t.Fatalf("result=%#v edges=%#v calls=%d tokens=%#v", result.Completeness, result.Edges, clusterCall, fake.listClusterTokens)
	}
}

// WO-120@v3: repeated token expiry yields incomplete artifact coverage and no partial edge.
func TestPodIdentitySourceCollect_RepeatedExpiredListTokenIsIncomplete(t *testing.T) {
	fake := singleAssociationFake("cluster-a", "a-one")
	clusterCall := 0
	fake.listClustersFn = func(input *eks.ListClustersInput) (*eks.ListClustersOutput, error) {
		clusterCall++
		if awssdk.ToString(input.NextToken) == "expired" {
			return nil, fakePodIdentityHTTPError{status: 410}
		}
		return &eks.ListClustersOutput{Clusters: []string{"partial"}, NextToken: awssdk.String("expired")}, nil
	}
	source, err := NewPodIdentitySource(fake, "us-west-2")
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	result, err := source.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if result.Completeness.Complete || result.Completeness.Cause != "list_clusters_token_expired" || len(result.Edges) != 0 || clusterCall != 4 {
		t.Fatalf("result=%#v edges=%#v calls=%d", result.Completeness, result.Edges, clusterCall)
	}
	if result.Completeness.ListedClusters != 0 || result.Completeness.ListedAssociations != 0 ||
		result.Completeness.DescribedAssociations != 0 {
		t.Fatalf("expired attempt leaked counts: %#v", result.Completeness)
	}
}

// WO-120@v3: ordinary list HTTP 400 failures never enter the synthetic 410 restart path.
func TestPodIdentitySourceCollect_ListHTTP400IsTerminal(t *testing.T) {
	fake := singleAssociationFake("cluster-a", "a-one")
	listCalls := 0
	fake.listClustersFn = func(*eks.ListClustersInput) (*eks.ListClustersOutput, error) {
		listCalls++
		return nil, fakePodIdentityHTTPError{status: 400}
	}
	source, err := NewPodIdentitySource(fake, "us-west-2")
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	result, err := source.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if result.Completeness.Complete || result.Completeness.Cause != "list_clusters_failed" || listCalls != 1 {
		t.Fatalf("result=%#v list_calls=%d", result.Completeness, listCalls)
	}
}

// WO-120@v3: terminal later-page failures preserve the unique valid identities already enumerated.
func TestPodIdentitySourceCollect_PreservesPartialListCounts(t *testing.T) {
	t.Run("clusters", func(t *testing.T) {
		fake := singleAssociationFake("cluster-a", "a-one")
		fake.listClustersFn = func(input *eks.ListClustersInput) (*eks.ListClustersOutput, error) {
			if awssdk.ToString(input.NextToken) == "" {
				return &eks.ListClustersOutput{Clusters: []string{"cluster-a"}, NextToken: awssdk.String("page-2")}, nil
			}
			return nil, fakePodIdentityAPIHTTPError{
				fakePodIdentityAPIError: fakePodIdentityAPIError{code: "ServerException", fault: smithy.FaultServer}, status: 500,
			}
		}
		source, err := NewPodIdentitySource(fake, "us-west-2")
		if err != nil {
			t.Fatalf("new source: %v", err)
		}
		result, err := source.Collect(context.Background())
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if result.Completeness.Complete || result.Completeness.Cause != "list_clusters_failed" ||
			result.Completeness.ListedClusters != 1 || result.Completeness.ListedAssociations != 0 ||
			result.Completeness.DescribedAssociations != 0 || len(result.Edges) != 0 {
			t.Fatalf("result=%#v edges=%#v", result.Completeness, result.Edges)
		}
	})

	t.Run("associations", func(t *testing.T) {
		fake := singleAssociationFake("cluster-a", "a-one")
		fake.listAssociationsFn = func(input *eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
			if awssdk.ToString(input.NextToken) == "" {
				return &eks.ListPodIdentityAssociationsOutput{
					Associations: []ekstypes.PodIdentityAssociationSummary{podIdentitySummary("cluster-a", "a-one")},
					NextToken:    awssdk.String("page-2"),
				}, nil
			}
			return nil, fakePodIdentityAPIHTTPError{
				fakePodIdentityAPIError: fakePodIdentityAPIError{code: "ServerException", fault: smithy.FaultServer}, status: 500,
			}
		}
		source, err := NewPodIdentitySource(fake, "us-west-2")
		if err != nil {
			t.Fatalf("new source: %v", err)
		}
		result, err := source.Collect(context.Background())
		if err != nil {
			t.Fatalf("collect: %v", err)
		}
		if result.Completeness.Complete || result.Completeness.Cause != "list_associations_failed" ||
			result.Completeness.ListedClusters != 1 || result.Completeness.ListedAssociations != 1 ||
			result.Completeness.DescribedAssociations != 1 || len(result.Edges) != 1 {
			t.Fatalf("result=%#v edges=%#v", result.Completeness, result.Edges)
		}
	})
}

// WO-120@v3: repeated pagination tokens terminate while preserving already enumerated evidence counts.
func TestPodIdentitySourceCollect_RejectsPaginationTokenCycles(t *testing.T) {
	tests := []struct {
		name          string
		configure     func(*fakePodIdentityEKS)
		wantCause     string
		wantDescribes int
	}{
		{
			name: "clusters",
			configure: func(fake *fakePodIdentityEKS) {
				fake.listClustersFn = func(*eks.ListClustersInput) (*eks.ListClustersOutput, error) {
					return &eks.ListClustersOutput{Clusters: []string{"cluster-a"}, NextToken: awssdk.String("repeat")}, nil
				}
			},
			wantCause: "list_clusters_token_cycle",
		},
		{
			name: "associations",
			configure: func(fake *fakePodIdentityEKS) {
				fake.listAssociationsFn = func(*eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
					return &eks.ListPodIdentityAssociationsOutput{
						Associations: []ekstypes.PodIdentityAssociationSummary{podIdentitySummary("cluster-a", "a-one")},
						NextToken:    awssdk.String("repeat"),
					}, nil
				}
			},
			wantCause:     "list_associations_token_cycle",
			wantDescribes: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := singleAssociationFake("cluster-a", "a-one")
			tt.configure(fake)
			source, err := NewPodIdentitySource(fake, "us-west-2")
			if err != nil {
				t.Fatalf("new source: %v", err)
			}
			result, err := source.Collect(context.Background())
			if err != nil {
				t.Fatalf("collect: %v", err)
			}
			if result.Completeness.Complete || result.Completeness.Cause != tt.wantCause ||
				len(fake.describeKeys) != tt.wantDescribes ||
				result.Completeness.ListedAssociations != tt.wantDescribes ||
				result.Completeness.DescribedAssociations != tt.wantDescribes {
				t.Fatalf("result=%#v describes=%#v", result.Completeness, fake.describeKeys)
			}
		})
	}
}

// WO-120@v3: empty association identities lower coverage and never reach Describe.
func TestPodIdentitySourceCollect_RejectsEmptyAssociationID(t *testing.T) {
	fake := singleAssociationFake("cluster-a", "a-one")
	fake.listAssociationsFn = func(*eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
		return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
			podIdentitySummary("cluster-a", ""),
		}}, nil
	}
	source, err := NewPodIdentitySource(fake, "us-west-2")
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	result, err := source.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if result.Completeness.Complete || result.Completeness.Cause != "association_summary_invalid" ||
		result.Completeness.ListedAssociations != 0 || result.Completeness.DescribedAssociations != 0 ||
		len(fake.describeKeys) != 0 {
		t.Fatalf("result=%#v describes=%#v", result.Completeness, fake.describeKeys)
	}
}

// WO-120@v3: only non-nil, identity-consistent descriptions count as complete evidence.
func TestPodIdentitySourceCollect_RejectsInvalidDescriptions(t *testing.T) {
	tests := []struct {
		name   string
		output func() *eks.DescribePodIdentityAssociationOutput
	}{
		{name: "nil output"},
		{name: "nil association", output: func() *eks.DescribePodIdentityAssociationOutput {
			return &eks.DescribePodIdentityAssociationOutput{}
		}},
		{name: "wrong region", output: func() *eks.DescribePodIdentityAssociationOutput {
			association := podIdentityAssociation("aws", "eu-west-1", "123456789012", "cluster-a", "a-one", "arn:aws:iam::123456789012:role/source")
			return &eks.DescribePodIdentityAssociationOutput{Association: &association}
		}},
		{name: "malformed association ARN", output: func() *eks.DescribePodIdentityAssociationOutput {
			association := podIdentityAssociation("aws", "us-west-2", "123456789012", "cluster-a", "a-one", "arn:aws:iam::123456789012:role/source")
			association.AssociationArn = awssdk.String("not-an-arn")
			return &eks.DescribePodIdentityAssociationOutput{Association: &association}
		}},
		{name: "wrong cluster", output: func() *eks.DescribePodIdentityAssociationOutput {
			association := podIdentityAssociation("aws", "us-west-2", "123456789012", "cluster-other", "a-one", "arn:aws:iam::123456789012:role/source")
			return &eks.DescribePodIdentityAssociationOutput{Association: &association}
		}},
		{name: "wrong association ID", output: func() *eks.DescribePodIdentityAssociationOutput {
			association := podIdentityAssociation("aws", "us-west-2", "123456789012", "cluster-a", "a-other", "arn:aws:iam::123456789012:role/source")
			return &eks.DescribePodIdentityAssociationOutput{Association: &association}
		}},
		{name: "source role account mismatch", output: func() *eks.DescribePodIdentityAssociationOutput {
			association := podIdentityAssociation("aws", "us-west-2", "123456789012", "cluster-a", "a-one", "arn:aws:iam::210987654321:role/source")
			return &eks.DescribePodIdentityAssociationOutput{Association: &association}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := singleAssociationFake("cluster-a", "a-one")
			fake.describeFn = func(*eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
				if tt.output == nil {
					return nil, nil
				}
				return tt.output(), nil
			}
			source, err := NewPodIdentitySource(fake, "us-west-2")
			if err != nil {
				t.Fatalf("new source: %v", err)
			}
			result, err := source.Collect(context.Background())
			if err != nil {
				t.Fatalf("collect: %v", err)
			}
			if result.Completeness.Complete || result.Completeness.Cause != "describe_invalid" ||
				result.Completeness.ListedAssociations != 1 || result.Completeness.DescribedAssociations != 0 || len(result.Edges) != 0 {
				t.Fatalf("result=%#v edges=%#v", result.Completeness, result.Edges)
			}
		})
	}
}

// WO-120@v3: association-derived cluster ARNs preserve the configured AWS partition.
func TestPodIdentitySourceCollect_PreservesARNPartition(t *testing.T) {
	tests := []struct {
		partition string
		region    string
	}{
		{partition: "aws-us-gov", region: "us-gov-west-1"},
		{partition: "aws-cn", region: "cn-north-1"},
	}
	for _, tt := range tests {
		t.Run(tt.partition, func(t *testing.T) {
			fake := singleAssociationFake("cluster-a", "a-one")
			fake.describeFn = func(*eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
				association := podIdentityAssociation(
					tt.partition, tt.region, "123456789012", "cluster-a", "a-one",
					"arn:"+tt.partition+":iam::123456789012:role/source",
				)
				return &eks.DescribePodIdentityAssociationOutput{Association: &association}, nil
			}
			source, err := NewPodIdentitySource(fake, tt.region)
			if err != nil {
				t.Fatalf("new source: %v", err)
			}
			result, err := source.Collect(context.Background())
			if err != nil || len(result.Edges) != 1 {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			details, _ := iam.PodIdentityAssociationEvidence(result.Edges[0])
			want := "arn:" + tt.partition + ":eks:" + tt.region + ":123456789012:cluster/cluster-a"
			if details.ClusterARN != want {
				t.Fatalf("cluster ARN=%q, want %q", details.ClusterARN, want)
			}
		})
	}
}

// WO-120@v3: positive constructors make empty association and chain-target evidence unrepresentable.
func TestPodIdentityPositiveEdgeConstructors(t *testing.T) {
	fixedNow := time.Date(2026, time.July, 22, 15, 0, 0, 0, time.UTC)
	valid := iam.PodIdentityAssociationDetails{
		AssociationARN: "arn:aws:eks:us-west-2:123456789012:podidentityassociation/cluster-a/a-one",
		AssociationID:  "a-one",
		ClusterARN:     "arn:aws:eks:us-west-2:123456789012:cluster/cluster-a",
		ClusterName:    "cluster-a",
		Namespace:      "payments",
		ServiceAccount: "reader",
		SourceRoleARN:  "arn:aws:iam::123456789012:role/source",
		TargetRoleARN:  "arn:aws:iam::999999999999:role/target",
	}
	association := iam.NewPodIdentityAssociationObservedEdge(valid, fixedNow)
	chain := iam.NewPodIdentityChainTargetObservedEdge(valid, fixedNow)
	if association == nil || chain == nil || association.RoleName() != "source" || chain.RoleName() != "target" {
		t.Fatalf("association=%#v chain=%#v", association, chain)
	}
	invalid := []iam.IAMPositiveEdge{
		iam.NewPodIdentityAssociationObservedEdge(iam.PodIdentityAssociationDetails{}, fixedNow),
		iam.NewPodIdentityAssociationObservedEdge(valid, time.Time{}),
		iam.NewPodIdentityChainTargetObservedEdge(iam.PodIdentityAssociationDetails{
			AssociationARN: valid.AssociationARN, AssociationID: valid.AssociationID, ClusterARN: valid.ClusterARN,
			ClusterName: valid.ClusterName, Namespace: valid.Namespace, ServiceAccount: valid.ServiceAccount,
			SourceRoleARN: valid.SourceRoleARN,
		}, fixedNow),
		iam.NewPodIdentityAssociationObservedEdge(iam.PodIdentityAssociationDetails{
			AssociationARN: valid.AssociationARN, AssociationID: valid.AssociationID, ClusterARN: valid.ClusterARN,
			ClusterName: valid.ClusterName, Namespace: valid.Namespace, ServiceAccount: valid.ServiceAccount,
			SourceRoleARN: "arn:aws:iam::210987654321:role/source",
		}, fixedNow),
		iam.NewPodIdentityChainTargetObservedEdge(iam.PodIdentityAssociationDetails{
			AssociationARN: valid.AssociationARN, AssociationID: valid.AssociationID, ClusterARN: valid.ClusterARN,
			ClusterName: valid.ClusterName, Namespace: valid.Namespace, ServiceAccount: valid.ServiceAccount,
			SourceRoleARN: valid.SourceRoleARN, TargetRoleARN: "not-an-arn",
		}, fixedNow),
	}
	for i, edge := range invalid {
		if edge != nil {
			t.Fatalf("invalid edge[%d] = %#v", i, edge)
		}
	}
	for _, edge := range []iam.IAMPositiveEdge{association, chain} {
		encoded, err := json.Marshal(edge)
		if err != nil || string(encoded) != "{}" {
			t.Fatalf("marshal %T = %s, err=%v", edge, encoded, err)
		}
	}
	copyOne, _ := iam.PodIdentityAssociationEvidence(association)
	copyOne.AssociationID = "mutated"
	copyTwo, _ := iam.PodIdentityAssociationEvidence(association)
	if copyTwo.AssociationID != valid.AssociationID {
		t.Fatalf("evidence accessor leaked mutation: %#v", copyTwo)
	}
}

// WO-120@v3: source construction and collection normalize only explicit, valid regional inputs.
func TestNewPodIdentitySourceValidationAndUTCObservation(t *testing.T) {
	if source, err := NewPodIdentitySource(nil, "us-west-2"); err == nil || source != nil {
		t.Fatalf("nil client source=%#v err=%v", source, err)
	}
	fake := singleAssociationFake("cluster-a", "a-one")
	for _, region := range []string{"", "  \t"} {
		if source, err := NewPodIdentitySource(fake, region); err == nil || source != nil {
			t.Fatalf("region %q source=%#v err=%v", region, source, err)
		}
	}
	source, err := NewPodIdentitySource(fake, " us-west-2 ")
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	local := time.Date(2026, time.July, 22, 23, 0, 0, 0, time.FixedZone("UTC+8", 8*60*60))
	source.now = func() time.Time { return local }
	result, err := source.Collect(context.Background())
	if err != nil || len(result.Edges) != 1 || !result.Edges[0].ObservedAt().Equal(local.UTC()) ||
		result.Edges[0].ObservedAt().Location() != time.UTC {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

// WO-120@v3: retry delay growth is capped before jitter is applied.
func TestPodIdentityBackoffCap(t *testing.T) {
	if got := podIdentityBackoff(100); got != podIdentityRetryMaxDelay {
		t.Fatalf("backoff=%s, want cap %s", got, podIdentityRetryMaxDelay)
	}
}

// WO-120@v3: cancellation is the only provider failure that aborts the artifact rather than lowering coverage.
func TestPodIdentitySourceCollect_ContextCancellation(t *testing.T) {
	fake := singleAssociationFake("cluster-a", "a-one")
	fake.listClustersFn = func(*eks.ListClustersInput) (*eks.ListClustersOutput, error) {
		return nil, context.Canceled
	}
	source, err := NewPodIdentitySource(fake, "us-west-2")
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	result, err := source.Collect(context.Background())
	if !errors.Is(err, context.Canceled) || result != nil {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

// WO-120@v3: cancellation during source-owned backoff stops before a second provider attempt.
func TestPodIdentitySourceCollect_ContextCancellationDuringBackoff(t *testing.T) {
	fake := singleAssociationFake("cluster-a", "a-one")
	fake.describeFn = func(*eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
		return nil, fakePodIdentityAPIError{code: "ThrottlingException", fault: smithy.FaultClient}
	}
	source, err := NewPodIdentitySource(fake, "us-west-2")
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	sleepCalls := 0
	source.sleep = func(context.Context, time.Duration) error {
		sleepCalls++
		return context.Canceled
	}
	result, err := source.Collect(context.Background())
	if !errors.Is(err, context.Canceled) || result != nil || len(fake.describeKeys) != 1 || sleepCalls != 1 {
		t.Fatalf("result=%#v err=%v describes=%v sleep_calls=%d", result, err, fake.describeKeys, sleepCalls)
	}
}

// WO-120@v3: cancellation racing with a successful final response still suppresses the artifact.
func TestPodIdentitySourceCollect_ContextCancellationAfterProviderSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	fake := singleAssociationFake("cluster-a", "a-one")
	fake.describeFn = func(*eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
		association := podIdentityAssociation(
			"aws", "us-west-2", "123456789012", "cluster-a", "a-one", "arn:aws:iam::123456789012:role/source",
		)
		cancel()
		return &eks.DescribePodIdentityAssociationOutput{Association: &association}, nil
	}
	source, err := NewPodIdentitySource(fake, "us-west-2")
	if err != nil {
		t.Fatalf("new source: %v", err)
	}
	result, err := source.Collect(ctx)
	if !errors.Is(err, context.Canceled) || result != nil || len(fake.describeKeys) != 1 {
		t.Fatalf("result=%#v err=%v describes=%#v", result, err, fake.describeKeys)
	}
}

// WO-120@v3: singleAssociationFake provides the minimum complete regional artifact fixture.
func singleAssociationFake(cluster, associationID string) *fakePodIdentityEKS {
	fake := &fakePodIdentityEKS{}
	fake.listClustersFn = func(*eks.ListClustersInput) (*eks.ListClustersOutput, error) {
		return &eks.ListClustersOutput{Clusters: []string{cluster}}, nil
	}
	fake.listAssociationsFn = func(*eks.ListPodIdentityAssociationsInput) (*eks.ListPodIdentityAssociationsOutput, error) {
		return &eks.ListPodIdentityAssociationsOutput{Associations: []ekstypes.PodIdentityAssociationSummary{
			podIdentitySummary(cluster, associationID),
		}}, nil
	}
	fake.describeFn = func(*eks.DescribePodIdentityAssociationInput) (*eks.DescribePodIdentityAssociationOutput, error) {
		association := podIdentityAssociation("aws", "us-west-2", "123456789012", cluster, associationID, "arn:aws:iam::123456789012:role/source")
		return &eks.DescribePodIdentityAssociationOutput{Association: &association}, nil
	}
	return fake
}

// WO-120@v3: podIdentitySummary builds one list-level identity without role evidence.
func podIdentitySummary(cluster, associationID string) ekstypes.PodIdentityAssociationSummary {
	return ekstypes.PodIdentityAssociationSummary{
		AssociationArn: awssdk.String("arn:aws:eks:us-west-2:123456789012:podidentityassociation/" + cluster + "/" + associationID),
		AssociationId:  awssdk.String(associationID),
		ClusterName:    awssdk.String(cluster),
		Namespace:      awssdk.String("payments"),
		ServiceAccount: awssdk.String("reader"),
	}
}

// WO-120@v3: podIdentityAssociation builds one fully described provider response.
func podIdentityAssociation(partition, region, accountID, cluster, associationID, roleARN string) ekstypes.PodIdentityAssociation {
	return ekstypes.PodIdentityAssociation{
		AssociationArn: awssdk.String("arn:" + partition + ":eks:" + region + ":" + accountID + ":podidentityassociation/" + cluster + "/" + associationID),
		AssociationId:  awssdk.String(associationID),
		ClusterName:    awssdk.String(cluster),
		Namespace:      awssdk.String("payments"),
		ServiceAccount: awssdk.String("reader"),
		RoleArn:        awssdk.String(roleARN),
	}
}

// WO-120@v3: countStrings proves logical deduplication independently of provider order.
func countStrings(values []string) map[string]int {
	counts := make(map[string]int, len(values))
	for _, value := range values {
		counts[value]++
	}
	return counts
}
