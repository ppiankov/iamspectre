package aws

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-120@v3: bound collection restart and source-owned Describe retry independently.
const (
	podIdentityDescribeAttempts   = 3
	podIdentityCollectionAttempts = 2
	podIdentityRetryBaseDelay     = 100 * time.Millisecond
	podIdentityRetryMaxDelay      = 2 * time.Second
)

// WO-120@v3: podIdentityEKSAPI bounds the collector to the three read-only EKS operations it needs.
type podIdentityEKSAPI interface {
	ListClusters(context.Context, *eks.ListClustersInput, ...func(*eks.Options)) (*eks.ListClustersOutput, error)
	ListPodIdentityAssociations(context.Context, *eks.ListPodIdentityAssociationsInput, ...func(*eks.Options)) (*eks.ListPodIdentityAssociationsOutput, error)
	DescribePodIdentityAssociation(context.Context, *eks.DescribePodIdentityAssociationInput, ...func(*eks.Options)) (*eks.DescribePodIdentityAssociationOutput, error)
}

// WO-120@v3: PodIdentitySourceResult is an internal pipeline artifact, not a report payload.
type PodIdentitySourceResult struct {
	Edges        []iam.IAMPositiveEdge  `json:"-"` // WO-120@v3: expose only validated positive observations to downstream joins.
	Completeness iam.SourceCompleteness `json:"-"` // WO-120@v3: preserve regional collection truth with the artifact.
}

// WO-120@v3: PodIdentitySource binds every artifact to exactly one configured AWS region.
type PodIdentitySource struct {
	client podIdentityEKSAPI                          // WO-120@v3: limit collection to the injected read-only EKS surface.
	region string                                     // WO-120@v3: bind one source instance to one region.
	now    func() time.Time                           // WO-120@v3: make the artifact observation instant deterministic in tests.
	sleep  func(context.Context, time.Duration) error // WO-120@v3: make cancellation-aware backoff deterministic in tests.
	jitter func(time.Duration) time.Duration          // WO-120@v3: inject full jitter without weakening retry bounds.
}

// WO-120@v3: NewPodIdentitySource rejects sources that cannot establish a concrete regional scope.
func NewPodIdentitySource(client podIdentityEKSAPI, region string) (*PodIdentitySource, error) {
	region = strings.TrimSpace(region)
	if client == nil {
		return nil, errors.New("pod identity EKS client is required")
	}
	if region == "" {
		return nil, errors.New("pod identity region is required")
	}
	return &PodIdentitySource{
		client: client,
		region: region,
		now:    time.Now,
		sleep:  sleepWithContext,
		jitter: fullJitter,
	}, nil
}

// WO-120@v3: Collect restarts a token-expired region from empty buffers once and never returns an artifact on cancellation.
func (s *PodIdentitySource) Collect(ctx context.Context) (*PodIdentitySourceResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	observedAt := s.now().UTC()
	for attempt := 0; attempt < podIdentityCollectionAttempts; attempt++ {
		result, restart, err := s.collectAttempt(ctx, observedAt)
		if err != nil {
			return nil, err
		}
		if restart && attempt+1 < podIdentityCollectionAttempts {
			continue
		}
		if restart {
			cause := result.Completeness.Cause
			result = newPodIdentitySourceResult(s.region)
			markIncomplete(&result.Completeness, cause)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return result, nil
	}
	return nil, errors.New("pod identity collection attempts exhausted")
}

// WO-120@v3: podIdentityAssociationKey deduplicates provider summaries without trusting display fields.
type podIdentityAssociationKey struct {
	cluster       string // WO-120@v3: bind the summary to the cluster scope used for Describe.
	associationID string // WO-120@v3: retain the only list field needed to obtain full evidence.
}

// WO-120@v3: collectAttempt uses local buffers so a 410 restart cannot leak evidence or counts.
func (s *PodIdentitySource) collectAttempt(
	ctx context.Context,
	observedAt time.Time,
) (*PodIdentitySourceResult, bool, error) {
	result := newPodIdentitySourceResult(s.region)
	clusters, restart, err := s.listClusters(ctx, &result.Completeness)
	if err != nil || restart || !result.Completeness.Complete {
		return result, restart, err
	}

	seenAssociations := make(map[podIdentityAssociationKey]struct{})
	for _, cluster := range clusters {
		clusterKeys, clusterRestart, listErr := s.listAssociations(ctx, cluster, &result.Completeness)
		if listErr != nil || clusterRestart {
			return result, clusterRestart, listErr
		}
		sort.Slice(clusterKeys, func(i, j int) bool {
			return clusterKeys[i].associationID < clusterKeys[j].associationID
		})
		for _, key := range clusterKeys {
			if _, exists := seenAssociations[key]; exists {
				continue
			}
			seenAssociations[key] = struct{}{}
			result.Completeness.ListedAssociations++
			output, describeErr := s.describe(ctx, key)
			if describeErr != nil {
				if isContextError(ctx, describeErr) {
					return nil, false, contextError(ctx, describeErr)
				}
				markIncomplete(&result.Completeness, describeCause(describeErr))
				continue
			}
			details, valid := s.detailsFromDescription(key, output)
			if !valid {
				markIncomplete(&result.Completeness, "describe_invalid")
				continue
			}
			associationEdge := iam.NewPodIdentityAssociationObservedEdge(details, observedAt)
			if associationEdge == nil {
				markIncomplete(&result.Completeness, "describe_invalid")
				continue
			}
			var chainEdge iam.IAMPositiveEdge
			if details.TargetRoleARN != "" {
				chainEdge = iam.NewPodIdentityChainTargetObservedEdge(details, observedAt)
				if chainEdge == nil {
					markIncomplete(&result.Completeness, "describe_invalid")
					continue
				}
			}
			result.Completeness.DescribedAssociations++
			result.Edges = append(result.Edges, associationEdge)
			if chainEdge != nil {
				result.Edges = append(result.Edges, chainEdge)
			}
		}
	}
	sort.Slice(result.Edges, func(i, j int) bool {
		left, _ := iam.PodIdentityAssociationEvidence(result.Edges[i])
		right, _ := iam.PodIdentityAssociationEvidence(result.Edges[j])
		if left.AssociationARN == right.AssociationARN {
			return result.Edges[i].Type() < result.Edges[j].Type()
		}
		return left.AssociationARN < right.AssociationARN
	})
	return result, false, nil
}

// WO-120@v3: newPodIdentitySourceResult starts every region attempt with clean transactional state.
func newPodIdentitySourceResult(region string) *PodIdentitySourceResult {
	return &PodIdentitySourceResult{Completeness: iam.SourceCompleteness{
		Source: "eks_pod_identity", Region: region, Complete: true,
	}}
}

// WO-120@v3: listClusters bounds pagination and counts unique valid cluster identities.
func (s *PodIdentitySource) listClusters(
	ctx context.Context,
	completeness *iam.SourceCompleteness,
) ([]string, bool, error) {
	clusters := make(map[string]struct{})
	seenTokens := make(map[string]struct{})
	var token *string
	for {
		output, err := s.client.ListClusters(ctx, &eks.ListClustersInput{NextToken: token}, disableEKSRetries)
		if err != nil {
			if isContextError(ctx, err) {
				return nil, false, contextError(ctx, err)
			}
			if isExpiredListToken(err) {
				markIncomplete(completeness, "list_clusters_token_expired")
				return nil, true, nil
			}
			markIncomplete(completeness, "list_clusters_failed")
			return finishClusterList(clusters, completeness), false, nil
		}
		if output == nil {
			markIncomplete(completeness, "list_clusters_invalid")
			return finishClusterList(clusters, completeness), false, nil
		}
		for _, cluster := range output.Clusters {
			cluster = strings.TrimSpace(cluster)
			if cluster == "" {
				markIncomplete(completeness, "list_clusters_invalid")
				continue
			}
			clusters[cluster] = struct{}{}
		}
		next := awssdk.ToString(output.NextToken)
		if next == "" {
			break
		}
		if _, exists := seenTokens[next]; exists {
			markIncomplete(completeness, "list_clusters_token_cycle")
			return finishClusterList(clusters, completeness), false, nil
		}
		seenTokens[next] = struct{}{}
		token = output.NextToken
	}
	return finishClusterList(clusters, completeness), false, nil
}

// WO-120@v3: finishClusterList records unique valid identities even when a later page fails.
func finishClusterList(clusters map[string]struct{}, completeness *iam.SourceCompleteness) []string {
	ordered := make([]string, 0, len(clusters))
	for cluster := range clusters {
		ordered = append(ordered, cluster)
	}
	sort.Strings(ordered)
	completeness.ListedClusters = len(ordered)
	return ordered
}

// WO-120@v3: listAssociations rejects malformed identities and bounds pagination per cluster.
func (s *PodIdentitySource) listAssociations(
	ctx context.Context,
	cluster string,
	completeness *iam.SourceCompleteness,
) ([]podIdentityAssociationKey, bool, error) {
	keys := make([]podIdentityAssociationKey, 0)
	seenTokens := make(map[string]struct{})
	var token *string
	for {
		output, err := s.client.ListPodIdentityAssociations(ctx, &eks.ListPodIdentityAssociationsInput{
			ClusterName: awssdk.String(cluster), NextToken: token,
		}, disableEKSRetries)
		if err != nil {
			if isContextError(ctx, err) {
				return nil, false, contextError(ctx, err)
			}
			if isExpiredListToken(err) {
				markIncomplete(completeness, "list_associations_token_expired")
				return nil, true, nil
			}
			markIncomplete(completeness, "list_associations_failed")
			return keys, false, nil
		}
		if output == nil {
			markIncomplete(completeness, "list_associations_invalid")
			return keys, false, nil
		}
		for _, summary := range output.Associations {
			associationID := strings.TrimSpace(awssdk.ToString(summary.AssociationId))
			summaryCluster := strings.TrimSpace(awssdk.ToString(summary.ClusterName))
			if associationID == "" || (summaryCluster != "" && summaryCluster != cluster) {
				markIncomplete(completeness, "association_summary_invalid")
				continue
			}
			keys = append(keys, podIdentityAssociationKey{cluster: cluster, associationID: associationID})
		}
		next := awssdk.ToString(output.NextToken)
		if next == "" {
			break
		}
		if _, exists := seenTokens[next]; exists {
			markIncomplete(completeness, "list_associations_token_cycle")
			return keys, false, nil
		}
		seenTokens[next] = struct{}{}
		token = output.NextToken
	}
	return keys, false, nil
}

// WO-120@v3: describe owns the sole retry loop while each SDK call has nested retries disabled.
func (s *PodIdentitySource) describe(
	ctx context.Context,
	key podIdentityAssociationKey,
) (*eks.DescribePodIdentityAssociationOutput, error) {
	var lastErr error
	for attempt := 0; attempt < podIdentityDescribeAttempts; attempt++ {
		output, err := s.client.DescribePodIdentityAssociation(ctx, &eks.DescribePodIdentityAssociationInput{
			ClusterName: awssdk.String(key.cluster), AssociationId: awssdk.String(key.associationID),
		}, disableEKSRetries)
		if err == nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return output, nil
		}
		lastErr = err
		if isContextError(ctx, err) || !isRetryablePodIdentityError(err) || attempt+1 == podIdentityDescribeAttempts {
			return nil, err
		}
		if err := s.sleep(ctx, s.jitter(podIdentityBackoff(attempt))); err != nil {
			return nil, err
		}
	}
	return nil, lastErr
}

// WO-120@v3: detailsFromDescription accepts only responses matching the requested regional identity.
func (s *PodIdentitySource) detailsFromDescription(
	key podIdentityAssociationKey,
	output *eks.DescribePodIdentityAssociationOutput,
) (iam.PodIdentityAssociationDetails, bool) {
	if output == nil || output.Association == nil {
		return iam.PodIdentityAssociationDetails{}, false
	}
	association := output.Association
	associationARN := strings.TrimSpace(awssdk.ToString(association.AssociationArn))
	associationID := strings.TrimSpace(awssdk.ToString(association.AssociationId))
	clusterName := strings.TrimSpace(awssdk.ToString(association.ClusterName))
	clusterARN, valid := clusterARNFromAssociationARN(associationARN, s.region, key.cluster, key.associationID)
	if !valid || associationID != key.associationID || clusterName != key.cluster {
		return iam.PodIdentityAssociationDetails{}, false
	}
	return iam.PodIdentityAssociationDetails{
		AssociationARN: associationARN,
		AssociationID:  associationID,
		ClusterARN:     clusterARN,
		ClusterName:    clusterName,
		Namespace:      strings.TrimSpace(awssdk.ToString(association.Namespace)),
		ServiceAccount: strings.TrimSpace(awssdk.ToString(association.ServiceAccount)),
		SourceRoleARN:  strings.TrimSpace(awssdk.ToString(association.RoleArn)),
		TargetRoleARN:  strings.TrimSpace(awssdk.ToString(association.TargetRoleArn)),
	}, true
}

// WO-120@v3: clusterARNFromAssociationARN preserves the observed partition, region, and account.
func clusterARNFromAssociationARN(associationARN, region, cluster, associationID string) (string, bool) {
	parts := strings.SplitN(associationARN, ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[2] != "eks" ||
		parts[3] != region || parts[4] == "" ||
		parts[5] != "podidentityassociation/"+cluster+"/"+associationID {
		return "", false
	}
	return strings.Join(parts[:5], ":") + ":cluster/" + cluster, true
}

// WO-120@v3: disableEKSRetries structurally prevents multiplicative SDK and source retries.
func disableEKSRetries(options *eks.Options) {
	options.Retryer = awssdk.NopRetryer{}
	options.RetryMaxAttempts = 1
}

// WO-120@v3: podIdentityBackoff caps exponential growth before jitter is applied.
func podIdentityBackoff(attempt int) time.Duration {
	delay := podIdentityRetryBaseDelay
	for i := 0; i < attempt && delay < podIdentityRetryMaxDelay; i++ {
		delay *= 2
		if delay > podIdentityRetryMaxDelay {
			return podIdentityRetryMaxDelay
		}
	}
	return delay
}

// WO-120@v3: fullJitter returns a delay bounded by the current retry cap.
func fullJitter(max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(max) + 1))
}

// WO-120@v3: sleepWithContext makes cancellation abort backoff without a completed artifact.
func sleepWithContext(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// WO-120@v3: isRetryablePodIdentityError admits only throttles, transport, and server failures.
func isRetryablePodIdentityError(err error) bool {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		code := strings.ToLower(apiError.ErrorCode())
		if strings.Contains(code, "throttl") || strings.Contains(code, "toomanyrequests") ||
			strings.Contains(code, "internalserver") || strings.Contains(code, "serverexception") ||
			strings.Contains(code, "serviceunavailable") {
			return true
		}
	}
	var statusError interface{ HTTPStatusCode() int }
	if errors.As(err, &statusError) {
		status := statusError.HTTPStatusCode()
		return status == 429 || status >= 500
	}
	var sendError *smithyhttp.RequestSendError
	if errors.As(err, &sendError) && sendError.ConnectionError() {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError) && networkError.Timeout()
}

// WO-120@v3: isExpiredListToken keeps synthetic restart narrower than ordinary 4xx handling.
func isExpiredListToken(err error) bool {
	var statusError interface{ HTTPStatusCode() int }
	return errors.As(err, &statusError) && statusError.HTTPStatusCode() == 410
}

// WO-120@v3: describeCause maps provider details to a stable bounded coverage cause.
func describeCause(err error) string {
	var apiError smithy.APIError
	if errors.As(err, &apiError) {
		code := strings.ToLower(apiError.ErrorCode())
		switch {
		case strings.Contains(code, "throttl"), strings.Contains(code, "toomanyrequests"):
			return "describe_throttled"
		case strings.Contains(code, "accessdenied"), strings.Contains(code, "unauthorized"):
			return "describe_access_denied"
		}
	}
	return "describe_failed"
}

// WO-120@v3: markIncomplete preserves the first cause so later failures cannot reorder diagnostics.
func markIncomplete(completeness *iam.SourceCompleteness, cause string) {
	completeness.Complete = false
	if completeness.Cause == "" {
		completeness.Cause = cause
	}
}

// WO-120@v3: isContextError separates cancellation from ordinary incomplete provider coverage.
func isContextError(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// WO-120@v3: contextError returns the canonical cancellation signal to callers.
func contextError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	return fmt.Errorf("pod identity context failure: %w", err)
}
