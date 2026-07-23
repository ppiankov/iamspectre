package aws

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/aws/aws-sdk-go-v2/service/eks"
	iamsvc "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/ppiankov/iamspectre/internal/iam"
)

const (
	podIdentityCapability          = "aws_eks_pod_identity_associations" // WO-126@v2: identify regional Pod Identity coverage independently.
	podIdentityEvidenceUnavailable = "evidence_unavailable"              // WO-126@v2: preserve a stable fallback for malformed incomplete artifacts.
	awsRegionScopePrefix           = "aws-region:"                       // WO-126@v2: bind every Pod Identity gap to its regional boundary.
)

// WO-126@v2: PodIdentityCollector keeps regional EKS collection mockable at the orchestration boundary.
type PodIdentityCollector interface {
	Collect(context.Context) (*PodIdentitySourceResult, error)
}

// AWSScanner orchestrates all AWS IAM scanners.
// WO-126@v2: include regional Pod Identity collection in the command path.
type AWSScanner struct {
	client                 *Client
	iamClient              IAMAPI
	scanCfg                iam.ScanConfig
	podIdentitySource      PodIdentityCollector // WO-126@v2: make the reviewed EKS source reachable from the AWS command.
	podIdentitySourceError error                // WO-126@v2: retain deterministic regional-construction failure for ScanAll.
}

// NewAWSScanner creates an orchestrator for AWS IAM scanning.
// WO-126@v2: production construction includes the regional Pod Identity source.
func NewAWSScanner(client *Client, scanCfg iam.ScanConfig) *AWSScanner {
	iamClient := iamsvc.NewFromConfig(client.Config())
	return newAWSScanner(client, iamClient, scanCfg)
}

// NewAWSScannerWithIAM creates an orchestrator with a custom IAM client and production-configured EKS source.
// WO-126@v2: preserve IAM injection while constructing the regional Pod Identity source.
func NewAWSScannerWithIAM(client *Client, iamClient IAMAPI, scanCfg iam.ScanConfig) *AWSScanner {
	return newAWSScanner(client, iamClient, scanCfg)
}

// WO-126@v2: NewAWSScannerWithSources injects both external source boundaries for deterministic orchestration tests.
func NewAWSScannerWithSources(
	client *Client,
	iamClient IAMAPI,
	podIdentitySource PodIdentityCollector,
	scanCfg iam.ScanConfig,
) *AWSScanner {
	return &AWSScanner{
		client:            client,
		iamClient:         iamClient,
		scanCfg:           scanCfg,
		podIdentitySource: podIdentitySource,
	}
}

// WO-126@v2: construct IAM and regional EKS sources from the same resolved SDK configuration.
func newAWSScanner(client *Client, iamClient IAMAPI, scanCfg iam.ScanConfig) *AWSScanner {
	cfg := client.Config()
	source, sourceErr := NewPodIdentitySource(eks.NewFromConfig(cfg), cfg.Region)
	return &AWSScanner{
		client:                 client,
		iamClient:              iamClient,
		scanCfg:                scanCfg,
		podIdentitySource:      source,
		podIdentitySourceError: sourceErr,
	}
}

// ScanAll runs all AWS IAM scanners and returns combined results.
// WO-126@v2: extend the normal AWS scan with bounded regional Pod Identity evidence.
func (s *AWSScanner) ScanAll(ctx context.Context) (*iam.ScanResult, error) {
	if s.podIdentitySourceError != nil {
		return nil, fmt.Errorf("initialize pod identity source: %w", s.podIdentitySourceError)
	}

	// Get account ID for cross-account trust detection
	accountID, err := s.client.GetAccountID(ctx)
	if err != nil {
		return nil, fmt.Errorf("get account ID: %w", err)
	}
	slog.Info("Scanning AWS account", "account_id", accountID)

	// Fetch credential report (shared by UserScanner)
	slog.Debug("Fetching credential report")
	entries, err := FetchCredentialReport(ctx, s.iamClient)
	if err != nil {
		return nil, fmt.Errorf("fetch credential report: %w", err)
	}

	// Build scanners
	scanners := []iam.Scanner{
		NewUserScanner(entries),
		NewRoleScanner(s.iamClient, accountID),
		NewPolicyScanner(s.iamClient),
	}

	// WO-26@v2: provider setup stays local while orchestration policy is shared.
	result, err := iam.RunScanners(ctx, scanners, s.scanCfg)
	if err != nil {
		return nil, err
	}
	// WO-126@v2: regional collection extends the private evidence planes without changing IAM findings.
	if err := s.collectPodIdentity(ctx, result); err != nil {
		return nil, fmt.Errorf("collect pod identity source: %w", err)
	}
	return result, nil
}

// WO-126@v2: append positive regional evidence and translate incomplete collection into the coverage plane.
func (s *AWSScanner) collectPodIdentity(ctx context.Context, result *iam.ScanResult) error {
	if s.podIdentitySourceError != nil {
		return s.podIdentitySourceError
	}
	if s.podIdentitySource == nil {
		return errors.New("pod identity source is required")
	}

	sourceResult, err := s.podIdentitySource.Collect(ctx)
	if err != nil {
		return err
	}
	if sourceResult == nil {
		return errors.New("pod identity source returned no result")
	}
	result.IAMPositiveEdges = append(result.IAMPositiveEdges, sourceResult.Edges...)
	result.SourceCompleteness = append(result.SourceCompleteness, sourceResult.Completeness)
	if sourceResult.Completeness.Complete {
		return nil
	}

	cause := sourceResult.Completeness.Cause
	if cause == "" {
		cause = podIdentityEvidenceUnavailable
	}
	result.CoverageGaps = append(result.CoverageGaps, iam.CoverageGapObservation{
		Capability:     podIdentityCapability,
		Cause:          cause,
		Scope:          awsRegionScopePrefix + sourceResult.Completeness.Region,
		EvaluableCount: sourceResult.Completeness.DescribedAssociations,
		TotalCount:     sourceResult.Completeness.ListedAssociations,
	})
	return nil
}

// ScannerCount returns the number of AWS data sources used.
// WO-126@v2: count the regional Pod Identity source exposed by ScanAll.
func ScannerCount() int {
	return 4 // UserScanner, RoleScanner, PolicyScanner, PodIdentitySource
}
