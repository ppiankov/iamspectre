package aws

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	iamsvc "github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/ppiankov/iamspectre/internal/iam"
	"golang.org/x/sync/errgroup"
)

// AWSScanner orchestrates all AWS IAM scanners.
type AWSScanner struct {
	client    *Client
	iamClient IAMAPI
	scanCfg   iam.ScanConfig
}

// NewAWSScanner creates an orchestrator for AWS IAM scanning.
func NewAWSScanner(client *Client, scanCfg iam.ScanConfig) *AWSScanner {
	iamClient := iamsvc.NewFromConfig(client.Config())
	return &AWSScanner{
		client:    client,
		iamClient: iamClient,
		scanCfg:   scanCfg,
	}
}

// NewAWSScannerWithIAM creates an orchestrator with a custom IAM client (for testing).
func NewAWSScannerWithIAM(client *Client, iamClient IAMAPI, scanCfg iam.ScanConfig) *AWSScanner {
	return &AWSScanner{
		client:    client,
		iamClient: iamClient,
		scanCfg:   scanCfg,
	}
}

// ScanAll runs all AWS IAM scanners and returns combined results.
func (s *AWSScanner) ScanAll(ctx context.Context) (*iam.ScanResult, error) {
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

	// Run scanners concurrently
	var (
		mu       sync.Mutex
		combined iam.ScanResult
	)

	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(5)

	for _, scanner := range scanners {
		scanner := scanner
		g.Go(func() error {
			slog.Debug("Running scanner", "type", scanner.Type())
			result, err := scanner.Scan(ctx, s.scanCfg)
			if err != nil {
				mu.Lock()
				combined.Errors = append(combined.Errors, fmt.Sprintf("%s: %v", scanner.Type(), err))
				mu.Unlock()
				slog.Warn("Scanner failed", "type", scanner.Type(), "error", err)
				return nil // don't abort other scanners
			}

			mu.Lock()
			combined.Findings = append(combined.Findings, result.Findings...)
			combined.Errors = append(combined.Errors, result.Errors...)
			combined.PrincipalsScanned += result.PrincipalsScanned
			mu.Unlock()
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}

	return &combined, nil
}

// ScannerCount returns the number of scanners used.
func ScannerCount() int {
	return 3 // UserScanner, RoleScanner, PolicyScanner
}
