package gcp

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/ppiankov/iamspectre/internal/iam"
	"golang.org/x/sync/errgroup"
)

// GCPScanner orchestrates all GCP IAM scanners.
type GCPScanner struct {
	client  *Client
	scanCfg iam.ScanConfig
}

// NewGCPScanner creates an orchestrator for GCP IAM scanning.
func NewGCPScanner(client *Client, scanCfg iam.ScanConfig) *GCPScanner {
	return &GCPScanner{
		client:  client,
		scanCfg: scanCfg,
	}
}

// ScanAll runs all GCP IAM scanners and returns combined results.
func (s *GCPScanner) ScanAll(ctx context.Context) (*iam.ScanResult, error) {
	slog.Info("Scanning GCP project", "project", s.client.Project)

	scanners := []iam.Scanner{
		NewServiceAccountScanner(s.client.IAM, s.client.Project),
		NewBindingScanner(s.client.ResourceManager, s.client.Project),
	}

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
	return 2 // ServiceAccountScanner, BindingScanner
}
