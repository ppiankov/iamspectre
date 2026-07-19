package gcp

import (
	"context"
	"log/slog"

	"github.com/ppiankov/iamspectre/internal/iam"
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

	// WO-26@v2: provider setup stays local while orchestration policy is shared.
	return iam.RunScanners(ctx, scanners, s.scanCfg)
}

// ScannerCount returns the number of scanners used.
func ScannerCount() int {
	return 2 // ServiceAccountScanner, BindingScanner
}
