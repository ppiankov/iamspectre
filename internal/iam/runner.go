package iam

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"golang.org/x/sync/errgroup"
)

const scannerConcurrencyLimit = 5

// WO-26@v2: run independent scanners without making one resource failure fatal.
func RunScanners(ctx context.Context, scanners []Scanner, cfg ScanConfig) (*ScanResult, error) {
	var (
		mu                                  sync.Mutex
		combined                            ScanResult
		observedPrincipalIDs                = make(map[string]struct{})
		principalIdentityAccountingComplete = true
	)
	g, scanCtx := errgroup.WithContext(ctx)
	g.SetLimit(scannerConcurrencyLimit)
	for _, scanner := range scanners {
		scanner := scanner
		g.Go(func() error {
			slog.Debug("Running scanner", "type", scanner.Type())
			result, err := scanner.Scan(scanCtx, cfg)
			// WO-87: merge independently acquired evidence before recording a sibling source failure.
			if result != nil {
				mergeScanResult(&mu, &combined, observedPrincipalIDs, &principalIdentityAccountingComplete, result)
			}
			if err != nil {
				recordScannerError(&mu, &combined, &principalIdentityAccountingComplete, scanner, err)
				return nil
			}
			if result == nil {
				recordScannerError(&mu, &combined, &principalIdentityAccountingComplete, scanner, fmt.Errorf("scanner returned nil result"))
				return nil
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	// WO-89@v4: derive cardinality only after all concurrent identity sets are complete.
	if principalIdentityAccountingComplete {
		combined.PrincipalsScanned = len(observedPrincipalIDs)
	}
	return &combined, nil
}

// WO-87: merge all result planes even when the same scanner also reports an error.
func mergeScanResult(mu *sync.Mutex, combined *ScanResult, observedPrincipalIDs map[string]struct{}, principalIdentityAccountingComplete *bool, result *ScanResult) {
	mu.Lock()
	combined.Findings = append(combined.Findings, result.Findings...)
	combined.Errors = append(combined.Errors, result.Errors...)
	combined.CoverageGaps = append(combined.CoverageGaps, result.CoverageGaps...)                   // WO-70@v4: preserve the independent coverage plane.
	combined.CoverageGapDetails = append(combined.CoverageGapDetails, result.CoverageGapDetails...) // WO-110@v5: preserve private detail for dependent in-process enrichment.
	combined.IAMPositiveEdges = append(combined.IAMPositiveEdges, result.IAMPositiveEdges...)       // WO-130@v2: preserve private positive evidence across scanner aggregation.
	combined.SourceCompleteness = append(combined.SourceCompleteness, result.SourceCompleteness...) // WO-130@v2: preserve source truth alongside partial scanner outcomes.
	combined.PrincipalsScanned += result.PrincipalsScanned
	// WO-89@v4: the union is authoritative only when every participant proves complete accounting.
	if !result.PrincipalIdentityAccountingComplete || len(result.ObservedPrincipalIDs) != result.PrincipalsScanned {
		*principalIdentityAccountingComplete = false
	}
	for principalID := range result.ObservedPrincipalIDs {
		observedPrincipalIDs[principalID] = struct{}{}
	}
	mu.Unlock()
}

// WO-26@v2: serialize type-prefixed failure recording while sibling scanners continue.
func recordScannerError(mu *sync.Mutex, combined *ScanResult, principalIdentityAccountingComplete *bool, scanner Scanner, err error) {
	mu.Lock()
	combined.Errors = append(combined.Errors, fmt.Sprintf("%s: %v", scanner.Type(), err))
	*principalIdentityAccountingComplete = false // WO-89@v4: failed scanners cannot prove complete union membership.
	mu.Unlock()
	slog.Warn("Scanner failed", "type", scanner.Type(), "error", err)
}
