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
			if err != nil {
				recordScannerError(&mu, &combined, &principalIdentityAccountingComplete, scanner, err)
				return nil
			}
			if result == nil {
				recordScannerError(&mu, &combined, &principalIdentityAccountingComplete, scanner, fmt.Errorf("scanner returned nil result"))
				return nil
			}
			mu.Lock()
			combined.Findings = append(combined.Findings, result.Findings...)
			combined.Errors = append(combined.Errors, result.Errors...)
			combined.CoverageGaps = append(combined.CoverageGaps, result.CoverageGaps...) // WO-70@v4: preserve the independent coverage plane.
			combined.PrincipalsScanned += result.PrincipalsScanned
			// WO-89: the union is authoritative only when every participant proves complete accounting.
			if !result.PrincipalIdentityAccountingComplete || len(result.ObservedPrincipalIDs) != result.PrincipalsScanned {
				principalIdentityAccountingComplete = false
			}
			for principalID := range result.ObservedPrincipalIDs {
				observedPrincipalIDs[principalID] = struct{}{}
			}
			mu.Unlock()
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	// WO-89: derive cardinality only after all concurrent identity sets are complete.
	if principalIdentityAccountingComplete {
		combined.PrincipalsScanned = len(observedPrincipalIDs)
	}
	return &combined, nil
}

// WO-26@v2: serialize type-prefixed failure recording while sibling scanners continue.
func recordScannerError(mu *sync.Mutex, combined *ScanResult, principalIdentityAccountingComplete *bool, scanner Scanner, err error) {
	mu.Lock()
	combined.Errors = append(combined.Errors, fmt.Sprintf("%s: %v", scanner.Type(), err))
	*principalIdentityAccountingComplete = false // WO-89: failed scanners cannot prove complete union membership.
	mu.Unlock()
	slog.Warn("Scanner failed", "type", scanner.Type(), "error", err)
}
