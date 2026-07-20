package iam

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type runnerScanner struct {
	typeID ResourceType
	result *ScanResult
	err    error
	scan   func(context.Context, ScanConfig)
}

type runnerContextKey string

// WO-26@v2: expose a deterministic fake scanner implementation.
func (s runnerScanner) Scan(ctx context.Context, cfg ScanConfig) (*ScanResult, error) {
	if s.scan != nil {
		s.scan(ctx, cfg)
	}
	return s.result, s.err
}

// WO-26@v2: identify injected failures in aggregate error output.
func (s runnerScanner) Type() ResourceType { return s.typeID }

// WO-26@v2: pin aggregation, continuation, forwarding, and nil-result defense.
func TestRunScannersAggregatesAndContinues(t *testing.T) {
	const key runnerContextKey = "key"
	ctx := context.WithValue(context.Background(), key, "value")
	cfg := ScanConfig{StaleDays: 42}
	var forwarded bool
	scanners := []Scanner{
		runnerScanner{typeID: ResourceIAMUser, result: &ScanResult{
			Findings: []Finding{{ID: FindingStaleUser}}, Errors: []string{"nested"}, PrincipalsScanned: 2,
			CoverageGaps: []CoverageGapObservation{{Capability: "activity", Scope: "account:a", FindingID: FindingStaleUser}},
		}, scan: func(gotCtx context.Context, gotCfg ScanConfig) {
			forwarded = gotCtx.Value(key) == "value" && gotCfg.StaleDays == cfg.StaleDays
		}},
		runnerScanner{typeID: ResourceIAMRole, err: errors.New("failed")},
		runnerScanner{typeID: ResourceIAMPolicy},
	}
	result, err := RunScanners(ctx, scanners, cfg)
	if err != nil {
		t.Fatalf("RunScanners: %v", err)
	}
	if !forwarded || len(result.Findings) != 1 || len(result.CoverageGaps) != 1 || result.PrincipalsScanned != 2 {
		t.Fatalf("unexpected aggregate: %#v forwarded=%v", result, forwarded)
	}
	joined := strings.Join(result.Errors, "|")
	for _, want := range []string{"nested", "iam_role: failed", "iam_policy: scanner returned nil result"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("errors %q missing %q", joined, want)
		}
	}
}

// WO-26@v2: keep the empty scanner set zero-value safe.
func TestRunScannersEmpty(t *testing.T) {
	result, err := RunScanners(context.Background(), nil, ScanConfig{})
	if err != nil || result == nil || len(result.Findings) != 0 || len(result.Errors) != 0 {
		t.Fatalf("empty result = %#v, err=%v", result, err)
	}
}

// WO-26@v2: prove the named worker bound without timing-dependent assertions.
func TestRunScannersConcurrencyLimit(t *testing.T) {
	const scannerCount = scannerConcurrencyLimit + 2
	var active, maximum atomic.Int32
	release := make(chan struct{})
	started := make(chan struct{}, scannerCount)
	var once sync.Once
	scanners := make([]Scanner, scannerCount)
	for i := range scanners {
		scanners[i] = runnerScanner{typeID: ResourceIAMUser, result: &ScanResult{}, scan: func(context.Context, ScanConfig) {
			current := active.Add(1)
			for {
				old := maximum.Load()
				if current <= old || maximum.CompareAndSwap(old, current) {
					break
				}
			}
			started <- struct{}{}
			if current == scannerConcurrencyLimit {
				once.Do(func() { close(release) })
			}
			select {
			case <-release:
			case <-time.After(time.Second):
				t.Error("workers did not reach concurrency limit")
			}
			active.Add(-1)
		}}
	}
	if _, err := RunScanners(context.Background(), scanners, ScanConfig{}); err != nil {
		t.Fatal(err)
	}
	if got := maximum.Load(); got != scannerConcurrencyLimit {
		t.Fatalf("maximum concurrency = %d, want %d", got, scannerConcurrencyLimit)
	}
}
