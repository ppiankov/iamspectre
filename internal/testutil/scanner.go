package testutil

import (
	"context"
	"strings"
	"testing"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-28@v2: keep non-fatal scanner error assertions exact across provider packages.
func AssertNonFatalScannerErrors(
	t *testing.T,
	scan func(context.Context) (*iam.ScanResult, error),
	wantErrors int,
	wantSubstring string,
) {
	t.Helper()
	result, err := scan(context.Background())
	if err != nil {
		t.Fatalf("scan should not return a top-level error: %v", err)
	}
	if result == nil {
		t.Fatal("scan returned nil result")
	}
	if len(result.Errors) != wantErrors {
		t.Fatalf("errors = %v, want exactly %d", result.Errors, wantErrors)
	}
	for _, got := range result.Errors {
		if strings.Contains(got, wantSubstring) {
			return
		}
	}
	t.Fatalf("errors %v do not contain %q", result.Errors, wantSubstring)
}
