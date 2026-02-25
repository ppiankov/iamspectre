package aws

import "testing"

func TestScannerCount(t *testing.T) {
	if ScannerCount() != 3 {
		t.Fatalf("expected 3 scanners, got %d", ScannerCount())
	}
}
