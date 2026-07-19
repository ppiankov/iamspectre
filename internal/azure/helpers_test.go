package azure

import (
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// WO-14@v3: retain the Azure resource-exclusion regression test at the shared boundary.
func TestIsExcluded_ByResourceID(t *testing.T) {
	cfg := iam.ScanConfig{
		Exclude: iam.ExcludeConfig{
			ResourceIDs: map[string]bool{"res-123": true},
		},
	}

	if !iam.IsExcluded(cfg, "res-123", "anything") {
		t.Fatal("expected excluded by resource ID")
	}
	if iam.IsExcluded(cfg, "res-456", "anything") {
		t.Fatal("should not be excluded")
	}
}

// WO-14@v3: retain the Azure principal-exclusion regression test at the shared boundary.
func TestIsExcluded_ByPrincipal(t *testing.T) {
	cfg := iam.ScanConfig{
		Exclude: iam.ExcludeConfig{
			Principals: map[string]bool{"admin@example.com": true},
		},
	}

	if !iam.IsExcluded(cfg, "anything", "admin@example.com") {
		t.Fatal("expected excluded by principal name")
	}
	if iam.IsExcluded(cfg, "anything", "user@example.com") {
		t.Fatal("should not be excluded")
	}
}

// WO-14@v3: retain the Azure nil-map regression test at the shared boundary.
func TestIsExcluded_NilMaps(t *testing.T) {
	cfg := iam.ScanConfig{}

	if iam.IsExcluded(cfg, "res-123", "admin@example.com") {
		t.Fatal("should not be excluded with nil maps")
	}
}

// WO-24@v2: retain the Azure cutoff regression test against the shared primitive.
func TestDaysAgo(t *testing.T) {
	now := time.Now()
	result := iam.StaleThreshold(now, 90)
	expected := now.AddDate(0, 0, -90)
	diff := result.Sub(expected)
	if diff < -time.Second || diff > time.Second {
		t.Fatalf("daysAgo(90) off by more than 1 second: %v", diff)
	}
}
