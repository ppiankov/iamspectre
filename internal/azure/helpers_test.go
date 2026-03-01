package azure

import (
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

func TestIsExcluded_ByResourceID(t *testing.T) {
	cfg := iam.ScanConfig{
		Exclude: iam.ExcludeConfig{
			ResourceIDs: map[string]bool{"res-123": true},
		},
	}

	if !isExcluded(cfg, "res-123", "anything") {
		t.Fatal("expected excluded by resource ID")
	}
	if isExcluded(cfg, "res-456", "anything") {
		t.Fatal("should not be excluded")
	}
}

func TestIsExcluded_ByPrincipal(t *testing.T) {
	cfg := iam.ScanConfig{
		Exclude: iam.ExcludeConfig{
			Principals: map[string]bool{"admin@example.com": true},
		},
	}

	if !isExcluded(cfg, "anything", "admin@example.com") {
		t.Fatal("expected excluded by principal name")
	}
	if isExcluded(cfg, "anything", "user@example.com") {
		t.Fatal("should not be excluded")
	}
}

func TestIsExcluded_NilMaps(t *testing.T) {
	cfg := iam.ScanConfig{}

	if isExcluded(cfg, "res-123", "admin@example.com") {
		t.Fatal("should not be excluded with nil maps")
	}
}

func TestDaysAgo(t *testing.T) {
	result := daysAgo(90)
	expected := time.Now().AddDate(0, 0, -90)
	diff := result.Sub(expected)
	if diff < -time.Second || diff > time.Second {
		t.Fatalf("daysAgo(90) off by more than 1 second: %v", diff)
	}
}
