package azure

import (
	"time"

	"github.com/ppiankov/iamspectre/internal/iam"
)

// isExcluded returns true if the resource should be skipped based on exclusion config.
func isExcluded(cfg iam.ScanConfig, resourceID, principalName string) bool {
	if cfg.Exclude.ResourceIDs != nil && cfg.Exclude.ResourceIDs[resourceID] {
		return true
	}
	if cfg.Exclude.Principals != nil && cfg.Exclude.Principals[principalName] {
		return true
	}
	return false
}

// daysAgo returns the time that was n days ago from now.
func daysAgo(n int) time.Time {
	return time.Now().AddDate(0, 0, -n)
}
