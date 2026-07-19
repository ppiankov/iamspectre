package iam

import "time"

// WO-24@v2: derive every stale cutoff from the caller's own clock sample.
func StaleThreshold(now time.Time, days int) time.Time {
	return now.AddDate(0, 0, -days)
}
