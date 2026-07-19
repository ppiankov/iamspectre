package iam

import (
	"testing"
	"time"
)

// WO-24@v2: pin calendar-day arithmetic independently of wall-clock timing.
func TestStaleThreshold(t *testing.T) {
	location := time.FixedZone("test", 8*60*60)
	now := time.Date(2024, time.March, 1, 12, 30, 0, 0, location)
	tests := []struct {
		name string
		days int
		want time.Time
	}{
		{name: "zero", days: 0, want: now},
		{name: "leap boundary", days: 1, want: time.Date(2024, time.February, 29, 12, 30, 0, 0, location)},
		{name: "month boundary", days: 31, want: time.Date(2024, time.January, 30, 12, 30, 0, 0, location)},
		{name: "negative", days: -1, want: time.Date(2024, time.March, 2, 12, 30, 0, 0, location)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StaleThreshold(now, tt.days); !got.Equal(tt.want) || got.Location() != location {
				t.Fatalf("threshold = %v (%v), want %v (%v)", got, got.Location(), tt.want, location)
			}
		})
	}
}
