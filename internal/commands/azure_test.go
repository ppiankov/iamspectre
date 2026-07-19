package commands

import (
	"testing"

	"github.com/ppiankov/iamspectre/internal/config"
)

// WO-15: pin the include-guests flag inversion at the command boundary.
func TestBuildAzureScanConfigGuestFlag(t *testing.T) {
	tests := []struct {
		name          string
		includeGuests bool
		excludeGuests bool
	}{
		{name: "default includes guests", includeGuests: true, excludeGuests: false},
		{name: "false excludes guests", includeGuests: false, excludeGuests: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAzureScanConfig(90, config.Exclude{}, tt.includeGuests)
			if got.ExcludeGuests != tt.excludeGuests {
				t.Fatalf("ExcludeGuests = %t, want %t", got.ExcludeGuests, tt.excludeGuests)
			}
		})
	}
}
