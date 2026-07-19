package commands

import (
	"context"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/config"
)

// WO-12@v2: pin timeout default resolution across all cloud commands.
func TestConfigTimeoutDefaults(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		initial    time.Duration
		want       time.Duration
	}{
		{name: "configured", configured: "2m", initial: defaultScanTimeout, want: 2 * time.Minute},
		{name: "empty", initial: defaultScanTimeout, want: defaultScanTimeout},
		{name: "invalid", configured: "later", initial: defaultScanTimeout, want: defaultScanTimeout},
		{name: "zero", configured: "0s", initial: defaultScanTimeout, want: defaultScanTimeout},
		{name: "non-default flag", configured: "2m", initial: time.Minute, want: time.Minute},
	}

	providers := []struct {
		name  string
		set   func(time.Duration)
		get   func() time.Duration
		apply func()
	}{
		{name: "aws", set: func(v time.Duration) { awsFlags.timeout = v }, get: func() time.Duration { return awsFlags.timeout }, apply: applyAWSConfigDefaults},
		{name: "gcp", set: func(v time.Duration) { gcpFlags.timeout = v }, get: func() time.Duration { return gcpFlags.timeout }, apply: applyGCPConfigDefaults},
		{name: "azure", set: func(v time.Duration) { azureFlags.timeout = v }, get: func() time.Duration { return azureFlags.timeout }, apply: applyAzureConfigDefaults},
	}

	oldConfig := cfg
	t.Cleanup(func() { cfg = oldConfig })
	for _, provider := range providers {
		for _, tt := range tests {
			t.Run(provider.name+"/"+tt.name, func(t *testing.T) {
				cfg = config.Config{Timeout: tt.configured}
				provider.set(tt.initial)
				provider.apply()
				if got := provider.get(); got != tt.want {
					t.Fatalf("timeout = %s, want %s", got, tt.want)
				}
			})
		}
	}
}

// WO-12@v2: pin resolved timeout ordering without wall-clock assertions.
func TestResolvedTimeoutPrecedesContextConstruction(t *testing.T) {
	oldConfig := cfg
	oldTimeout := awsFlags.timeout
	t.Cleanup(func() {
		cfg = oldConfig
		awsFlags.timeout = oldTimeout
	})

	cfg = config.Config{Timeout: "2m"}
	awsFlags.timeout = defaultScanTimeout
	applyAWSConfigDefaults()
	var captured time.Duration
	ctx, cancel := withScanTimeout(
		context.Background(),
		awsFlags.timeout,
		func(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
			captured = timeout
			return parent, func() {}
		},
	)
	defer cancel()

	if ctx == nil {
		t.Fatal("expected context")
	}
	if captured != 2*time.Minute {
		t.Fatalf("captured timeout = %s, want 2m", captured)
	}
}
