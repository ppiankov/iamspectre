package commands

import (
	"context"
	"testing"
	"time"

	"github.com/ppiankov/iamspectre/internal/config"
	"github.com/spf13/cobra"
)

// WO-16@v2: pin equal-to-default explicit flags across every provider and shared option.
func TestExplicitSharedFlagsOverrideConfig(t *testing.T) {
	oldConfig := cfg
	t.Cleanup(func() {
		cfg = oldConfig
		for _, cmd := range []*cobra.Command{awsCmd, gcpCmd, azureCmd} {
			for _, name := range []string{"stale-days", "severity-min", "format", "timeout"} {
				cmd.Flags().Lookup(name).Changed = false
			}
		}
	})
	cfg = config.Config{StaleDays: 30, SeverityMin: "high", Format: "json", Timeout: "2m"}

	providers := []struct {
		name  string
		cmd   *cobra.Command
		reset func()
		apply func(*cobra.Command)
		check func(t *testing.T)
	}{
		{name: "aws", cmd: awsCmd, reset: func() {
			awsFlags.staleDays, awsFlags.severityMin, awsFlags.format, awsFlags.timeout = 90, "low", "text", defaultScanTimeout
		}, apply: applyAWSConfigDefaults, check: func(t *testing.T) {
			assertCommonDefaults(t, awsFlags.staleDays, awsFlags.severityMin, awsFlags.format, awsFlags.timeout)
		}},
		{name: "gcp", cmd: gcpCmd, reset: func() {
			gcpFlags.staleDays, gcpFlags.severityMin, gcpFlags.format, gcpFlags.timeout = 90, "low", "text", defaultScanTimeout
		}, apply: applyGCPConfigDefaults, check: func(t *testing.T) {
			assertCommonDefaults(t, gcpFlags.staleDays, gcpFlags.severityMin, gcpFlags.format, gcpFlags.timeout)
		}},
		{name: "azure", cmd: azureCmd, reset: func() {
			azureFlags.staleDays, azureFlags.severityMin, azureFlags.format, azureFlags.timeout = 90, "low", "text", defaultScanTimeout
		}, apply: applyAzureConfigDefaults, check: func(t *testing.T) {
			assertCommonDefaults(t, azureFlags.staleDays, azureFlags.severityMin, azureFlags.format, azureFlags.timeout)
		}},
	}
	for _, provider := range providers {
		t.Run(provider.name, func(t *testing.T) {
			provider.reset()
			for _, name := range []string{"stale-days", "severity-min", "format", "timeout"} {
				provider.cmd.Flags().Lookup(name).Changed = true
			}
			provider.apply(provider.cmd)
			provider.check(t)
		})
	}
}

// WO-16@v2: prove every unchanged shared flag still inherits its configured value.
func TestImplicitSharedFlagsInheritConfig(t *testing.T) {
	oldConfig := cfg
	t.Cleanup(func() {
		cfg = oldConfig
		for _, cmd := range []*cobra.Command{awsCmd, gcpCmd, azureCmd} {
			for _, name := range []string{"stale-days", "severity-min", "format", "timeout"} {
				cmd.Flags().Lookup(name).Changed = false
			}
		}
	})
	cfg = config.Config{StaleDays: 30, SeverityMin: "high", Format: "json", Timeout: "2m"}

	providers := []struct {
		name  string
		cmd   *cobra.Command
		reset func()
		apply func(*cobra.Command)
		check func(t *testing.T)
	}{
		{name: "aws", cmd: awsCmd, reset: func() {
			awsFlags.staleDays, awsFlags.severityMin, awsFlags.format, awsFlags.timeout = 90, "low", "text", defaultScanTimeout
		}, apply: applyAWSConfigDefaults, check: func(t *testing.T) {
			assertInheritedConfig(t, awsFlags.staleDays, awsFlags.severityMin, awsFlags.format, awsFlags.timeout)
		}},
		{name: "gcp", cmd: gcpCmd, reset: func() {
			gcpFlags.staleDays, gcpFlags.severityMin, gcpFlags.format, gcpFlags.timeout = 90, "low", "text", defaultScanTimeout
		}, apply: applyGCPConfigDefaults, check: func(t *testing.T) {
			assertInheritedConfig(t, gcpFlags.staleDays, gcpFlags.severityMin, gcpFlags.format, gcpFlags.timeout)
		}},
		{name: "azure", cmd: azureCmd, reset: func() {
			azureFlags.staleDays, azureFlags.severityMin, azureFlags.format, azureFlags.timeout = 90, "low", "text", defaultScanTimeout
		}, apply: applyAzureConfigDefaults, check: func(t *testing.T) {
			assertInheritedConfig(t, azureFlags.staleDays, azureFlags.severityMin, azureFlags.format, azureFlags.timeout)
		}},
	}
	for _, provider := range providers {
		t.Run(provider.name, func(t *testing.T) {
			provider.reset()
			for _, name := range []string{"stale-days", "severity-min", "format", "timeout"} {
				provider.cmd.Flags().Lookup(name).Changed = false
			}
			provider.apply(provider.cmd)
			provider.check(t)
		})
	}
}

// WO-16@v2: compare the explicit default-shaped values as one shared assertion.
func assertCommonDefaults(t *testing.T, stale int, severity, format string, timeout time.Duration) {
	t.Helper()
	if stale != 90 || severity != "low" || format != "text" || timeout != defaultScanTimeout {
		t.Fatalf("explicit defaults changed: %d %s %s %s", stale, severity, format, timeout)
	}
}

// WO-16@v2: compare all inherited shared settings as one shared assertion.
func assertInheritedConfig(t *testing.T, stale int, severity, format string, timeout time.Duration) {
	t.Helper()
	if stale != 30 || severity != "high" || format != "json" || timeout != 2*time.Minute {
		t.Fatalf("inherited config = %d %s %s %s", stale, severity, format, timeout)
	}
}

// WO-12@v2: pin timeout default resolution across all cloud commands.
func TestConfigTimeoutDefaults(t *testing.T) {
	tests := []struct {
		name       string
		configured string
		initial    time.Duration
		want       time.Duration
		explicit   bool
	}{
		{name: "configured", configured: "2m", initial: defaultScanTimeout, want: 2 * time.Minute},
		{name: "empty", initial: defaultScanTimeout, want: defaultScanTimeout},
		{name: "invalid", configured: "later", initial: defaultScanTimeout, want: defaultScanTimeout},
		{name: "zero", configured: "0s", initial: defaultScanTimeout, want: defaultScanTimeout},
		{name: "non-default flag", configured: "2m", initial: time.Minute, want: time.Minute, explicit: true},
	}

	providers := []struct {
		name  string
		cmd   *cobra.Command
		set   func(time.Duration)
		get   func() time.Duration
		apply func(*cobra.Command)
	}{
		{name: "aws", cmd: awsCmd, set: func(v time.Duration) { awsFlags.timeout = v }, get: func() time.Duration { return awsFlags.timeout }, apply: applyAWSConfigDefaults},
		{name: "gcp", cmd: gcpCmd, set: func(v time.Duration) { gcpFlags.timeout = v }, get: func() time.Duration { return gcpFlags.timeout }, apply: applyGCPConfigDefaults},
		{name: "azure", cmd: azureCmd, set: func(v time.Duration) { azureFlags.timeout = v }, get: func() time.Duration { return azureFlags.timeout }, apply: applyAzureConfigDefaults},
	}

	oldConfig := cfg
	t.Cleanup(func() {
		cfg = oldConfig
		for _, provider := range providers {
			provider.set(defaultScanTimeout)
			provider.cmd.Flags().Lookup("timeout").Changed = false
		}
	})
	for _, provider := range providers {
		for _, tt := range tests {
			t.Run(provider.name+"/"+tt.name, func(t *testing.T) {
				cfg = config.Config{Timeout: tt.configured}
				provider.set(tt.initial)
				provider.cmd.Flags().Lookup("timeout").Changed = tt.explicit
				provider.apply(provider.cmd)
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
	awsCmd.Flags().Lookup("timeout").Changed = false
	applyAWSConfigDefaults(awsCmd)
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

// WO-17: pin shared default resolution and exclusion conversion as one operation.
func TestResolveCommonOptions(t *testing.T) {
	oldConfig := cfg
	t.Cleanup(func() { cfg = oldConfig })
	cfg = config.Config{
		StaleDays: 30, SeverityMin: "high", Format: "json", Timeout: "2m",
		Exclude: config.Exclude{ResourceIDs: []string{"resource"}, Principals: []string{"principal"}},
	}
	cmd := &cobra.Command{Use: "test"}
	var flags commonScanFlags
	registerCommonScanFlags(cmd, &flags)
	got := resolveCommonOptions(cmd, &flags)
	if got.scanConfig.StaleDays != 30 || got.severityMin != "high" || got.format != "json" || got.timeout != 2*time.Minute {
		t.Fatalf("resolved options = %#v", got)
	}
	if !got.scanConfig.Exclude.ResourceIDs["resource"] || !got.scanConfig.Exclude.Principals["principal"] {
		t.Fatalf("resolved exclusions = %#v", got.scanConfig.Exclude)
	}
}

// WO-44@v2: explicit AWS boolean flags take precedence even at false.
func TestAWSServiceLinkedRoleConfigPrecedence(t *testing.T) {
	oldConfig := cfg
	oldValue := awsFlags.includeServiceLinkedRoles
	flag := awsCmd.Flags().Lookup("include-service-linked-roles")
	oldChanged := flag.Changed
	t.Cleanup(func() {
		cfg = oldConfig
		awsFlags.includeServiceLinkedRoles = oldValue
		flag.Changed = oldChanged
	})

	cfg.IncludeServiceLinkedRoles = true
	awsFlags.includeServiceLinkedRoles = false
	flag.Changed = false
	applyAWSConfigDefaults(awsCmd)
	if !awsFlags.includeServiceLinkedRoles {
		t.Fatal("expected unchanged flag to inherit YAML true")
	}

	awsFlags.includeServiceLinkedRoles = false
	flag.Changed = true
	applyAWSConfigDefaults(awsCmd)
	if awsFlags.includeServiceLinkedRoles {
		t.Fatal("expected explicit false to override YAML true")
	}

	cfg.IncludeServiceLinkedRoles = false
	awsFlags.includeServiceLinkedRoles = true
	flag.Changed = true
	applyAWSConfigDefaults(awsCmd)
	if !awsFlags.includeServiceLinkedRoles {
		t.Fatal("expected explicit true to override YAML false")
	}
}
