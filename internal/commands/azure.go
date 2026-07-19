package commands

import (
	"context"
	"log/slog"
	"time"

	azurescanner "github.com/ppiankov/iamspectre/internal/azure"
	"github.com/ppiankov/iamspectre/internal/config"
	"github.com/ppiankov/iamspectre/internal/iam"
	"github.com/spf13/cobra"
)

type azureScanFlags struct {
	commonScanFlags
	tenant        string
	includeGuests bool
}

var azureFlags azureScanFlags

var azureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Audit Azure AD / Entra ID resources",
	Long: `Scan Azure AD users, guest users, app registrations, service principals, and
directory roles for stale, over-permissioned, and misconfigured identities.
Reports severity and recommendations for each finding.`,
	RunE: runAzure,
}

// WO-27@v2: install Azure flags through the shared registration boundary.
func init() {
	registerAzureFlags(azureCmd, &azureFlags)
}

// WO-27@v2: compose shared and Azure-only flags on any command instance.
func registerAzureFlags(cmd *cobra.Command, flags *azureScanFlags) {
	registerCommonScanFlags(cmd, &flags.commonScanFlags)
	cmd.Flags().StringVar(&flags.tenant, "tenant", "", "Azure tenant ID")
	cmd.Flags().BoolVar(&flags.includeGuests, "include-guests", true, "Include guest/external users in audit")
}

func runAzure(cmd *cobra.Command, _ []string) error {
	// WO-17: resolve every shared runtime option once before provider setup.
	common := resolveCommonOptions(cmd, &azureFlags.commonScanFlags)

	ctx, cancel := withScanTimeout(cmd.Context(), common.timeout, context.WithTimeout)
	defer cancel()

	tenant := azureFlags.tenant
	if tenant == "" {
		tenant = cfg.TenantID
	}

	slog.Info("Starting Azure AD audit", "tenant", tenant, "stale_days", azureFlags.staleDays)

	client, err := azurescanner.NewClient(ctx, tenant)
	if err != nil {
		return enhanceError("initialize Azure client", err)
	}

	scanCfg := common.scanConfig
	scanCfg.ExcludeGuests = !azureFlags.includeGuests

	scanner := azurescanner.NewAzureScanner(client, scanCfg)
	result, err := scanner.ScanAll(ctx)
	if err != nil {
		return enhanceError("scan Azure AD", err)
	}

	targetID := tenant
	if targetID == "" {
		targetID = "default"
	}

	// WO-25@v2: delegate the provider-independent post-scan pipeline.
	return analyzeAndReport(result, postScanOptions{
		cloud: "azure", targetType: "azure-tenant", targetID: targetID,
		staleDays: common.scanConfig.StaleDays, severityMin: common.severityMin,
		format: common.format, outputFile: common.outputFile, timestamp: time.Now().UTC(),
	})
}

// WO-15: make the existing include-guests flag mapping directly testable.
func buildAzureScanConfig(staleDays int, exclude config.Exclude, includeGuests bool) iam.ScanConfig {
	return iam.ScanConfig{
		StaleDays:     staleDays,
		Exclude:       toExcludeConfig(exclude), // WO-11@v2: honor persisted Azure exclusions.
		ExcludeGuests: !includeGuests,
	}
}

// WO-16@v2: explicit CLI flags win even when their values equal documented defaults.
func applyAzureConfigDefaults(cmd *cobra.Command) {
	// WO-17: retain a policy-free compatibility wrapper around the shared resolver.
	applyCommonConfigDefaults(cmd, &azureFlags.commonScanFlags)
}
