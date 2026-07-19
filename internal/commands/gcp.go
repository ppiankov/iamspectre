package commands

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gcpscanner "github.com/ppiankov/iamspectre/internal/gcp"
	"github.com/spf13/cobra"
)

type gcpScanFlags struct {
	commonScanFlags
	project string
}

var gcpFlags gcpScanFlags

var gcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Audit GCP IAM resources",
	Long: `Scan GCP service accounts, keys, and IAM bindings for unused, over-permissioned,
and stale identities. Reports severity and recommendations for each finding.`,
	RunE: runGCP,
}

// WO-27@v2: install GCP flags through the shared registration boundary.
func init() {
	registerGCPFlags(gcpCmd, &gcpFlags)
}

// WO-27@v2: compose shared and GCP-only flags on any command instance.
func registerGCPFlags(cmd *cobra.Command, flags *gcpScanFlags) {
	registerCommonScanFlags(cmd, &flags.commonScanFlags)
	cmd.Flags().StringVar(&flags.project, "project", "", "GCP project ID")
}

func runGCP(cmd *cobra.Command, _ []string) error {
	// WO-17: resolve every shared runtime option once before provider setup.
	common := resolveCommonOptions(cmd, &gcpFlags.commonScanFlags)

	ctx, cancel := withScanTimeout(cmd.Context(), common.timeout, context.WithTimeout)
	defer cancel()

	project := gcpFlags.project
	if project == "" {
		project = cfg.Project
	}
	if project == "" {
		return fmt.Errorf("GCP project required; use --project or set in .iamspectre.yaml")
	}

	slog.Info("Starting GCP IAM audit", "project", project, "stale_days", gcpFlags.staleDays)

	// Initialize GCP client
	client, err := gcpscanner.NewClient(ctx, project)
	if err != nil {
		return enhanceError("initialize GCP client", err)
	}

	// Build scan config
	scanCfg := common.scanConfig

	// Run GCP IAM scan
	scanner := gcpscanner.NewGCPScanner(client, scanCfg)
	result, err := scanner.ScanAll(ctx)
	if err != nil {
		return enhanceError("scan GCP IAM", err)
	}

	// WO-25@v2: delegate the provider-independent post-scan pipeline.
	return analyzeAndReport(result, postScanOptions{
		cloud: "gcp", targetType: "gcp-project", targetID: project,
		staleDays: common.scanConfig.StaleDays, severityMin: common.severityMin,
		format: common.format, outputFile: common.outputFile, timestamp: time.Now().UTC(),
	})
}

// WO-16@v2: explicit CLI flags win even when their values equal documented defaults.
func applyGCPConfigDefaults(cmd *cobra.Command) {
	// WO-17: retain a policy-free compatibility wrapper around the shared resolver.
	applyCommonConfigDefaults(cmd, &gcpFlags.commonScanFlags)
}
