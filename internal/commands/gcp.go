package commands

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ppiankov/iamspectre/internal/analyzer"
	gcpscanner "github.com/ppiankov/iamspectre/internal/gcp"
	"github.com/ppiankov/iamspectre/internal/iam"
	"github.com/ppiankov/iamspectre/internal/report"
	"github.com/spf13/cobra"
)

var gcpFlags struct {
	project     string
	staleDays   int
	severityMin string
	format      string
	outputFile  string
	timeout     time.Duration
}

var gcpCmd = &cobra.Command{
	Use:   "gcp",
	Short: "Audit GCP IAM resources",
	Long: `Scan GCP service accounts, keys, and IAM bindings for unused, over-permissioned,
and stale identities. Reports severity and recommendations for each finding.`,
	RunE: runGCP,
}

func init() {
	gcpCmd.Flags().StringVar(&gcpFlags.project, "project", "", "GCP project ID")
	gcpCmd.Flags().IntVar(&gcpFlags.staleDays, "stale-days", 90, "Inactivity threshold (days)")
	gcpCmd.Flags().StringVar(&gcpFlags.severityMin, "severity-min", "low", "Minimum severity to report: critical, high, medium, low")
	gcpCmd.Flags().StringVar(&gcpFlags.format, "format", "text", "Output format: text, json, sarif, spectrehub")
	gcpCmd.Flags().StringVarP(&gcpFlags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	// WO-12@v2: use the same timeout sentinel consumed by YAML default resolution.
	gcpCmd.Flags().DurationVar(&gcpFlags.timeout, "timeout", defaultScanTimeout, "Scan timeout")
}

func runGCP(cmd *cobra.Command, _ []string) error {
	// WO-12@v2: resolve YAML defaults before the timeout context observes the flag value.
	applyGCPConfigDefaults(cmd)

	ctx, cancel := withScanTimeout(cmd.Context(), gcpFlags.timeout, context.WithTimeout)
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
	scanCfg := iam.ScanConfig{
		StaleDays: gcpFlags.staleDays,
		Exclude:   toExcludeConfig(cfg.Exclude), // WO-11@v2: honor persisted GCP exclusions.
	}

	// Run GCP IAM scan
	scanner := gcpscanner.NewGCPScanner(client, scanCfg)
	result, err := scanner.ScanAll(ctx)
	if err != nil {
		return enhanceError("scan GCP IAM", err)
	}

	// Analyze results: filter by severity, compute summary
	analysis := analyzer.Analyze(result, analyzer.AnalyzerConfig{
		SeverityMin: iam.Severity(gcpFlags.severityMin),
	})

	// Build report data
	data := report.Data{
		Tool:      "iamspectre",
		Version:   version,
		Timestamp: time.Now().UTC(),
		Target: report.Target{
			Type:    "gcp-project",
			URIHash: computeTargetHash(project),
		},
		Config: report.ReportConfig{
			StaleDays:   gcpFlags.staleDays,
			SeverityMin: gcpFlags.severityMin,
			Cloud:       "gcp",
		},
		Findings: analysis.Findings,
		Summary:  analysis.Summary,
		Errors:   analysis.Errors,
	}

	reporter, err := selectReporter(gcpFlags.format, gcpFlags.outputFile)
	if err != nil {
		return err
	}
	return reporter.Generate(data)
}

// WO-16@v2: explicit CLI flags win even when their values equal documented defaults.
func applyGCPConfigDefaults(cmd *cobra.Command) {
	if !cmd.Flags().Changed("stale-days") && cfg.StaleDays > 0 {
		gcpFlags.staleDays = cfg.StaleDays
	}
	if !cmd.Flags().Changed("severity-min") && cfg.SeverityMin != "" {
		gcpFlags.severityMin = cfg.SeverityMin
	}
	if !cmd.Flags().Changed("format") && cfg.Format != "" {
		gcpFlags.format = cfg.Format
	}
	// WO-12@v2: a valid YAML timeout replaces only the unchanged CLI default.
	if timeout := cfg.TimeoutDuration(); !cmd.Flags().Changed("timeout") && timeout > 0 {
		gcpFlags.timeout = timeout
	}
}
