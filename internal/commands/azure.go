package commands

import (
	"context"
	"log/slog"
	"time"

	"github.com/ppiankov/iamspectre/internal/analyzer"
	azurescanner "github.com/ppiankov/iamspectre/internal/azure"
	"github.com/ppiankov/iamspectre/internal/iam"
	"github.com/ppiankov/iamspectre/internal/report"
	"github.com/spf13/cobra"
)

var azureFlags struct {
	tenant        string
	staleDays     int
	severityMin   string
	format        string
	outputFile    string
	timeout       time.Duration
	includeGuests bool
}

var azureCmd = &cobra.Command{
	Use:   "azure",
	Short: "Audit Azure AD / Entra ID resources",
	Long: `Scan Azure AD users, guest users, app registrations, service principals, and
directory roles for stale, over-permissioned, and misconfigured identities.
Reports severity and recommendations for each finding.`,
	RunE: runAzure,
}

func init() {
	azureCmd.Flags().StringVar(&azureFlags.tenant, "tenant", "", "Azure tenant ID")
	azureCmd.Flags().IntVar(&azureFlags.staleDays, "stale-days", 90, "Inactivity threshold (days)")
	azureCmd.Flags().StringVar(&azureFlags.severityMin, "severity-min", "low", "Minimum severity to report: critical, high, medium, low")
	azureCmd.Flags().StringVar(&azureFlags.format, "format", "text", "Output format: text, json, sarif, spectrehub")
	azureCmd.Flags().StringVarP(&azureFlags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	azureCmd.Flags().DurationVar(&azureFlags.timeout, "timeout", 5*time.Minute, "Scan timeout")
	azureCmd.Flags().BoolVar(&azureFlags.includeGuests, "include-guests", true, "Include guest/external users in audit")
}

func runAzure(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if azureFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, azureFlags.timeout)
		defer cancel()
	}

	applyAzureConfigDefaults()

	tenant := azureFlags.tenant
	if tenant == "" {
		tenant = cfg.TenantID
	}

	slog.Info("Starting Azure AD audit", "tenant", tenant, "stale_days", azureFlags.staleDays)

	client, err := azurescanner.NewClient(ctx, tenant)
	if err != nil {
		return enhanceError("initialize Azure client", err)
	}

	scanCfg := iam.ScanConfig{
		StaleDays: azureFlags.staleDays,
	}

	scanner := azurescanner.NewAzureScanner(client, scanCfg)
	result, err := scanner.ScanAll(ctx)
	if err != nil {
		return enhanceError("scan Azure AD", err)
	}

	analysis := analyzer.Analyze(result, analyzer.AnalyzerConfig{
		SeverityMin: iam.Severity(azureFlags.severityMin),
	})

	targetID := tenant
	if targetID == "" {
		targetID = "default"
	}

	data := report.Data{
		Tool:      "iamspectre",
		Version:   version,
		Timestamp: time.Now().UTC(),
		Target: report.Target{
			Type:    "azure-tenant",
			URIHash: computeTargetHash(targetID),
		},
		Config: report.ReportConfig{
			StaleDays:   azureFlags.staleDays,
			SeverityMin: azureFlags.severityMin,
			Cloud:       "azure",
		},
		Findings: analysis.Findings,
		Summary:  analysis.Summary,
		Errors:   analysis.Errors,
	}

	reporter, err := selectReporter(azureFlags.format, azureFlags.outputFile)
	if err != nil {
		return err
	}
	return reporter.Generate(data)
}

func applyAzureConfigDefaults() {
	if azureFlags.staleDays == 90 && cfg.StaleDays > 0 {
		azureFlags.staleDays = cfg.StaleDays
	}
	if azureFlags.severityMin == "low" && cfg.SeverityMin != "" {
		azureFlags.severityMin = cfg.SeverityMin
	}
	if azureFlags.format == "text" && cfg.Format != "" {
		azureFlags.format = cfg.Format
	}
}
