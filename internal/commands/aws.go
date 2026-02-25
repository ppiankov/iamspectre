package commands

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/ppiankov/iamspectre/internal/analyzer"
	awsscanner "github.com/ppiankov/iamspectre/internal/aws"
	"github.com/ppiankov/iamspectre/internal/iam"
	"github.com/ppiankov/iamspectre/internal/report"
	"github.com/spf13/cobra"
)

var awsFlags struct {
	profile     string
	staleDays   int
	severityMin string
	format      string
	outputFile  string
	timeout     time.Duration
}

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Audit AWS IAM resources",
	Long: `Scan AWS IAM users, roles, and policies for unused, over-permissioned, and
stale identities. Reports severity and recommendations for each finding.`,
	RunE: runAWS,
}

func init() {
	awsCmd.Flags().StringVar(&awsFlags.profile, "profile", "", "AWS profile name")
	awsCmd.Flags().IntVar(&awsFlags.staleDays, "stale-days", 90, "Inactivity threshold (days)")
	awsCmd.Flags().StringVar(&awsFlags.severityMin, "severity-min", "low", "Minimum severity to report: critical, high, medium, low")
	awsCmd.Flags().StringVar(&awsFlags.format, "format", "text", "Output format: text, json, sarif, spectrehub")
	awsCmd.Flags().StringVarP(&awsFlags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	awsCmd.Flags().DurationVar(&awsFlags.timeout, "timeout", 5*time.Minute, "Scan timeout")
}

func runAWS(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if awsFlags.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, awsFlags.timeout)
		defer cancel()
	}

	// Apply config file defaults where flags were not explicitly set
	applyAWSConfigDefaults()

	// Resolve profile from flag or config
	prof := awsFlags.profile
	if prof == "" {
		prof = cfg.Profile
	}

	slog.Info("Starting AWS IAM audit", "profile", prof, "stale_days", awsFlags.staleDays)

	// Initialize AWS client
	client, err := awsscanner.NewClient(ctx, prof)
	if err != nil {
		return enhanceError("initialize AWS client", err)
	}

	// Build scan config
	scanCfg := iam.ScanConfig{
		StaleDays: awsFlags.staleDays,
	}

	// Run AWS IAM scan
	scanner := awsscanner.NewAWSScanner(client, scanCfg)
	result, err := scanner.ScanAll(ctx)
	if err != nil {
		return enhanceError("scan AWS IAM", err)
	}

	// Analyze results: filter by severity, compute summary
	analysis := analyzer.Analyze(result, analyzer.AnalyzerConfig{
		SeverityMin: iam.Severity(awsFlags.severityMin),
	})

	// Build report data
	data := report.Data{
		Tool:      "iamspectre",
		Version:   version,
		Timestamp: time.Now().UTC(),
		Target: report.Target{
			Type:    "aws-account",
			URIHash: computeTargetHash(prof),
		},
		Config: report.ReportConfig{
			StaleDays:   awsFlags.staleDays,
			SeverityMin: awsFlags.severityMin,
			Cloud:       "aws",
		},
		Findings: analysis.Findings,
		Summary:  analysis.Summary,
		Errors:   analysis.Errors,
	}

	reporter, err := selectReporter(awsFlags.format, awsFlags.outputFile)
	if err != nil {
		return err
	}
	return reporter.Generate(data)
}

func applyAWSConfigDefaults() {
	if awsFlags.staleDays == 90 && cfg.StaleDays > 0 {
		awsFlags.staleDays = cfg.StaleDays
	}
	if awsFlags.severityMin == "low" && cfg.SeverityMin != "" {
		awsFlags.severityMin = cfg.SeverityMin
	}
	if awsFlags.format == "text" && cfg.Format != "" {
		awsFlags.format = cfg.Format
	}
}

func computeTargetHash(profile string) string {
	return fmt.Sprintf("sha256:%x", sha256Sum(fmt.Sprintf("profile:%s", profile)))
}
