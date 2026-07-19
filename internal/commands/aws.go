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

// WO-12@v2: keep the CLI and YAML timeout fallback anchored to one default.
const defaultScanTimeout = 5 * time.Minute

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
	// WO-12@v2: use the same timeout sentinel consumed by YAML default resolution.
	awsCmd.Flags().DurationVar(&awsFlags.timeout, "timeout", defaultScanTimeout, "Scan timeout")
}

func runAWS(cmd *cobra.Command, _ []string) error {
	// WO-12@v2: resolve YAML defaults before the timeout context observes the flag value.
	applyAWSConfigDefaults()

	ctx, cancel := withScanTimeout(cmd.Context(), awsFlags.timeout, context.WithTimeout)
	defer cancel()

	// Resolve profile from flag or config
	prof := awsFlags.profile
	if prof == "" {
		prof = cfg.Profile
	}

	slog.Info("Starting AWS IAM audit", "profile", prof, "stale_days", awsFlags.staleDays)

	// Initialize AWS client
	region, err := resolveAWSRegion(cfg.Regions)
	if err != nil {
		return err
	}

	client, err := awsscanner.NewClient(ctx, prof, region)
	if err != nil {
		return enhanceError("initialize AWS client", err)
	}

	// Build scan config
	scanCfg := iam.ScanConfig{
		StaleDays: awsFlags.staleDays,
		Exclude:   toExcludeConfig(cfg.Exclude), // WO-11@v2: honor persisted AWS exclusions.
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
	// WO-12@v2: a valid YAML timeout replaces only the unchanged CLI default.
	if timeout := cfg.TimeoutDuration(); awsFlags.timeout == defaultScanTimeout && timeout > 0 {
		awsFlags.timeout = timeout
	}
}

// WO-12@v2: construct scan contexts from the already-resolved timeout.
func withScanTimeout(
	parent context.Context,
	timeout time.Duration,
	create func(context.Context, time.Duration) (context.Context, context.CancelFunc),
) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return parent, func() {}
	}
	return create(parent, timeout)
}

// WO-13@v2: global IAM scans accept at most one distinct SDK region.
func resolveAWSRegion(regions []string) (string, error) {
	resolved := ""
	for _, region := range regions {
		if region == "" || region == resolved {
			continue
		}
		if resolved != "" {
			return "", fmt.Errorf("AWS IAM is account-global; regions must contain at most one distinct non-empty region")
		}
		resolved = region
	}
	return resolved, nil
}

func computeTargetHash(profile string) string {
	return fmt.Sprintf("sha256:%x", sha256Sum(fmt.Sprintf("profile:%s", profile)))
}
