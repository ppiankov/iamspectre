package commands

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ppiankov/iamspectre/internal/analyzer"
	"github.com/ppiankov/iamspectre/internal/config"
	"github.com/ppiankov/iamspectre/internal/iam"
	"github.com/ppiankov/iamspectre/internal/report"
	"github.com/spf13/cobra"
)

// WO-27@v2: keep shared cloud flag storage and registration structurally identical.
type commonScanFlags struct {
	staleDays   int
	severityMin string
	format      string
	outputFile  string
	timeout     time.Duration
}

// WO-27@v2: register the five flags shared by every cloud command in one place.
func registerCommonScanFlags(cmd *cobra.Command, flags *commonScanFlags) {
	cmd.Flags().IntVar(&flags.staleDays, "stale-days", 90, "Inactivity threshold (days)")
	cmd.Flags().StringVar(&flags.severityMin, "severity-min", "low", "Minimum severity to report: critical, high, medium, low")
	cmd.Flags().StringVar(&flags.format, "format", "text", "Output format: text, json, sarif, spectrehub")
	cmd.Flags().StringVarP(&flags.outputFile, "output", "o", "", "Output file path (default: stdout)")
	cmd.Flags().DurationVar(&flags.timeout, "timeout", defaultScanTimeout, "Scan timeout")
}

// WO-17: apply shared YAML defaults with explicit CLI flags taking precedence.
func applyCommonConfigDefaults(cmd *cobra.Command, flags *commonScanFlags) {
	if !cmd.Flags().Changed("stale-days") && cfg.StaleDays > 0 {
		flags.staleDays = cfg.StaleDays
	}
	if !cmd.Flags().Changed("severity-min") && cfg.SeverityMin != "" {
		flags.severityMin = cfg.SeverityMin
	}
	if !cmd.Flags().Changed("format") && cfg.Format != "" {
		flags.format = cfg.Format
	}
	if timeout := cfg.TimeoutDuration(); !cmd.Flags().Changed("timeout") && timeout > 0 {
		flags.timeout = timeout
	}
}

// WO-17: resolve shared defaults and exclusion conversion through one provider-neutral boundary.
func resolveCommonOptions(cmd *cobra.Command, flags *commonScanFlags) resolvedCommonOptions {
	applyCommonConfigDefaults(cmd, flags)
	return resolvedCommonOptions{
		scanConfig:  iam.ScanConfig{StaleDays: flags.staleDays, Exclude: toExcludeConfig(cfg.Exclude)},
		severityMin: flags.severityMin,
		format:      flags.format,
		outputFile:  flags.outputFile,
		timeout:     flags.timeout,
	}
}

// WO-17: carry the shared runtime options consumed identically by all providers.
type resolvedCommonOptions struct {
	scanConfig  iam.ScanConfig
	severityMin string
	format      string
	outputFile  string
	timeout     time.Duration
}

// WO-11@v2: convert persisted exclusions into the scanner's lookup representation.
func toExcludeConfig(exclude config.Exclude) iam.ExcludeConfig {
	result := iam.ExcludeConfig{
		ResourceIDs: make(map[string]bool, len(exclude.ResourceIDs)),
		Principals:  make(map[string]bool, len(exclude.Principals)),
	}
	for _, resourceID := range exclude.ResourceIDs {
		result.ResourceIDs[resourceID] = true
	}
	for _, principal := range exclude.Principals {
		result.Principals[principal] = true
	}
	return result
}

// enhanceError wraps an error with context and suggestions for common cloud issues.
func enhanceError(action string, err error) error {
	msg := err.Error()

	var hint string
	switch {
	case strings.Contains(msg, "NoCredentialProviders"):
		hint = "Configure AWS credentials: set AWS_PROFILE, AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY, or run 'aws configure'"
	case strings.Contains(msg, "ExpiredToken"):
		hint = "AWS session token expired. Refresh credentials or run 'aws sso login'"
	case strings.Contains(msg, "AccessDenied") || strings.Contains(msg, "UnauthorizedAccess"):
		hint = "Insufficient permissions. Apply the IAM policy from 'iamspectre init' to your role/user"
	case strings.Contains(msg, "RequestExpired"):
		hint = "Request expired. Check system clock synchronization"
	case strings.Contains(msg, "Throttling"):
		hint = "AWS API rate limit hit. Increase timeout or retry"
	case strings.Contains(msg, "could not find default credentials"):
		hint = "Configure GCP credentials: run 'gcloud auth application-default login' or set GOOGLE_APPLICATION_CREDENTIALS"
	case strings.Contains(msg, "AADSTS"):
		hint = "Azure AD authentication failed. Run 'az login' or set AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET"
	case strings.Contains(msg, "Authorization_RequestDenied"):
		hint = "Insufficient Graph API permissions. Grant the required API permissions in Azure AD app registration"
	}

	if hint != "" {
		return fmt.Errorf("%s: %w\n  hint: %s", action, err, hint)
	}
	return fmt.Errorf("%s: %w", action, err)
}

// WO-25@v2: construct reporters without taking ownership of their writer.
func selectReporter(format string, w io.Writer) (report.Reporter, error) {
	switch format {
	case "json":
		return &report.JSONReporter{Writer: w}, nil
	case "text":
		return &report.TextReporter{Writer: w}, nil
	case "sarif":
		return &report.SARIFReporter{Writer: w}, nil
	case "spectrehub":
		return &report.SpectreHubReporter{Writer: w}, nil
	default:
		return nil, fmt.Errorf("unsupported format: %s (use text, json, sarif, or spectrehub)", format)
	}
}

// WO-25@v2: centralize analysis, report construction, and output-file ownership.
func analyzeAndReport(result *iam.ScanResult, opts postScanOptions) (returnErr error) {
	if _, err := selectReporter(opts.format, io.Discard); err != nil {
		return err
	}

	w := io.Writer(os.Stdout)
	if opts.writer != nil {
		w = opts.writer
	}
	var output io.WriteCloser
	if opts.outputFile != "" {
		openOutput := opts.openOutput
		if openOutput == nil {
			openOutput = func(path string) (io.WriteCloser, error) { return os.Create(path) }
		}
		var err error
		output, err = openOutput(opts.outputFile)
		if err != nil {
			return fmt.Errorf("create output file: %w", err)
		}
		w = output
		defer func() {
			if err := output.Close(); err != nil && returnErr == nil {
				returnErr = fmt.Errorf("close output file: %w", err)
			}
		}()
	}

	analysis := analyzer.Analyze(result, analyzer.AnalyzerConfig{SeverityMin: iam.Severity(opts.severityMin)})
	data := report.Data{
		Tool:      "iamspectre",
		Version:   version,
		Timestamp: opts.timestamp,
		Target:    report.Target{Type: opts.targetType, URIHash: computeTargetHash(opts.targetID)},
		Config: report.ReportConfig{
			StaleDays:   opts.staleDays,
			SeverityMin: opts.severityMin,
			Cloud:       opts.cloud,
		},
		Findings: analysis.Findings,
		Summary:  analysis.Summary,
		Errors:   analysis.Errors,
		Coverage: report.BuildCoverageManifest(result.CoverageGaps), // WO-70@v4: coverage bypasses severity filtering.
	}
	reporter, err := selectReporter(opts.format, w)
	if err != nil {
		return err
	}
	return reporter.Generate(data)
}

// WO-25@v2: carry only provider-varying report inputs across the shared boundary.
type postScanOptions struct {
	cloud       string
	targetType  string
	targetID    string
	staleDays   int
	severityMin string
	format      string
	outputFile  string
	timestamp   time.Time
	writer      io.Writer
	openOutput  func(string) (io.WriteCloser, error)
}

// sha256Sum returns the SHA256 hash of a string.
func sha256Sum(input string) []byte {
	h := sha256.Sum256([]byte(input))
	return h[:]
}
