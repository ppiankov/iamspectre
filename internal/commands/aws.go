package commands

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	awsscanner "github.com/ppiankov/iamspectre/internal/aws"
	"github.com/spf13/cobra"
)

type awsScanFlags struct {
	commonScanFlags
	profile                   string
	region                    string // WO-103@v3: explicit CLI region wins before config and SDK defaults.
	includeServiceLinkedRoles bool   // WO-44@v2: opt in to otherwise suppressed AWS-owned-role noise.
}

var awsFlags awsScanFlags

// WO-12@v2: keep the CLI and YAML timeout fallback anchored to one default.
const defaultScanTimeout = 5 * time.Minute

var awsCmd = &cobra.Command{
	Use:   "aws",
	Short: "Audit AWS IAM resources",
	Long: `Scan AWS IAM users, roles, and policies for unused, over-permissioned, and
stale identities. Reports severity and recommendations for each finding.`,
	RunE: runAWS,
}

// WO-27@v2: install AWS flags through the shared registration boundary.
func init() {
	registerAWSFlags(awsCmd, &awsFlags)
}

// WO-27@v2: compose shared and AWS-only flags on any command instance.
func registerAWSFlags(cmd *cobra.Command, flags *awsScanFlags) {
	registerCommonScanFlags(cmd, &flags.commonScanFlags)
	cmd.Flags().StringVar(&flags.profile, "profile", "", "AWS profile name")
	cmd.Flags().StringVar(&flags.region, "region", "", "AWS region for SDK endpoint resolution") // WO-103@v3: expose the missing-region escape hatch.
	cmd.Flags().BoolVar(&flags.includeServiceLinkedRoles, "include-service-linked-roles", false, "Include unused AWS service-linked roles")
}

// WO-44@v2: resolve the AWS-only service-linked role policy before scanner construction.
func runAWS(cmd *cobra.Command, _ []string) error {
	applyAWSConfigDefaults(cmd)
	// WO-17: resolve every shared runtime option once before provider setup.
	common := resolveCommonOptions(cmd, &awsFlags.commonScanFlags)

	ctx, cancel := withScanTimeout(cmd.Context(), common.timeout, context.WithTimeout)
	defer cancel()

	// Resolve profile from flag or config
	prof := awsFlags.profile
	if prof == "" {
		prof = cfg.Profile
	}

	slog.Info("Starting AWS IAM audit", "profile", prof, "stale_days", awsFlags.staleDays)

	// Initialize AWS client
	region, err := resolveAWSRegion(awsFlags.region, cfg.Regions)
	if err != nil {
		return err
	}

	client, err := awsscanner.NewClient(ctx, prof, region)
	if err != nil {
		return enhanceAWSClientError(err)
	}

	// Build scan config
	scanCfg := common.scanConfig
	scanCfg.IncludeServiceLinkedRoles = awsFlags.includeServiceLinkedRoles // WO-44@v2: carry the AWS-only operator choice.

	// Run AWS IAM scan
	scanner := awsscanner.NewAWSScanner(client, scanCfg)
	result, err := scanner.ScanAll(ctx)
	if err != nil {
		return enhanceError("scan AWS IAM", err)
	}

	// WO-25@v2: delegate the provider-independent post-scan pipeline.
	return analyzeAndReport(result, postScanOptions{
		cloud: "aws", targetType: "aws-account", targetID: prof,
		staleDays: common.scanConfig.StaleDays, severityMin: common.severityMin,
		format: common.format, outputFile: common.outputFile, timestamp: time.Now().UTC(),
	})
}

// WO-16@v2: explicit CLI flags win even when their values equal documented defaults.
func applyAWSConfigDefaults(cmd *cobra.Command) {
	// WO-17: retain a policy-free compatibility wrapper around the shared resolver.
	applyCommonConfigDefaults(cmd, &awsFlags.commonScanFlags)
	if !cmd.Flags().Changed("include-service-linked-roles") {
		awsFlags.includeServiceLinkedRoles = cfg.IncludeServiceLinkedRoles // WO-44@v2: explicit CLI false must beat YAML true.
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
// WO-103@v3: explicit CLI selection wins before config validation and SDK fallback.
func resolveAWSRegion(flagRegion string, regions []string) (string, error) {
	if flagRegion != "" {
		return flagRegion, nil
	}

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

// WO-103@v3: turn only the SDK missing-region failure into an actionable command error.
func enhanceAWSClientError(err error) error {
	if !strings.Contains(strings.ToLower(err.Error()), "missing region") {
		return enhanceError("initialize AWS client", err)
	}
	return fmt.Errorf("initialize AWS client: AWS region unavailable; set --region, AWS_REGION, or config regions: %w", err)
}

func computeTargetHash(profile string) string {
	return fmt.Sprintf("sha256:%x", sha256Sum(fmt.Sprintf("profile:%s", profile)))
}
