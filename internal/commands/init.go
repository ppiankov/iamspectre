package commands

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var initFlags struct {
	force bool
}

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Generate sample config and IAM policies",
	Long:  `Creates a sample .iamspectre.yaml config file and IAM policy files for read-only access.`,
	RunE:  runInit,
}

func init() {
	initCmd.Flags().BoolVar(&initFlags.force, "force", false, "Overwrite existing files")
}

func runInit(_ *cobra.Command, _ []string) error {
	configPath := ".iamspectre.yaml"
	awsPolicyPath := "iamspectre-aws-policy.json"

	wrote := 0

	if err := writeIfNotExists(configPath, sampleConfig, initFlags.force); err != nil {
		return err
	}
	wrote++

	if err := writeIfNotExists(awsPolicyPath, sampleAWSIAMPolicy, initFlags.force); err != nil {
		return err
	}
	wrote++

	if wrote > 0 {
		fmt.Printf("Created %s and %s\n", configPath, awsPolicyPath)
		fmt.Println("\nNext steps:")
		fmt.Println("  1. Edit .iamspectre.yaml to customize audit settings")
		fmt.Println("  2. Apply iamspectre-aws-policy.json to your AWS IAM role/user")
		fmt.Println("  3. Run: iamspectre aws")
	}
	return nil
}

func writeIfNotExists(path, content string, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("Skipping %s (already exists, use --force to overwrite)\n", path)
			return nil
		}
	}

	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}

	return os.WriteFile(path, []byte(content), 0o644)
}

const sampleConfig = `# iamspectre configuration
# See: https://github.com/ppiankov/iamspectre

# AWS profile (or set AWS_PROFILE env var)
# profile: default

# GCP project ID (or set GOOGLE_CLOUD_PROJECT env var)
# project: my-gcp-project

# Inactivity threshold (days)
stale_days: 90

# Minimum severity to report: critical, high, medium, low
severity_min: low

# Output format: text, json, sarif, spectrehub
format: text

# Scan timeout
timeout: 5m

# Resources to exclude from scanning
# exclude:
#   principals:
#     - "arn:aws:iam::123456789012:user/admin"
#   resource_ids:
#     - "i-0abc123def456"
`

const sampleAWSIAMPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IamSpectreReadOnly",
      "Effect": "Allow",
      "Action": [
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        "iam:GetPolicy",
        "iam:ListAttachedUserPolicies",
        "iam:ListAttachedRolePolicies",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
`
