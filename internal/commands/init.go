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

// WO-85@v2: keep generated next steps usable outside a source checkout.
const azureSetupDocsURL = "https://github.com/ppiankov/iamspectre/blob/main/docs/cli-reference.md#azure-authentication"

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
	azurePermsPath := "iamspectre-azure-permissions.json"

	wrote := 0

	if err := writeIfNotExists(configPath, sampleConfig, initFlags.force); err != nil {
		return err
	}
	wrote++

	if err := writeIfNotExists(awsPolicyPath, sampleAWSIAMPolicy, initFlags.force); err != nil {
		return err
	}
	wrote++

	if err := writeIfNotExists(azurePermsPath, sampleAzureGraphPermissions, initFlags.force); err != nil {
		return err
	}
	wrote++

	if wrote > 0 {
		fmt.Printf("Created %s, %s, and %s\n", configPath, awsPolicyPath, azurePermsPath)
		fmt.Println("\nNext steps:")
		fmt.Println("  1. Edit .iamspectre.yaml to customize audit settings")
		fmt.Println("  2. AWS: Apply iamspectre-aws-policy.json to your IAM role/user")
		fmt.Printf("  3. Azure: Choose delegated or app-only setup: %s\n", azureSetupDocsURL) // WO-85@v2: distinguish credentials from app grants.
		fmt.Println("  4. Run: iamspectre aws | iamspectre gcp | iamspectre azure")
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

# Azure tenant ID (or set AZURE_TENANT_ID env var)
# tenant_id: my-azure-tenant-id

# Inactivity threshold (days)
stale_days: 90

# Minimum severity to report: critical, high, medium, low
severity_min: low

# Output format: text, json, sarif, spectrehub
format: text

# Scan timeout
timeout: 5m

# Include unused AWS service-linked roles (default: false)
include_service_linked_roles: false

# Resources to exclude from scanning
# exclude:
#   principals:
#     - "arn:aws:iam::123456789012:user/admin"
#   resource_ids:
#     - "i-0abc123def456"
`

// WO-85@v2: Azure CLI consumes the required-resource-access array directly.
const sampleAzureGraphPermissions = `[
  {
    "resourceAppId": "00000003-0000-0000-c000-000000000000",
    "resourceAccess": [
      { "id": "df021288-bdef-4463-88db-98f22de89214", "type": "Role" },
      { "id": "9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30", "type": "Role" },
      { "id": "b0afded3-3588-46d8-8b3d-9842eff778da", "type": "Role" },
      { "id": "483bed4a-2ad3-4361-a73b-c83ccdbdc53c", "type": "Role" },
      { "id": "38d9df27-64da-44fd-b7c5-a6fbac20248f", "type": "Role" },
      { "id": "246dd0d5-5bd0-4def-940b-0421030a5b68", "type": "Role" }
    ]
  }
]
`

// WO-113@v3: generated credentials include the read-only role enrichment prerequisite.
// WO-127@v3: generated credentials cover the three read-only regional Pod Identity calls.
const sampleAWSIAMPolicy = `{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "IamSpectreReadOnly",
      "Effect": "Allow",
      "Action": [
        "eks:DescribePodIdentityAssociation",
        "eks:ListClusters",
        "eks:ListPodIdentityAssociations",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport",
        "iam:ListUsers",
        "iam:ListRoles",
        "iam:GetRole",
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
