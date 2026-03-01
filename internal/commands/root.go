package commands

import (
	"log/slog"

	"github.com/ppiankov/iamspectre/internal/config"
	"github.com/ppiankov/iamspectre/internal/logging"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	version string
	commit  string
	date    string
	cfg     config.Config
)

var rootCmd = &cobra.Command{
	Use:   "iamspectre",
	Short: "iamspectre — cross-cloud IAM auditor",
	Long: `iamspectre audits IAM roles, policies, and service accounts across AWS, GCP,
and Azure AD for unused, over-permissioned, and stale identities.

Each finding includes a severity level and actionable recommendation.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		logging.Init(verbose)
		loaded, err := config.Load(".")
		if err != nil {
			slog.Warn("Failed to load config file", "error", err)
		} else {
			cfg = loaded
		}
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

// Execute runs the root command with injected build info.
func Execute(v, c, d string) error {
	version = v
	commit = c
	date = d
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	rootCmd.AddCommand(awsCmd)
	rootCmd.AddCommand(gcpCmd)
	rootCmd.AddCommand(azureCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(versionCmd)
}
