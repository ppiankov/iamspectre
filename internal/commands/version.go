package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	// WO-91@v2: use Cobra's writer so every version entry point has one output contract.
	Run: func(cmd *cobra.Command, _ []string) {
		cmd.Print(formatVersionLine(version, commit, date))
	},
}

// WO-91@v2: keep the established version bytes identical across flags and the subcommand.
func formatVersionLine(v, c, d string) string {
	return fmt.Sprintf("iamspectre %s (commit: %s, built: %s)\n", v, c, d)
}
