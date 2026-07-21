package commands

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/ppiankov/iamspectre/internal/config"
	"github.com/spf13/cobra"
)

// WO-91@v2: isolate executions of the package-level Cobra command across deterministic tests.
func preserveRootCommandState(t *testing.T) {
	t.Helper()

	oldOut := rootCmd.OutOrStdout()
	oldErr := rootCmd.ErrOrStderr()
	oldVersion := rootCmd.Version
	oldVersionTemplate := rootCmd.VersionTemplate()
	oldPersistentPreRun := rootCmd.PersistentPreRun
	oldPersistentPreRunE := rootCmd.PersistentPreRunE
	oldBuildVersion, oldCommit, oldDate := version, commit, date
	oldVerbose, oldConfig := verbose, cfg

	verboseFlag := rootCmd.PersistentFlags().Lookup("verbose")
	oldVerboseValue, oldVerboseChanged := verboseFlag.Value.String(), verboseFlag.Changed
	resetRootBoolFlag := func(name string) {
		if flag := rootCmd.Flags().Lookup(name); flag != nil {
			if err := flag.Value.Set("false"); err != nil {
				t.Fatalf("reset %s flag: %v", name, err)
			}
			flag.Changed = false
		}
	}
	resetRootBoolFlag("version")
	resetRootBoolFlag("help")

	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(oldOut)
		rootCmd.SetErr(oldErr)
		rootCmd.Version = oldVersion
		rootCmd.SetVersionTemplate(oldVersionTemplate)
		rootCmd.PersistentPreRun = oldPersistentPreRun
		rootCmd.PersistentPreRunE = oldPersistentPreRunE
		version, commit, date = oldBuildVersion, oldCommit, oldDate
		verbose, cfg = oldVerbose, oldConfig
		if err := verboseFlag.Value.Set(oldVerboseValue); err != nil {
			t.Fatalf("restore verbose flag: %v", err)
		}
		verboseFlag.Changed = oldVerboseChanged
		resetRootBoolFlag("version")
		resetRootBoolFlag("help")
	})
}

// WO-91@v2: every supported version entry point must share exact output and bypass setup for flags.
func TestRootVersionEntryPoints(t *testing.T) {
	const want = "iamspectre 1.2.3 (commit: abc, built: date)\n"
	tests := []struct {
		name           string
		args           []string
		wantPreRunCall int
	}{
		{name: "long flag", args: []string{"--version"}},
		{name: "short flag", args: []string{"-v"}},
		{name: "subcommand", args: []string{"version"}, wantPreRunCall: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preserveRootCommandState(t)

			var stdout, stderr bytes.Buffer
			preRunCalls := 0
			rootCmd.SetArgs(tt.args)
			rootCmd.SetOut(&stdout)
			rootCmd.SetErr(&stderr)
			rootCmd.PersistentPreRun = func(_ *cobra.Command, _ []string) {
				preRunCalls++
			}

			if err := Execute("1.2.3", "abc", "date"); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if rootCmd.PersistentFlags().Lookup("version") != nil {
				t.Fatal("version flag became persistent")
			}
			if got := stdout.String(); got != want {
				t.Fatalf("stdout = %q, want %q", got, want)
			}
			if got := stderr.String(); got != "" {
				t.Fatalf("stderr = %q, want empty", got)
			}
			if preRunCalls != tt.wantPreRunCall {
				t.Fatalf("PersistentPreRun calls = %d, want %d", preRunCalls, tt.wantPreRunCall)
			}
		})
	}
}

// WO-91@v2: adding root-local aliases must retain the discoverable version subcommand.
func TestRootHelpRetainsVersionSubcommand(t *testing.T) {
	preserveRootCommandState(t)

	var stdout, stderr bytes.Buffer
	rootCmd.SetArgs([]string{"--help"})
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)

	if err := Execute("1.2.3", "abc", "date"); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !strings.Contains(stdout.String(), "  version") {
		t.Fatalf("help missing version subcommand: %q", stdout.String())
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("stderr = %q, want empty", got)
	}
}

// WO-101@v3: pin root config loading for both absent and malformed test-owned files.
func TestRootPersistentPreRunConfigOutcomes(t *testing.T) {
	previousLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previousLogger) })

	tests := []struct {
		name       string
		configBody string
		wantStale  int
	}{
		{name: "absent config", wantStale: 0},
		{name: "malformed config preserves prior state", configBody: "stale_days: [", wantStale: 123},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			preserveRootCommandState(t)
			t.Chdir(t.TempDir())
			if test.configBody != "" {
				if err := os.WriteFile(".iamspectre.yaml", []byte(test.configBody), 0o644); err != nil {
					t.Fatalf("write config: %v", err)
				}
			}

			cfg = config.Config{StaleDays: 123}
			var output bytes.Buffer
			rootCmd.SetArgs([]string{"version"})
			rootCmd.SetOut(&output)
			if err := Execute("1.2.3", "abc", "date"); err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if cfg.StaleDays != test.wantStale {
				t.Fatalf("stale days = %d, want %d", cfg.StaleDays, test.wantStale)
			}
			if output.String() != "iamspectre 1.2.3 (commit: abc, built: date)\n" {
				t.Fatalf("version output = %q", output.String())
			}
		})
	}
}
