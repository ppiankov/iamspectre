// Command publish-homebrew-formula renders and publishes an explicit-version
// Homebrew Formula to ppiankov/homebrew-tap.
//
// GoReleaser's built-in `brews` publisher is deprecated in favor of
// `homebrew_casks`, but this repository's packaging policy requires a
// Formula (not a Cask), so this release-only tool takes over that step: it
// reads the checksums GoReleaser already produced, renders Formula/<name>.rb
// with an explicit version, and pushes it to the tap repository. Any
// failure exits non-zero so the release workflow step (and job) fails
// instead of silently skipping the tap update.
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ppiankov/iamspectre/internal/release"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "publish-homebrew-formula:", err)
		os.Exit(1)
	}
}

type config struct {
	projectName   string
	version       string
	homepage      string
	description   string
	license       string
	checksumsPath string
	repoOwner     string
	tapOwner      string
	tapRepo       string
	tapBranch     string
	formulaPath   string
	tokenEnv      string
	dryRun        bool
}

func run(args []string) error {
	cfg, err := parseFlags(args)
	if err != nil {
		return err
	}

	checksumBytes, err := os.ReadFile(cfg.checksumsPath)
	if err != nil {
		return fmt.Errorf("read checksums file %s: %w", cfg.checksumsPath, err)
	}
	checksums, err := release.ParseChecksums(string(checksumBytes))
	if err != nil {
		return fmt.Errorf("parse checksums file %s: %w", cfg.checksumsPath, err)
	}

	formula, err := release.RenderFormula(release.FormulaInput{
		ProjectName: cfg.projectName,
		Version:     cfg.version,
		Homepage:    cfg.homepage,
		Description: cfg.description,
		License:     cfg.license,
		RepoOwner:   cfg.repoOwner,
		Checksums:   checksums,
	})
	if err != nil {
		return fmt.Errorf("render formula: %w", err)
	}

	if cfg.dryRun {
		fmt.Print(formula)
		return nil
	}

	token := os.Getenv(cfg.tokenEnv)
	if token == "" {
		return fmt.Errorf("environment variable %s is not set", cfg.tokenEnv)
	}

	return publish(cfg, token, formula)
}

func parseFlags(args []string) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("publish-homebrew-formula", flag.ContinueOnError)
	fs.StringVar(&cfg.projectName, "project", "iamspectre", "project/binary name")
	fs.StringVar(&cfg.version, "version", "", "release version, semver, with or without leading v (required)")
	fs.StringVar(&cfg.homepage, "homepage", "https://github.com/ppiankov/iamspectre", "formula homepage")
	fs.StringVar(&cfg.description, "description", "Cross-cloud IAM auditor — finds unused, over-permissioned, and stale identities", "formula description")
	fs.StringVar(&cfg.license, "license", "MIT", "formula license")
	fs.StringVar(&cfg.checksumsPath, "checksums", "dist/checksums.txt", "path to GoReleaser's checksums.txt")
	fs.StringVar(&cfg.repoOwner, "repo-owner", "ppiankov", "GitHub owner of the project repo (used in release-asset download URLs)")
	fs.StringVar(&cfg.tapOwner, "tap-owner", "ppiankov", "GitHub owner of the tap repository (independent of -repo-owner)")
	fs.StringVar(&cfg.tapRepo, "tap-repo", "homebrew-tap", "tap repository name")
	fs.StringVar(&cfg.tapBranch, "tap-branch", "main", "tap repository branch to push to")
	fs.StringVar(&cfg.formulaPath, "formula-path", "Formula/iamspectre.rb", "formula path within the tap repository")
	fs.StringVar(&cfg.tokenEnv, "token-env", "HOMEBREW_TAP_TOKEN", "environment variable holding the tap push token")
	fs.BoolVar(&cfg.dryRun, "dry-run", false, "render the formula to stdout and exit without publishing")
	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	cfg.version = strings.TrimPrefix(cfg.version, "v")
	if cfg.version == "" {
		return cfg, fmt.Errorf("-version is required")
	}
	return cfg, nil
}

// publish clones the tap repository, writes the rendered formula, and pushes
// the commit. Every git invocation's combined output has all secrets
// redacted before it can reach an error message.
//
// Authentication is supplied to the clone and push invocations via
// GIT_CONFIG_* environment variables (see gitAuthEnv), not embedded in the
// remote URL and not placed on the git argv: it applies only to that single
// process and is never written to the cloned repo's .git/config.
func publish(cfg config, token, formula string) error {
	tmpDir, err := os.MkdirTemp("", "homebrew-tap-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	cloneURL := fmt.Sprintf("https://github.com/%s/%s.git", cfg.tapOwner, cfg.tapRepo)
	authHeader := "AUTHORIZATION: basic " + base64.StdEncoding.EncodeToString([]byte("x-access-token:"+token))
	secrets := []string{token, authHeader}
	redact := func(s string) string {
		for _, secret := range secrets {
			s = strings.ReplaceAll(s, secret, "***")
		}
		return s
	}

	runGitEnv := func(dir string, extraEnv []string, args ...string) error {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if len(extraEnv) > 0 {
			cmd.Env = append(os.Environ(), extraEnv...)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("git %s: %w: %s", redact(strings.Join(args, " ")), err, redact(string(out)))
		}
		return nil
	}
	runGit := func(dir string, args ...string) error {
		return runGitEnv(dir, nil, args...)
	}
	// runGitAuth is for invocations that talk to the remote (clone, push);
	// add/commit are local-only and never need the auth header.
	//
	// WO-141: the credential travels via GIT_CONFIG_* environment variables
	// (see gitAuthEnv), not a `-c http.extraheader=` argv override, so the
	// base64 Authorization header never appears in the process table
	// (/proc/<pid>/cmdline, ps). It is still never written to the clone's
	// .git/config (WO-139) — GIT_CONFIG_* config applies to this process only.
	runGitAuth := func(dir string, args ...string) error {
		return runGitEnv(dir, gitAuthEnv(authHeader), args...)
	}

	if err := runGitAuth(tmpDir, "clone", "--depth", "1", "--branch", cfg.tapBranch, cloneURL, "."); err != nil {
		return fmt.Errorf("clone tap: %w", err)
	}

	formulaFullPath := filepath.Join(tmpDir, cfg.formulaPath)
	if err := os.MkdirAll(filepath.Dir(formulaFullPath), 0o755); err != nil {
		return fmt.Errorf("create formula directory: %w", err)
	}
	if err := os.WriteFile(formulaFullPath, []byte(formula), 0o644); err != nil {
		return fmt.Errorf("write formula: %w", err)
	}

	if err := runGit(tmpDir, "add", cfg.formulaPath); err != nil {
		return fmt.Errorf("stage formula: %w", err)
	}
	if err := runGit(tmpDir, "-c", "user.name=goreleaserbot", "-c", "user.email=goreleaserbot@users.noreply.github.com",
		"commit", "-m", fmt.Sprintf("Brew formula update for %s version %s", cfg.projectName, cfg.version)); err != nil {
		if strings.Contains(err.Error(), "nothing to commit") {
			fmt.Fprintln(os.Stderr, "publish-homebrew-formula: formula unchanged, nothing to publish")
			return nil
		}
		return fmt.Errorf("commit formula: %w", err)
	}
	if err := runGitAuth(tmpDir, "push", "origin", "HEAD:"+cfg.tapBranch); err != nil {
		return fmt.Errorf("push formula: %w", err)
	}

	fmt.Printf("publish-homebrew-formula: published %s to %s/%s@%s\n", cfg.formulaPath, cfg.tapOwner, cfg.tapRepo, cfg.tapBranch)
	return nil
}

// WO-141: gitAuthEnv returns the GIT_CONFIG_* environment entries that inject
// the tap Authorization header into a single git invocation without placing
// the credential on the process argv or persisting it to the clone's
// .git/config. It is the one place the auth header is wired into git, so a
// regression back to an argv-visible `-c http.extraheader=` override is caught
// by TestGitAuthEnvKeepsCredentialOffArgv.
func gitAuthEnv(authHeader string) []string {
	return []string{
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.extraheader",
		"GIT_CONFIG_VALUE_0=" + authHeader,
	}
}
