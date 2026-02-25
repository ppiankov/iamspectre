# Changelog

All notable changes to IAMSpectre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-25

### Added

- AWS IAM scanning: users (credential report), roles (ListRoles), policies (ListPolicies + GetPolicyVersion)
- 7 AWS finding types: STALE_USER, STALE_ACCESS_KEY, NO_MFA, UNUSED_ROLE, CROSS_ACCOUNT_TRUST, UNATTACHED_POLICY, WILDCARD_POLICY
- GCP IAM scanning: service accounts (ListServiceAccounts + ListServiceAccountKeys), project IAM bindings (GetIamPolicy)
- 3 GCP finding types: STALE_SA, STALE_SA_KEY, OVERPRIVILEGED_SA
- 4 severity levels: critical, high, medium, low with `--severity-min` filtering
- Analyzer with severity filtering and summary aggregation (by severity, resource type, finding ID)
- 4 output formats: text (terminal table), JSON (`spectre/v1` envelope), SARIF (v2.1.0), SpectreHub (`spectrehub/v1`)
- AWS credential report CSV parser with handling of N/A, not_supported, no_information values
- AWS policy document parser with StringOrSlice and Principal custom JSON unmarshalers
- Cross-account trust detection by comparing trust policy principal account IDs
- Configuration via `.iamspectre.yaml` with `iamspectre init` generator
- IAM policy generator for minimal read-only AWS permissions
- Enhanced error messages with actionable hints for common cloud failures
- Bounded concurrency via errgroup (max 5 concurrent scanner goroutines)
- GoReleaser config for multi-platform releases (Linux, macOS, Windows; amd64, arm64)
- Docker images via multi-stage distroless build with multi-arch manifests on ghcr.io
- Homebrew formula via GoReleaser brews section
- CI/CD: GitHub Actions for build, test, lint, and release

[0.1.0]: https://github.com/ppiankov/iamspectre/releases/tag/v0.1.0
