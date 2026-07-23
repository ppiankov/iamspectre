# Changelog

All notable changes to IAMSpectre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.1] - 2026-07-23

### Fixed

- Release workflows now guard against duplicate tag runs with tag-normalized concurrency and built-in-token single release dispatch from CI
- Release now hard-fails when the checked-out `CHANGELOG.md` lacks a `## [<tag>]` section before publishing assets
- Added contract tests under `internal/release/workflow_contract_test.go` for release trigger shape, dispatch flow, changelog presence, and asset/formula sequencing

## [0.6.0] - 2026-07-23

### Added

- AWS EKS Pod Identity scanning: `iamspectre aws` now enumerates EKS Pod Identity associations across the resolved region (`eks:ListClusters` → `eks:ListPodIdentityAssociations` → `eks:DescribePodIdentityAssociation`) and records them as observed IAM-role trust evidence. Incomplete or throttled collection is reported as a bounded coverage gap (capability `aws_eks_pod_identity_associations`), never as a false negative
- `iamspectre init` generated IAM policy now includes the three read-only EKS actions required for Pod Identity scanning (`eks:ListClusters`, `eks:ListPodIdentityAssociations`, `eks:DescribePodIdentityAssociation`); the CLI-reference permission list is kept in exact sync with the generated policy by a contract test

### Changed

- The AWS scan now carries an internal positive-evidence plane (observed IAM trust paths, role activity, and Pod Identity associations) used for cross-tool correlation; default findings, severities, and report output are unchanged

### Fixed

- A missing or unresolved AWS region no longer aborts the entire IAM audit: EKS Pod Identity collection degrades to a coverage gap while account-global IAM findings (users, roles, policies) are still reported
- EKS Pod Identity Describe throttling or access-denial reduces reported coverage for the affected region instead of failing the scan

## [0.5.3] - 2026-07-22

### Fixed

- AWS unused-role detection is restored: `ListRoles` does not return `RoleLastUsed`, so the scanner now fetches it per role via `GetRole` when the list response omits it; roles without usable usage evidence still degrade to a coverage gap rather than a false finding
- Microsoft Graph request errors no longer include the request URL, so tenant identifiers and query parameters cannot leak through error output
- README linked SpectreHub to a repository that is not publicly reachable; it now points to https://spectrehub.dev

## [0.5.2] - 2026-07-22

### Added

- `iamspectre aws --region` flag to set the SDK region explicitly (precedence: flag, then config, then the SDK default chain)

### Fixed

- AWS scans no longer fail with a cryptic "Missing Region" error when no region is configured; the error is now actionable and names how to set one
- README documented a nonexistent `scan --provider` command; corrected to the real per-cloud commands (`aws`, `gcp`, `azure`), with a test that keeps the docs aligned with the registered commands
- Azure setup documentation now lists the exact Microsoft Graph permissions and directory roles required, and correctly separates the Entra ID P1/P2 license requirement (for sign-in activity) from the permission-scope requirement (for MFA and other reads)
- Azure MFA and security-defaults checks report a Graph 403 (missing permission or license) as a bounded coverage gap instead of one error per user, so an under-permissioned scan is reported as incomplete rather than flooded with errors

## [0.5.1] - 2026-07-21

### Fixed

- Azure user checks (MFA, guest, legacy-auth) now still run when sign-in activity is unavailable on non-premium tenants: base user fields are fetched independently and missing sign-in activity is reported as a coverage gap instead of failing the whole user scan
- GCP: the local Google APIs Service Agent's expected Editor grant is no longer flagged as over-privileged (it is provider-managed and cannot be changed), while user-managed default accounts remain actionable; classification fails closed as a coverage gap if the project number cannot be resolved
- Partial audits (some scanners failed, others succeeded) now report available evidence and then exit non-zero with a clear "scan incomplete" reason, so an incomplete audit no longer looks clean
- Scanner results returned alongside an error are preserved rather than discarded, so one failing evidence source no longer erases findings from other sources

## [0.5.0] - 2026-07-21

### Added

- `report` output format (`--format report`): a customer-deliverable Markdown report with an executive summary, per-finding evidence and full (untruncated) recommendations, a coverage-gap section, and a scope/methodology footer

### Changed

- `WILDCARD_POLICY` severity is now graded by correlated statement risk: a wildcard action scoped to a specific resource or bounded by a condition is no longer rated critical; critical is reserved for admin-equivalent (unscoped action-and-resource) grants
- AWS roles whose `RoleLastUsed` evidence is unavailable are now reported as a single deduplicated coverage-gap observation instead of one error per role, so large accounts no longer produce a flood of error lines

## [0.4.2] - 2026-07-21

### Added

- `--version` (and `-v`) flag now prints version information, matching the existing `version` subcommand

### Changed

- macOS release binaries are now signed and notarized before archiving, so downloads pass Gatekeeper without a manual quarantine-removal step
- Stale GCP service-account keys are graded from evidence rather than age alone; age-only findings are reported at medium rather than critical severity

### Fixed

- Microsoft Graph error details are preserved so authorization failures can be distinguished from license gating
- GCP audit no longer double-counts principals scanned across concurrent scanners
- GCP key-list failures and malformed key timestamps are surfaced as coverage gaps instead of being silently skipped
- The local Google APIs Service Agent's expected Editor grant is no longer reported as an over-privileged finding (it is provider-managed and cannot be changed); user-restrictable default accounts remain actionable

## [0.4.1] - 2026-07-20

### Fixed

- GCP disabled service-account keys are no longer reported as stale keys — a disabled key cannot present stale-credential exposure
- Azure user activity now uses complete sign-in evidence and reports member and guest coverage gaps independently, so exclusions and missing evidence no longer distort either count
- Azure MFA detection classifies authentication methods against an explicit allowlist of families that can actually satisfy MFA, and grades guest evidence conservatively
- Disabled Azure Security Defaults is reported as an indeterminate legacy-auth risk ("Conditional Access not evaluated, coverage unknown") at low severity rather than as proven legacy-auth exposure
- Dangerous Azure app-role assignments are matched only when scoped to Microsoft Graph's resource identity, and are not classified when that identity cannot be resolved — preventing misattribution from tenant-local apps reusing the same role GUIDs

## [0.4.0] - 2026-07-20

### Added

- Coverage manifest: scan output now carries a second plane alongside actionable findings — a deduplicated, order-independent manifest of evidence gaps (capability, cause, scope, and affected finding classes) so missing evidence is reported explicitly instead of silently narrowing coverage
- `DISABLED_SA` finding: a disabled GCP service account is reported as an informational, low-severity lifecycle fact (disabling is the recommended reversible pre-deletion state), preserving the observation without high-severity delete advice

### Changed

- GCP disabled service accounts are no longer reported as `STALE_SA` with delete advice; staleness is driven only by key evidence, and the disabled fact and stale-key evidence are independent axes (both can be reported for the same account)
- Azure `STALE_SP` is no longer emitted as a severity finding from Microsoft Graph beta sign-in data; service-principal sign-in activity is now reported as a coverage gap (and used only to enrich role-activity evidence)
- Azure `UNUSED_ROLE` distinguishes principal inactivity from missing sign-in evidence rather than treating absence as inactivity

### Fixed

- Azure service-principal coverage counts now exclude out-of-scope principals so exclusions no longer inflate evidence-gap totals
- SpectreHub envelope projection no longer loses resource identity for partial or unidentified scans

## [0.3.0] - 2026-07-20

### Added

- `INACTIVE_IAM_USER` finding for whole-principal dormancy (no console *and* no access-key activity), distinct from console-credential staleness

### Changed

- `STALE_USER` now reflects console-credential staleness only — access-key activity no longer masks a dormant console credential
- `WILDCARD_POLICY` is now evidence-aware: severity is graded using a pinned action resource-applicability catalog and a condition-boundedness assessment, so mandatory (no resource-level support), resource-scoped, and condition-bounded wildcards are no longer uniformly rated critical
- Credential-report findings are evaluated against the report's generation time rather than scan time

### Fixed

- `UNUSED_ROLE` no longer reports a role as unused when `RoleLastUsed` evidence is unavailable (missing evidence is not proof of never-used)
- `NO_MFA` distinguishes API-only users (no console password) from console users
- `STALE_ACCESS_KEY` handles never-recorded-use and key-rotation evidence explicitly

## [0.2.4] - 2026-07-20

### Fixed

- AWS policies whose `Statement` is a single object (not an array) are now parsed instead of silently skipped, closing a policy-analysis coverage gap
- Text report is now sorted by severity (critical first) and preserves the full resource identifier (UTF-8-safe truncation)
- AWS service-linked and IAM Identity Center roles are no longer flagged as unused with un-actionable "delete" advice — they are suppressed by default, down-ranked to low severity, and given lifecycle-appropriate guidance
- Unused-role findings no longer report a fabricated age when a role's creation date is unavailable

### Added

- `include_service_linked_roles` config key to opt AWS-owned roles back into unused-role scanning
- Restraint-first IAM action assessment: case-insensitive `*`/`?` action matching and sensitive-action detection, with explicit indeterminate handling for `NotAction` complements, `NotResource`, and policy variables

## [0.2.3] - 2026-07-19

### Fixed

- SARIF reporter now surfaces sub-scanner errors (previously dropped), so partial-scan failures are visible to CI/CD consumers
- SARIF driver name now reflects the actual tool metadata instead of a hardcoded literal, and canonical SARIF properties are protected from metadata collisions
- Text reporter now includes the stable finding ID, scan timestamp, and active severity-min filter, and preserves scan errors when no findings are present
- Cross-account trust findings are gated on assume-role actions to reduce false positives

### Added

- Wildcard-principal detection in cross-account role trust policies
- Restraint-first severity assessment: findings may carry an evidence tier, reachability, blast radius, and per-authorization-layer evaluation, scored by a versioned severity rubric; findings without assessment metadata keep their existing severity (no change to current output)

## [0.2.2] - 2026-07-19

### Fixed

- Honor `exclude.principals` and `exclude.resource_ids` config keys across the `aws`, `gcp`, and `azure` commands (previously parsed but ignored)
- Honor the `timeout` config key across all cloud commands when the `--timeout` flag is not explicitly set
- Honor the `regions` config key for AWS IAM scans: a single region sets the SDK region; multiple distinct regions fail closed (AWS IAM is account-global)
- Azure `include-guests` now excludes guest users before scanning when disabled, and reports only the principals actually scanned
- Explicit CLI flags now take precedence over config-file values even when set to a value equal to the built-in default

### Changed

- Consolidated duplicated per-provider scan orchestration, config resolution, and staleness logic into shared internal helpers (no change in behavior or output)

## [0.2.1] - 2026-07-18

### Added

- Windows quick-start instructions in README (download, extract, PATH, PowerShell usage)
- Windows build and race-test legs in CI (ubuntu-latest and windows-latest matrix)

### Fixed

- Azure Graph client lint failures: unchecked `Close()` returns and a capitalized error string

## [0.2.0] - 2026-03-01

### Added

- Azure AD / Entra ID scanning: users, guest users, app registrations, service principals, directory roles
- 10 Azure finding types: STALE_USER, STALE_GUEST_USER, NO_MFA, LEGACY_AUTH, STALE_APP, EXPIRED_SECRET, EXPIRING_SECRET, STALE_SP, OVERPRIVILEGED_APP, UNUSED_ROLE
- `iamspectre azure` subcommand with `--tenant`, `--stale-days`, `--severity-min`, `--format`, `--include-guests` flags
- Microsoft Graph API client using `azidentity` + direct REST (lightweight, no kiota dependency)
- Azure AD Premium P1 graceful degradation: stale user detection skipped when signInActivity unavailable, MFA and credential checks still work
- Security defaults check for legacy authentication risk detection
- Overprivileged app detection using static map of known dangerous Microsoft Graph API role GUIDs
- Azure Graph API permissions template generated by `iamspectre init`
- `tenant_id` config field in `.iamspectre.yaml`
- Azure-specific error hints for AADSTS and Authorization_RequestDenied errors
- 7 new SARIF rules for Azure finding types

## [0.1.0] - 2026-02-25

### Added

- AWS IAM scanning: users (credential report), roles (ListRoles), policies (ListPolicies + GetPolicyVersion)
- 7 AWS finding types: STALE_USER, STALE_ACCESS_KEY, NO_MFA, UNUSED_ROLE, CROSS_ACCOUNT_TRUST, UNATTACHED_POLICY, WILDCARD_POLICY
- GCP IAM scanning: service accounts (ListServiceAccounts + ListServiceAccountKeys), project IAM bindings (GetIamPolicy)
- 3 GCP finding types: STALE_SA, STALE_SA_KEY, OVERPRIVILEGED_SA
- 4 severity levels: critical, high, medium, low with `--severity-min` filtering
- Analyzer with severity filtering and summary aggregation (by severity, resource type, finding ID)
- 4 output formats: text (terminal table), JSON (`spectre/v1` envelope), SARIF (v2.1.0), SpectreHub (`spectre/v1`)
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

[0.2.0]: https://github.com/ppiankov/iamspectre/releases/tag/v0.2.0
[0.1.0]: https://github.com/ppiankov/iamspectre/releases/tag/v0.1.0
