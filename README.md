# IAMSpectre

[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)
[![CI](https://github.com/ppiankov/iamspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/iamspectre/actions/workflows/ci.yml)
[![Go 1.25+](https://img.shields.io/badge/Go-1.25+-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Cross-cloud IAM auditor. Finds unused, over-permissioned, and stale identities across AWS and GCP.

Part of the [Spectre family](https://github.com/ppiankov) of infrastructure cleanup tools.

## What it is

IAMSpectre scans IAM resources across AWS and GCP for security and compliance risks. It checks credential reports, key ages, role usage, policy documents, and service account bindings to identify stale users, unused roles, wildcard policies, missing MFA, and overprivileged service accounts. Each finding includes a severity level and actionable recommendation.

## What it is NOT

- Not a remediation tool. It reports findings and lets you decide what to do.
- Not a real-time monitor. IAMSpectre is a point-in-time scanner, not a daemon.
- Not a cost estimator. IAM findings are security/compliance risks, not dollar waste.
- Not an access management tool. It does not create, modify, or delete IAM resources.
- Not a vulnerability scanner. It checks IAM hygiene, not CVEs or network exposure.
- Not a CSPM replacement. It focuses specifically on identity and access, not full cloud posture.

## Philosophy

*Principiis obsta* -- resist the beginnings.

IAM is the #1 compliance pain point. Every SOC2/ISO audit asks "who has access to what and when was it last used?" Stale credentials, wildcard policies, and missing MFA are not theoretical risks -- they are the attack surface. IAMSpectre surfaces these conditions early so they can be addressed before they become incidents.

The tool presents evidence and lets humans decide. It does not auto-revoke permissions, does not guess intent, and does not use ML where deterministic checks suffice.

## Installation

```bash
# Homebrew
brew install ppiankov/tap/iamspectre

# Docker
docker pull ghcr.io/ppiankov/iamspectre:latest

# From source
git clone https://github.com/ppiankov/iamspectre.git
cd iamspectre && make build
```

## Quick start

```bash
# Audit AWS IAM
iamspectre aws --profile production

# Audit GCP IAM
iamspectre gcp --project my-project-id

# JSON output for automation
iamspectre aws --format json --output report.json

# SARIF output for GitHub Security tab
iamspectre aws --format sarif --output results.sarif

# Only show high and critical findings
iamspectre aws --severity-min high

# Generate config and IAM policy
iamspectre init
```

Requires valid cloud credentials (AWS profile/environment or GCP application-default credentials).

## What it audits

### AWS

| Resource | Finding | Signal | Severity |
|----------|---------|--------|----------|
| IAM users | `STALE_USER` | No console login > stale_days | high |
| IAM users | `STALE_ACCESS_KEY` | Access key unused > stale_days | high |
| IAM users | `NO_MFA` | Console user without MFA | critical |
| IAM roles | `UNUSED_ROLE` | Not assumed > stale_days | medium |
| IAM roles | `CROSS_ACCOUNT_TRUST` | External account in trust policy without conditions | critical |
| IAM policies | `UNATTACHED_POLICY` | Customer-managed, not attached to anything | medium |
| IAM policies | `WILDCARD_POLICY` | Action or Resource is `*` in Allow statement | critical |

### GCP

| Resource | Finding | Signal | Severity |
|----------|---------|--------|----------|
| Service accounts | `STALE_SA` | Disabled service account | high |
| Service account keys | `STALE_SA_KEY` | User-managed key older than stale_days | critical |
| IAM bindings | `OVERPRIVILEGED_SA` | Service account with Owner/Editor role | critical |

## Usage

### AWS

```bash
iamspectre aws [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--profile` | | AWS profile name |
| `--stale-days` | `90` | Inactivity threshold (days) |
| `--severity-min` | `low` | Minimum severity: critical, high, medium, low |
| `--format` | `text` | Output format: text, json, sarif, spectrehub |
| `-o, --output` | stdout | Output file path |
| `--timeout` | `5m` | Scan timeout |

### GCP

```bash
iamspectre gcp [flags]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--project` | | GCP project ID (required) |
| `--stale-days` | `90` | Inactivity threshold (days) |
| `--severity-min` | `low` | Minimum severity: critical, high, medium, low |
| `--format` | `text` | Output format: text, json, sarif, spectrehub |
| `-o, --output` | stdout | Output file path |
| `--timeout` | `5m` | Scan timeout |

### Other commands

| Command | Description |
|---------|-------------|
| `iamspectre init` | Generate `.iamspectre.yaml` config and IAM policy |
| `iamspectre version` | Print version, commit, and build date |

## Configuration

IAMSpectre reads `.iamspectre.yaml` from the current directory:

```yaml
profile: production
project: my-gcp-project
stale_days: 90
severity_min: medium
format: json
exclude:
  principals:
    - ci-bot
    - terraform@my-project.iam.gserviceaccount.com
  resource_ids:
    - arn:aws:iam::123456789012:role/service-linked-role
```

Generate a sample config with `iamspectre init`.

## IAM permissions

IAMSpectre requires read-only access. Run `iamspectre init` to generate the minimal IAM policy.

### AWS

- `iam:GenerateCredentialReport`, `iam:GetCredentialReport`
- `iam:ListRoles`, `iam:ListPolicies`, `iam:GetPolicyVersion`
- `sts:GetCallerIdentity`

### GCP

- `iam.serviceAccounts.list`, `iam.serviceAccountKeys.list`
- `resourcemanager.projects.getIamPolicy`

## Output formats

**Text** (default): Human-readable table with severity, resource, and recommendation.

**JSON** (`--format json`): `spectre/v1` envelope with findings and summary.

**SARIF** (`--format sarif`): SARIF v2.1.0 for GitHub Security tab integration.

**SpectreHub** (`--format spectrehub`): `spectre/v1` envelope for SpectreHub ingestion.

## Architecture

```
iamspectre/
├── cmd/iamspectre/main.go          # Entry point (LDFLAGS)
├── internal/
│   ├── commands/                   # Cobra CLI: aws, gcp, init, version
│   ├── iam/                        # Shared types: Finding, Severity, Scanner
│   ├── aws/                        # AWS scanners: users, roles, policies
│   │   ├── credential_report.go    # Credential Report CSV parser
│   │   ├── user.go                 # Stale users, stale keys, no MFA
│   │   ├── role.go                 # Unused roles, cross-account trust
│   │   ├── policy.go               # Unattached, wildcard policies
│   │   ├── policy_document.go      # Policy document parser (StringOrSlice)
│   │   └── scanner.go              # AWS scanner orchestrator
│   ├── gcp/                        # GCP scanners: service accounts, bindings
│   │   ├── service_account.go      # Stale SAs, stale SA keys
│   │   ├── binding.go              # Overprivileged SA bindings
│   │   └── scanner.go              # GCP scanner orchestrator
│   ├── analyzer/                   # Severity filtering, summary aggregation
│   └── report/                     # Text, JSON, SARIF, SpectreHub reporters
├── Makefile
└── go.mod
```

Key design decisions:

- Subcommand-per-cloud (`aws`, `gcp`) because each cloud has fundamentally different IAM models.
- `internal/iam/` holds shared types (Finding, Severity, Scanner interface) used by both clouds.
- Each scanner implements `Scanner` interface: `Scan(ctx, ScanConfig) (*ScanResult, error)`.
- Bounded concurrency via `errgroup.SetLimit(5)`. Scanner errors are collected, not fatal.
- AWS credential report is fetched once and shared across user-level checks.
- AWS policy documents handle the "string or array" pattern via custom `StringOrSlice` JSON unmarshaler.
- GCP uses `google.golang.org/api` REST clients with interface-based mocking.
- Severity levels: critical > high > medium > low (numeric rank for filtering).
- `Recommendation` field instead of cost estimation -- IAM findings are security risks, not dollar waste.

## Project Status

**Status: Beta** · **v0.1.0** · Pre-1.0

| Milestone | Status |
|-----------|--------|
| AWS scanners: users, roles, policies (7 finding types) | Complete |
| GCP scanners: service accounts, bindings (3 finding types) | Complete |
| Credential report parsing and key age analysis | Complete |
| Cross-account trust and wildcard policy detection | Complete |
| 4 output formats (text, JSON, SARIF, SpectreHub) | Complete |
| Config file + init command with IAM policy generation | Complete |
| CI pipeline (test/lint/build) | Complete |
| Homebrew + Docker distribution | Complete |
| API stability guarantees | Partial |
| v1.0 release | Planned |

Pre-1.0: CLI flags and config schemas may change between minor versions. JSON output structure (`spectre/v1`) is stable.

## Known limitations

- **Single account/project.** Scans one AWS account or GCP project at a time.
- **No Policy Analyzer integration.** GCP service account "last used" detection relies on disabled status and key age, not the Policy Analyzer activity API.
- **No group membership analysis.** Does not trace IAM group memberships to find inherited permissions.
- **No resource-level policy analysis.** Only checks IAM policies, not S3 bucket policies, KMS key policies, etc.
- **Trust policy parsing.** Cross-account trust detection checks `Principal.AWS` but does not evaluate complex condition expressions.
- **GCP binding scope.** Only checks project-level IAM bindings, not folder or organization-level.

## License

MIT License -- see [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues and pull requests welcome.

Part of the Spectre family:
[AWSSpectre](https://github.com/ppiankov/awsspectre) |
[S3Spectre](https://github.com/ppiankov/s3spectre) |
[VaultSpectre](https://github.com/ppiankov/vaultspectre) |
[ClickSpectre](https://github.com/ppiankov/clickspectre) |
[KafkaSpectre](https://github.com/ppiankov/kafkaspectre)
