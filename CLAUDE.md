# iamspectre

Cross-cloud IAM auditor. Finds unused, over-permissioned, and stale identities across AWS and GCP.

## Commands

- `make build` — Build binary to ./bin/iamspectre
- `make test` — Run tests with -race flag
- `make lint` — Run golangci-lint
- `make fmt` — Format with gofmt/goimports
- `make clean` — Clean build artifacts

## Architecture

- Entry: cmd/iamspectre/main.go — minimal, single Execute() call delegates to internal/commands
- commands — Cobra CLI commands (aws, gcp, init, version) and shared helpers
- iam — Shared types: Finding, Severity (critical/high/medium/low), ResourceType, ScanResult
- aws — AWS IAM scanners: users (credential report), roles, policies, cross-account trust
- gcp — GCP IAM scanners: service accounts, keys, bindings
- analyzer — Finding classification, severity filtering, summary generation
- report — Text, JSON (spectre/v1), SARIF, SpectreHub output formatters
- config — .iamspectre.yaml config file loading
- logging — slog initialization

## Conventions

- Minimal main.go — single Execute() call
- Internal packages: short single-word names (iam, aws, gcp, analyzer, report, commands)
- Struct-based domain models with json tags
- Interface-based AWS/GCP client mocking for tests
- All cloud API calls go through context-aware methods
- Bounded concurrency: max 5 concurrent scanner goroutines

## Anti-Patterns

- NEVER modify or delete IAM resources — read-only auditing only
- NEVER make cloud API calls without context
- NEVER skip error handling
- NEVER use init() functions unless absolutely necessary
- NEVER use global mutable state
- NEVER hardcode cloud credentials

## Verification

- Run `make test` after code changes (includes -race)
- Run `make lint` before marking complete
- Run `go vet ./...` for suspicious constructs
