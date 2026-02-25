# Contributing to IAMSpectre

Thank you for considering contributing. This document outlines the process.

## Getting started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/iamspectre`
3. Create a feature branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test your changes
6. Commit and push
7. Create a pull request

## Development setup

### Prerequisites

- Go 1.25 or later
- Make
- golangci-lint

### Building

```bash
make build
```

### Running tests

```bash
make test
```

### Linting

```bash
make lint
```

### Code formatting

```bash
make fmt
```

## Project structure

```
iamspectre/
├── cmd/iamspectre/           # CLI entry point
├── internal/
│   ├── commands/             # Cobra CLI commands
│   ├── iam/                  # Shared types (Finding, Severity, Scanner)
│   ├── aws/                  # AWS IAM scanners
│   ├── gcp/                  # GCP IAM scanners
│   ├── analyzer/             # Finding classification + summary
│   ├── report/               # Output formatters
│   ├── config/               # Config file loader
│   └── logging/              # slog initialization
└── docs/                     # Documentation
```

## Contribution areas

### New AWS scanners

Add support for additional AWS IAM checks:
1. Add the finding ID to `internal/iam/types.go`
2. Create or extend a scanner in `internal/aws/`
3. Write tests with interface-based mocks
4. Add SARIF rule in `internal/report/sarif.go`

### New GCP scanners

Add support for additional GCP IAM checks:
1. Add the finding ID to `internal/iam/types.go`
2. Extend the API interface in `internal/gcp/client.go`
3. Create or extend a scanner in `internal/gcp/`
4. Write tests with interface-based mocks
5. Add SARIF rule in `internal/report/sarif.go`

### New cloud providers

Add support for Azure or other cloud providers:
1. Create `internal/azure/` package with client and scanners
2. Implement the `iam.Scanner` interface for each resource type
3. Add a new subcommand in `internal/commands/`
4. Wire scanner -> analyzer -> reporter

### Report formats

Add new output formats in `internal/report/`:
- HTML reports
- CSV exports
- Slack/webhook notifications

## Coding guidelines

- Follow [Effective Go](https://golang.org/doc/effective_go.html)
- Pass `golangci-lint` checks
- Write tests for new code (coverage target: >85%)
- Use interface-based mocking for cloud API clients
- Check all errors, wrap with context using `fmt.Errorf`
- Comments explain "why" not "what"

## Commit messages

Format: `type: concise imperative statement`

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `perf`, `ci`, `build`

Examples:
- `feat: add Azure AD scanner`
- `fix: handle nil keys in GCP service account scanner`
- `test: add coverage for cross-account trust detection`

## Pull request process

1. Ensure `make test && make lint` pass
2. Update CHANGELOG.md if adding features or fixing bugs
3. Create PR with clear description of what and why
4. Respond to review feedback

## SpectreHub compatibility

When modifying JSON output, ensure compatibility with SpectreHub:
- Maintain `spectre/v1` schema
- Include `tool`, `version`, `timestamp` fields
- Follow Spectre family conventions

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
