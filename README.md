# iamspectre

[![CI](https://github.com/ppiankov/iamspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/iamspectre/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/ppiankov/iamspectre)](https://goreportcard.com/report/github.com/ppiankov/iamspectre)
[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)

**iamspectre** — Cross-cloud IAM auditor for AWS, GCP, and Azure AD. Part of [SpectreHub](https://github.com/ppiankov/spectrehub).

## What it is

- Scans IAM resources across AWS, GCP, and Azure AD
- Detects stale users, unused roles, wildcard policies, missing MFA, and expired secrets
- Checks credential reports, key ages, service account bindings, and directory roles
- Each finding includes severity and actionable recommendation
- Outputs text, JSON, SARIF, and SpectreHub formats

## What it is NOT

- Not a remediation tool — reports only, never modifies IAM resources
- Not a real-time monitor — point-in-time scanner
- Not a cost estimator — IAM findings are security risks, not dollar waste
- Not a CSPM replacement — focuses on identity and access only

## Quick start

### Homebrew

```sh
brew tap ppiankov/tap
brew install iamspectre
```

### From source

```sh
git clone https://github.com/ppiankov/iamspectre.git
cd iamspectre
make build
```

### Usage

```sh
iamspectre scan --provider aws --format json
```

## CLI commands

| Command | Description |
|---------|-------------|
| `iamspectre scan` | Scan IAM resources across cloud providers |
| `iamspectre init` | Generate config file and IAM permissions |
| `iamspectre version` | Print version |

## SpectreHub integration

iamspectre feeds IAM hygiene findings into [SpectreHub](https://github.com/ppiankov/spectrehub) for unified visibility across your infrastructure.

```sh
spectrehub collect --tool iamspectre
```

## Safety

iamspectre operates in **read-only mode**. It inspects and reports — never modifies, deletes, or alters your IAM resources.

## Documentation

| Document | Contents |
|----------|----------|
| [CLI Reference](docs/cli-reference.md) | Full command reference, flags, and configuration |

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Obsta Labs](https://obstalabs.dev)
