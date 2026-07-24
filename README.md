# iamspectre

[![CI](https://github.com/ppiankov/iamspectre/actions/workflows/ci.yml/badge.svg)](https://github.com/ppiankov/iamspectre/actions/workflows/ci.yml)
[![ANCC](https://img.shields.io/badge/ANCC-compliant-brightgreen)](https://ancc.dev)

**iamspectre** — Cross-cloud IAM auditor for AWS, GCP, and Azure AD. Part of [SpectreHub](https://spectrehub.dev).

## What it is

- Scans IAM resources across AWS, GCP, and Azure AD
- Detects stale users, unused roles, wildcard policies, missing MFA, and expired secrets
- Checks credential reports, key ages, service account bindings, and directory roles
- Each finding includes severity and actionable recommendation
- Outputs text, Markdown report, JSON, SARIF, and SpectreHub formats

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

### Docker

```sh
docker pull ghcr.io/ppiankov/iamspectre:latest
docker run --rm ghcr.io/ppiankov/iamspectre:latest aws --format json
```

### Windows

Download the latest Windows `.zip` from [GitHub Releases](https://github.com/ppiankov/iamspectre/releases), extract `iamspectre.exe`, and add its folder to `PATH` or run it in place.

```powershell
.\iamspectre.exe aws --format json
```

<!-- WO-85@v2: Azure requires explicit Graph authorization beyond credential discovery. -->
AWS credentials resolve through the SDK default chain from standard Windows locations such as `%USERPROFILE%\.aws\`. Azure also uses its default credential chain, but Microsoft Graph permissions, admin consent, directory roles, and some licensing requirements must be configured explicitly; follow the [Azure authentication setup](docs/cli-reference.md#azure-authentication).

### From source

```sh
git clone https://github.com/ppiankov/iamspectre.git
cd iamspectre
make build
```

### Usage

```sh
iamspectre aws --format json
```

## CLI commands

<!-- WO-6@v2: list only commands registered by the Cobra root. -->
| Command | Description |
|---------|-------------|
| `iamspectre aws` | Audit AWS IAM resources |
| `iamspectre gcp` | Audit GCP IAM resources |
| `iamspectre azure` | Audit Microsoft Entra ID resources |
| `iamspectre init` | Generate config file and IAM permissions |
| `iamspectre version` | Print version |

## SpectreHub integration

iamspectre feeds IAM hygiene findings into [SpectreHub](https://spectrehub.dev) for unified visibility across your infrastructure.

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
