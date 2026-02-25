---
name: iamspectre
description: Cross-cloud IAM auditor — finds unused, over-permissioned, and stale identities across AWS and GCP
user-invocable: false
metadata: {"requires":{"bins":["iamspectre"]}}
---

# iamspectre -- Cross-Cloud IAM Auditor

Scans AWS and GCP IAM resources for unused, over-permissioned, and stale identities. Reports severity and recommendations for each finding.

## Install

```bash
go install github.com/ppiankov/iamspectre/cmd/iamspectre@latest
```

## Commands

### iamspectre aws

Scan AWS IAM users, roles, and policies for security and compliance risks.

**Flags:**
- `--profile` -- AWS profile name
- `--stale-days` -- inactivity threshold in days (default: 90)
- `--severity-min` -- minimum severity to report: critical, high, medium, low (default: low)
- `--format` -- output format: text, json, sarif, spectrehub (default: text)
- `-o, --output` -- output file path (default: stdout)
- `--timeout` -- scan timeout (default: 5m)

### iamspectre gcp

Scan GCP service accounts, keys, and IAM bindings for security and compliance risks.

**Flags:**
- `--project` -- GCP project ID (required)
- `--stale-days` -- inactivity threshold in days (default: 90)
- `--severity-min` -- minimum severity to report: critical, high, medium, low (default: low)
- `--format` -- output format: text, json, sarif, spectrehub (default: text)
- `-o, --output` -- output file path (default: stdout)
- `--timeout` -- scan timeout (default: 5m)

**JSON output:**
```json
{
  "$schema": "spectre/v1",
  "tool": "iamspectre",
  "version": "0.1.0",
  "timestamp": "2026-02-25T12:00:00Z",
  "target": {
    "type": "aws-account",
    "uri_hash": "sha256:abc123..."
  },
  "config": {
    "stale_days": 90,
    "severity_min": "low",
    "cloud": "aws"
  },
  "findings": [
    {
      "id": "NO_MFA",
      "severity": "critical",
      "resource_type": "iam_user",
      "resource_id": "arn:aws:iam::123456789012:user/admin",
      "resource_name": "admin",
      "message": "Console user without MFA enabled",
      "recommendation": "Enable MFA for this user immediately",
      "metadata": {
        "password_enabled": true,
        "mfa_active": false
      }
    }
  ],
  "summary": {
    "total_principals_scanned": 15,
    "total_findings": 5,
    "by_severity": {"critical": 2, "high": 2, "medium": 1},
    "by_resource_type": {"iam_user": 3, "iam_role": 1, "iam_policy": 1},
    "by_finding_id": {"NO_MFA": 1, "STALE_USER": 1, "STALE_ACCESS_KEY": 1, "UNUSED_ROLE": 1, "WILDCARD_POLICY": 1}
  }
}
```

**Exit codes:**
- 0: scan completed (findings may or may not be present)
- 1: error (credentials, permissions, network)

### iamspectre init

Generate `.iamspectre.yaml` config file and `iamspectre-aws-policy.json` IAM policy.

### iamspectre version

Print version, commit hash, and build date.

## What this does NOT do

- Does not modify or delete IAM resources -- read-only auditing only
- Does not store cloud credentials -- uses standard SDK credential chains
- Does not require admin access -- works with read-only IAM policies
- Does not use ML or probabilistic analysis -- deterministic checks
- Does not estimate costs -- IAM findings are security risks, not dollar waste

## Parsing examples

```bash
# List all critical findings
iamspectre aws --format json | jq '[.findings[] | select(.severity == "critical")]'

# Count findings by type
iamspectre aws --format json | jq '.summary.by_finding_id'

# Users without MFA
iamspectre aws --format json | jq '[.findings[] | select(.id == "NO_MFA")] | .[] | .resource_name'

# GCP overprivileged service accounts
iamspectre gcp --project my-project --format json | jq '[.findings[] | select(.id == "OVERPRIVILEGED_SA")] | .[] | {email: .resource_name, role: .metadata.role}'

# Stale access keys older than 180 days
iamspectre aws --stale-days 180 --format json | jq '[.findings[] | select(.id == "STALE_ACCESS_KEY")]'
```
