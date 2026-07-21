# iamspectre IAM Audit Report

## Executive summary

- Audit completeness: incomplete
- Principals scanned: 42
- Findings: 2
- Critical severity: 1
- Medium severity: 1

### Notable facts

- Oldest credential: 3650 days
- Longest inactivity: 365 days

## Findings

### 1. WILDCARD\_POLICY (CRITICAL)

- Resource type: iam\_policy
- Resource ID: arn:aws:iam::123456789012:policy/admin
- Resource name: admin
- Risk rationale: Critical evidence indicates unrestricted or immediate high-consequence access risk.
- Evidence: Policy grants unrestricted actions and resources
- Recommendation: Restrict actions and resources before the next review
- Evidence metadata:
  - wildcard\_action: true
  - wildcard\_resource: true

### 2. STALE\_ACCESS\_KEY (MEDIUM)

- Resource type: iam\_user
- Resource ID: access-key-redacted
- Resource name: alice-key
- Risk rationale: Medium-severity evidence indicates elevated exposure that warrants planned remediation.
- Evidence: Access key has no recorded use
- Recommendation: review this permission carefully review this permission carefully review this permission carefully review this permission carefully review this permission carefully before changing access
- Evidence metadata:
  - days\_old: 3650
  - days\_since\_use: 365
  - last\_used: unknown

## Coverage gaps

Evaluable opportunities: 41/42

- aws\_role\_last\_used [aws-account:123456789012]: evidence\_unavailable; affected=UNUSED\_ROLE=1; evaluable=41/42; maximum consequence=medium

## Errors

Reported errors: 1

- fetch policy version: access denied

## Scope and methodology

- Tool: iamspectre 0.4.2
- Target: aws-account (sha256:customer)
- Cloud: aws
- Stale threshold: 90 days
- Severity filter: low
- Scanned at: 2026-07-21T08:09:10Z
- Method: read-only cloud control-plane inspection; iamspectre does not modify IAM resources.
