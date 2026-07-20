# Finding compatibility contract

IAMSpectre findings expose two independent compatibility dimensions:

- `id` is the stable machine-readable classification of a finding.
- `severity` is the effective urgency of that finding for the available evidence and context.

Consumers must not infer that every occurrence of one finding ID has the same severity. IAMSpectre may grade severity within an existing ID without changing the finding's classification.

## Stable IDs

Finding IDs are compatibility identifiers, not presentation labels. SpectreHub uses them to:

- map findings into normalized categories;
- classify IAM credential types; and
- derive finding lifecycle identity together with the tool and resource location.

Changing, removing, or splitting an ID can therefore recategorize a finding or make an existing lifecycle record appear resolved while creating a new one. Such a change requires a coordinated producer and consumer migration. Adding a new ID likewise requires consumer review so its category and IAM metadata do not fall back to an unknown classification.

Changing severity while preserving the ID and resource location does not change lifecycle identity. This is the supported mechanism for evidence-aware grading.

## Severity

Severity is consumed independently from the finding ID. It controls prioritization, filtering, summaries, and policy thresholds. Consumers must evaluate the emitted severity for each finding rather than assigning severity from its ID.

The SpectreHub wire format must preserve all IAMSpectre severity values, including `critical`. A consumer must not silently downgrade an unrecognized severity. Producer and consumer schema changes are required before introducing another severity value.

The current `spectre/v1` consumer does not yet accept `critical` or a run-level coverage manifest. IAMSpectre therefore fails closed before writing SpectreHub output when either is present. Coordinated producer and consumer support is required before those values can cross this transport.

## GitHub Action behavior

The `iamspectre-action` wrapper does not inspect finding IDs or individual finding severities. It passes the configured `severity-min` value to the IAMSpectre CLI, exposes the report path and CLI exit code, and converts finding and error exit codes into GitHub Actions annotations.

Consequently, grading a finding within a stable ID can intentionally change whether it passes the configured severity threshold and whether the scan reports findings. It does not require an action schema change. Changes to CLI severity names, filtering semantics, or exit-code meanings require coordinated action changes.

## Compatibility rules

The following changes are compatible without a finding-ID migration:

- changing severity from evidence while retaining `id` and resource identity;
- changing human-readable messages or recommendations without changing their machine-readable meaning; and
- adding optional evidence fields that consumers ignore when unsupported.

The following changes require coordinated consumer work:

- renaming, removing, merging, or splitting a finding ID;
- changing the resource identity used for lifecycle correlation;
- changing the meaning of an existing ID to a different category;
- adding a severity value not accepted and preserved by consumers; or
- changing CLI filtering or exit-code semantics used by the GitHub Action.

## Evidence anchors

This contract is pinned by the current public integration surfaces:

- IAMSpectre finding and severity definitions: `internal/iam/types.go`
- IAMSpectre SpectreHub envelope: `internal/report/spectrehub.go`
- SpectreHub category and severity normalization: `internal/aggregator/normalizer.go`
- SpectreHub lifecycle identity and IAM classification: `internal/ingest/lifecycle.go`
- SpectreHub spectre/v1 model and validation: `internal/models/spectrev1.go` and `internal/validator/validator.go`
- GitHub Action input and exit-code handling: `action.yml` in `iamspectre-action`

This contract does not guarantee that arbitrary new IDs or severity values are understood by older consumers. It also does not authorize a finding-ID migration without coordinated rollout and regression coverage.
