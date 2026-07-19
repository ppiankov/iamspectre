# AWS IAM exposure detections v2

WO-18 defines a restraint-first contract for AWS IAM findings. Static policy shapes are evidence, not proof that a request succeeds.

## What this is not

This is not an IAM simulator, exploit engine, CSPM charter, or claim of effective authorization. It does not execute actions, modify policies, auto-remediate, or infer unevaluated SCP, RCP, permissions-boundary, resource-policy, session-policy, tag, or request-context outcomes.

## Authoritative premises

AWS evaluates a request across applicable identity and resource policies, permissions boundaries, session policies, Organizations SCPs/RCPs, and explicit denies; an isolated identity-policy allow is therefore not an effective-authorization proof [AWS policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html). `NotAction` under Allow is a complement over actions applicable to the resource and can grant more than intended [AWS NotAction](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html). Action/NotAction and Resource/NotResource are mutually exclusive pairs [AWS policy elements](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html). Access Analyzer external findings reason over declarative resource policies and do not prove observed access; internal analyzers use a broader policy set and are a distinct analyzer type [AWS Access Analyzer concepts](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-concepts.html).

## Claim and evidence ladder

| Tier | Evidence | Maximum language |
|---|---|---|
| 0 | Direct account/IAM fact | “is configured/present” |
| 1 | Policy shape or attached capability | “policy permits/capability exists” |
| 2 | Capability contextualized with principal, resource, and restrictive conditions | “contextualized capability” |
| 3 | All applicable authorization layers evaluated for a concrete request | “authorization-layer reachable”; excludes service, network, and execution success |
| 4 | Deterministic simulation of a complete multi-step path | “simulated path” |
| 5 | Authorized witnessed execution evidence | “witnessed path” |

Reachability is independent: `unknown`, `blocked`, or `reachable`. Tiers 0-2 normally have unknown reachability. A finding label, message, severity rationale, and remediation must not imply a higher tier.

## Required finding assessment

Every v2 finding records one `evidence_tier` integer 0-5, `state` (`determinate` or `indeterminate`), `reachability` (`unknown`, `blocked`, or `reachable`), `impact` and `blast_radius` (`low`, `medium`, `high`, or `critical`), `rubric_version` (`v1`), and an ordered map of canonical layers to `evaluated`, `not_applicable`, or `unresolved`. Canonical layers are `identity_policy`, `resource_policy`, `permissions_boundary`, `scp`, `rcp`, `session_policy`, `explicit_deny`, `request_context`, and `service_enforcement`. Tier 0 facts require only their named source; tier 1 policy shapes require `identity_policy` or `resource_policy` as applicable and mark every other applicable layer unresolved. Missing metadata selects the documented legacy path; invalid partial metadata is indeterminate and reporters use the capped effective severity.

## Approved tier 0-1 set

| FindingID | Exact input | Tier | Unevaluated layers / reachability | State and maximum claim | False-positive bound | Remediation | SARIF rule |
|---|---|---:|---|---|---|---|---|
| ROOT_ACCESS_KEY | Credential report root access-key active field | 0 | Authorization layers; unknown | Determinate fact: “root access key is active” | API freshness/error becomes indeterminate | Disable and replace root key | `ROOT_ACCESS_KEY` |
| ADMINISTRATOR_ACCESS_POLICY_ATTACHED | Attached policy ARN exactly AWS AdministratorAccess | 1 | Boundaries, SCP/RCP, session, denies; unknown | “AdministratorAccess capability is attached” | Do not say effective admin | Review attachment and boundaries | `ADMINISTRATOR_ACCESS_POLICY_ATTACHED` |
| UNSCOPED_ALLOW_STATEMENT | Allow with Action breadth and Resource `*` | 1 | All effective layers; unknown | “unscoped allow statement is present” | Conditions may contextualize, not erase shape | Scope actions/resources/conditions | `UNSCOPED_ALLOW_STATEMENT` |
| BROAD_NOTACTION_ALLOW | Allow with NotAction and broad applicable Resource | 1 | Applicable-action universe and effective layers; unknown | “broad complement allow is present” | Concrete exclusions remain in evidence | Replace with explicit least-privilege actions | `BROAD_NOTACTION_ALLOW` |
| UNCONSTRAINED_ROLE_TRUST | Allow trust principal outside account with no restrictive condition | 1 | Caller policies, SCP/RCP, session; unknown | “trust policy admits external principal shape” | Restrictive-condition contract below | Add bounded principal/condition | `UNCONSTRAINED_ROLE_TRUST` |
| SENSITIVE_IAM_ACTION_IN_ALLOW | Allow action pattern names a ratified IAM control-plane action | 1 | Resource applicability/effective layers; unknown | “an Allow statement names a sensitive IAM action” | Variables or unresolved complements are indeterminate | Remove or scope the statement | `SENSITIVE_IAM_ACTION_IN_ALLOW` |
| PASSROLE_ACTION_IN_ALLOW | Allow action pattern names `iam:PassRole` | 1 | Target role, service, effective layers; unknown | “an Allow statement names iam:PassRole” | Never call it escalation without path evidence | Scope role and `iam:PassedToService` | `PASSROLE_ACTION_IN_ALLOW` |

The initial sensitive-action list for matching is the lexicographically emitted set `iam:AttachRolePolicy`, `iam:AttachUserPolicy`, `iam:CreatePolicyVersion`, `iam:PassRole`, `iam:PutRolePolicy`, `iam:PutUserPolicy`, `iam:SetDefaultPolicyVersion`, and `iam:UpdateAssumeRolePolicy`. Emit at most one finding per policy statement and matched sensitive action; identity is policy ARN plus statement index plus normalized action, with deterministic sort and exact-key deduplication. Changes require a new charter review.

Required-layer matrix (`E` evaluated, `U` unresolved, `N` not applicable):

| Finding family | identity_policy | resource_policy | permissions_boundary | scp | rcp | session_policy | explicit_deny | request_context | service_enforcement |
|---|---|---|---|---|---|---|---|---|---|
| ROOT_ACCESS_KEY | N | N | N | N | N | N | N | N | N |
| Attachment / identity Allow shape | E | N | U | U | U | U | U | U | U |
| Trust / resource-policy shape | N | E | U | U | U | U | U | U | U |
| Access Analyzer external passthrough | N | E | N | N | N | N | E | E | U |
| Access Analyzer internal passthrough | E | E | E | E | E | U | E | E | U |
| UNKNOWN_COVERAGE | N | N | N | N | N | N | N | N | N |

The coverage query is evidence outside the authorization-layer map. No implementation may infer a different value or omit a canonical layer.

## Action, complement, resource, and principal contract

Normalize Action/NotAction scalar or array strings to lowercase ASCII for matching. The statement pattern matches a concrete catalog action; `*` means zero or more characters and `?` exactly one, with no character-class grammar. `${...}`, non-string members, or both/neither Action forms are indeterminate. For permission-policy action detectors, both/neither Resource forms are indeterminate. Role trust-policy statements validly omit Resource/NotResource because the role is the resource; those statements still undergo Principal and Condition classification. Examples: `*` matches every catalog action; `iam:*` and `IAM:Pass*` match their normalized IAM actions; exact names match exactly; `s3:*` does not match an IAM action.

In v1, every Allow+NotAction sensitive-action inference is indeterminate because no versioned service-action/resource-applicability catalog is bundled. `BROAD_NOTACTION_ALLOW` may report only the observed complement shape. NotResource breadth is likewise deferred: an Allow+NotResource statement is recorded as an observed shape with indeterminate resource breadth and cannot suppress or prove a sensitive capability.

Trust-principal classification is determinate external for `*`, a different 12-digit account ID/root ARN, or an IAM user/role ARN whose account differs. The current account ID is internal. Service principals are not external-account principals for this finding; federated principals, policy variables, malformed principals, and failed account ownership resolution are indeterminate. Arrays are OR-like: one external entry supports the shape finding, while an unknown entry preserves indeterminate state.

## Condition boundedness contract

A condition suppresses `UNCONSTRAINED_ROLE_TRUST` only for these key/operator pairs: `sts:ExternalId`, `aws:PrincipalOrgID`, and `aws:SourceAccount` with `StringEquals`; `aws:SourceArn` with `ArnEquals` or wildcard-free `ArnLike`; and `aws:SourceIp` with `IpAddress`. Exact/string/ARN values must be nonempty and contain no wildcard or variable; SourceAccount is exactly 12 digits; SourceArn parses as an ARN; SourceIp contains valid non-universal CIDRs. Operators and keys are AND-like, values under one key are OR-like, so every value must be bounded. A supported pair with an explicitly broad value is determinate nonconstraining. Unsupported keys/operators, inverted operators, every Null/IfExists/set-operator form, malformed values, variables, invalid CIDRs, and mixed supported/unsupported structures are indeterminate and do not suppress; any emitted observation is limited to the trust-policy shape, not “unconstrained.” Parsing remains permissive.

## Severity rubric v1 contract

Severity uses this ordered v1 algorithm: start at impact rank; lower one rank for `blast_radius=low`, leave unchanged for medium, raise one for high, and raise two for critical; clamp low-critical. Then cap by evidence tier: tiers 0-1 high, tier 2 high, tier 3 high unless reachable, tiers 4-5 critical. Then cap at medium when reachability is unknown or any required layer is unresolved. The only direct-harm exception is `ROOT_ACCESS_KEY`, whose tier-0 fact may retain critical; tier-5 witnessed paths may also retain critical. `blocked` reachability caps low. Caps always win over blast-radius raises. Legacy findings without assessment metadata retain raw severity. Invalid partial metadata becomes indeterminate and uses the lower of raw severity and medium. Analyzer normalizes a copy before filtering/summarizing; every reporter consumes that normalized severity, and SARIF repeats the idempotent function for direct use.

## Access Analyzer boundary

Only bounded pass-through is approved. Coverage is recorded per queried `(region, analyzer_type)` with analyzer ARN/status, zone of trust, supported resource types, query result, and retrieval error. Missing, inactive, unsupported, or failed entries are `UNKNOWN_COVERAGE`; one successful region/type never implies account coverage. Coverage gaps are metadata and a single deterministic `UNKNOWN_COVERAGE` finding per missing pair. External findings remain declarative evidence, not witnessed access. Class B1 local reconstruction is rejected.

## Rejected classes

Classes C (confused-deputy claims) and F (MFA enforcement claims) are cut because static local inputs do not establish the required request context or enforcement path. Class A is capability language only. No “privilege escalation path,” “effective admin,” or “exploitable” label is allowed below its evidence tier.

## Dependency graph

WO-18 must pass its killgate and land first. WO-19 implements condition semantics. WO-20 implements the assessment schema/rubric across analyzer and reporters. WO-21 then implements action/complement matching using this ratified sensitive-action list and WO-20 indeterminate state.

## Killgate audit

Three independent reviewers evaluate: evidence/claim alignment, AWS semantic correctness, and implementability without invented rules. At least two must return PASS. Findings, integrated changes, unresolved dissent, and final verdict are appended before WO-18 closes.

| Reviewer | Focus | Verdict | Findings / integration |
|---|---|---|---|
| A | Evidence and overclaim restraint | PASS | Initial rejection corrected permission-grant overclaims, split broad from unsupported conditions, and bounded tier-3 language. |
| B | AWS policy semantics | PASS | Initial rejection added deterministic action/principal/condition/resource semantics and per-region Access Analyzer coverage; trust-policy Resource omission was corrected on re-review. |
| C | Downstream implementability | PASS | Initial rejection added field types, cardinality, complete severity algorithm, explicit nine-layer matrix, and determinate v1 NotAction deferral. |

Final convergence is 3/3 PASS. No unresolved dissent remains. The rejected intermediate drafts are represented by the integrated-change summaries above; downstream WOs may begin only after this artifact lands on the default branch.
