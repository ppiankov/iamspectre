# Severity rubric v1

iamspectre separates observed impact from confidence that an authorization path is usable. Static policy shape is evidence, not proof that a request succeeds.

## What this is not

This rubric is not an IAM simulator, exploitability score, or claim of effective authorization. It never treats an unevaluated authorization layer as evaluated.

## Assessment schema

Assessed findings record rubric version `v1`, evidence tier, state, reachability, impact, blast radius, and every canonical authorization layer. States are `determinate` and `indeterminate`. Reachability is `unknown`, `blocked`, or `reachable`. Impact and blast radius use `low`, `medium`, `high`, and `critical`.

Evidence tiers are:

| Tier | Evidence |
|---:|---|
| 0 | Direct account or IAM fact |
| 1 | Policy shape or attached capability |
| 2 | Capability contextualized with principal, resource, and restrictive conditions |
| 3 | All applicable authorization layers evaluated for a concrete request |
| 4 | Deterministic simulation of a complete multi-step path |
| 5 | Authorized witnessed execution evidence |

The nine canonical layers are `identity_policy`, `resource_policy`, `permissions_boundary`, `scp`, `rcp`, `session_policy`, `explicit_deny`, `request_context`, and `service_enforcement`. Each is `evaluated`, `not_applicable`, or `unresolved`.

## Effective severity

Version 1 derives severity in this order:

1. Start at impact. Low blast radius lowers one rank, medium leaves it unchanged, high raises one, and critical raises two. Clamp the result between low and critical.
2. Apply the evidence cap. Tiers 0–2 cap at high. Tier 3 caps at high unless reachability is reachable. Tiers 4–5 cap at critical.
3. Unknown reachability or any unresolved layer caps at medium. A blocked path caps at low.
4. Caps win over blast-radius increases. A tier-0 `ROOT_ACCESS_KEY` fact and tier-5 witnessed evidence may retain critical despite the unknown/unresolved cap; blocked still caps at low.

Findings with no assessment metadata retain their existing severity. Invalid partial metadata becomes indeterminate and uses the lower of its existing severity and medium. This fail-closed compatibility path lets producers adopt the rubric incrementally without overstating incomplete evidence.

Changes to the algorithm, layer set, or meanings require a new rubric version.
