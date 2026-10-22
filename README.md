# Policy Forge

An offline cloud-security configuration review desk. A Bash and jq adapter reads **synthetic**
AWS-CLI-shaped exports and a PowerShell 7 adapter reads **synthetic** Azure-PowerShell-shaped
exports; both write one normalized inventory. Python resolves the exact source line of every
cited value, redacts sensitive fields and links related resources. OPA evaluates a bounded set of
Rego rules, Conftest checks the inputs and the exception registry, and every proposed patch is
applied to a copy of the snapshot and the whole review re-run before it is offered. Nothing ever
touches a cloud account.

- **Live site:** https://mrrishit909.github.io/policy-forge/
- **Current release record:** [`releases/current.json` on the state branch](https://github.com/mrrishit909/policy-forge/blob/state/releases/current.json)
- **Run records and results:** the [`state` branch](https://github.com/mrrishit909/policy-forge/tree/state)

## What it does

| Part | Where |
|---|---|
| Three synthetic snapshots of a fictional organisation (AWS baseline, AWS after drift, Azure lab) with planted fake secrets that prove redaction | `snapshots/` |
| Bash + jq adapter (AWS) and PowerShell 7 adapter (Azure) | `adapters/` |
| Normalization, source-line resolution, redaction, relationship graph, exceptions, remediation and outputs | `src/policyforge/` |
| 13 Rego rules across storage, IAM, network, audit and relationship packs; catalog; positive, negative and boundary fixtures; Conftest hygiene checks | `policy/` |
| Narrowly scoped, expiring exceptions | `exceptions/registry.json` |
| GitHub-native harness: intake, admission, publication, reconciler, outcome loop, memory | `harness/` |
| Static, embeddable review desk | `frontend/` |

## Results on the committed snapshots

All packs, remediation proposed, exceptions evaluated as of 2026-10-21:

| Snapshot | Resources | Checks: failed / unknown / passed | Excepted | Patches verified / rejected |
|---|---|---|---|---|
| aws-baseline-2026-10 | 25 | 3 / 1 / 38 | 1 | 2 / 0 |
| aws-drifted-2026-10 | 45 | 18 / 14 / 49 | 1 | 8 / 3 |
| azure-lab-2026-10 | 42 | 11 / 10 / 21 | 1 | 5 / 0 |

Coverage is partial for every snapshot, and every output says so: unsupported resource types are
inventoried and marked, and semantics the rules do not model make a check "could not be evaluated",
never "passed". The three rejected patches would each have changed another rule's result, so they
are reported, not offered.

## Use it

- Browse reviews anonymously: the coverage tally, findings with their cited source lines, the
  inventory, the policy catalog, the rules' own fixture tests, the exception registry and the
  verified patches with a downloadable `remediation.patch`.
- Request a review: open the *Policy review request* issue form. The owner's requests run
  automatically; anyone else's wait for the owner's `job:approved` label. See
  [docs/OPERATIONS.md](docs/OPERATIONS.md).

## Documents

[Architecture](docs/ARCHITECTURE.md), [operations](docs/OPERATIONS.md),
[state model](docs/STATE_MODEL.md), [security](docs/SECURITY.md),
[cost limits](docs/COST_LIMITS.md), [verification](docs/VERIFICATION.md),
[portfolio integration](docs/PORTFOLIO_INTEGRATION.md), [design contract](docs/DESIGN_CONTRACT.md),
[portfolio manifest](portfolio-manifest.json).

## Limitations

Synthetic snapshots only; no real cloud account is read or changed and no upload path exists.
The rules are a deliberately bounded set. They do not evaluate, among other things, account-level
S3 Block Public Access, object ACLs, presigned URLs or SAS tokens, SCPs, permissions boundaries,
session policies, PIM, deny assignments, Azure DataActions, NACLs, route tables, load balancers,
subnet NSGs, egress, whether anything listens on an open port, CloudTrail event selectors, the
absence of any trail, or retention; each rule's catalog entry lists what it does not evaluate. IAM
Conditions, NotAction, NotResource, NotPrincipal, group-inherited permissions, Azure NotActions and
conditional assignments, unparseable policy documents, prefix lists and most service tags produce
"could not be evaluated". Patches are desired-state edits of the captured JSON (for example
`IsLogging: true` stands in for starting logging); acceptance is strict, so a patch that would also
improve another result is rejected. Wildcard IAM findings have manual guidance only. The optional AI
grader runs only if the owner adds an inference secret; release records state whether it ran.
