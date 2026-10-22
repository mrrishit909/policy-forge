# Architecture

```
 GitHub Issue (form)          workflow_dispatch / weekly schedule
        |                                  |
   intake.yml  -- validate, authorize -->  run.yml
                                           |
          admit (state: running|blocked, idempotency, ceilings)
                                           |
          compute (read-only token, no secrets, pinned tools): python -m harness compute -> policyforge run
                                           |  artifact run-<run_id> (14 days)
          publish (validate outputs, immutable runs/<run_id>/, latest.json)
                                           |
          pages.yml (workflow_call): snapshot state -> build -> deploy -> smoke
                                           |
          outcome.yml: hard gates + live browser evidence + optional grader -> release record
                                           |
          memory.yml: deterministic lesson proposals -> type:memory issue
```

## Review pipeline (`src/policyforge`)

1. **Adapter.** `adapters/aws/normalize.sh` (Bash wrapper around one jq program,
   `normalize.jq`) or `adapters/azure/Normalize-Azure.ps1` (PowerShell 7, StrictMode, no Az module)
   reads the snapshot's files in manifest order and writes JSON Lines of normalized resources:
   provider-neutral types and properties, raw references, and an RFC 6901 pointer into the source
   file. Unknown native types are emitted as `unsupported`, never dropped. Sensitive fields are not
   copied.
2. **Validation and source lines.** Each record is checked against `schemas/inventory.schema.json`;
   `jsonpos.py`, a position-tracking JSON scanner, turns each pointer into an exact line.
3. **Redaction (second layer).** Fields with sensitive names or credential-shaped values are dropped
   or masked; what was redacted is recorded by path, never by value. Excerpts of cited lines are
   produced with sensitive string tokens replaced by `"[redacted]"`.
4. **Relationships.** Raw references become a graph (attached policies, instance roles, network
   groups, log destinations, role assignments); unresolved references are listed.
5. **Conftest.** Hygiene checks over the normalized inventory (fatal on failure) and over the
   exception registry (failing entries are rejected).
6. **OPA.** `opa eval` queries `data.policyforge.results`: for every rule and applicable resource a
   `pass`, `fail` or `unknown` result with a reason and evidence paths. The rules' own fixture tests run
   with `opa test` inside every run and are published.
7. **Exceptions.** Active from `created` to `expires` inclusive, as of the request's date; an active
   exception marks its exact finding `excepted` (still listed); expired, rejected and not-yet-active
   entries are reported and not applied.
8. **Remediation** (when requested). Each auto-remediable finding gets an RFC 6902 patch against the raw
   snapshot file, applied to a temporary copy; the whole review re-runs on the copy. A patch is offered
   only if its target result goes from fail to pass, every other result and finding is unchanged, and no
   other resource changed. Accepted patches are combined into one `remediation.patch` (re-verified as a
   whole, applicable with `git apply`).
9. **Outputs and self-checks.** Counts reconcile, no sensitive value appears in any output (excerpts and
   patches included), only bash, jq, pwsh, opa and conftest were launched, the committed snapshot is
   unchanged, the coverage statement matches the counts, and the run stays under 2 MB.

## Decisions

| Decision | Why |
|---|---|
| Two adapters in two shells, one normalized schema | The brief asks for Bash and PowerShell; making each own one provider keeps both real and the rules provider-neutral |
| `unknown` as a first-class result | A check the rules cannot evaluate must never count as passed; it is shown as prominently as a failure |
| Excerpts instead of raw files | The site shows the cited lines without ever publishing a snapshot file that holds sensitive fields |
| Strict patch acceptance | A patch that changes anything besides its target is reported, not offered, even when the change looks like an improvement; side effects deserve a person's review |
| Exceptions name one rule and one exact resource and expire within 90 days | Broad or permanent exceptions are how reviews quietly stop meaning anything |
| Pinned, checksum-verified tools | The review's results depend on OPA and Conftest versions; see SECURITY.md |
| Shared harness, distinct site | Operations are identical across the five projects; the visual layer is per product |

The harness, state model and workflows are documented in [STATE_MODEL.md](STATE_MODEL.md),
[SECURITY.md](SECURITY.md) and [OPERATIONS.md](OPERATIONS.md).
