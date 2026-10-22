# Verification

**The single current release record is `releases/current.json` on the `state` branch.** It is
written only by the Outcome Verification Loop and only when every hard gate passed. Every attempt,
including blocked ones, is in `releases/history.json`, with findings and small evidence files in
`outcomes/<release_id>/`. This document explains the checks; it does not restate their status.

## Hard gates (objective; rubric locked by `rubric/rubric.lock`)

| Gate | What it proves | How |
|---|---|---|
| policy-gates | positive, negative and boundary fixtures exist for every rule and pass under `opa test`; unsupported resources and unevaluable semantics are marked unknown, never pass; each accepted patch resolves its finding; unrelated results, findings and resources stay unchanged; no cloud CLI or mutation command executes (stub executables for aws, az, gcloud, terraform, kubectl, curl and wget record any call, plus a static scan); no planted canary or sensitive-field value appears in any output, excerpts and patches included; partial coverage is never presented as complete; outputs are byte-identical on rerun | `pytest -m gate tests/policyforge` (8 tests) |
| shell-checks | ShellCheck on every shell script, Bats tests for the Bash adapter, Pester tests for the PowerShell adapter, PSScriptAnalyzer at Warning and Error severity | `scripts/shell_checks.sh` |
| harness | state machine, idempotency, duplicate detection, compare-and-swap concurrency, immutability, intake authorization by identity, injection-safe parsing, ceilings, repair-round bounds, memory guard | `pytest tests/harness` |
| secret-scan | no credential patterns in tracked files or in the live site's HTML, JS and CSS | `scripts/secret_scan.py --live` |
| live-site | the Pages URL serves the app and its snapshot points at the state branch's latest run | HTTP checks |
| published-matches-state | every published result file of the latest run is byte-identical to the state branch | `python -m harness verify-published` |
| browser | 14 checks x 3 widths (390, 768, 1440), all 42 must pass, against the live site: coverage headline, tally and legend with partial coverage stated and no "compliant" wording; a finding opening its evidence at the cited line; not-evaluated and excepted views and pack filters; every tab by link with focus and back button; unsupported resources shown as having no rule; policy "does not evaluate" disclosures; rule fixture matrix all passing; active, expired and rejected exceptions with validity spans; verified patch diff with before and after views and the download link; skip link and focus; dark theme (axe plus a direct primary-action contrast check); reduced motion; loading / empty / error-retry / stale states; the portfolio preview image; axe (WCAG 2.2 AA serious and critical), horizontal overflow, console errors and failed same-origin requests | Playwright, `frontend/tests/e2e/site.spec.ts` |

## Independent security review

A separate security verifier (an agent that did not build the engine) attacked the redaction,
no-cloud-access, coverage, exception and determinism guarantees with crafted snapshots and requests,
recording each confirmed defect as a strict-xfail test in `tests/policyforge/test_pf_adversarial.py`.
It confirmed 18 defects (PF-01 to PF-18). The blocker: a value whose sibling key was sensitive (a tag
`{"Key": "db_password", "Value": ...}`) appeared in finding excerpts, and both the run's self-check and
gate 6 missed it. Majors included secrets inside JSON-encoded strings, short secrets in patch context,
exception rejection matched by message text, `complete_coverage` ignoring unevaluated resources,
case-sensitive and literal-only matching of admin actions and wildcards, partial Deny rules treated as
total, and a narrow rule-pack request accepting a patch the full review rejects. Three were reachable
with the committed snapshots (the narrow-request patch, an impossible `as_of` date crashing the run,
and an `as_of` before capture reviving an expired exception). All 18 are fixed and their tests now pass
as plain regression tests; seven further tests guard claims that held (argument-list subprocesses,
path traversal refused, payload strings stay data, stub cloud CLIs never invoked, patches apply with
`git apply`, exception lookalikes never match, byte-identical replay across hash seeds and working
directories). The committed drifted snapshot carries two extra planted values (a sensitive tag and a
secret inside a JSON environment variable) so the gates exercise those paths on published data.

## Subjective review (separate from gates)

The rubric's subjective criteria (hierarchy, typography, spacing, palette, motion, responsive
adaptation, distinctiveness, fidelity to `docs/DESIGN_CONTRACT.md`) are scored by an independent
grader only when the repository has an inference secret; otherwise the release record says the
grader did not run. Scores never change a gate result. Screenshots from every outcome run are kept
as Actions artifacts for 14 days and a small representative set is committed with the release
evidence.

## Repairs

A failing gate opens or updates one `type:repair` issue per gate. The same failing set on a new
commit counts as another repair round; after three rounds the release is marked blocked for human
review and its evidence is kept.

## Reproduce locally (optional)

```sh
uv sync --frozen && uv run pytest
cd frontend && npm ci && npm run build && npx playwright install chromium && npm run e2e
```
