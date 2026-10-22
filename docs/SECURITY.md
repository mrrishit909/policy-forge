# Security

## Trust boundaries

| Input | Trust | Handling |
|---|---|---|
| Issue title and body | untrusted | read from the event JSON file by Python; coerced field by field (`harness/issueform.py`) and validated against `schemas/request.schema.json`; never interpolated into shell, never echoed back verbatim |
| Workflow dispatch inputs | untrusted | passed through `env:` only; re-validated by the admit step |
| Labels | untrusted (issue-form labels are applied for any author) | authorization never depends on labels; it checks `issue.user.login` / `sender.login` against the repository owner |
| Repository code on `main` | trusted after review | the only code executed by workflows |
| Snapshot files (`snapshots/`) | data, never executed | read by the Bash and PowerShell adapters as JSON only; adapters never evaluate snapshot content as code |
| Grader output | untrusted | schema-validated; can add subjective scores only; cannot change hard-gate results |
| Memory proposals | untrusted until accepted | schema + guard (no security, cost, threshold, publication or requirement subjects); accepted only by the owner's `memory:accept` label |

## Workflow rules

- Top-level `permissions: {}`; each job requests only what it needs:
  intake `issues: write, actions: write`; compute `contents: read`; publish/admit
  `contents: write, issues: write`; Pages deploy `pages: write, id-token: write`.
- Compute (which runs project code over requests) has no write token and no secrets.
- No `pull_request_target`. Pull requests run CI with read-only permissions and no secrets.
- Third-party actions are pinned to full commit SHAs (tag noted in a comment).
- Dependencies install from lockfiles (`uv.lock` with `uv sync --frozen`, `package-lock.json`
  with `npm ci`).
- Every job has `timeout-minutes`; state writers serialize through `state-writer`.

## No cloud access

- The adapters, policies and remediation operate on committed files only. No workflow holds cloud
  credentials, and no code path calls a cloud CLI, SDK or API. A release gate runs the whole pipeline
  with `aws`, `az`, `gcloud`, `terraform`, `kubectl`, `curl` and `wget` replaced by stubs that record
  any invocation, and statically scans the adapters, engine and policies for cloud mutation commands.
- Remediation writes patches against a temporary copy of a snapshot and re-verifies them; it never
  modifies the committed snapshot and never applies anything to real infrastructure.

## Tool supply chain

- OPA v1.21.1, Conftest v0.71.1 and ShellCheck v0.11.0 are downloaded from their GitHub releases and
  checked against SHA-256 values pinned in `scripts/install_tools.sh`; Bats is cloned at tag v1.14.0
  and checked against the tag's pinned commit; Pester 6.2.0 and PSScriptAnalyzer 1.25.0 come from
  the PowerShell Gallery at exact versions (the Gallery does not offer a hash to pin; signature
  checking is not available on Linux). PowerShell 7 is the runner's preinstalled `pwsh`, recorded in
  each run manifest.

## Credentials

- No credential is stored in this repository or shipped to the browser. CI and the Outcome
  Verification Loop run `scripts/secret_scan.py` over tracked files and the live site's HTML,
  JS and CSS.
- The only secret-bearing job is the optional grader in `outcome.yml`. It runs only when the
  repository has `ANTHROPIC_API_KEY` or `CLAUDE_CODE_OAUTH_TOKEN`, uses `claude -p --bare` with
  the `Read` and `Glob` tools only, a `--max-budget-usd` cap, over screenshots and the rubric;
  it never executes repository or generated code. Without the secret it is skipped and the
  release record says so.
- Visitors are never asked for tokens. The site has no write path; durable requests go through
  GitHub Issues, which require a GitHub sign-in, and only the owner's requests run unattended.

## Publication

- Only allow-listed result files of completed runs are copied into the Pages snapshot
  (`project_hooks.PUBLIC_FILES`). Raw snapshot files are never published by a run; the site shows
  redacted excerpts produced by the engine.
- Sensitive field names follow one rule shared by the Python engine, the jq and PowerShell adapters and
  Conftest (`policy/sensitive-names.json`, with examples tested in all four). A value is also treated as
  sensitive when a sibling `Key`/`Name` member is sensitive-named, and JSON-encoded strings are checked
  recursively. Patches whose context or changes would include a sensitive line are withheld, never
  redacted (a redacted patch would not apply).
- The synthetic snapshots contain planted, obviously fake values in fields a real export could hold
  secrets in (access-key secrets, storage keys, connection strings, admin passwords). They exist to
  prove redaction: a release gate fails if any of them, or any value from a sensitive-named field,
  appears in any output file. They do not match real credential formats.
- All data is synthetic, for a fictional organisation, with documentation IP ranges and fake account
  ids, and is labelled as such.
- Reports contain no logs, environment dumps or personal data. Run records name the GitHub
  account that requested the run (a public login).

## Reporting

Open an issue without sensitive details, or use GitHub's private vulnerability reporting.
