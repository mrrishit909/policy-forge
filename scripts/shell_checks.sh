#!/usr/bin/env bash
# Shell-side checks: ShellCheck (adapters/, scripts/, Bats files), Bats (tests/bats), Pester (tests/pester) and
# PSScriptAnalyzer at Warning and Error severity (adapters/azure). Exits non-zero if any check fails.
# Expects shellcheck, bats, pwsh and jq on PATH and Pester / PSScriptAnalyzer on PSModulePath.
# pwsh runs with HOME set to HOME_FOR_PWSH, or to a fresh temporary directory, so it never writes caches into the
# real home directory.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
export POWERSHELL_UPDATECHECK=Off POWERSHELL_TELEMETRY_OPTOUT=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
pwsh_home="${HOME_FOR_PWSH:-}"
if [[ -z "$pwsh_home" ]]; then
  pwsh_home="$(mktemp -d)"
  trap 'rm -rf "$pwsh_home"' EXIT
fi
failed=()

run_pwsh() { HOME="$pwsh_home" pwsh -NoProfile -NonInteractive -Command "$1"; }

echo "== ShellCheck"
files=()
while IFS= read -r f; do files+=("$f"); done < <(find adapters scripts tests/bats -type f \( -name '*.sh' -o -name '*.bats' \) | LC_ALL=C sort)
shellcheck -x "${files[@]}" || failed+=("shellcheck")

echo "== Bats"
bats tests/bats || failed+=("bats")

echo "== Pester"
# shellcheck disable=SC2016 # PowerShell source: $-expressions are expanded by pwsh, not by bash
run_pwsh '
  $ErrorActionPreference = "Stop"
  Import-Module Pester -MinimumVersion 6.0
  $c = New-PesterConfiguration
  $c.Run.Path = "tests/pester"
  $c.Run.PassThru = $true
  $c.Output.Verbosity = "Detailed"
  $c.TestResult.Enabled = $false
  $c.TestDrive.Enabled = $false
  $r = Invoke-Pester -Configuration $c
  if ($r.Result -ne "Passed" -or $r.FailedCount -gt 0) { exit 1 }
' || failed+=("pester")

echo "== PSScriptAnalyzer"
# shellcheck disable=SC2016 # PowerShell source: $-expressions are expanded by pwsh, not by bash
run_pwsh '
  $ErrorActionPreference = "Stop"
  Import-Module PSScriptAnalyzer
  $r = @(Invoke-ScriptAnalyzer -Path adapters/azure -Recurse -Severity Warning, Error)
  $r | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize -Wrap | Out-String -Width 200 | Write-Output
  Write-Output ("PSScriptAnalyzer: {0} warning/error finding(s)" -f $r.Count)
  if ($r.Count -gt 0) { exit 1 }
' || failed+=("psscriptanalyzer")

if [[ ${#failed[@]} -gt 0 ]]; then
  echo "shell checks failed: ${failed[*]}" >&2
  exit 1
fi
echo "shell checks passed"
