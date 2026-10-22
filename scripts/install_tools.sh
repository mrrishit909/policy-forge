#!/usr/bin/env bash
# Install the pinned analysis tools for GitHub's ubuntu-24.04 (x86_64) runners into DEST.
# Every download is checked against a pinned SHA-256 (Bats: a pinned commit) before it is used.
# PowerShell 7 itself is the runner's preinstalled pwsh; its version is recorded in each run manifest.
# Usage: scripts/install_tools.sh DEST   then add DEST/bin and DEST/bats/bin to PATH and
# DEST/psmodules to PSModulePath.
set -euo pipefail

dest="${1:?usage: install_tools.sh DEST}"

OPA_VERSION="v1.21.1"
OPA_SHA256="668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031"
CONFTEST_VERSION="0.71.1"
CONFTEST_SHA256="c3f6b2a753bd56e377a1e51a95ae3e057f926f2e9139f7d5b5dfbbaf810f7985"
SHELLCHECK_VERSION="v0.11.0"
SHELLCHECK_SHA256="b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6"
BATS_COMMIT="eb7f42f8d608ac693d7a4b67474f6714ea68cfc5" # tag v1.14.0
PESTER_VERSION="6.2.0"
PSSA_VERSION="1.25.0"

if [[ "$(uname -s)-$(uname -m)" != "Linux-x86_64" ]]; then
  echo "install_tools.sh pins Linux x86_64 binaries only" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
export POWERSHELL_TELEMETRY_OPTOUT=1 POWERSHELL_UPDATECHECK=Off DOTNET_CLI_TELEMETRY_OPTOUT=1
mkdir -p "$dest/bin" "$dest/psmodules"

fetch() { curl -fsSL --retry 3 --proto '=https' -o "$2" "$1"; }
verify() { printf '%s  %s\n' "$1" "$2" | sha256sum --check --quiet -; }

fetch "https://github.com/open-policy-agent/opa/releases/download/${OPA_VERSION}/opa_linux_amd64_static" "$tmp/opa"
verify "$OPA_SHA256" "$tmp/opa"
install -m 0755 "$tmp/opa" "$dest/bin/opa"

fetch "https://github.com/open-policy-agent/conftest/releases/download/v${CONFTEST_VERSION}/conftest_${CONFTEST_VERSION}_Linux_x86_64.tar.gz" "$tmp/conftest.tgz"
verify "$CONFTEST_SHA256" "$tmp/conftest.tgz"
tar -xzf "$tmp/conftest.tgz" -C "$tmp" conftest
install -m 0755 "$tmp/conftest" "$dest/bin/conftest"

fetch "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.gz" "$tmp/shellcheck.tgz"
verify "$SHELLCHECK_SHA256" "$tmp/shellcheck.tgz"
tar -xzf "$tmp/shellcheck.tgz" -C "$tmp"
install -m 0755 "$tmp/shellcheck-${SHELLCHECK_VERSION}/shellcheck" "$dest/bin/shellcheck"

git -c advice.detachedHead=false clone --quiet --depth 1 --branch v1.14.0 https://github.com/bats-core/bats-core.git "$dest/bats"
if [[ "$(git -C "$dest/bats" rev-parse HEAD)" != "$BATS_COMMIT" ]]; then
  echo "bats-core v1.14.0 does not resolve to the pinned commit" >&2
  exit 1
fi

pwsh -NoProfile -NonInteractive -Command "
  \$ErrorActionPreference = 'Stop'
  Save-Module -Name Pester -RequiredVersion '${PESTER_VERSION}' -Repository PSGallery -Path '${dest}/psmodules'
  Save-Module -Name PSScriptAnalyzer -RequiredVersion '${PSSA_VERSION}' -Repository PSGallery -Path '${dest}/psmodules'
"

"$dest/bin/opa" version | head -n 1
"$dest/bin/conftest" --version | head -n 1
"$dest/bin/shellcheck" --version | sed -n 2p
"$dest/bats/bin/bats" --version
# shellcheck disable=SC2016 # the expression is PowerShell, expanded by pwsh, not by bash
pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'
