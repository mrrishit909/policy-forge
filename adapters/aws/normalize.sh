#!/usr/bin/env bash
# Policy Forge AWS adapter. Offline file transform only: reads an AWS snapshot directory (AWS-CLI-shaped JSON
# exports listed in its manifest.json) and writes normalized resources as JSON Lines to stdout.
# It never invokes a cloud CLI or the network; the only external program is jq.
# Usage: normalize.sh SNAPSHOT_DIR
set -euo pipefail

usage() { echo "usage: normalize.sh SNAPSHOT_DIR" >&2; exit 2; }
[[ $# -eq 1 ]] || usage
dir="${1%/}"
if [[ ! -d "$dir" || ! -f "$dir/manifest.json" ]]; then
  echo "normalize.sh: not a snapshot directory (missing manifest.json): $dir" >&2
  exit 2
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

provider="$(jq -r '.provider // empty' "$dir/manifest.json")"
if [[ "$provider" != "aws" ]]; then
  echo "normalize.sh: manifest provider is '$provider', expected 'aws'" >&2
  exit 2
fi

# Inputs in a fixed order: manifest, context, then the data files in manifest order (never a glob, whose
# order depends on the locale).
inputs=("$dir/manifest.json")
if [[ -f "$dir/context.json" ]]; then inputs+=("$dir/context.json"); fi
while IFS= read -r name; do
  if [[ "$name" == */* || "$name" == .* ]]; then
    echo "normalize.sh: manifest file name must be a plain file name: $name" >&2
    exit 2
  fi
  if [[ ! -f "$dir/$name" ]]; then
    echo "normalize.sh: manifest lists a missing file: $name" >&2
    exit 2
  fi
  inputs+=("$dir/$name")
done < <(jq -r '.files[]' "$dir/manifest.json")

LC_ALL=C jq -n -c -f "$here/normalize.jq" "${inputs[@]}"
