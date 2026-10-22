#!/usr/bin/env bats
# AWS adapter contract: JSON Lines, deterministic, unsupported types kept, sensitive fields dropped, clean failure.

bats_require_minimum_version 1.5.0

setup() {
  ROOT="$(cd "$BATS_TEST_DIRNAME/../.." && pwd)"
  ADAPTER="$ROOT/adapters/aws/normalize.sh"
  SNAP="$ROOT/snapshots/aws-drifted-2026-10"
}

@test "emits valid JSON Lines, one normalized resource per line" {
  run --separate-stderr bash "$ADAPTER" "$SNAP"
  [ "$status" -eq 0 ]
  [ "${#lines[@]}" -gt 20 ]
  for line in "${lines[@]}"; do
    printf '%s\n' "$line" | jq -e 'type == "object" and (.id | startswith("aws:")) and has("source")' >/dev/null
  done
}

@test "output is deterministic" {
  first="$(bash "$ADAPTER" "$SNAP")"
  second="$(bash "$ADAPTER" "$SNAP")"
  [ "$first" = "$second" ]
}

@test "emits unsupported resource types instead of dropping them" {
  run bash -c "bash '$ADAPTER' '$SNAP' | jq -r 'select(.type == \"unsupported\") | .native_type' | sort -u"
  [ "$status" -eq 0 ]
  [[ "$output" == *"AWS::lambda::Function"* ]]
  [[ "$output" == *"AWS::IAM::Group"* ]]
}

@test "drops sensitive raw fields" {
  out="$(bash "$ADAPTER" "$SNAP")"
  # Each sensitive raw value, JSON-escaped onto one line exactly as it would appear inside the JSON Lines output.
  values="$(jq -r '.. | objects | to_entries[]
    | select(.key | test("secret|passw(or)?d|user_?data|connection_?string"; "i"))
    | .value | strings | select(length > 0) | @json | .[1:-1]' "$SNAP"/*.json)"
  [ -n "$values" ]
  leaked=0
  while IFS= read -r v; do
    if [[ "$out" == *"$v"* ]]; then
      echo "leaked: $v"
      leaked=1
    fi
  done <<< "$values"
  # Plain [ ] tests: bash 3.2 does not fail a Bats test on a [[ ]] that is not the last command.
  [ "$leaked" -eq 0 ]
  [ "$(grep -c "SecretAccessKey" <<< "$out")" -eq 0 ]
  [ "$(grep -c "UserData" <<< "$out")" -eq 0 ]
}

@test "fails cleanly on a missing directory" {
  run --separate-stderr bash "$ADAPTER" "$BATS_TEST_TMPDIR/no-such-snapshot"
  [ "$status" -eq 2 ]
  [ -z "$output" ]
  [[ "$stderr" == *"not a snapshot directory"* ]]
}
