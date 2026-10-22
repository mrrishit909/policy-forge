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
  values="$(jq -r '.. | objects | to_entries[]
    | select(.key | test("secret|passw(or)?d|user_?data|connection_?string"; "i"))
    | .value | strings' "$SNAP"/*.json)"
  [ -n "$values" ]
  while IFS= read -r v; do
    [[ "$out" != *"$v"* ]]
  done <<< "$values"
  [[ "$out" != *"SecretAccessKey"* ]]
  [[ "$out" != *"UserData"* ]]
}

@test "fails cleanly on a missing directory" {
  run --separate-stderr bash "$ADAPTER" "$BATS_TEST_TMPDIR/no-such-snapshot"
  [ "$status" -eq 2 ]
  [ -z "$output" ]
  [[ "$stderr" == *"not a snapshot directory"* ]]
}
