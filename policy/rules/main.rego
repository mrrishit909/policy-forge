# Single entry point: `opa eval --format json -d policy/rules -i INPUT 'data.policyforge.results'`.
package policyforge

import rego.v1

results := sort([res | some name; some res in data.policyforge.rules[name].results])

rule_ids := sort([id | some name; id := data.policyforge.rules[name].rule_id])
