# Fixture runner. Each policy/fixtures/<RULE_ID>/<kind>-<n>.json file holds {"<kind>-<n>": {description, input,
# expected}}; OPA loads them as data.fixtures[RULE_ID]["<kind>-<n>"] (the file content is keyed by its own stem so
# several files can share one directory).
package policyforge.testlib

import rego.v1

statuses(rule_id, fx) := {r.resource_id: r.status | some r in results; r.rule_id == rule_id} if {
	results := data.policyforge.results with input as fx.input
}

names(rule_id, kind) := [n |
	some n, _ in data.fixtures[rule_id]
	startswith(n, concat("", [kind, "-"]))
]

kind_shape_ok(fx, "positive") if "fail" in {s | some s in fx.expected}

kind_shape_ok(fx, "negative") if {
	count(fx.expected) > 0
	every s in fx.expected {
		s == "pass"
	}
}

kind_shape_ok(fx, "boundary") if count(fx.expected) > 0

kind_ok(rule_id, kind) if {
	count(names(rule_id, kind)) > 0
	every n in names(rule_id, kind) {
		fx := data.fixtures[rule_id][n]
		kind_shape_ok(fx, kind)
		statuses(rule_id, fx) == fx.expected
	}
}
