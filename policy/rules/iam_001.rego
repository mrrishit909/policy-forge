# PF-IAM-001: an Allow statement grants every action on every resource ("*" on "*"; for Azure custom roles,
# Actions "*" assignable at subscription or root scope).
package policyforge.rules.iam_001

import data.policyforge.lib
import rego.v1

rule_id := "PF-IAM-001"

applicable(r) if r.type in {"iam_role", "iam_user"}

applicable(r) if {
	r.type == "iam_policy"
	r.properties.managed_by == "customer"
}

applicable(r) if {
	r.type == "role_definition"
	r.properties.is_custom == true
}

results contains res if {
	some r in input.resources
	applicable(r)
	res := lib.result(rule_id, r, verdict(r.properties.permissions))
}

full(perms) := [lib.stmt_ev(s) | some s in perms.statements; lib.grants_full(s)]

unevaluable(perms) := [lib.stmt_ev(s) | some s in perms.statements; lib.unevaluable_allow(s)]

conditional(perms) := [lib.stmt_ev(s) |
	some s in perms.statements
	lib.allows(s)
	s.has_condition == true
	lib.full_wildcard(s)
	lib.all_resources(s)
]

verdict(perms) := lib.verdict(
	"fail",
	sprintf("%d Allow statement(s) grant every action on every resource.", [count(full(perms))]),
	full(perms),
) if {
	count(full(perms)) > 0
	not lib.negated(perms.statements)
} else := lib.verdict(
	"pass",
	"Every Allow is negated by an unconditional Deny of every action on every resource in the same document.",
	full(perms),
) if {
	lib.negated(perms.statements)
} else := lib.verdict(
	"unknown",
	"An Allow statement uses NotAction or NotResource; the effective grant is not computed.",
	unevaluable(perms),
) if {
	count(unevaluable(perms)) > 0
} else := lib.verdict(
	"unknown",
	"A wildcard Allow is conditional; Condition semantics are not evaluated.",
	conditional(perms),
) if {
	count(conditional(perms)) > 0
} else := lib.verdict(
	"unknown",
	"A policy document could not be parsed.",
	[lib.ev("/properties/permissions/parse_error", true, null)],
) if {
	perms.parse_error == true
} else := lib.verdict("pass", "No Allow statement grants every action on every resource.", [])
