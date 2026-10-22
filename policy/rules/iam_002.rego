# PF-IAM-002: an Allow statement grants a whole service ("s3:*", "Microsoft.Storage/*") on every resource.
package policyforge.rules.iam_002

import data.policyforge.lib
import rego.v1

rule_id := "PF-IAM-002"

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

broad(perms) := [object.union(lib.stmt_ev(s), {"service_wildcards": lib.service_wildcards(s)}) |
	some s in perms.statements
	lib.allows(s)
	lib.plain(s)
	count(lib.service_wildcards(s)) > 0
	lib.all_resources(s)
]

unevaluable(perms) := [lib.stmt_ev(s) | some s in perms.statements; unevaluable_stmt(s)]

unevaluable_stmt(s) if lib.unevaluable_allow(s)

unevaluable_stmt(s) if {
	lib.allows(s)
	s.has_condition == true
	count(lib.service_wildcards(s)) > 0
	lib.all_resources(s)
}

unevaluable_stmt(s) if {
	lib.allows(s)
	count(lib.service_wildcards(s)) > 0
	lib.maybe_all_resources(s)
}

unevaluable_stmt(s) if {
	lib.odd_effect(s)
	count(lib.service_wildcards(s)) > 0
}

unevaluable_stmt(s) if lib.unreadable_actions(s)

verdict(perms) := lib.verdict(
	"fail",
	sprintf("%d Allow statement(s) grant a whole service on every resource.", [count(broad(perms))]),
	broad(perms),
) if {
	count(broad(perms)) > 0
	not lib.negated(perms.statements)
} else := lib.verdict(
	"pass",
	"Every Allow is negated by an unconditional Deny of every action on every resource.",
	broad(perms),
) if {
	lib.negated(perms.statements)
} else := lib.verdict(
	"unknown",
	"A statement uses NotAction, NotResource, a Condition, a wildcard resource pattern or an unreadable Effect or action alongside service-level actions; not evaluated.",
	unevaluable(perms),
) if {
	count(unevaluable(perms)) > 0
} else := lib.verdict(
	"unknown",
	"A policy document could not be parsed.",
	[lib.ev("/properties/permissions/parse_error", true, null)],
) if {
	perms.parse_error == true
} else := lib.verdict("pass", "No Allow statement grants a whole service on every resource.", [])
