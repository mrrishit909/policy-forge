# PF-STOR-002: an S3 bucket policy allows an anonymous principal ("*") without the public access guard
# (RestrictPublicBuckets) neutralizing it.
package policyforge.rules.stor_002

import data.policyforge.lib
import rego.v1

rule_id := "PF-STOR-002"

results contains res if {
	some r in input.resources
	r.type == "storage_bucket"
	r.provider == "aws"
	res := lib.result(rule_id, r, verdict(r))
}

unknown_ev(r) := [lib.stmt_ev(s) | some s in lib.policy_statements(r); lib.unknown_public_statement(s)]

verdict(r) := lib.verdict(
	"fail",
	sprintf("The bucket policy allows the anonymous principal \"*\" in %d statement(s) and RestrictPublicBuckets is off.", [count(lib.public_stmt_ev(r))]),
	array.concat(lib.public_stmt_ev(r), [lib.guard_ev(r)]),
) if {
	lib.policy_public(r)
} else := lib.verdict(
	"unknown",
	"The bucket policy document could not be parsed, so public grants cannot be evaluated.",
	[lib.ev("/properties/public_access/policy", {"parse_error": true}, r.properties.raw.policy), lib.guard_ev(r)],
) if {
	lib.policy_unknown(r)
	lib.policy_parse_error(r)
} else := lib.verdict(
	"unknown",
	"A policy statement uses NotPrincipal, a Condition on an anonymous principal, or a Principal or Effect that could not be read; those semantics are not evaluated.",
	array.concat(unknown_ev(r), [lib.guard_ev(r)]),
) if {
	lib.policy_unknown(r)
} else := lib.verdict(
	"pass",
	"The bucket policy grants the anonymous principal but RestrictPublicBuckets neutralizes it.",
	array.concat(lib.public_stmt_ev(r), [lib.guard_ev(r)]),
) if {
	count(lib.public_stmt_ev(r)) > 0
} else := lib.verdict("pass", "No bucket policy statement allows an anonymous principal.", [lib.guard_ev(r)])
