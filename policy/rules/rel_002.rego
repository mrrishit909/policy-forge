# PF-REL-002: storage that receives audit logs (an audit trail / diagnostic setting delivers to it, or the
# context lists it as an audit log target) is publicly readable.
package policyforge.rules.rel_002

import data.policyforge.lib
import rego.v1

rule_id := "PF-REL-002"

audit_target(r) if {
	some id in lib.sources(r.id, "delivers_logs_to")
	lib.by_id[id].type in {"audit_trail", "diagnostic_setting"}
}

audit_target(r) if {
	some t in object.get(lib.ctx, "audit_log_targets", [])
	t in {r.name, r.id, split(r.id, ":storage_bucket:")[1]}
}

results contains res if {
	some r in input.resources
	r.type == "storage_bucket"
	audit_target(r)
	res := lib.result(rule_id, r, verdict(r))
}

feeders(r) := [lib.ev("/refs", {"delivered_by": sort(lib.sources(r.id, "delivers_logs_to"))}, null)]

verdict(r) := lib.verdict(
	"fail",
	"This storage receives audit logs and is publicly readable, exposing the audit record.",
	array.concat(array.concat(feeders(r), lib.acl_ev(r)), array.concat(lib.public_stmt_ev(r), [lib.guard_ev(r)])),
) if {
	lib.acl_public(r)
} else := lib.verdict(
	"fail",
	"This storage receives audit logs and its bucket policy allows anonymous access.",
	array.concat(array.concat(feeders(r), lib.public_stmt_ev(r)), [lib.guard_ev(r)]),
) if {
	lib.policy_public(r)
} else := lib.verdict(
	"unknown",
	"This storage receives audit logs and its public access could not be fully evaluated.",
	array.concat(feeders(r), [lib.guard_ev(r)]),
) if {
	lib.acl_unknown(r)
} else := lib.verdict(
	"unknown",
	"This storage receives audit logs and its public access could not be fully evaluated.",
	array.concat(feeders(r), [lib.guard_ev(r)]),
) if {
	lib.policy_unknown(r)
} else := lib.verdict("pass", "This audit log storage is not publicly readable.", array.concat(feeders(r), [lib.guard_ev(r)]))
