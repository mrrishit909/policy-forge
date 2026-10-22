# PF-STOR-001: storage readable anonymously through ACL grants (AWS) or container access levels (Azure)
# that the public access guard does not neutralize.
package policyforge.rules.stor_001

import data.policyforge.lib
import rego.v1

rule_id := "PF-STOR-001"

results contains res if {
	some r in input.resources
	r.type == "storage_bucket"
	res := lib.result(rule_id, r, verdict(r))
}

grant_text(r) := concat(", ", [sprintf("%s %s", [g.grantee, g.permission]) | some g in lib.acl_grants(r)])

verdict(r) := lib.verdict(
	"fail",
	sprintf("Anonymous access is granted (%s) and the public access guard does not neutralize it.", [grant_text(r)]),
	array.concat(lib.acl_ev(r), [lib.guard_ev(r)]),
) if {
	lib.acl_public(r)
} else := lib.verdict(
	"unknown",
	sprintf("Anonymous access is configured (%s) but the account-level guard is not set, so the effective behaviour depends on account defaults that are not evaluated.", [grant_text(r)]),
	array.concat(lib.acl_ev(r), [lib.guard_ev(r)]),
) if {
	lib.acl_unknown(r)
} else := lib.verdict(
	"pass",
	"Anonymous grants exist but the public access guard neutralizes them.",
	array.concat(lib.acl_ev(r), [lib.guard_ev(r)]),
) if {
	count(lib.acl_grants(r)) > 0
} else := lib.verdict("pass", "No anonymous ACL grant or public container access level.", [lib.guard_ev(r)])
