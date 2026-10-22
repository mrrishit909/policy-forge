# PF-AUD-004: an Azure subscription Activity Log export is missing a required category or a destination.
package policyforge.rules.aud_004

import data.policyforge.lib
import rego.v1

rule_id := "PF-AUD-004"

required := object.get(lib.ctx, "required_activity_log_categories", ["Administrative", "Security", "Policy"])

results contains res if {
	some r in input.resources
	r.type == "diagnostic_setting"
	res := lib.result(rule_id, r, verdict(r))
}

enabled(r, c) if {
	some x in r.properties.categories
	x.category == c
	x.enabled == true
}

missing(r) := [c | some c in required; not enabled(r, c)]

has_destination(r) if {
	some d in object.keys(r.properties.destinations)
	r.properties.destinations[d] != null
}

cat_ev(r) := [lib.ev(sprintf("/properties/categories/%d", [i]), x, x.raw) | some i, x in r.properties.categories; x.category in required]

dest_ev(r) := lib.ev("/properties/destinations", r.properties.destinations, r.properties.raw.destinations)

verdict(r) := lib.verdict(
	"unknown",
	"Resource-level diagnostic settings have per-resource-type categories that are not evaluated.",
	[lib.ev("/properties/target_resource_id", r.properties.target_resource_id, r.properties.raw.categories)],
) if {
	r.properties.scope_kind != "subscription"
} else := lib.verdict("fail", "The Activity Log export has no destination.", [dest_ev(r)]) if {
	not has_destination(r)
} else := lib.verdict(
	"fail",
	sprintf("Required Activity Log categories are not exported: %s.", [concat(", ", missing(r))]),
	array.concat(cat_ev(r), [lib.ev("/properties/categories", {"missing": missing(r)}, r.properties.raw.categories)]),
) if {
	count(missing(r)) > 0
} else := lib.verdict("pass", "Every required Activity Log category is exported to a destination.", cat_ev(r))
