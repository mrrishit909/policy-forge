# PF-REL-001: an internet-exposed compute instance (public IP plus an attached security group / NSG that
# admits internet-wide sources on any port) runs with an admin-capable identity (AWS instance role; Azure
# managed identity with an admin-capable role at subscription, management group or root scope).
package policyforge.rules.rel_001

import data.policyforge.lib
import rego.v1

rule_id := "PF-REL-001"

results contains res if {
	some r in input.resources
	r.type == "compute_instance"
	res := lib.result(rule_id, r, verdict(r))
}

groups(r) := lib.resolved_targets(r.id, "uses_network_group")

open_groups(r) := [g.id | some g in groups(r); lib.internet_open(g)]

exposed(r) if {
	count(r.properties.public_ips) > 0
	count(open_groups(r)) > 0
}

exposure_unknown(r) if {
	count(r.properties.public_ips) > 0
	count(lib.unresolved_targets(r.id, "uses_network_group")) > 0
}

# AWS: instance role and its inline + attached permissions.
roles(r) := lib.resolved_targets(r.id, "instance_role")

perm_sets(role) := array.concat(
	[role.properties.permissions],
	[p.properties.permissions | some p in lib.resolved_targets(role.id, "attached_policy")],
)

aws_admin(r) if {
	some role in roles(r)
	some ps in perm_sets(role)
	lib.admin_capability(ps) == "yes"
}

aws_admin_unknown(r) if {
	some role in roles(r)
	some ps in perm_sets(role)
	lib.admin_capability(ps) == "unknown"
}

aws_admin_unknown(r) if count(lib.unresolved_targets(r.id, "instance_role")) > 0

aws_admin_unknown(r) if {
	some role in roles(r)
	count(lib.unresolved_targets(role.id, "attached_policy")) > 0
}

# Azure: role assignments whose principal is this VM's managed identity (an unreadable scope may be broad).
assignments(r) := [a |
	some id in lib.sources(r.id, "assigned_to")
	a := lib.by_id[id]
	a.properties.scope_level in {"root", "management_group", "subscription", "unknown"}
]

role_of(a) := lib.resolved_targets(a.id, "assigned_role")

assignment_capability(a) := "unknown" if {
	a.properties.has_condition == true
} else := "no" if {
	a.properties.scope_level == "unknown"
	count(role_of(a)) > 0
	lib.admin_capability(role_of(a)[0].properties.permissions) == "no"
} else := "unknown" if {
	a.properties.scope_level == "unknown"
} else := lib.admin_capability(role_of(a)[0].properties.permissions) if {
	count(role_of(a)) > 0
} else := "unknown"

azure_admin(r) if {
	some a in assignments(r)
	assignment_capability(a) == "yes"
}

azure_admin_unknown(r) if {
	some a in assignments(r)
	assignment_capability(a) == "unknown"
}

admin(r) if aws_admin(r)

admin(r) if azure_admin(r)

admin_unknown(r) if aws_admin_unknown(r)

admin_unknown(r) if azure_admin_unknown(r)

identity_ev(r) := array.concat(
	[lib.ev("/properties/instance_profile", role.id, r.properties.raw.instance_profile) | some role in roles(r)],
	[lib.ev("/refs/assigned_to", {"assignment": a.id, "role": a.properties.role_name, "scope": a.properties.scope}, a.properties.raw.role) |
		some a in assignments(r)
	],
)

exposure_ev(r) := [lib.ev("/properties/network_groups", {"public_ips": r.properties.public_ips, "open_groups": open_groups(r)}, r.properties.raw.network_groups)]

verdict(r) := lib.verdict(
	"fail",
	"The instance has a public IP, admits internet-wide ingress and runs with an admin-capable identity.",
	array.concat(exposure_ev(r), identity_ev(r)),
) if {
	exposed(r)
	admin(r)
} else := lib.verdict("pass", "The instance is not internet-exposed.", exposure_ev(r)) if {
	not exposed(r)
	not exposure_unknown(r)
} else := lib.verdict("pass", "The instance identity is not admin-capable.", identity_ev(r)) if {
	not admin(r)
	not admin_unknown(r)
} else := lib.verdict(
	"unknown",
	"Exposure or identity permissions could not be fully evaluated (unresolved references, NotAction or conditional grants).",
	array.concat(exposure_ev(r), identity_ev(r)),
)
