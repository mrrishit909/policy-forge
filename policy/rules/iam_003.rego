# PF-IAM-003: a principal outside the break-glass list holds standing admin-capable access: an IAM user with
# admin-capable permissions (inline or attached), or an Azure role assignment of an admin-capable role at
# subscription, management group or root scope.
package policyforge.rules.iam_003

import data.policyforge.lib
import rego.v1

rule_id := "PF-IAM-003"

results contains res if {
	some r in input.resources
	r.type in {"iam_user", "role_assignment"}
	res := lib.result(rule_id, r, verdict(r))
}

admin_policy_arn := "arn:aws:iam::aws:policy/AdministratorAccess"

attached(r) := lib.resolved_targets(r.id, "attached_policy")

# AWS users ------------------------------------------------------------
user_admin_ev(r) := array.concat(
	lib.admin_evidence(r.properties.permissions),
	array.concat(
		[lib.ev("/properties/attached_policy_arns", a, r.properties.raw.attached_policy_arns) |
			some a in r.properties.attached_policy_arns
			a == admin_policy_arn
		],
		[lib.ev("/properties/attached_policy_arns", p.properties.arn, r.properties.raw.attached_policy_arns) |
			some p in attached(r)
			p.properties.arn != admin_policy_arn
			lib.admin_capability(p.properties.permissions) == "yes"
		],
	),
)

user_unknown(r) if count(r.properties.group_names) > 0

user_unknown(r) if lib.admin_capability(r.properties.permissions) == "unknown"

user_unknown(r) if {
	some p in attached(r)
	lib.admin_capability(p.properties.permissions) == "unknown"
}

user_unknown(r) if count(lib.unresolved_targets(r.id, "attached_policy")) > 0

# Azure role assignments ------------------------------------------------
broad_scope := {"root", "management_group", "subscription"}

role_def(r) := lib.resolved_targets(r.id, "assigned_role")

assignment_ev(r) := [
	lib.ev("/properties/scope", r.properties.scope, r.properties.raw.scope),
	lib.ev("/properties/role_definition_id", {"id": r.properties.role_definition_id, "name": r.properties.role_name}, r.properties.raw.role),
]

# ----------------------------------------------------------------------
verdict(r) := lib.verdict("pass", "Principal is on the break-glass list.", []) if {
	r.type == "iam_user"
	lib.listed([r.properties.arn, r.name])
} else := lib.verdict(
	"fail",
	"The user holds admin-capable permissions directly and is not a break-glass principal.",
	user_admin_ev(r),
) if {
	r.type == "iam_user"
	count(user_admin_ev(r)) > 0
} else := lib.verdict(
	"unknown",
	"Permissions inherited from IAM groups, or statements using NotAction/Condition, are not evaluated.",
	[lib.ev("/properties/group_names", r.properties.group_names, r.properties.raw.group_names)],
) if {
	r.type == "iam_user"
	user_unknown(r)
} else := lib.verdict("pass", "No admin-capable permission is attached to the user.", []) if {
	r.type == "iam_user"
} else := lib.verdict("pass", "Principal is on the break-glass list.", assignment_ev(r)) if {
	lib.listed([r.properties.principal_id, r.properties.principal_name])
} else := lib.verdict("pass", "Assignment scope is narrower than a subscription.", assignment_ev(r)) if {
	not r.properties.scope_level in broad_scope
} else := lib.verdict(
	"unknown",
	"The role assignment carries a Condition; conditional assignments are not evaluated.",
	array.concat(assignment_ev(r), [lib.ev("/properties/has_condition", true, r.properties.raw.condition)]),
) if {
	r.properties.has_condition == true
} else := lib.verdict(
	"unknown",
	"The assigned role definition is not in the snapshot.",
	assignment_ev(r),
) if {
	count(role_def(r)) == 0
} else := lib.verdict(
	"fail",
	sprintf("Admin-capable role \"%s\" is assigned at %s scope to a principal outside the break-glass list.", [role_def(r)[0].name, r.properties.scope_level]),
	array.concat(assignment_ev(r), lib.admin_evidence(role_def(r)[0].properties.permissions)),
) if {
	lib.admin_capability(role_def(r)[0].properties.permissions) == "yes"
} else := lib.verdict(
	"unknown",
	sprintf("Role \"%s\" uses NotActions; its effective permissions are not computed.", [role_def(r)[0].name]),
	assignment_ev(r),
) if {
	lib.admin_capability(role_def(r)[0].properties.permissions) == "unknown"
} else := lib.verdict("pass", "The assigned role is not admin-capable.", assignment_ev(r))
