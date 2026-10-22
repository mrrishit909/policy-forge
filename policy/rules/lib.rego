# Shared helpers for the Policy Forge rules. Input shape:
#   {"resources": [normalized resource...], "edges": [{"from", "to", "kind"}...], "context": {...}}
# Every rule package under data.policyforge.rules exposes rule_id and a set `results` of
# {rule_id, resource_id, status (pass|fail|unknown), reason, evidence: [{path, value, raw, ...}]}.
package policyforge.lib

import rego.v1

ctx := object.get(input, "context", {})

by_id[r.id] := r if some r in input.resources

edges := object.get(input, "edges", [])

targets(id, kind) := [e.to | some e in edges; e.from == id; e.kind == kind]

sources(id, kind) := [e.from | some e in edges; e.to == id; e.kind == kind]

resolved_targets(id, kind) := [by_id[t] | some t in targets(id, kind); by_id[t]]

# References the engine could not resolve to a resource in the snapshot: input.unresolved [{from, kind, target}].
unresolved_targets(id, kind) := [u.target |
	some u in object.get(input, "unresolved", [])
	u.from == id
	u.kind == kind
]

ev(path, value, raw) := {"path": path, "value": value, "raw": raw}

verdict(status, reason, evidence) := {"status": status, "reason": reason, "evidence": evidence}

result(rule_id, r, v) := object.union({"rule_id": rule_id, "resource_id": r.id}, v)

listed(principal_ids) if {
	some p in principal_ids
	p != null
	p in object.get(ctx, "break_glass_principals", [])
}

# ------------------------------------------------------------------ permission statements
# Normalized statement: {effect, actions, not_actions, resources, not_resources, principals, not_principals,
# has_condition, raw, policy}. null means "the field is absent"; a list means it is present.

allows(s) if s.effect == "Allow"

denies(s) if s.effect == "Deny"

plain(s) if {
	s.not_actions == null
	s.not_resources == null
	s.has_condition == false
}

all_resources(s) if {
	is_array(s.resources)
	some x in s.resources
	x in {"*", "/"}
}

all_resources(s) if {
	is_array(s.resources)
	some x in s.resources
	regex.match(`^/subscriptions/[^/]+$`, x)
}

full_wildcard(s) if {
	is_array(s.actions)
	some a in s.actions
	a in {"*", "*:*"}
}

service_wildcards(s) := [a |
	is_array(s.actions)
	some a in s.actions
	regex.match(`^([A-Za-z0-9-]+:\*|Microsoft\.[A-Za-z0-9]+/\*)$`, a)
]

admin_actions := {"*", "*:*", "iam:*", "Microsoft.Authorization/*", "Microsoft.Authorization/roleAssignments/write"}

admin_action(s) if {
	is_array(s.actions)
	some a in s.actions
	a in admin_actions
}

# An unconditional Deny of every action on every resource negates every Allow in the same document.
negated(statements) if {
	some d in statements
	denies(d)
	full_wildcard(d)
	all_resources(d)
	plain(d)
}

grants_full(s) if {
	allows(s)
	plain(s)
	full_wildcard(s)
	all_resources(s)
}

grants_admin(s) if {
	allows(s)
	plain(s)
	admin_action(s)
	all_resources(s)
}

# Statements whose effective grant the rules do not compute: NotAction / NotResource on an Allow, or a
# Condition on an Allow that would otherwise match.
unevaluable_allow(s) if {
	allows(s)
	s.not_actions != null
}

unevaluable_allow(s) if {
	allows(s)
	s.not_resources != null
}

unevaluable_admin(s) if unevaluable_allow(s)

unevaluable_admin(s) if {
	allows(s)
	s.has_condition == true
	admin_action(s)
	all_resources(s)
}

stmt_ev(s) := ev(
	"/properties/permissions/statements", {
		"policy": object.get(s, "policy", null), "sid": s.sid, "effect": s.effect, "actions": s.actions,
		"not_actions": s.not_actions, "resources": s.resources, "has_condition": s.has_condition,
	},
	s.raw,
)

# Admin capability of a permission set {parse_error, statements}: "yes", "unknown" or "no".
admin_capability(perms) := "yes" if {
	not negated(perms.statements)
	some s in perms.statements
	grants_admin(s)
} else := "unknown" if {
	not negated(perms.statements)
	some s in perms.statements
	unevaluable_admin(s)
} else := "unknown" if {
	perms.parse_error == true
} else := "no"

admin_evidence(perms) := [stmt_ev(s) | some s in perms.statements; grants_admin(s)]

# ------------------------------------------------------------------ storage public access
acl_grants(b) := b.properties.public_access.anonymous_grants

acl_public(b) if {
	count(acl_grants(b)) > 0
	b.properties.public_access.anonymous_grants_blocked == false
}

acl_unknown(b) if {
	count(acl_grants(b)) > 0
	b.properties.public_access.anonymous_grants_blocked == null
}

acl_ev(b) := [ev(sprintf("/properties/public_access/anonymous_grants/%d", [i]), g, g.raw) | some i, g in acl_grants(b)]

guard_ev(b) := ev("/properties/public_access/guard", b.properties.public_access.guard, b.properties.raw.guard)

policy_statements(b) := object.get(b.properties.public_access, "policy", null).statements if {
	object.get(b.properties.public_access, "policy", null) != null
} else := []

public_statement(s) if {
	allows(s)
	is_array(s.principals)
	"*" in s.principals
	s.has_condition == false
	s.not_principals == null
}

unknown_public_statement(s) if {
	allows(s)
	s.not_principals != null
}

unknown_public_statement(s) if {
	allows(s)
	is_array(s.principals)
	"*" in s.principals
	s.has_condition == true
}

policy_parse_error(b) if object.get(b.properties.public_access, "policy", null).parse_error == true

policy_public(b) if {
	some s in policy_statements(b)
	public_statement(s)
	b.properties.public_access.public_policy_blocked == false
}

policy_unknown(b) if {
	b.properties.public_access.public_policy_blocked == false
	some s in policy_statements(b)
	unknown_public_statement(s)
}

policy_unknown(b) if {
	b.properties.public_access.public_policy_blocked == false
	policy_parse_error(b)
}

public_stmt_ev(b) := [stmt_ev(s) | some s in policy_statements(b); public_statement(s)]

# ------------------------------------------------------------------ network exposure
internet_tags := {"*", "Internet", "Any", "internet", "any"}

internal_tags := {"VirtualNetwork", "AzureLoadBalancer"}

private_v4 := ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16"]

cidr_norm(c) := c if contains(c, "/")

cidr_norm(c) := concat("", [c, "/32"]) if {
	not contains(c, "/")
	not contains(c, ":")
}

cidr_norm(c) := concat("", [c, "/128"]) if {
	not contains(c, "/")
	contains(c, ":")
}

prefix_len(c) := to_number(split(cidr_norm(c), "/")[1])

valid_cidr(c) if net.cidr_is_valid(cidr_norm(c))

# "Internet-wide": 0.0.0.0/0 and any IPv4 block of /8 or larger outside private space, any IPv6 block of
# /16 or larger outside fc00::/7, and the provider tags for "any source".
wide_cidr(c) if {
	valid_cidr(c)
	not contains(c, ":")
	prefix_len(c) <= 8
	not in_private_v4(cidr_norm(c))
}

wide_cidr(c) if {
	valid_cidr(c)
	contains(c, ":")
	prefix_len(c) <= 16
	not net.cidr_contains("fc00::/7", cidr_norm(c))
}

in_private_v4(n) if {
	some p in private_v4
	net.cidr_contains(p, n)
}

internet_sources(e) := array.concat(
	[c | some c in e.cidrs; wide_cidr(c)],
	[t | some t in e.source_tags; t in internet_tags],
)

unevaluable_sources(e) := array.concat(
	array.concat([c | some c in e.cidrs; not valid_cidr(c)], [t | some t in e.source_tags; not t in internet_tags; not t in internal_tags]),
	[sprintf("prefix-list:%s", [p]) | some p in e.prefix_lists],
)

port_protocols := {"tcp", "udp", "all"}

known_protocols := {"tcp", "udp", "all", "icmp", "icmpv6"}

covers(e, p) if {
	e.port_from != null
	e.port_to != null
	e.port_from <= p
	p <= e.port_to
}

# A higher-priority (lower number) deny from any source covering the port and protocol shadows an allow.
deny_any_source(d) if {
	d.action == "deny"
	count([t | some t in d.source_tags; t in internet_tags]) + count([c | some c in d.cidrs; c in {"0.0.0.0/0", "::/0"}]) > 0
}

outranks(d, e) if {
	d.priority != null
	e.priority != null
	d.priority < e.priority
	d.protocol in {"all", e.protocol}
}

shadowed(g, e, p) if {
	some d in g.properties.ingress
	deny_any_source(d)
	outranks(d, e)
	covers(d, p)
}

fully_shadowed(g, e) if {
	some d in g.properties.ingress
	deny_any_source(d)
	outranks(d, e)
	e.port_from != null
	covers(d, e.port_from)
	covers(d, e.port_to)
}

ingress_ev(i, e, extra) := object.union(
	ev(
		sprintf("/properties/ingress/%d", [i]), {
			"protocol": e.protocol, "port_from": e.port_from, "port_to": e.port_to, "cidrs": e.cidrs,
			"source_tags": e.source_tags, "prefix_lists": e.prefix_lists, "priority": e.priority,
		},
		e.raw,
	),
	extra,
)

exposures(g, ports) := [ingress_ev(i, e, {"ports": hit, "internet_sources": internet_sources(e)}) |
	some i, e in g.properties.ingress
	e.action == "allow"
	e.protocol in port_protocols
	count(internet_sources(e)) > 0
	hit := [p | some p in ports; covers(e, p); not shadowed(g, e, p)]
	count(hit) > 0
]

exposure_unknowns(g, ports) := array.concat(
	[ingress_ev(i, e, {"why": "protocol form not evaluated"}) |
		some i, e in g.properties.ingress
		e.action == "allow"
		not e.protocol in known_protocols
		count(internet_sources(e)) + count(unevaluable_sources(e)) > 0
	],
	array.concat(
		[ingress_ev(i, e, {"why": "port range not parseable"}) |
			some i, e in g.properties.ingress
			e.action == "allow"
			e.protocol in port_protocols
			e.port_from == null
			count(internet_sources(e)) + count(unevaluable_sources(e)) > 0
		],
		[ingress_ev(i, e, {"why": "source not expanded", "unevaluable_sources": unevaluable_sources(e)}) |
			some i, e in g.properties.ingress
			e.action == "allow"
			e.protocol in port_protocols
			count(unevaluable_sources(e)) > 0
			count([p | some p in ports; covers(e, p)]) > 0
		],
	),
)

internet_open(g) if {
	some e in g.properties.ingress
	e.action == "allow"
	count(internet_sources(e)) > 0
	not fully_shadowed(g, e)
}
