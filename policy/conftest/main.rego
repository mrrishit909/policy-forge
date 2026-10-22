# Conftest input hygiene (package main, deny/warn). Run against two inputs:
#   (a) the normalized inventory, wrapped as {"resources": [...]}
#   (b) exceptions/registry.json, {"exceptions": [...]}, with the rule catalog loaded as data (--data policy/catalog.json)
# Each message starts with the resource or exception id it concerns and never quotes a checked value.
package main

import rego.v1

# ------------------------------------------------------------------ (a) inventory
resource_fields := ["id", "provider", "type", "native_type", "name", "region", "properties", "refs", "source"]

deny contains msg if {
	some r in input.resources
	some f in resource_fields
	not f in object.keys(r)
	msg := sprintf("%s: missing required field %s", [object.get(r, "id", "unidentified"), f])
}

deny contains msg if {
	some r in input.resources
	not valid_source(object.get(r, "source", {}))
	msg := sprintf("%s: source must name a snapshot file, a JSON pointer and a line", [object.get(r, "id", "unidentified")])
}

valid_source(s) if {
	regex.match(`^snapshots/[a-z0-9-]+/[A-Za-z0-9._-]+\.json$`, s.file)
	regex.match(`^(/.*)?$`, s.pointer)
	s.line >= 1
}

deny contains msg if {
	some r in input.resources
	walk(object.get(r, "properties", {}), [path, value])
	is_string(value)
	credential_like(value)
	msg := sprintf("%s: a property value looks like a credential (path %s)", [r.id, concat("/", [sprintf("%v", [p]) | some p in path])])
}

deny contains msg if {
	some r in input.resources
	walk(object.get(r, "properties", {}), [path, _])
	count(path) > 0
	key := path[count(path) - 1]
	is_string(key)
	sensitive_key(key)
	msg := sprintf("%s: property name looks sensitive (path %s)", [r.id, concat("/", [sprintf("%v", [p]) | some p in path])])
}

sensitive_key(k) if regex.match(`(?i)passw(or)?d|secret|token|credential|connection_?string|private_?key|account_?key|user_?data|sas_?token`, k)

credential_like(v) if regex.match(`pf-canary-[0-9a-f]+-not-a-secret`, v)

credential_like(v) if regex.match(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`, v)

credential_like(v) if regex.match(`(?i)\b(password|pwd|accountkey|sharedaccesskey)=[^;\s]+`, v)

credential_like(v) if contains(v, "PRIVATE KEY-----")

deny contains msg if {
	some r in input.resources
	count([x | some x in input.resources; x.id == r.id]) > 1
	msg := sprintf("%s: duplicate resource id", [r.id])
}

warn contains msg if {
	some r in input.resources
	r.type == "unsupported"
	msg := sprintf("%s: native type %s is inventoried but no rule evaluates it", [r.id, r.native_type])
}

# ------------------------------------------------------------------ (b) exceptions registry
exception_fields := ["id", "rule_id", "resource_id", "reason", "owner", "ticket", "created", "expires"]

known_rule_ids := {r.id | some r in data.rules}

exc_id(e) := object.get(e, "id", "unidentified")

blank(v) if not is_string(v)

blank(v) if trim_space(v) == ""

deny contains msg if {
	some e in input.exceptions
	some f in exception_fields
	blank(object.get(e, f, null))
	msg := sprintf("%s: missing %s", [exc_id(e), f])
}

deny contains msg if {
	some e in input.exceptions
	is_string(e.resource_id)
	regex.match(`[*?\[\]{}|^$]`, e.resource_id)
	msg := sprintf("%s: resource_id must be one exact resource id, not a wildcard or pattern", [exc_id(e)])
}

deny contains msg if {
	some e in input.exceptions
	is_string(e.resource_id)
	not regex.match(`^(aws|azure):[a-z_]+:.+$`, e.resource_id)
	msg := sprintf("%s: resource_id is not a normalized resource id", [exc_id(e)])
}

deny contains msg if {
	some e in input.exceptions
	is_string(e.rule_id)
	not e.rule_id in known_rule_ids
	msg := sprintf("%s: unknown rule id", [exc_id(e)])
}

valid_date(s) if {
	is_string(s)
	regex.match(`^\d{4}-\d{2}-\d{2}$`, s)
	time.parse_ns("2006-01-02", s)
}

deny contains msg if {
	some e in input.exceptions
	some f in ["created", "expires"]
	not blank(object.get(e, f, null))
	not valid_date(e[f])
	msg := sprintf("%s: %s is not a YYYY-MM-DD date", [exc_id(e), f])
}

days_between(a, b) := (time.parse_ns("2006-01-02", b) - time.parse_ns("2006-01-02", a)) / 86400000000000

deny contains msg if {
	some e in input.exceptions
	valid_date(e.created)
	valid_date(e.expires)
	days_between(e.created, e.expires) < 0
	msg := sprintf("%s: expires before it was created", [exc_id(e)])
}

deny contains msg if {
	some e in input.exceptions
	valid_date(e.created)
	valid_date(e.expires)
	days_between(e.created, e.expires) > 90
	msg := sprintf("%s: expiry is more than 90 days after created", [exc_id(e)])
}

deny contains msg if {
	some e in input.exceptions
	count([x | some x in input.exceptions; x.id == e.id]) > 1
	msg := sprintf("%s: duplicate exception id", [exc_id(e)])
}
