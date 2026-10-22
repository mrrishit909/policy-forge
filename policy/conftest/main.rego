# Conftest input hygiene (package main, deny/warn). Run against two inputs:
#   (a) the normalized inventory, wrapped as {"resources": [...]}
#   (b) exceptions/registry.json, {"exceptions": [...]}
# with the rule catalog and the sensitive-name vocabulary loaded as data (--data policy/catalog.json
# --data policy/sensitive-names.json). Inventory messages start with the resource id. Registry denials are
# structured {msg, index, reason}: the engine maps a rejection back to its registry entry by index, never by
# parsing the message, so an id containing ": " (or a missing id) cannot escape rejection. No message quotes a
# checked value.
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

# The word rule documented in policy/sensitive-names.json (the engine and the adapters implement the same rule).
key_words(k) := [w |
	some w in regex.split(`[^a-z0-9]+`, ascii_lower(regex.replace(
		regex.replace(regex.replace(k, `([a-z0-9])([A-Z])`, "${1}_${2}"), `([A-Z]+)([A-Z][a-z])`, "${1}_${2}"),
		`([A-Za-z])([0-9])`, "${1}_${2}",
	)))
	w != ""
	not regex.match(`^[0-9]+$`, w)
]

ascii_lower(s) := concat("", [c | some ch in split(s, ""); c := lower_ascii_char(ch)])

lower_ascii_char(ch) := lower(ch) if regex.match(`^[A-Z]$`, ch)

lower_ascii_char(ch) := ch if not regex.match(`^[A-Z]$`, ch)

sensitive_key(k) if {
	w := key_words(k)
	count(w) > 0
	w[count(w) - 1] in data.sensitive_names.words
}

sensitive_key(k) if {
	w := key_words(k)
	count(w) > 1
	concat("_", [w[count(w) - 2], w[count(w) - 1]]) in data.sensitive_names.pairs
}

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

exc_id(e) := sprintf("%v", [object.get(e, "id", "unidentified")]) if is_object(e)

else := "unidentified"

reject(i, e, reason) := {"msg": sprintf("%s: %s", [exc_id(e), reason]), "index": i, "reason": reason}

blank(v) if not is_string(v)

blank(v) if trim_space(v) == ""

deny contains msg if {
	"exceptions" in object.keys(input)
	not is_array(input.exceptions)
	msg := "registry: exceptions must be a list"
}

deny contains reject(i, e, "entry is not an object") if {
	some i, e in input.exceptions
	not is_object(e)
}

deny contains reject(i, e, sprintf("missing %s", [f])) if {
	some i, e in input.exceptions
	is_object(e)
	some f in exception_fields
	blank(object.get(e, f, null))
}

deny contains reject(i, e, "resource_id must be one exact resource id, not a wildcard or pattern") if {
	some i, e in input.exceptions
	is_string(e.resource_id)
	regex.match(`[*?\[\]{}|^$]`, e.resource_id)
}

deny contains reject(i, e, "resource_id is not a normalized resource id") if {
	some i, e in input.exceptions
	is_string(e.resource_id)
	not regex.match(`^(aws|azure):[a-z_]+:.+$`, e.resource_id)
}

deny contains reject(i, e, "unknown rule id") if {
	some i, e in input.exceptions
	is_string(e.rule_id)
	not e.rule_id in known_rule_ids
}

valid_date(s) if {
	is_string(s)
	regex.match(`^\d{4}-\d{2}-\d{2}$`, s)
	time.parse_ns("2006-01-02", s)
}

deny contains reject(i, e, sprintf("%s is not a YYYY-MM-DD date", [f])) if {
	some i, e in input.exceptions
	is_object(e)
	some f in ["created", "expires"]
	not blank(object.get(e, f, null))
	not valid_date(e[f])
}

days_between(a, b) := (time.parse_ns("2006-01-02", b) - time.parse_ns("2006-01-02", a)) / 86400000000000

deny contains reject(i, e, "expires before it was created") if {
	some i, e in input.exceptions
	valid_date(e.created)
	valid_date(e.expires)
	days_between(e.created, e.expires) < 0
}

deny contains reject(i, e, "expiry is more than 90 days after created") if {
	some i, e in input.exceptions
	valid_date(e.created)
	valid_date(e.expires)
	days_between(e.created, e.expires) > 90
}

deny contains reject(i, e, "duplicate exception id") if {
	some i, e in input.exceptions
	is_object(e)
	count([x | some x in input.exceptions; is_object(x); x.id == e.id]) > 1
}
