# Unit tests for the Conftest hygiene policy (package main).
package main_test

import rego.v1

good_exception := {
	"id": "EXC-T1", "rule_id": "PF-NET-001", "resource_id": "aws:security_group:sg-1",
	"reason": "r", "owner": "o", "ticket": "T-1", "created": "2026-10-01", "expires": "2026-12-30",
}

deny_for(e) := {d.msg | some d in denials} if {
	denials := data.main.deny with input as {"exceptions": [e]}
}

test_rejection_carries_index_and_reason if {
	denials := data.main.deny with input as {"exceptions": [good_exception, object.union(good_exception, {"id": "X: y", "rule_id": "PF-XYZ-001"})]}
	denials == {{"msg": "X: y: unknown rule id", "index": 1, "reason": "unknown rule id"}}
}

test_null_id_rejected if "null: missing id" in deny_for(object.union(good_exception, {"id": null}))

test_non_object_entry_rejected if {
	denials := data.main.deny with input as {"exceptions": ["EXC-9"]}
	denials == {{"msg": "unidentified: entry is not an object", "index": 0, "reason": "entry is not an object"}}
}

test_sensitive_property_names if {
	data.main.sensitive_key("clientSecret")
	data.main.sensitive_key("x-api-key")
	data.main.sensitive_key("SecretAccessKey")
	data.main.sensitive_key("DeliveryToken")
	not data.main.sensitive_key("TokenEndpoint")
	not data.main.sensitive_key("AccessKeyId")
	not data.main.sensitive_key("PasswordLastUsed")
}

test_valid_exception_passes if count(deny_for(good_exception)) == 0

test_expiry_exactly_90_days_passes if count(deny_for(object.union(good_exception, {"expires": "2026-12-30"}))) == 0

test_expiry_91_days_rejected if "EXC-T1: expiry is more than 90 days after created" in deny_for(object.union(good_exception, {"expires": "2026-12-31"}))

test_wildcard_resource_rejected if "EXC-T1: resource_id must be one exact resource id, not a wildcard or pattern" in deny_for(object.union(good_exception, {"resource_id": "aws:security_group:*"}))

test_unknown_rule_rejected if "EXC-T1: unknown rule id" in deny_for(object.union(good_exception, {"rule_id": "PF-XYZ-001"}))

test_expiry_before_created_rejected if "EXC-T1: expires before it was created" in deny_for(object.union(good_exception, {"expires": "2026-09-30"}))

test_missing_owner_rejected if "EXC-T1: missing owner" in deny_for(object.remove(good_exception, ["owner"]))

test_missing_expiry_rejected if "EXC-T1: missing expires" in deny_for(object.union(good_exception, {"expires": ""}))

test_inventory_credential_value_rejected if {
	msgs := data.main.deny with input as {"resources": [{
		"id": "aws:iam_user:u", "provider": "aws", "type": "iam_user", "native_type": "x", "name": "u",
		"region": "global", "refs": [], "source": {"file": "snapshots/s/f.json", "pointer": "/0", "line": 3},
		"properties": {"tags": {"note": "pf-canary-00ff-not-a-secret"}},
	}]}
	count(msgs) == 1
}

test_inventory_missing_source_rejected if {
	msgs := data.main.deny with input as {"resources": [{
		"id": "aws:iam_user:u", "provider": "aws", "type": "iam_user", "native_type": "x", "name": "u",
		"region": "global", "refs": [], "properties": {}, "source": {"file": "snapshots/s/f.json", "pointer": "/0"},
	}]}
	"aws:iam_user:u: source must name a snapshot file, a JSON pointer and a line" in msgs
}
