# PF-AUD-001: an AWS CloudTrail trail is not logging.
package policyforge.rules.aud_001

import data.policyforge.lib
import rego.v1

rule_id := "PF-AUD-001"

results contains res if {
	some r in input.resources
	r.type == "audit_trail"
	res := lib.result(rule_id, r, verdict(r))
}

flag(r) := [lib.ev("/properties/is_logging", r.properties.is_logging, r.properties.raw.is_logging)]

verdict(r) := lib.verdict("fail", "The trail exists but is not logging (IsLogging is false).", flag(r)) if {
	r.properties.is_logging == false
} else := lib.verdict("unknown", "No trail status was captured for this trail, so logging state is unknown.", flag(r)) if {
	r.properties.is_logging == null
} else := lib.verdict("pass", "The trail is logging.", flag(r))
