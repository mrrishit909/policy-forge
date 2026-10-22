# PF-AUD-002: an AWS CloudTrail trail records only its home region.
package policyforge.rules.aud_002

import data.policyforge.lib
import rego.v1

rule_id := "PF-AUD-002"

results contains res if {
	some r in input.resources
	r.type == "audit_trail"
	res := lib.result(rule_id, r, verdict(r))
}

flag(r) := [lib.ev("/properties/multi_region", r.properties.multi_region, r.properties.raw.multi_region)]

verdict(r) := lib.verdict("fail", "The trail is not multi-region; activity in other regions is not recorded by it.", flag(r)) if {
	r.properties.multi_region == false
} else := lib.verdict("pass", "The trail is multi-region.", flag(r))
