# PF-AUD-003: an AWS CloudTrail trail has log file integrity validation turned off.
package policyforge.rules.aud_003

import data.policyforge.lib
import rego.v1

rule_id := "PF-AUD-003"

results contains res if {
	some r in input.resources
	r.type == "audit_trail"
	res := lib.result(rule_id, r, verdict(r))
}

flag(r) := [lib.ev("/properties/log_file_validation", r.properties.log_file_validation, r.properties.raw.log_file_validation)]

verdict(r) := lib.verdict("fail", "Log file integrity validation is disabled; tampering with delivered logs would not be detectable.", flag(r)) if {
	r.properties.log_file_validation == false
} else := lib.verdict("pass", "Log file integrity validation is enabled.", flag(r))
