# PF-NET-002: data-service ports (context sensitive_ports minus remote_admin_ports) are reachable
# from internet-wide sources.
package policyforge.rules.net_002

import data.policyforge.lib
import rego.v1

rule_id := "PF-NET-002"

ports := [p | some p in object.get(lib.ctx, "sensitive_ports", [1433, 3306, 5432, 6379, 9200, 27017]); not p in object.get(lib.ctx, "remote_admin_ports", [22, 3389])]

results contains res if {
	some r in input.resources
	r.type in {"security_group", "network_security_group"}
	res := lib.result(rule_id, r, verdict(r))
}

verdict(r) := lib.verdict(
	"fail",
	sprintf("%d ingress rule(s) expose data-service ports to internet-wide sources.", [count(lib.exposures(r, ports))]),
	lib.exposures(r, ports),
) if {
	count(lib.exposures(r, ports)) > 0
} else := lib.verdict(
	"unknown",
	"An ingress rule uses a protocol, port form, prefix list or service tag that is not evaluated.",
	lib.exposure_unknowns(r, ports),
) if {
	count(lib.exposure_unknowns(r, ports)) > 0
} else := lib.verdict("pass", "No data-service port is open to internet-wide sources.", [])
