# The catalog and the Rego rule packages describe exactly the same rules, and every rule has fixtures of each kind.
package policyforge.tests

import rego.v1

catalog_ids := {r.id | some r in data.rules}

rego_ids := {id | some id in data.policyforge.rule_ids}

test_catalog_matches_rules if {
	count(catalog_ids) > 0
	catalog_ids == rego_ids
}

test_catalog_fixture_references_exist if {
	every r in data.rules {
		every kind in ["positive", "negative", "boundary"] {
			count(r.fixtures[kind]) > 0
			every path in r.fixtures[kind] {
				stem := trim_suffix(split(path, "/")[3], ".json")
				data.fixtures[r.id][stem]
			}
		}
	}
}
