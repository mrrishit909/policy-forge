# Fixture tests for the storage pack: positive, negative and boundary fixtures per rule.
package policyforge.tests

import data.policyforge.testlib
import rego.v1

test_PF_STOR_001_positive if testlib.kind_ok("PF-STOR-001", "positive")

test_PF_STOR_001_negative if testlib.kind_ok("PF-STOR-001", "negative")

test_PF_STOR_001_boundary if testlib.kind_ok("PF-STOR-001", "boundary")

test_PF_STOR_002_positive if testlib.kind_ok("PF-STOR-002", "positive")

test_PF_STOR_002_negative if testlib.kind_ok("PF-STOR-002", "negative")

test_PF_STOR_002_boundary if testlib.kind_ok("PF-STOR-002", "boundary")
