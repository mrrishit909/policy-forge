# Fixture tests for the relationships pack: positive, negative and boundary fixtures per rule.
package policyforge.tests

import data.policyforge.testlib
import rego.v1

test_PF_REL_001_positive if testlib.kind_ok("PF-REL-001", "positive")

test_PF_REL_001_negative if testlib.kind_ok("PF-REL-001", "negative")

test_PF_REL_001_boundary if testlib.kind_ok("PF-REL-001", "boundary")

test_PF_REL_002_positive if testlib.kind_ok("PF-REL-002", "positive")

test_PF_REL_002_negative if testlib.kind_ok("PF-REL-002", "negative")

test_PF_REL_002_boundary if testlib.kind_ok("PF-REL-002", "boundary")
