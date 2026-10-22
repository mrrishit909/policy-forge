# Fixture tests for the audit pack: positive, negative and boundary fixtures per rule.
package policyforge.tests

import data.policyforge.testlib
import rego.v1

test_PF_AUD_001_positive if testlib.kind_ok("PF-AUD-001", "positive")

test_PF_AUD_001_negative if testlib.kind_ok("PF-AUD-001", "negative")

test_PF_AUD_001_boundary if testlib.kind_ok("PF-AUD-001", "boundary")

test_PF_AUD_002_positive if testlib.kind_ok("PF-AUD-002", "positive")

test_PF_AUD_002_negative if testlib.kind_ok("PF-AUD-002", "negative")

test_PF_AUD_002_boundary if testlib.kind_ok("PF-AUD-002", "boundary")

test_PF_AUD_003_positive if testlib.kind_ok("PF-AUD-003", "positive")

test_PF_AUD_003_negative if testlib.kind_ok("PF-AUD-003", "negative")

test_PF_AUD_003_boundary if testlib.kind_ok("PF-AUD-003", "boundary")

test_PF_AUD_004_positive if testlib.kind_ok("PF-AUD-004", "positive")

test_PF_AUD_004_negative if testlib.kind_ok("PF-AUD-004", "negative")

test_PF_AUD_004_boundary if testlib.kind_ok("PF-AUD-004", "boundary")
