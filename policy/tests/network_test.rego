# Fixture tests for the network pack: positive, negative and boundary fixtures per rule.
package policyforge.tests

import data.policyforge.testlib
import rego.v1

test_PF_NET_001_positive if testlib.kind_ok("PF-NET-001", "positive")

test_PF_NET_001_negative if testlib.kind_ok("PF-NET-001", "negative")

test_PF_NET_001_boundary if testlib.kind_ok("PF-NET-001", "boundary")

test_PF_NET_002_positive if testlib.kind_ok("PF-NET-002", "positive")

test_PF_NET_002_negative if testlib.kind_ok("PF-NET-002", "negative")

test_PF_NET_002_boundary if testlib.kind_ok("PF-NET-002", "boundary")
