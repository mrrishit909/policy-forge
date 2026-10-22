# Fixture tests for the iam pack: positive, negative and boundary fixtures per rule.
package policyforge.tests

import data.policyforge.testlib
import rego.v1

test_PF_IAM_001_positive if testlib.kind_ok("PF-IAM-001", "positive")

test_PF_IAM_001_negative if testlib.kind_ok("PF-IAM-001", "negative")

test_PF_IAM_001_boundary if testlib.kind_ok("PF-IAM-001", "boundary")

test_PF_IAM_002_positive if testlib.kind_ok("PF-IAM-002", "positive")

test_PF_IAM_002_negative if testlib.kind_ok("PF-IAM-002", "negative")

test_PF_IAM_002_boundary if testlib.kind_ok("PF-IAM-002", "boundary")

test_PF_IAM_003_positive if testlib.kind_ok("PF-IAM-003", "positive")

test_PF_IAM_003_negative if testlib.kind_ok("PF-IAM-003", "negative")

test_PF_IAM_003_boundary if testlib.kind_ok("PF-IAM-003", "boundary")
