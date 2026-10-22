# Policy Forge run: aws-baseline-2026-10

Synthetic snapshot `aws-baseline-2026-10` (aws), exceptions evaluated as of 2026-10-22, rule packs: storage, iam, network, audit, relationships, remediation: propose.

## Coverage

Evaluated 12 rules from the storage, iam, network, audit, relationships packs against 20 of 25 resources in aws-baseline-2026-10: 43 checks, 38 passed, 4 failed, 1 unknown. 1 unknown check relies on configuration semantics these rules do not evaluate (for example IAM Conditions, NotAction, unexpanded prefix lists or service tags) and are neither passes nor failures. 3 resources of unsupported types (AWS::IAM::Group, AWS::lambda::Function) were inventoried but not evaluated. 2 resources of covered types had no applicable rule and were not evaluated. Coverage is partial: passing checks describe only what was evaluated, not the whole configuration.

Complete coverage: **no**.

| Rule | Pack | Severity | Pass | Fail | Unknown |
| --- | --- | --- | --- | --- | --- |
| PF-STOR-001 Storage readable anonymously through ACL grants or container access levels | storage | high | 5 | 0 | 0 |
| PF-STOR-002 Bucket policy allows an anonymous principal | storage | high | 4 | 1 | 0 |
| PF-IAM-001 Allow statement grants every action on every resource | iam | critical | 6 | 0 | 0 |
| PF-IAM-002 Allow statement grants a whole service on every resource | iam | high | 5 | 1 | 0 |
| PF-IAM-003 Standing admin-capable access outside the break-glass list | iam | high | 2 | 0 | 1 |
| PF-NET-001 Remote administration ports open to internet-wide sources | network | critical | 4 | 0 | 0 |
| PF-NET-002 Data-service ports open to internet-wide sources | network | high | 4 | 0 | 0 |
| PF-AUD-001 Audit trail is not logging | audit | high | 2 | 0 | 0 |
| PF-AUD-002 Audit trail records only its home region | audit | medium | 1 | 1 | 0 |
| PF-AUD-003 Log file integrity validation is disabled | audit | medium | 1 | 1 | 0 |
| PF-REL-001 Internet-exposed compute runs with an admin-capable identity | relationships | critical | 3 | 0 | 0 |
| PF-REL-002 Storage that receives audit logs is publicly readable | relationships | critical | 1 | 0 | 0 |

## Findings

- **high** PF-IAM-002 on `fh-ci-deploy`: 1 Allow statement(s) grant a whole service on every resource. Source: `snapshots/aws-baseline-2026-10/iam-account-authorization-details.json` line 246.
- **high** PF-STOR-002 on `fh-public-docs` (excepted by EXC-001): The bucket policy allows the anonymous principal "*" in 1 statement(s) and RestrictPublicBuckets is off. Source: `snapshots/aws-baseline-2026-10/s3-buckets.json` line 213.
- **medium** PF-AUD-002 on `data-events-trail`: The trail is not multi-region; activity in other regions is not recorded by it. Source: `snapshots/aws-baseline-2026-10/cloudtrail-describe-trails.json` line 8.
- **medium** PF-AUD-003 on `data-events-trail`: Log file integrity validation is disabled; tampering with delivered logs would not be detectable. Source: `snapshots/aws-baseline-2026-10/cloudtrail-describe-trails.json` line 11.

## Unknown results

- PF-IAM-003 on `aws:iam_user:arn:aws:iam::111122223333:user/alice.ops`: Permissions inherited from IAM groups, or statements using NotAction/Condition, are not evaluated.

## Unsupported resources

- `aws:unsupported:arn:aws:iam::111122223333:group/ops-readers` (AWS::IAM::Group): inventoried, not evaluated.
- `aws:unsupported:arn:aws:lambda:us-east-2:111122223333:function:fh-report-export` (AWS::lambda::Function): inventoried, not evaluated.
- `aws:unsupported:arn:aws:lambda:us-east-2:111122223333:function:fh-thumbnailer` (AWS::lambda::Function): inventoried, not evaluated.

## Exceptions

- EXC-001 (PF-STOR-002 on `aws:storage_bucket:fh-public-docs`): **active**, excepts the matching finding
- EXC-002 (PF-NET-002 on `aws:security_group:sg-0fe00000000000005`): **expired**, expired: any matching finding stays active
- EXC-003 (PF-STOR-001 on `aws:storage_bucket:fh-*`): **rejected**, ignored: rejected by the registry hygiene checks Problems: resource_id must be one exact resource id, not a wildcard or pattern.
- EXC-004 (PF-NET-001 on `aws:security_group:sg-0fe00000000000002`): **rejected**, ignored: rejected by the registry hygiene checks Problems: expiry is more than 90 days after created.
- EXC-005 (PF-NET-001 on `azure:network_security_group:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-net/providers/Microsoft.Network/networkSecurityGroups/nsg-fh-jump`): **expired**, expired: any matching finding stays active
- EXC-006 (PF-STOR-099 on `aws:storage_bucket:fh-app-artifacts`): **rejected**, ignored: rejected by the registry hygiene checks Problems: missing ticket; unknown rule id.
- EXC-007 (PF-AUD-003 on `aws:audit_trail:arn:aws:cloudtrail:us-east-2:111122223333:trail/data-events-trail`): **rejected**, ignored: rejected by the registry hygiene checks Problems: expires before it was created.

## Remediation

Each auto-remediable active finding gets a JSON Patch against its raw snapshot file. The patch is applied to a temporary copy of the snapshot and the whole evaluation is re-run; it is accepted only when the targeted finding resolves to pass and nothing else changes. remediation.patch combines the accepted patches (one diff per file, re-verified together) and applies from the repository root. The committed snapshot is never modified.

- P-01 for PF-AUD-002 on `aws:audit_trail:arn:aws:cloudtrail:us-east-2:111122223333:trail/data-events-trail`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-02 for PF-AUD-003 on `aws:audit_trail:arn:aws:cloudtrail:us-east-2:111122223333:trail/data-events-trail`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- not proposed for PF-IAM-002 on `aws:iam_policy:arn:aws:iam::111122223333:policy/fh-ci-deploy`: manual remediation: Narrow the service wildcard to the actions in use and scope Resource to the specific ARNs or resource groups. Intent is required, so no patch is generated.
- not proposed for PF-STOR-002 on `aws:storage_bucket:fh-public-docs`: finding is excepted by EXC-001

## Limitations

- Snapshots are synthetic and offline; nothing here reflects a live cloud account.
- Only the rules listed above were evaluated. A pass means a rule's test did not fail, not that the resource is secure.
- Patches are local desired-state edits of the captured JSON files, verified by re-evaluation; they have not been applied to any cloud account.
