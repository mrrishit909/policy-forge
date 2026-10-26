# Policy Forge run: aws-drifted-2026-10

Synthetic snapshot `aws-drifted-2026-10` (aws), exceptions evaluated as of 2026-10-26, rule packs: storage, iam, network, audit, relationships, remediation: propose.

## Coverage

Evaluated 12 rules from the storage, iam, network, audit, relationships packs against 39 of 45 resources in aws-drifted-2026-10: 82 checks, 49 passed, 19 failed, 14 unknown. 14 unknown checks rely on configuration semantics these rules do not evaluate (for example IAM Conditions, NotAction, unexpanded prefix lists or service tags) and are neither passes nor failures. 4 resources of unsupported types (AWS::IAM::Group, AWS::lambda::Function) were inventoried but not evaluated. 2 resources of covered types had no applicable rule and were not evaluated. Coverage is partial: passing checks describe only what was evaluated, not the whole configuration.

Complete coverage: **no**.

| Rule | Pack | Severity | Pass | Fail | Unknown |
| --- | --- | --- | --- | --- | --- |
| PF-STOR-001 Storage readable anonymously through ACL grants or container access levels | storage | high | 9 | 1 | 0 |
| PF-STOR-002 Bucket policy allows an anonymous principal | storage | high | 5 | 2 | 3 |
| PF-IAM-001 Allow statement grants every action on every resource | iam | critical | 7 | 2 | 3 |
| PF-IAM-002 Allow statement grants a whole service on every resource | iam | high | 8 | 2 | 2 |
| PF-IAM-003 Standing admin-capable access outside the break-glass list | iam | high | 2 | 1 | 1 |
| PF-NET-001 Remote administration ports open to internet-wide sources | network | critical | 5 | 4 | 1 |
| PF-NET-002 Data-service ports open to internet-wide sources | network | high | 6 | 2 | 2 |
| PF-AUD-001 Audit trail is not logging | audit | high | 1 | 1 | 1 |
| PF-AUD-002 Audit trail records only its home region | audit | medium | 2 | 1 | 0 |
| PF-AUD-003 Log file integrity validation is disabled | audit | medium | 2 | 1 | 0 |
| PF-REL-001 Internet-exposed compute runs with an admin-capable identity | relationships | critical | 2 | 1 | 1 |
| PF-REL-002 Storage that receives audit logs is publicly readable | relationships | critical | 0 | 1 | 0 |

## Findings

- **critical** PF-IAM-001 on `fh-wildcard-admin`: 1 Allow statement(s) grant every action on every resource. Source: `snapshots/aws-drifted-2026-10/iam-account-authorization-details.json` line 464.
- **critical** PF-IAM-001 on `app-server-role`: 1 Allow statement(s) grant every action on every resource. Source: `snapshots/aws-drifted-2026-10/iam-account-authorization-details.json` line 146.
- **critical** PF-NET-001 on `bastion-admin`: 1 ingress rule(s) expose remote administration ports to internet-wide sources. Source: `snapshots/aws-drifted-2026-10/ec2-describe-security-groups.json` line 67.
- **critical** PF-NET-001 on `legacy-ops`: 1 ingress rule(s) expose remote administration ports to internet-wide sources. Source: `snapshots/aws-drifted-2026-10/ec2-describe-security-groups.json` line 211.
- **critical** PF-NET-001 on `rdp-jump`: 1 ingress rule(s) expose remote administration ports to internet-wide sources. Source: `snapshots/aws-drifted-2026-10/ec2-describe-security-groups.json` line 252.
- **critical** PF-NET-001 on `ftp-legacy`: 1 ingress rule(s) expose remote administration ports to internet-wide sources. Source: `snapshots/aws-drifted-2026-10/ec2-describe-security-groups.json` line 294.
- **critical** PF-REL-001 on `web-1`: The instance has a public IP, admits internet-wide ingress and runs with an admin-capable identity. Source: `snapshots/aws-drifted-2026-10/ec2-describe-instances.json` line 27.
- **critical** PF-REL-002 on `fh-audit-logs`: This storage receives audit logs and its bucket policy allows anonymous access. Source: `snapshots/aws-drifted-2026-10/s3-buckets.json` line 68.
- **high** PF-AUD-001 on `org-management-trail`: The trail exists but is not logging (IsLogging is false). Source: `snapshots/aws-drifted-2026-10/cloudtrail-get-trail-status.json` line 13.
- **high** PF-IAM-002 on `fh-ci-deploy`: 1 Allow statement(s) grant a whole service on every resource. Source: `snapshots/aws-drifted-2026-10/iam-account-authorization-details.json` line 404.
- **high** PF-IAM-002 on `ci.deployer`: 1 Allow statement(s) grant a whole service on every resource. Source: `snapshots/aws-drifted-2026-10/iam-account-authorization-details.json` line 53.
- **high** PF-IAM-003 on `contractor.temp`: The user holds admin-capable permissions directly and is not a break-glass principal. Source: `snapshots/aws-drifted-2026-10/iam-account-authorization-details.json` line 79.
- **high** PF-NET-002 on `legacy-ops`: 1 ingress rule(s) expose data-service ports to internet-wide sources. Source: `snapshots/aws-drifted-2026-10/ec2-describe-security-groups.json` line 211.
- **high** PF-NET-002 on `db-exposed`: 1 ingress rule(s) expose data-service ports to internet-wide sources. Source: `snapshots/aws-drifted-2026-10/ec2-describe-security-groups.json` line 362.
- **high** PF-STOR-001 on `fh-marketing-assets`: Anonymous access is granted (AllUsers READ) and the public access guard does not neutralize it. Source: `snapshots/aws-drifted-2026-10/s3-buckets.json` line 244.
- **high** PF-STOR-002 on `fh-audit-logs`: The bucket policy allows the anonymous principal "*" in 1 statement(s) and RestrictPublicBuckets is off. Source: `snapshots/aws-drifted-2026-10/s3-buckets.json` line 68.
- **high** PF-STOR-002 on `fh-public-docs` (excepted by EXC-001): The bucket policy allows the anonymous principal "*" in 1 statement(s) and RestrictPublicBuckets is off. Source: `snapshots/aws-drifted-2026-10/s3-buckets.json` line 332.
- **medium** PF-AUD-002 on `data-events-trail`: The trail is not multi-region; activity in other regions is not recorded by it. Source: `snapshots/aws-drifted-2026-10/cloudtrail-describe-trails.json` line 8.
- **medium** PF-AUD-003 on `data-events-trail`: Log file integrity validation is disabled; tampering with delivered logs would not be detectable. Source: `snapshots/aws-drifted-2026-10/cloudtrail-describe-trails.json` line 11.

## Unknown results

- PF-AUD-001 on `aws:audit_trail:arn:aws:cloudtrail:us-east-2:111122223333:trail/partner-trail`: No trail status was captured for this trail, so logging state is unknown.
- PF-IAM-001 on `aws:iam_role:arn:aws:iam::111122223333:role/legacy-etl-role`: A policy document could not be parsed.
- PF-IAM-001 on `aws:iam_role:arn:aws:iam::111122223333:role/ops-automation-role`: An Allow statement uses NotAction or NotResource; the effective grant is not computed.
- PF-IAM-001 on `aws:iam_role:arn:aws:iam::111122223333:role/scoped-admin-role`: A wildcard Allow is conditional; Condition semantics are not evaluated.
- PF-IAM-002 on `aws:iam_role:arn:aws:iam::111122223333:role/legacy-etl-role`: A policy document could not be parsed.
- PF-IAM-002 on `aws:iam_role:arn:aws:iam::111122223333:role/ops-automation-role`: A statement uses NotAction, NotResource, a Condition, a wildcard resource pattern or an unreadable Effect or action alongside service-level actions; not evaluated.
- PF-IAM-003 on `aws:iam_user:arn:aws:iam::111122223333:user/alice.ops`: Permissions inherited from IAM groups, or statements using NotAction/Condition, are not evaluated.
- PF-NET-001 on `aws:security_group:sg-0fe00000000000010`: An ingress rule uses a protocol, port form, prefix list or service tag that is not evaluated.
- PF-NET-002 on `aws:security_group:sg-0fe00000000000009`: An ingress rule uses a protocol, port form, prefix list or service tag that is not evaluated.
- PF-NET-002 on `aws:security_group:sg-0fe00000000000010`: An ingress rule uses a protocol, port form, prefix list or service tag that is not evaluated.
- PF-REL-001 on `aws:compute_instance:i-0fe0000000000a004`: Exposure or identity permissions could not be fully evaluated (unresolved references, NotAction or conditional grants).
- PF-STOR-002 on `aws:storage_bucket:fh-legacy-reports`: The bucket policy document could not be parsed, so public grants cannot be evaluated.
- PF-STOR-002 on `aws:storage_bucket:fh-shared-research`: A policy statement uses NotPrincipal, a Condition on an anonymous principal, or a Principal or Effect that could not be read; those semantics are not evaluated.
- PF-STOR-002 on `aws:storage_bucket:fh-vendor-drop`: A policy statement uses NotPrincipal, a Condition on an anonymous principal, or a Principal or Effect that could not be read; those semantics are not evaluated.

## Unsupported resources

- `aws:unsupported:arn:aws:iam::111122223333:group/ops-readers` (AWS::IAM::Group): inventoried, not evaluated.
- `aws:unsupported:arn:aws:lambda:us-east-2:111122223333:function:fh-ops-hook` (AWS::lambda::Function): inventoried, not evaluated.
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

- P-01 for PF-AUD-001 on `aws:audit_trail:arn:aws:cloudtrail:us-east-2:111122223333:trail/org-management-trail`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-02 for PF-AUD-002 on `aws:audit_trail:arn:aws:cloudtrail:us-east-2:111122223333:trail/data-events-trail`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-03 for PF-AUD-003 on `aws:audit_trail:arn:aws:cloudtrail:us-east-2:111122223333:trail/data-events-trail`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-04 for PF-NET-001 on `aws:security_group:sg-0fe00000000000002`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-05 for PF-NET-001 on `aws:security_group:sg-0fe00000000000005`: **rejected**. other rule results change: PF-NET-002 on aws:security_group:sg-0fe00000000000005 (fail -> pass), PF-REL-001 on aws:compute_instance:i-0fe0000000000a004 (unknown -> pass)
- P-06 for PF-NET-001 on `aws:security_group:sg-0fe00000000000006`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-07 for PF-NET-001 on `aws:security_group:sg-0fe00000000000007`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-08 for PF-NET-002 on `aws:security_group:sg-0fe00000000000005`: **rejected**. other rule results change: PF-NET-001 on aws:security_group:sg-0fe00000000000005 (fail -> pass), PF-REL-001 on aws:compute_instance:i-0fe0000000000a004 (unknown -> pass)
- P-09 for PF-NET-002 on `aws:security_group:sg-0fe00000000000008`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-10 for PF-STOR-001 on `aws:storage_bucket:fh-marketing-assets`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-11 for PF-STOR-002 on `aws:storage_bucket:fh-audit-logs`: **rejected**. other rule results change: PF-REL-002 on aws:storage_bucket:fh-audit-logs (fail -> pass)
- not proposed for PF-IAM-001 on `aws:iam_policy:arn:aws:iam::111122223333:policy/fh-wildcard-admin`: manual remediation: Replace the wildcard with the specific actions and resources the workload uses. The intended permission set cannot be inferred from configuration, so no patch is generated.
- not proposed for PF-IAM-001 on `aws:iam_role:arn:aws:iam::111122223333:role/app-server-role`: manual remediation: Replace the wildcard with the specific actions and resources the workload uses. The intended permission set cannot be inferred from configuration, so no patch is generated.
- not proposed for PF-IAM-002 on `aws:iam_policy:arn:aws:iam::111122223333:policy/fh-ci-deploy`: manual remediation: Narrow the service wildcard to the actions in use and scope Resource to the specific ARNs or resource groups. Intent is required, so no patch is generated.
- not proposed for PF-IAM-002 on `aws:iam_user:arn:aws:iam::111122223333:user/ci.deployer`: manual remediation: Narrow the service wildcard to the actions in use and scope Resource to the specific ARNs or resource groups. Intent is required, so no patch is generated.
- not proposed for PF-IAM-003 on `aws:iam_user:arn:aws:iam::111122223333:user/contractor.temp`: manual remediation: Move standing admin access to just-in-time elevation or the break-glass principal, and grant the user a least-privilege role. Requires an owner decision.
- not proposed for PF-REL-001 on `aws:compute_instance:i-0fe0000000000a001`: manual remediation: Remove the public exposure or replace the identity with a least-privilege one. Either change alters workload behaviour, so no patch is generated.
- not proposed for PF-REL-002 on `aws:storage_bucket:fh-audit-logs`: manual remediation: Make the audit storage private and review who read it while it was public. The storage-level patches for this bucket also change this result, so they are rejected by the regression check and the fix needs a reviewed change.
- not proposed for PF-STOR-002 on `aws:storage_bucket:fh-public-docs`: finding is excepted by EXC-001

## Limitations

- Snapshots are synthetic and offline; nothing here reflects a live cloud account.
- Only the rules listed above were evaluated. A pass means a rule's test did not fail, not that the resource is secure.
- Patches are local desired-state edits of the captured JSON files, verified by re-evaluation; they have not been applied to any cloud account.
