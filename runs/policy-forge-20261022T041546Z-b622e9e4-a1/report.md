# Policy Forge run: azure-lab-2026-10

Synthetic snapshot `azure-lab-2026-10` (azure), exceptions evaluated as of 2026-10-22, rule packs: storage, iam, network, audit, relationships, remediation: propose.

## Coverage

Evaluated 9 rules from the storage, iam, network, audit, relationships packs against 32 of 42 resources in azure-lab-2026-10: 43 checks, 21 passed, 12 failed, 10 unknown. 10 unknown checks rely on configuration semantics these rules do not evaluate (for example IAM Conditions, NotAction, unexpanded prefix lists or service tags) and are neither passes nor failures. 6 resources of unsupported types (Microsoft.KeyVault/vaults, Microsoft.Network/networkInterfaces, Microsoft.Web/sites) were inventoried but not evaluated. 4 resources of covered types had no applicable rule and were not evaluated. Coverage is partial: passing checks describe only what was evaluated, not the whole configuration.

Complete coverage: **no**.

| Rule | Pack | Severity | Pass | Fail | Unknown |
| --- | --- | --- | --- | --- | --- |
| PF-STOR-001 Storage readable anonymously through ACL grants or container access levels | storage | high | 3 | 1 | 1 |
| PF-IAM-001 Allow statement grants every action on every resource | iam | critical | 2 | 1 | 1 |
| PF-IAM-002 Allow statement grants a whole service on every resource | iam | high | 2 | 1 | 1 |
| PF-IAM-003 Standing admin-capable access outside the break-glass list | iam | high | 3 | 3 | 4 |
| PF-NET-001 Remote administration ports open to internet-wide sources | network | critical | 2 | 3 | 1 |
| PF-NET-002 Data-service ports open to internet-wide sources | network | high | 4 | 1 | 1 |
| PF-AUD-004 Activity Log export misses a required category or a destination | audit | high | 1 | 1 | 1 |
| PF-REL-001 Internet-exposed compute runs with an admin-capable identity | relationships | critical | 3 | 1 | 0 |
| PF-REL-002 Storage that receives audit logs is publicly readable | relationships | critical | 1 | 0 | 0 |

## Findings

- **critical** PF-IAM-001 on `FH Lab Operator`: 1 Allow statement(s) grant every action on every resource. Source: `snapshots/azure-lab-2026-10/Get-AzRoleDefinition.json` line 28.
- **critical** PF-NET-001 on `nsg-fh-edge`: 1 ingress rule(s) expose remote administration ports to internet-wide sources. Source: `snapshots/azure-lab-2026-10/Get-AzNetworkSecurityGroup.json` line 166.
- **critical** PF-NET-001 on `nsg-fh-jump`: 1 ingress rule(s) expose remote administration ports to internet-wide sources. Source: `snapshots/azure-lab-2026-10/Get-AzNetworkSecurityGroup.json` line 295.
- **critical** PF-NET-001 on `nsg-fh-rdp`: 1 ingress rule(s) expose remote administration ports to internet-wide sources. Source: `snapshots/azure-lab-2026-10/Get-AzNetworkSecurityGroup.json` line 405.
- **critical** PF-REL-001 on `vm-fh-ops`: The instance has a public IP, admits internet-wide ingress and runs with an admin-capable identity. Source: `snapshots/azure-lab-2026-10/Get-AzVM.json` line 55.
- **high** PF-AUD-004 on `activity-to-storage`: Required Activity Log categories are not exported: Security. Source: `snapshots/azure-lab-2026-10/Get-AzDiagnosticSetting.json` line 10.
- **high** PF-IAM-002 on `FH Storage Admin`: 1 Allow statement(s) grant a whole service on every resource. Source: `snapshots/azure-lab-2026-10/Get-AzRoleDefinition.json` line 81.
- **high** PF-IAM-003 on `00000000-0000-4000-9000-000000000702`: Admin-capable role "Owner" is assigned at subscription scope to a principal outside the break-glass list. Source: `snapshots/azure-lab-2026-10/Get-AzRoleAssignment.json` line 20.
- **high** PF-IAM-003 on `00000000-0000-4000-9000-000000000703`: Admin-capable role "Owner" is assigned at subscription scope to a principal outside the break-glass list. Source: `snapshots/azure-lab-2026-10/Get-AzRoleAssignment.json` line 35.
- **high** PF-IAM-003 on `00000000-0000-4000-9000-00000000070a`: Admin-capable role "FH Lab Operator" is assigned at subscription scope to a principal outside the break-glass list. Source: `snapshots/azure-lab-2026-10/Get-AzRoleAssignment.json` line 140.
- **high** PF-NET-002 on `nsg-fh-data`: 2 ingress rule(s) expose data-service ports to internet-wide sources. Source: `snapshots/azure-lab-2026-10/Get-AzNetworkSecurityGroup.json` line 55.
- **high** PF-STOR-001 on `stfhlabpublic`: Anonymous access is granted (downloads Blob) and the public access guard does not neutralize it. Source: `snapshots/azure-lab-2026-10/Get-AzStorageAccount.json` line 151.

## Unknown results

- PF-AUD-004 on `azure:diagnostic_setting:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-lab/providers/Microsoft.KeyVault/vaults/kv-fh-lab/providers/microsoft.insights/diagnosticSettings/kv-diagnostics`: Resource-level diagnostic settings have per-resource-type categories that are not evaluated.
- PF-IAM-001 on `azure:role_definition:00000000-0000-4000-9000-000000000903`: An Allow statement uses NotAction or NotResource; the effective grant is not computed.
- PF-IAM-002 on `azure:role_definition:00000000-0000-4000-9000-000000000903`: A statement uses NotAction, NotResource, a Condition, a wildcard resource pattern or an unreadable Effect or action alongside service-level actions; not evaluated.
- PF-IAM-003 on `azure:role_assignment:/subscriptions/00000000-0000-4000-8000-000000000001/providers/Microsoft.Authorization/roleAssignments/00000000-0000-4000-9000-000000000704`: Role "Contributor" uses NotActions; its effective permissions are not computed.
- PF-IAM-003 on `azure:role_assignment:/subscriptions/00000000-0000-4000-8000-000000000001/providers/Microsoft.Authorization/roleAssignments/00000000-0000-4000-9000-000000000707`: The role assignment carries a Condition; conditional assignments are not evaluated.
- PF-IAM-003 on `azure:role_assignment:/subscriptions/00000000-0000-4000-8000-000000000001/providers/Microsoft.Authorization/roleAssignments/00000000-0000-4000-9000-000000000708`: Role "Contributor" uses NotActions; its effective permissions are not computed.
- PF-IAM-003 on `azure:role_assignment:/subscriptions/00000000-0000-4000-8000-000000000001/providers/Microsoft.Authorization/roleAssignments/00000000-0000-4000-9000-000000000709`: The assigned role definition is not in the snapshot.
- PF-NET-001 on `azure:network_security_group:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-net/providers/Microsoft.Network/networkSecurityGroups/nsg-fh-vpn`: An ingress rule uses a protocol, port form, prefix list or service tag that is not evaluated.
- PF-NET-002 on `azure:network_security_group:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-net/providers/Microsoft.Network/networkSecurityGroups/nsg-fh-vpn`: An ingress rule uses a protocol, port form, prefix list or service tag that is not evaluated.
- PF-STOR-001 on `azure:storage_bucket:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-lab/providers/Microsoft.Storage/storageAccounts/stfhlablegacy`: Anonymous access is configured (archive Container) but the account-level guard is not set, so the effective behaviour depends on account defaults that are not evaluated.

## Unsupported resources

- `azure:unsupported:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-lab/providers/Microsoft.KeyVault/vaults/kv-fh-lab` (Microsoft.KeyVault/vaults): inventoried, not evaluated.
- `azure:unsupported:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-lab/providers/Microsoft.Web/sites/app-fh-portal` (Microsoft.Web/sites): inventoried, not evaluated.
- `azure:unsupported:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-net/providers/Microsoft.Network/networkInterfaces/nic-fh-jump` (Microsoft.Network/networkInterfaces): inventoried, not evaluated.
- `azure:unsupported:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-net/providers/Microsoft.Network/networkInterfaces/nic-fh-ops` (Microsoft.Network/networkInterfaces): inventoried, not evaluated.
- `azure:unsupported:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-net/providers/Microsoft.Network/networkInterfaces/nic-fh-rdp` (Microsoft.Network/networkInterfaces): inventoried, not evaluated.
- `azure:unsupported:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-net/providers/Microsoft.Network/networkInterfaces/nic-fh-worker` (Microsoft.Network/networkInterfaces): inventoried, not evaluated.

## Exceptions

- EXC-001 (PF-STOR-002 on `aws:storage_bucket:fh-public-docs`): **active**, active, but its rule or resource is not evaluated in this run
- EXC-002 (PF-NET-002 on `aws:security_group:sg-0fe00000000000005`): **expired**, expired: any matching finding stays active
- EXC-003 (PF-STOR-001 on `aws:storage_bucket:fh-*`): **rejected**, ignored: rejected by the registry hygiene checks Problems: resource_id must be one exact resource id, not a wildcard or pattern.
- EXC-004 (PF-NET-001 on `aws:security_group:sg-0fe00000000000002`): **rejected**, ignored: rejected by the registry hygiene checks Problems: expiry is more than 90 days after created.
- EXC-005 (PF-NET-001 on `azure:network_security_group:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-net/providers/Microsoft.Network/networkSecurityGroups/nsg-fh-jump`): **expired**, expired: any matching finding stays active
- EXC-006 (PF-STOR-099 on `aws:storage_bucket:fh-app-artifacts`): **rejected**, ignored: rejected by the registry hygiene checks Problems: missing ticket; unknown rule id.
- EXC-007 (PF-AUD-003 on `aws:audit_trail:arn:aws:cloudtrail:us-east-2:111122223333:trail/data-events-trail`): **rejected**, ignored: rejected by the registry hygiene checks Problems: expires before it was created.

## Remediation

Each auto-remediable active finding gets a JSON Patch against its raw snapshot file. The patch is applied to a temporary copy of the snapshot and the whole evaluation is re-run; it is accepted only when the targeted finding resolves to pass and nothing else changes. remediation.patch combines the accepted patches (one diff per file, re-verified together) and applies from the repository root. The committed snapshot is never modified.

- P-01 for PF-AUD-004 on `azure:diagnostic_setting:/subscriptions/00000000-0000-4000-8000-000000000001/providers/microsoft.insights/diagnosticSettings/activity-to-storage`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-02 for PF-NET-001 on `azure:network_security_group:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-net/providers/Microsoft.Network/networkSecurityGroups/nsg-fh-edge`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-03 for PF-NET-001 on `azure:network_security_group:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-net/providers/Microsoft.Network/networkSecurityGroups/nsg-fh-jump`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-04 for PF-NET-001 on `azure:network_security_group:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-net/providers/Microsoft.Network/networkSecurityGroups/nsg-fh-rdp`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-05 for PF-NET-002 on `azure:network_security_group:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-net/providers/Microsoft.Network/networkSecurityGroups/nsg-fh-data`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- P-06 for PF-STOR-001 on `azure:storage_bucket:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-lab/providers/Microsoft.Storage/storageAccounts/stfhlabpublic`: **accepted**. target finding resolves to pass; no other rule result, finding or resource changes
- not proposed for PF-IAM-001 on `azure:role_definition:00000000-0000-4000-9000-000000000901`: manual remediation: Replace the wildcard with the specific actions and resources the workload uses. The intended permission set cannot be inferred from configuration, so no patch is generated.
- not proposed for PF-IAM-002 on `azure:role_definition:00000000-0000-4000-9000-000000000904`: manual remediation: Narrow the service wildcard to the actions in use and scope Resource to the specific ARNs or resource groups. Intent is required, so no patch is generated.
- not proposed for PF-IAM-003 on `azure:role_assignment:/subscriptions/00000000-0000-4000-8000-000000000001/providers/Microsoft.Authorization/roleAssignments/00000000-0000-4000-9000-000000000702`: manual remediation: Move standing admin access to just-in-time elevation or the break-glass principal, and grant the user a least-privilege role. Requires an owner decision.
- not proposed for PF-IAM-003 on `azure:role_assignment:/subscriptions/00000000-0000-4000-8000-000000000001/providers/Microsoft.Authorization/roleAssignments/00000000-0000-4000-9000-000000000703`: manual remediation: Move standing admin access to just-in-time elevation or the break-glass principal, and grant the user a least-privilege role. Requires an owner decision.
- not proposed for PF-IAM-003 on `azure:role_assignment:/subscriptions/00000000-0000-4000-8000-000000000001/providers/Microsoft.Authorization/roleAssignments/00000000-0000-4000-9000-00000000070a`: manual remediation: Move standing admin access to just-in-time elevation or the break-glass principal, and grant the user a least-privilege role. Requires an owner decision.
- not proposed for PF-REL-001 on `azure:compute_instance:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/rg-fh-lab/providers/Microsoft.Compute/virtualMachines/vm-fh-ops`: manual remediation: Remove the public exposure or replace the identity with a least-privilege one. Either change alters workload behaviour, so no patch is generated.

## Limitations

- Snapshots are synthetic and offline; nothing here reflects a live cloud account.
- Only the rules listed above were evaluated. A pass means a rule's test did not fail, not that the resource is secure.
- Patches are local desired-state edits of the captured JSON files, verified by re-evaluation; they have not been applied to any cloud account.
