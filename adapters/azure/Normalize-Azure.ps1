#Requires -Version 7.4
<#
.SYNOPSIS
Policy Forge Azure adapter: Azure-PowerShell-shaped JSON exports -> normalized resources as JSON Lines.

.DESCRIPTION
Offline file transform only. Reads the snapshot's manifest.json, context.json and the data files the manifest
lists (in manifest order) and writes one compact JSON object per resource to stdout. It needs no Az module,
makes no network call and runs no cloud command. Properties are an explicit allowlist, so raw fields that are
not listed (passwords, connection strings, keys) are never copied; tags whose key looks sensitive are dropped.

.PARAMETER SnapshotPath
The snapshot directory (for example snapshots/azure-lab-2026-10).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $SnapshotPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:SensitiveName = 'passw(or)?d|secret|token|credential|connection_?string|private_?key|account_?key|user_?data|sas_?token'

function ConvertTo-JsonPointer {
    param([object[]] $Path)
    if ($null -eq $Path -or $Path.Count -eq 0) { return '' }
    $parts = foreach ($p in $Path) { "$p".Replace('~', '~0').Replace('/', '~1') }
    return '/' + ($parts -join '/')
}

function Get-PathValue {
    # Walks nested hashtables / arrays; returns $null when any step is missing.
    param($Object, [object[]] $Path)
    $cur = $Object
    foreach ($step in $Path) {
        if ($null -eq $cur) { return $null }
        if ($cur -is [System.Collections.IDictionary]) {
            if (-not $cur.Contains($step)) { return $null }
            $cur = $cur[$step]
        }
        elseif ($cur -is [System.Collections.IList] -and $step -is [int]) {
            if ($step -ge $cur.Count) { return $null }
            $cur = $cur[$step]
        }
        else { return $null }
    }
    return $cur
}

function Get-ListValue {
    # Always returns an array (possibly empty) for a value that may be $null, a scalar or a list.
    param($Value)
    if ($null -eq $Value) { return , @() }
    if ($Value -is [System.Collections.IList]) { return , @($Value) }
    return , @($Value)
}

function Get-TagMap {
    param($Tags)
    $out = [ordered]@{}
    if ($Tags -is [System.Collections.IDictionary]) {
        foreach ($k in $Tags.Keys) {
            if ($k -notmatch $script:SensitiveName) { $out[$k] = $Tags[$k] }
        }
    }
    return $out
}

function Get-RawRef {
    param([string] $File, [object[]] $Path)
    return "$File#$(ConvertTo-JsonPointer $Path)"
}

function Get-NormalizedRecord {
    param([string] $Type, [string] $NativeType, [string] $NativeId, [string] $Name, [string] $Region,
        $Properties, $Refs, [string] $File, [object[]] $Path)
    return [ordered]@{
        id          = "azure:${Type}:$NativeId"
        provider    = 'azure'
        type        = $Type
        native_type = $NativeType
        name        = $Name
        region      = $Region
        properties  = $Properties
        refs        = $Refs
        source      = [ordered]@{ file = $File; pointer = (ConvertTo-JsonPointer $Path) }
    }
}

function Get-ProviderType {
    # "/subscriptions/x/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/name" -> "Microsoft.KeyVault/vaults"
    param([string] $Id)
    if ($Id -match '/providers/([^/]+)/([^/]+)/[^/]+$') { return "$($Matches[1])/$($Matches[2])" }
    return 'unknown'
}

function Get-UnsupportedRecord {
    param($Item, [string] $File, [object[]] $Path, [string] $Region)
    $nativeId = $null
    foreach ($k in @('Id', 'ResourceId')) {
        $v = Get-PathValue $Item @($k)
        if ($v -is [string] -and $v) { $nativeId = $v; break }
    }
    $name = $null
    foreach ($k in @('Name', 'VaultName', 'StorageAccountName')) {
        $v = Get-PathValue $Item @($k)
        if ($v -is [string] -and $v) { $name = $v; break }
    }
    $loc = Get-PathValue $Item @('Location')
    $nativeType = if ($nativeId) { Get-ProviderType $nativeId } else { 'unknown' }
    if (-not $nativeId) { $nativeId = if ($name) { $name } else { Get-RawRef $File $Path } }
    if (-not $name) { $name = $nativeId }
    $reg = if ($loc -is [string] -and $loc) { $loc } else { $Region }
    return Get-NormalizedRecord 'unsupported' $nativeType $nativeId $name $reg ([ordered]@{}) @() $File $Path
}

function Get-ProtocolName {
    param([string] $Protocol)
    switch ($Protocol.ToLowerInvariant()) {
        '*' { return 'all' }
        'tcp' { return 'tcp' }
        'udp' { return 'udp' }
        'icmp' { return 'icmp' }
        default { return $Protocol.ToLowerInvariant() }
    }
}

function Get-PortRange {
    # Returns @(from, to); @($null, $null) when the form is not a port, a range or '*'.
    param([string] $Text)
    $t = $Text.Trim()
    if ($t -eq '*') { return , @(0, 65535) }
    if ($t -match '^(\d+)$') { return , @([int]$Matches[1], [int]$Matches[1]) }
    if ($t -match '^(\d+)-(\d+)$') { return , @([int]$Matches[1], [int]$Matches[2]) }
    return , @($null, $null)
}

function Get-ScopeLevel {
    param([string] $Scope)
    if ($Scope -eq '/') { return 'root' }
    if ($Scope -match '^/providers/Microsoft\.Management/managementGroups/[^/]+$') { return 'management_group' }
    if ($Scope -match '^/subscriptions/[^/]+$') { return 'subscription' }
    if ($Scope -match '^/subscriptions/[^/]+/resourceGroups/[^/]+$') { return 'resource_group' }
    return 'resource'
}

function Get-IngressEntry {
    param($Rule, [string] $Raw)
    $entries = [System.Collections.Generic.List[object]]::new()
    $protocol = Get-ProtocolName ([string](Get-PathValue $Rule @('Protocol')))
    $cidrs = [System.Collections.Generic.List[object]]::new()
    $tags = [System.Collections.Generic.List[object]]::new()
    foreach ($src in (Get-ListValue (Get-PathValue $Rule @('SourceAddressPrefix')))) {
        if ("$src" -match '^[0-9a-fA-F:.]+(/\d{1,3})?$' -and "$src" -match '[.:]') { $cidrs.Add("$src") } else { $tags.Add("$src") }
    }
    $groups = [System.Collections.Generic.List[object]]::new()
    foreach ($g in (Get-ListValue (Get-PathValue $Rule @('SourceApplicationSecurityGroups')))) {
        $gid = Get-PathValue $g @('Id')
        if ($gid) { $groups.Add("azure:application_security_group:$gid") }
    }
    $portless = $protocol -notin @('tcp', 'udp', 'all')
    foreach ($range in (Get-ListValue (Get-PathValue $Rule @('DestinationPortRange')))) {
        $ports = Get-PortRange ([string]$range)
        $entries.Add([ordered]@{
                protocol      = $protocol
                port_from     = if ($portless) { $null } else { $ports[0] }
                port_to       = if ($portless) { $null } else { $ports[1] }
                cidrs         = $cidrs
                source_tags   = $tags
                source_groups = $groups
                prefix_lists  = @()
                action        = ([string](Get-PathValue $Rule @('Access'))).ToLowerInvariant()
                priority      = Get-PathValue $Rule @('Priority')
                raw           = $Raw
            })
    }
    return , $entries
}

function Read-JsonFile {
    param([string] $Path)
    return , (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable -NoEnumerate)
}

# ------------------------------------------------------------------ main
$dir = $SnapshotPath.TrimEnd('/', '\')
if (-not (Test-Path -LiteralPath (Join-Path $dir 'manifest.json') -PathType Leaf)) {
    [Console]::Error.WriteLine("Normalize-Azure.ps1: not a snapshot directory (missing manifest.json): $dir")
    exit 2
}
$manifest = Read-JsonFile (Join-Path $dir 'manifest.json')
if ((Get-PathValue $manifest @('provider')) -ne 'azure') {
    [Console]::Error.WriteLine("Normalize-Azure.ps1: manifest provider is '$(Get-PathValue $manifest @('provider'))', expected 'azure'")
    exit 2
}
$contextPath = Join-Path $dir 'context.json'
$context = if (Test-Path -LiteralPath $contextPath -PathType Leaf) { Read-JsonFile $contextPath } else { @{} }
$region = [string](Get-PathValue $context @('default_region'))
if (-not $region) { $region = 'unknown' }
$base = "snapshots/$(Get-PathValue $manifest @('name'))"

$docs = [ordered]@{}
foreach ($name in (Get-ListValue (Get-PathValue $manifest @('files')))) {
    if ($name -match '[/\\]' -or $name.StartsWith('.')) {
        [Console]::Error.WriteLine("Normalize-Azure.ps1: manifest file name must be a plain file name: $name")
        exit 2
    }
    $p = Join-Path $dir $name
    if (-not (Test-Path -LiteralPath $p -PathType Leaf)) {
        [Console]::Error.WriteLine("Normalize-Azure.ps1: manifest lists a missing file: $name")
        exit 2
    }
    $docs[$name] = Read-JsonFile $p
}

# Lookups used to fold network interfaces into VMs and to link role assignments to VM identities.
$nicInfo = @{}
$nicDoc = $docs['Get-AzNetworkInterface.json']
foreach ($n in (Get-ListValue $nicDoc)) {
    $ips = [System.Collections.Generic.List[object]]::new()
    foreach ($cfg in (Get-ListValue (Get-PathValue $n @('IpConfigurations')))) {
        $ip = Get-PathValue $cfg @('PublicIpAddress', 'IpAddress')
        if ($ip) { $ips.Add($ip) }
    }
    $nicInfo[([string](Get-PathValue $n @('Id'))).ToLowerInvariant()] = @{
        Nsg = Get-PathValue $n @('NetworkSecurityGroup', 'Id')
        Ips = $ips
    }
}
$principalVm = @{}
foreach ($v in (Get-ListValue $docs['Get-AzVM.json'])) {
    $pid_ = Get-PathValue $v @('Identity', 'PrincipalId')
    if ($pid_) { $principalVm[$pid_] = "azure:compute_instance:$(Get-PathValue $v @('Id'))" }
}

foreach ($fileName in $docs.Keys) {
    $file = "$base/$fileName"
    $doc = $docs[$fileName]
    $items = Get-ListValue $doc
    for ($i = 0; $i -lt $items.Count; $i++) {
        $it = $items[$i]
        $path = @($i)
        $rec = $null
        switch ($fileName) {
            'Get-AzStorageAccount.json' {
                $allow = Get-PathValue $it @('AllowBlobPublicAccess')
                $grants = [System.Collections.Generic.List[object]]::new()
                $containers = Get-ListValue (Get-PathValue $it @('Containers'))
                for ($c = 0; $c -lt $containers.Count; $c++) {
                    $access = Get-PathValue $containers[$c] @('PublicAccess')
                    if ($access -and $access -ne 'None') {
                        $grants.Add([ordered]@{
                                via = 'container'; grantee = Get-PathValue $containers[$c] @('Name'); permission = $access
                                raw = Get-RawRef $file @($i, 'Containers', $c)
                            })
                    }
                }
                $blocked = if ($allow -eq $true) { $false } elseif ($allow -eq $false) { $true } else { $null }
                $props = [ordered]@{
                    public_access = [ordered]@{
                        anonymous_grants         = $grants
                        anonymous_grants_blocked = $blocked
                        policy                   = $null
                        public_policy_blocked    = $null
                        guard                    = [ordered]@{ allow_blob_public_access = $allow }
                    }
                    network       = [ordered]@{
                        public_network_access = Get-PathValue $it @('PublicNetworkAccess')
                        default_action        = Get-PathValue $it @('NetworkRuleSet', 'DefaultAction')
                    }
                    tags          = Get-TagMap (Get-PathValue $it @('Tags'))
                    raw           = [ordered]@{ guard = Get-RawRef $file @($i, 'AllowBlobPublicAccess') }
                }
                $rec = Get-NormalizedRecord 'storage_bucket' 'Microsoft.Storage/storageAccounts' (Get-PathValue $it @('Id')) `
                (Get-PathValue $it @('StorageAccountName')) (Get-PathValue $it @('Location')) $props @() $file $path
            }
            'Get-AzNetworkSecurityGroup.json' {
                $ingress = [System.Collections.Generic.List[object]]::new()
                foreach ($set in @('SecurityRules', 'DefaultSecurityRules')) {
                    $rules = Get-ListValue (Get-PathValue $it @($set))
                    for ($r = 0; $r -lt $rules.Count; $r++) {
                        if ((Get-PathValue $rules[$r] @('Direction')) -ne 'Inbound') { continue }
                        foreach ($e in (Get-IngressEntry $rules[$r] (Get-RawRef $file @($i, $set, $r)))) { $ingress.Add($e) }
                    }
                }
                $props = [ordered]@{ ingress = $ingress; tags = Get-TagMap (Get-PathValue $it @('Tags')) }
                $rec = Get-NormalizedRecord 'network_security_group' 'Microsoft.Network/networkSecurityGroups' `
                (Get-PathValue $it @('Id')) (Get-PathValue $it @('Name')) (Get-PathValue $it @('Location')) $props @() $file $path
            }
            'Get-AzVM.json' {
                $ips = [System.Collections.Generic.List[object]]::new()
                $groups = [System.Collections.Generic.List[object]]::new()
                $refs = [System.Collections.Generic.List[object]]::new()
                foreach ($ni in (Get-ListValue (Get-PathValue $it @('NetworkProfile', 'NetworkInterfaces')))) {
                    $nid = [string](Get-PathValue $ni @('Id'))
                    $refs.Add([ordered]@{ kind = 'network_interface'; target = $nid })
                    $info = $nicInfo[$nid.ToLowerInvariant()]
                    if ($null -eq $info) { continue }
                    foreach ($ip in $info.Ips) { $ips.Add($ip) }
                    if ($info.Nsg) {
                        $g = "azure:network_security_group:$($info.Nsg)"
                        if (-not $groups.Contains($g)) {
                            $groups.Add($g)
                            $refs.Add([ordered]@{ kind = 'uses_network_group'; target = $g })
                        }
                    }
                }
                $props = [ordered]@{
                    public_ips            = $ips
                    network_groups        = $groups
                    identity_type         = Get-PathValue $it @('Identity', 'Type')
                    identity_principal_id = Get-PathValue $it @('Identity', 'PrincipalId')
                    tags                  = Get-TagMap (Get-PathValue $it @('Tags'))
                    raw                   = [ordered]@{
                        network_groups = Get-RawRef $file @($i, 'NetworkProfile', 'NetworkInterfaces')
                        identity       = Get-RawRef $file @($i, 'Identity')
                    }
                }
                $rec = Get-NormalizedRecord 'compute_instance' 'Microsoft.Compute/virtualMachines' (Get-PathValue $it @('Id')) `
                (Get-PathValue $it @('Name')) (Get-PathValue $it @('Location')) $props $refs $file $path
            }
            'Get-AzRoleDefinition.json' {
                $notActions = Get-ListValue (Get-PathValue $it @('NotActions'))
                $statement = [ordered]@{
                    sid            = $null
                    effect         = 'Allow'
                    actions        = Get-ListValue (Get-PathValue $it @('Actions'))
                    not_actions    = if ($notActions.Count -gt 0) { , $notActions } else { $null }
                    resources      = Get-ListValue (Get-PathValue $it @('AssignableScopes'))
                    not_resources  = $null
                    principals     = $null
                    not_principals = $null
                    has_condition  = ($null -ne (Get-PathValue $it @('Condition')))
                    raw            = Get-RawRef $file @($i, 'Actions')
                    policy         = 'role-definition'
                }
                $props = [ordered]@{
                    role_name         = Get-PathValue $it @('Name')
                    is_custom         = (Get-PathValue $it @('IsCustom')) -eq $true
                    assignable_scopes = Get-ListValue (Get-PathValue $it @('AssignableScopes'))
                    data_actions      = Get-ListValue (Get-PathValue $it @('DataActions'))
                    permissions       = [ordered]@{ parse_error = $false; statements = @($statement) }
                }
                $rec = Get-NormalizedRecord 'role_definition' 'Microsoft.Authorization/roleDefinitions' (Get-PathValue $it @('Id')) `
                (Get-PathValue $it @('Name')) 'global' $props @() $file $path
            }
            'Get-AzRoleAssignment.json' {
                $scope = [string](Get-PathValue $it @('Scope'))
                $principal = Get-PathValue $it @('ObjectId')
                $refs = [System.Collections.Generic.List[object]]::new()
                $refs.Add([ordered]@{ kind = 'assigned_role'; target = "azure:role_definition:$(Get-PathValue $it @('RoleDefinitionId'))" })
                if ($principal -and $principalVm.ContainsKey($principal)) {
                    $refs.Add([ordered]@{ kind = 'assigned_to'; target = $principalVm[$principal] })
                }
                $signIn = Get-PathValue $it @('SignInName')
                $props = [ordered]@{
                    scope              = $scope
                    scope_level        = Get-ScopeLevel $scope
                    principal_id       = $principal
                    principal_type     = Get-PathValue $it @('ObjectType')
                    principal_name     = if ($signIn) { $signIn } else { Get-PathValue $it @('DisplayName') }
                    role_definition_id = Get-PathValue $it @('RoleDefinitionId')
                    role_name          = Get-PathValue $it @('RoleDefinitionName')
                    has_condition      = ($null -ne (Get-PathValue $it @('Condition')))
                    raw                = [ordered]@{
                        scope     = Get-RawRef $file @($i, 'Scope')
                        role      = Get-RawRef $file @($i, 'RoleDefinitionId')
                        principal = Get-RawRef $file @($i, 'ObjectId')
                        condition = Get-RawRef $file @($i, 'Condition')
                    }
                }
                $rec = Get-NormalizedRecord 'role_assignment' 'Microsoft.Authorization/roleAssignments' `
                (Get-PathValue $it @('RoleAssignmentId')) (Get-PathValue $it @('RoleAssignmentName')) 'global' $props $refs $file $path
            }
            'Get-AzDiagnosticSetting.json' {
                $id = [string](Get-PathValue $it @('Id'))
                $marker = $id.ToLowerInvariant().IndexOf('/providers/microsoft.insights/diagnosticsettings/')
                $target = if ($marker -ge 0) { $id.Substring(0, $marker) } else { $null }
                $kind = if ($target -and $target -match '^/subscriptions/[^/]+$') { 'subscription' } else { 'resource' }
                $cats = [System.Collections.Generic.List[object]]::new()
                $logs = Get-ListValue (Get-PathValue $it @('Log'))
                for ($l = 0; $l -lt $logs.Count; $l++) {
                    $cats.Add([ordered]@{
                            category = Get-PathValue $logs[$l] @('Category')
                            enabled  = (Get-PathValue $logs[$l] @('Enabled')) -eq $true
                            raw      = Get-RawRef $file @($i, 'Log', $l)
                        })
                }
                $storage = Get-PathValue $it @('StorageAccountId')
                $workspace = Get-PathValue $it @('WorkspaceId')
                $hub = Get-PathValue $it @('EventHubAuthorizationRuleId')
                $refs = [System.Collections.Generic.List[object]]::new()
                if ($storage) { $refs.Add([ordered]@{ kind = 'delivers_logs_to'; target = "azure:storage_bucket:$storage" }) }
                if ($workspace) { $refs.Add([ordered]@{ kind = 'delivers_logs_to'; target = $workspace }) }
                if ($hub) { $refs.Add([ordered]@{ kind = 'delivers_logs_to'; target = $hub }) }
                if ($kind -eq 'resource' -and $target) { $refs.Add([ordered]@{ kind = 'monitors'; target = $target }) }
                $props = [ordered]@{
                    scope_kind         = $kind
                    target_resource_id = $target
                    categories         = $cats
                    destinations       = [ordered]@{ storage_account_id = $storage; workspace_id = $workspace; event_hub_rule_id = $hub }
                    raw                = [ordered]@{
                        categories   = Get-RawRef $file @($i, 'Log')
                        destinations = Get-RawRef $file @($i, 'StorageAccountId')
                    }
                }
                $rec = Get-NormalizedRecord 'diagnostic_setting' 'Microsoft.Insights/diagnosticSettings' $id `
                (Get-PathValue $it @('Name')) 'global' $props $refs $file $path
            }
            default {
                # Network interfaces are folded into the VMs they attach to (public IPs, NSG links), but no rule
                # evaluates an interface on its own, so they are emitted as unsupported like any unknown type.
                $rec = Get-UnsupportedRecord $it $file $path $region
            }
        }
        if ($null -ne $rec) {
            Write-Output (ConvertTo-Json -InputObject $rec -Depth 32 -Compress)
        }
    }
}
