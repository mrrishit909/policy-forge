# Sensitive member-name rule shared by the Azure adapter (policy/sensitive-names.json documents it; the Python
# engine, the AWS adapter and the Conftest policy implement the same rule).
Set-StrictMode -Version Latest

function Get-SensitiveNameVocabulary {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory = $true)] [string] $Path)
    $doc = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -AsHashtable
    return $doc['sensitive_names']
}

function Get-NameWord {
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory = $true)] [AllowEmptyString()] [string] $Name)
    $s = $Name -creplace '([a-z0-9])([A-Z])', '${1}_${2}'
    $s = $s -creplace '([A-Z]+)([A-Z][a-z])', '${1}_${2}'
    $s = $s -creplace '([A-Za-z])([0-9])', '${1}_${2}'
    $s = [regex]::Replace($s, '[A-Z]', { param($m) $m.Value.ToLowerInvariant() })
    return , @($s -csplit '[^a-z0-9]+' | Where-Object { $_ -and $_ -cnotmatch '^[0-9]+$' })
}

function Test-SensitiveName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)] [AllowNull()] $Name,
        [Parameter(Mandatory = $true)] [hashtable] $Vocabulary
    )
    if ($Name -isnot [string]) { return $false }
    $words = Get-NameWord -Name $Name
    if ($words.Count -eq 0) { return $false }
    if ($Vocabulary['words'] -ccontains $words[-1]) { return $true }
    if ($words.Count -ge 2) { return ($Vocabulary['pairs'] -ccontains ('{0}_{1}' -f $words[-2], $words[-1])) }
    return $false
}

Export-ModuleMember -Function Get-SensitiveNameVocabulary, Get-NameWord, Test-SensitiveName
