# Azure adapter contract: JSON Lines, deterministic, unsupported types kept, sensitive fields dropped, clean failure.
BeforeAll {
    $script:Root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:Adapter = Join-Path $Root 'adapters/azure/Normalize-Azure.ps1'
    $script:Snap = Join-Path $Root 'snapshots/azure-lab-2026-10'
    $script:Lines = @(& $Adapter $Snap)
}

Describe 'Normalize-Azure.ps1' {
    It 'emits valid JSON Lines, one normalized resource per line' {
        $Lines.Count | Should -BeGreaterThan 20
        foreach ($line in $Lines) {
            $obj = $line | ConvertFrom-Json -AsHashtable
            $obj['id'] | Should -BeLike 'azure:*'
            $obj.ContainsKey('source') | Should -BeTrue
        }
    }

    It 'is deterministic' {
        $again = @(& $Adapter $Snap)
        ($again -join "`n") | Should -BeExactly ($Lines -join "`n")
    }

    It 'emits unsupported resource types instead of dropping them' {
        $types = foreach ($line in $Lines) {
            $obj = $line | ConvertFrom-Json -AsHashtable
            if ($obj['type'] -eq 'unsupported') { $obj['native_type'] }
        }
        $types | Should -Contain 'Microsoft.KeyVault/vaults'
        $types | Should -Contain 'Microsoft.Web/sites'
    }

    It 'drops sensitive raw fields' {
        $output = $Lines -join "`n"
        $raw = Get-ChildItem -Path $Snap -Filter '*.json' | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }
        $found = [regex]::Matches(($raw -join "`n"), '"(AdminPassword|ConnectionString)":\s*"([^"]+)"')
        $found.Count | Should -BeGreaterThan 3
        foreach ($m in $found) {
            $output.Contains($m.Groups[2].Value) | Should -BeFalse
        }
        $output | Should -Not -Match 'AdminPassword|ConnectionString'
    }

    It 'applies the shared sensitive-name rule to the documented examples' {
        Import-Module (Join-Path $Root 'adapters/azure/SensitiveNames.psm1') -Force
        $vocabulary = Get-SensitiveNameVocabulary -Path (Join-Path $Root 'policy/sensitive-names.json')
        $examples = $vocabulary['examples']
        $missed = @($examples['sensitive'] | Where-Object { -not (Test-SensitiveName -Name $_ -Vocabulary $vocabulary) })
        $extra = @($examples['not_sensitive'] | Where-Object { Test-SensitiveName -Name $_ -Vocabulary $vocabulary })
        $missed.Count | Should -Be 0
        $extra.Count | Should -Be 0
    }

    It 'fails cleanly on a missing directory' {
        # A path that is never created (TestDrive is disabled so the run writes no temporary folders).
        $missing = Join-Path $Root '.tmp/no-such-snapshot-for-pester'
        $out = & $Adapter $missing 2>$null
        $LASTEXITCODE | Should -Be 2
        $out | Should -BeNullOrEmpty
    }
}
