<#
.SYNOPSIS
    Pester 5 unit tests for src/remediation/ (BackupManager, RemediationCatalog, and FixRunner).

.DESCRIPTION
    Verifies backup state capture, JSON persistence, reverse-order rollback, catalog metadata
    for all 10 Phase 1 AutoSafe controls, idempotency, WhatIf dry-run, privilege/exception
    guardrails, and closed-loop post-fix verification without touching real registry hives or
    Windows Defender settings.
#>

Set-StrictMode -Version 2

Describe 'BackupManager' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..\src\remediation\BackupManager.ps1')
        function Get-MpPreference { param($ErrorAction) }
        function Set-MpPreference { param($PUAProtection, $EnableNetworkProtection, $ErrorAction) }
        function Checkpoint-Computer { param($Description, $RestorePointType, $ErrorAction) }
    }

    It 'Backup-RegistryValueState captures absent key cleanly' {
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $false }

        $snap = Backup-RegistryValueState -Path 'HKLM:\SOFTWARE\Policies\MissingKey' -Name 'EnableMulticast'
        $snap.Type         | Should -Be 'RegistryValue'
        $snap.KeyExisted   | Should -Be $false
        $snap.ValueExisted | Should -Be $false
        $snap.OriginalValue | Should -Be $null
    }

    It 'Backup-RegistryValueState captures present key with absent value' {
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            return [PSCustomObject]@{ UnrelatedValue = 1 }
        }

        $snap = Backup-RegistryValueState -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' -Name 'fAllowToGetHelp'
        $snap.KeyExisted    | Should -Be $true
        $snap.ValueExisted  | Should -Be $false
        $snap.OriginalValue | Should -Be $null
    }

    It 'Backup-RegistryValueState captures existing DWord value and type' {
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            return [PSCustomObject]@{ HideFileExt = 1 }
        }
        Mock Get-Item -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $null }

        $snap = Backup-RegistryValueState -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'HideFileExt'
        $snap.KeyExisted    | Should -Be $true
        $snap.ValueExisted  | Should -Be $true
        $snap.ValueType     | Should -Be 'DWord'
        $snap.OriginalValue | Should -Be 1
    }

    It 'Add-RemediationBackupEntry deduplicates targets to preserve pre-session state across retries' {
        $session = New-RemediationBackupSession -BackupDirectory (Join-Path $TestDrive 'dedup')

        $first = [PSCustomObject]@{
            Type = 'RegistryValue'; Path = 'HKCU:\Software\Test'; Name = 'HideFileExt'
            KeyExisted = $true; ValueExisted = $true; ValueType = 'DWord'; OriginalValue = 1
        }
        $second = [PSCustomObject]@{
            Type = 'RegistryValue'; Path = 'HKCU:\Software\Test'; Name = 'HideFileExt'
            KeyExisted = $true; ValueExisted = $true; ValueType = 'DWord'; OriginalValue = 0
        }

        Add-RemediationBackupEntry -Session $session -ControlId 'HOME-SYS-001' -Entry $first
        Add-RemediationBackupEntry -Session $session -ControlId 'HOME-SYS-001' -Entry $second

        @($session.Entries).Count | Should -Be 1
        $session.Entries[0].OriginalValue | Should -Be 1
    }

    It 'Save-RemediationBackupSession writes valid JSON under TestDrive' {
        $backupDir = Join-Path $TestDrive 'saved_sessions'
        $session = New-RemediationBackupSession -BackupDirectory $backupDir -SessionId 'test_001'

        Add-RemediationBackupEntry -Session $session -ControlId 'HOME-PRV-001' -Entry ([PSCustomObject]@{
            Type = 'RegistryValue'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Name = 'AllowTelemetry'
            KeyExisted = $false; ValueExisted = $false; ValueType = $null; OriginalValue = $null
        })

        $path = Save-RemediationBackupSession -Session $session
        Test-Path -LiteralPath $path | Should -Be $true

        $parsed = Get-Content -LiteralPath $path -Raw -Encoding UTF8 | ConvertFrom-Json
        $parsed.SessionId | Should -Be 'test_001'
        @($parsed.Entries).Count | Should -Be 1
        $parsed.Entries[0].ControlId | Should -Be 'HOME-PRV-001'
    }

    It 'Restore-RemediationBackup restores pre-existing values, removes newly created properties, and rolls back Defender modes' {
        $backupDir = Join-Path $TestDrive 'restore_test'
        $session = New-RemediationBackupSession -BackupDirectory $backupDir -SessionId 'restore_001'

        Add-RemediationBackupEntry -Session $session -ControlId 'HOME-SYS-001' -Entry ([PSCustomObject]@{
            Type = 'RegistryValue'; Path = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Name = 'HideFileExt'
            KeyExisted = $true; ValueExisted = $true; ValueType = 'DWord'; OriginalValue = 1
        })
        Add-RemediationBackupEntry -Session $session -ControlId 'HOME-NET-003' -Entry ([PSCustomObject]@{
            Type = 'RegistryValue'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Name = 'EnableMulticast'
            KeyExisted = $false; ValueExisted = $false; ValueType = $null; OriginalValue = $null
        })
        Add-RemediationBackupEntry -Session $session -ControlId 'HOME-AV-005' -Entry ([PSCustomObject]@{
            Type = 'DefenderPreference'; PropertyName = 'PUAProtection'; OriginalValue = 0
        })
        Add-RemediationBackupEntry -Session $session -ControlId 'HOME-AV-010' -Entry ([PSCustomObject]@{
            Type = 'DefenderPreference'; PropertyName = 'EnableNetworkProtection'; OriginalValue = 2
        })

        $savedPath = Save-RemediationBackupSession -Session $session

        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock New-Item -ParameterFilter { $Path -like 'HK*' } { }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }
        Mock Remove-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }
        Mock Set-MpPreference { }

        $restoreResult = Restore-RemediationBackup -BackupPath $savedPath
        $restoreResult.TotalEntries  | Should -Be 4
        $restoreResult.RestoredCount | Should -Be 4
        $restoreResult.FailedCount   | Should -Be 0

        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'HideFileExt' -and [int]$Value -eq 1 -and $PropertyType -eq 'DWord'
        }
        Should -Invoke Remove-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'EnableMulticast'
        }
        Should -Invoke Set-MpPreference -Times 1 -ParameterFilter {
            $PUAProtection -eq 'Disabled'
        }
        Should -Invoke Set-MpPreference -Times 1 -ParameterFilter {
            $EnableNetworkProtection -eq 'AuditMode'
        }
    }
}

Describe 'RemediationCatalog' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..\src\remediation\BackupManager.ps1')
        . (Join-Path $PSScriptRoot '..\src\remediation\RemediationCatalog.ps1')

        $catalogPath = Join-Path $PSScriptRoot '..\catalog\home_profile.json'
        $script:mainCatalog = Get-Content -LiteralPath $catalogPath -Raw -Encoding UTF8 | ConvertFrom-Json
        $script:mainIds = @($script:mainCatalog.controls | ForEach-Object { $_.id })
    }

    It 'Registers all 29 AutoSafe, 11 AutoReboot, and 3 Guided controls with valid catalog IDs and metadata' {
        $autoSafeIds   = @(Get-AutoSafeControlIds)
        $autoRebootIds = @(Get-AutoRebootControlIds)
        $guidedIds     = @(Get-GuidedControlIds)

        $autoSafeIds.Count   | Should -Be 29
        $autoRebootIds.Count | Should -Be 11
        $guidedIds.Count     | Should -Be 3

        $expectedTier1 = @(
            'HOME-SYS-001', 'HOME-SYS-002', 'HOME-SYS-007', 'HOME-NET-002', 'HOME-NET-003',
            'HOME-NET-007', 'HOME-SEC-003', 'HOME-AV-005', 'HOME-AV-010', 'HOME-PRV-001',
            'HOME-FW-001', 'HOME-UAC-001', 'HOME-UAC-002', 'HOME-UAC-003', 'HOME-ACC-001',
            'HOME-ACC-004', 'HOME-UPD-001', 'HOME-AV-001', 'HOME-AV-002', 'HOME-AV-004',
            'HOME-SYS-003', 'HOME-SYS-005', 'HOME-SYS-006', 'HOME-SYS-008', 'HOME-SYS-009',
            'HOME-SYS-010', 'HOME-NET-005', 'HOME-NET-008', 'HOME-SEC-009'
        )
        foreach ($expectedId in $expectedTier1) {
            ($autoSafeIds -contains $expectedId) | Should -Be $true
        }

        $expectedTier2 = @(
            'HOME-SEC-002', 'HOME-SEC-006', 'HOME-NET-001', 'HOME-SYS-004', 'HOME-AV-009',
            'HOME-AV-011', 'HOME-RDP-001', 'HOME-NET-006', 'HOME-UAC-004', 'HOME-SEC-011', 'HOME-SEC-010'
        )
        foreach ($expectedId in $expectedTier2) {
            ($autoRebootIds -contains $expectedId) | Should -Be $true
        }

        $expectedTier3 = @('HOME-NET-009', 'HOME-ACC-002', 'HOME-FIL-009')
        foreach ($expectedId in $expectedTier3) {
            ($guidedIds -contains $expectedId) | Should -Be $true
        }

        foreach ($id in $autoSafeIds) {
            ($script:mainIds -contains $id) | Should -Be $true
            $def = Get-RemediationDefinition -ControlId $id
            $def.FixMode        | Should -Be 'AutoSafe'
            $def.RequiresReboot | Should -Be $false
            @($def.PreviewCommands).Count | Should -BeGreaterThan 0
            ($def.Apply -is [scriptblock]) | Should -Be $true

            if ($id -eq 'HOME-SYS-001') {
                $def.RequiresAdmin | Should -Be $false
            }
            else {
                $def.RequiresAdmin | Should -Be $true
            }
        }

        foreach ($id in (@($autoRebootIds) + @($guidedIds))) {
            ($script:mainIds -contains $id) | Should -Be $true
            $def = Get-RemediationDefinition -ControlId $id
            @($def.PreviewCommands).Count | Should -BeGreaterThan 0
            ($def.Apply -is [scriptblock]) | Should -Be $true
        }
    }

    It 'Defines Manual controls with Windows Settings deep-link URIs and null Apply blocks' {
        $expectedManual = @{
            'HOME-ACC-003' = 'ms-settings:signinoptions'
            'HOME-ENC-001' = 'ms-settings:deviceencryption'
            'HOME-AV-003'  = 'windowsdefender://threat'
            'HOME-AV-006'  = 'windowsdefender://threatsettings'
        }

        foreach ($id in $expectedManual.Keys) {
            ($script:mainIds -contains $id) | Should -Be $true
            $def = Get-RemediationDefinition -ControlId $id
            $def.FixMode     | Should -Be 'Manual'
            $def.Apply       | Should -Be $null
            $def.SettingsUri | Should -Be $expectedManual[$id]
        }
    }
}

Describe 'Phase 1 AutoSafe Controls (Apply, Idempotency, and Rollback)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..\src\remediation\BackupManager.ps1')
        . (Join-Path $PSScriptRoot '..\src\remediation\RemediationCatalog.ps1')
        . (Join-Path $PSScriptRoot '..\src\remediation\FixRunner.ps1')

        function Get-MpPreference { param($ErrorAction) }
        function Set-MpPreference { param($PUAProtection, $EnableNetworkProtection, $ErrorAction) }
        function Checkpoint-Computer { param($Description, $RestorePointType, $ErrorAction) }
        function Invoke-Controlli { param($Catalogo, $Ambiente, $ControlId, $CartellaChecks) }
    }

    It 'HOME-SYS-001 sets HideFileExt = 0 and rolls back to original value' {
        $backupDir = Join-Path $TestDrive 'sys001'
        Mock Test-IsAdministrator { return $false }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            return [PSCustomObject]@{ HideFileExt = 1 }
        }
        Mock Get-Item -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $null }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-SYS-001') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 1
        [System.IO.File]::Exists($res.BackupPath) | Should -Be $true

        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $LiteralPath -eq 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -and
            $Name -eq 'HideFileExt' -and [int]$Value -eq 0
        }

        $rb = Restore-RemediationBackup -BackupPath $res.BackupPath
        $rb.RestoredCount | Should -Be 1
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'HideFileExt' -and [int]$Value -eq 1
        }
    }

    It 'HOME-SYS-002 sets both NoDriveTypeAutoRun = 255 and DisableAutoplay = 1' {
        $backupDir = Join-Path $TestDrive 'sys002'
        Mock Test-IsAdministrator { return $true }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $false }
        Mock New-Item -ParameterFilter { $Path -like 'HK*' } { }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-SYS-002') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 1

        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'NoDriveTypeAutoRun' -and [int]$Value -eq 255
        }
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'DisableAutoplay' -and [int]$Value -eq 1
        }
    }

    It 'HOME-SYS-007 sets fAllowToGetHelp = 0' {
        $backupDir = Join-Path $TestDrive 'sys007'
        Mock Test-IsAdministrator { return $true }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            return [PSCustomObject]@{ fAllowToGetHelp = 1 }
        }
        Mock Get-Item -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $null }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-SYS-007') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 1
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'fAllowToGetHelp' -and [int]$Value -eq 0
        }
    }

    It 'HOME-NET-002 sets NetbiosOptions = 2 on every NetBT interface subkey' {
        $backupDir = Join-Path $TestDrive 'net002'
        Mock Test-IsAdministrator { return $true }
        Mock Get-ChildItem -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            return @(
                [PSCustomObject]@{ PSChildName = 'Tcpip_{AAA}' },
                [PSCustomObject]@{ PSChildName = 'Tcpip_{BBB}' }
            )
        }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            return [PSCustomObject]@{ NetbiosOptions = 0 }
        }
        Mock Get-Item -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $null }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-NET-002') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 1
        Should -Invoke New-ItemProperty -Times 2 -ParameterFilter {
            $Name -eq 'NetbiosOptions' -and [int]$Value -eq 2
        }
    }

    It 'HOME-NET-003 creates missing DNSClient parent key, is idempotent, and rolls back cleanly' {
        $backupDir = Join-Path $TestDrive 'net003_idem'
        $session = New-RemediationBackupSession -BackupDirectory $backupDir

        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $false }
        Mock New-Item -ParameterFilter { $Path -like 'HK*' } { }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }
        Mock Remove-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $def = Get-RemediationDefinition -ControlId 'HOME-NET-003'
        & $def.Apply $session $null
        & $def.Apply $session $null

        @($session.Entries).Count | Should -Be 1
        $session.Entries[0].ValueExisted | Should -Be $false
        Should -Invoke New-ItemProperty -Times 2 -ParameterFilter {
            $Name -eq 'EnableMulticast' -and [int]$Value -eq 0
        }

        $saved = Save-RemediationBackupSession -Session $session
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        $rb = Restore-RemediationBackup -BackupPath $saved
        $rb.RestoredCount | Should -Be 1
        Should -Invoke Remove-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'EnableMulticast' }
    }

    It 'HOME-NET-007, HOME-SEC-003, and HOME-PRV-001 create missing parent keys and write target values' {
        $backupDir = Join-Path $TestDrive 'reg_policies'
        Mock Test-IsAdministrator { return $true }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $false }
        Mock New-Item -ParameterFilter { $Path -like 'HK*' } { }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-NET-007', 'HOME-SEC-003', 'HOME-PRV-001') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 3

        Should -Invoke New-Item -Times 3 -ParameterFilter { $Path -like 'HK*' }
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'DisableWpad' -and [int]$Value -eq 1
        }
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'EnableScriptBlockLogging' -and [int]$Value -eq 1
        }
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'AllowTelemetry' -and [int]$Value -eq 1
        }
    }

    It 'HOME-AV-005 and HOME-AV-010 capture original Defender state, enable protection, and roll back cleanly' {
        $backupDir = Join-Path $TestDrive 'defender_fixes'
        Mock Test-IsAdministrator { return $true }
        Mock Get-MpPreference {
            return [PSCustomObject]@{ PUAProtection = 0; EnableNetworkProtection = 2 }
        }
        Mock Set-MpPreference { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-AV-005', 'HOME-AV-010') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 2

        Should -Invoke Set-MpPreference -Times 1 -ParameterFilter { $PUAProtection -eq 'Enabled' }
        Should -Invoke Set-MpPreference -Times 1 -ParameterFilter { $EnableNetworkProtection -eq 'Enabled' }

        $rb = Restore-RemediationBackup -BackupPath $res.BackupPath
        $rb.RestoredCount | Should -Be 2
        Should -Invoke Set-MpPreference -Times 1 -ParameterFilter { $PUAProtection -eq 'Disabled' }
        Should -Invoke Set-MpPreference -Times 1 -ParameterFilter { $EnableNetworkProtection -eq 'AuditMode' }
    }
}

Describe 'FixRunner' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..\src\remediation\BackupManager.ps1')
        . (Join-Path $PSScriptRoot '..\src\remediation\RemediationCatalog.ps1')
        . (Join-Path $PSScriptRoot '..\src\remediation\FixRunner.ps1')

        function Get-MpPreference { param($ErrorAction) }
        function Set-MpPreference { param($PUAProtection, $EnableNetworkProtection, $ErrorAction) }
        function Checkpoint-Computer { param($Description, $RestorePointType, $ErrorAction) }
        function Invoke-Controlli { param($Catalogo, $Ambiente, $ControlId, $CartellaChecks) }
    }

    It 'WhatIfMode returns preview results with zero system or disk modifications' {
        Mock New-Item { throw 'Should not write in WhatIfMode' }
        Mock New-ItemProperty { throw 'Should not write in WhatIfMode' }
        Mock Set-MpPreference { throw 'Should not write in WhatIfMode' }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-SYS-001', 'HOME-ACC-003', 'HOME-UNKNOWN-999') -WhatIfMode
        $res.WhatIf         | Should -Be $true
        $res.BackupPath     | Should -Be $null
        $res.TotalRequested | Should -Be 3
        $res.Results[0].Status | Should -Be 'WhatIf'
        $res.Results[1].Status | Should -Be 'ManualOnly'
        $res.Results[2].Status | Should -Be 'Unsupported'
    }

    It 'Enforces RequiresAdmin guardrail when running without elevation while still allowing user-scoped fixes' {
        $backupDir = Join-Path $TestDrive 'non_admin'
        Mock Test-IsAdministrator { return $false }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            return [PSCustomObject]@{ HideFileExt = 1 }
        }
        Mock Get-Item -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $null }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-SYS-001', 'HOME-NET-003') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 1
        $res.BlockedCount | Should -Be 1
        $res.Results[0].Status | Should -Be 'Applied'
        $res.Results[1].Status | Should -Be 'RequiresAdmin'
    }

    It 'Handles ManualOnly, Unsupported, and Blocked controls cleanly without halting batch execution' {
        $backupDir = Join-Path $TestDrive 'mixed_errors'
        Mock Test-IsAdministrator { return $true }
        Mock Get-MpPreference { return [PSCustomObject]@{ PUAProtection = 0 } }
        Mock Set-MpPreference {
            throw [System.UnauthorizedAccessException]::new('Tamper Protection active - Access is denied')
        }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            return [PSCustomObject]@{ HideFileExt = 1 }
        }
        Mock Get-Item -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $null }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-ACC-003', 'HOME-UNKNOWN-999', 'HOME-AV-005', 'HOME-SYS-001') -BackupDirectory $backupDir
        $res.TotalRequested | Should -Be 4
        $res.Results[0].Status      | Should -Be 'ManualOnly'
        $res.Results[0].SettingsUri | Should -Be 'ms-settings:signinoptions'
        $res.Results[1].Status      | Should -Be 'Unsupported'
        $res.Results[2].Status      | Should -Be 'Blocked'
        $res.Results[3].Status      | Should -Be 'Applied'
    }

    It 'Performs closed-loop post-fix verification via Invoke-Controlli' {
        $backupDir = Join-Path $TestDrive 'closed_loop'
        $fakeCatalog  = [PSCustomObject]@{ controls = @() }
        $fakeAmbiente = [PSCustomObject]@{ Edition = 'Pro' }

        Mock Test-IsAdministrator { return $true }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $false }
        Mock New-Item -ParameterFilter { $Path -like 'HK*' } { }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        Mock Invoke-Controlli {
            if ($ControlId -contains 'HOME-NET-003') {
                return @([PSCustomObject]@{
                    control_id = 'HOME-NET-003'; status = 'superato'
                    observed = 'LLMNR disabled'; expected = ''; evidence = $null; error = $null; duration_ms = 2
                })
            }
            return @([PSCustomObject]@{
                control_id = 'HOME-NET-007'; status = 'fallito'
                observed = 'WPAD still overridden by GPO'; expected = ''; evidence = $null; error = $null; duration_ms = 2
            })
        }

        $res = Invoke-SecurityRemediation `
            -ControlIds @('HOME-NET-003', 'HOME-NET-007') `
            -Catalogo $fakeCatalog `
            -Ambiente $fakeAmbiente `
            -BackupDirectory $backupDir

        $res.FixedCount  | Should -Be 1
        $res.FailedCount | Should -Be 1
        $res.Results[0].Status   | Should -Be 'Fixed'
        $res.Results[0].Verified | Should -Be $true
        $res.Results[1].Status   | Should -Be 'VerificationFailed'
        $res.Results[1].Verified | Should -Be $false
    }

    It 'Invokes Checkpoint-Computer when CreateRestorePoint is specified and tolerates failure cleanly' {
        $backupDir = Join-Path $TestDrive 'restore_point'
        Mock Test-IsAdministrator { return $true }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            return [PSCustomObject]@{ HideFileExt = 1 }
        }
        Mock Get-Item -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $null }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        Mock Checkpoint-Computer { }
        $okRes = Invoke-SecurityRemediation -ControlIds @('HOME-SYS-001') -BackupDirectory $backupDir -CreateRestorePoint
        $okRes.RestorePointCreated | Should -Be $true
        Should -Invoke Checkpoint-Computer -Times 1

        Mock Checkpoint-Computer { throw 'System Protection is disabled on drive C:' }
        $failRpRes = Invoke-SecurityRemediation -ControlIds @('HOME-SYS-001') -BackupDirectory $backupDir -CreateRestorePoint
        $failRpRes.RestorePointCreated | Should -Be $false
        $failRpRes.AppliedCount        | Should -Be 1
    }
}

Describe 'Phase 3 Tier 1 & Tier 2 Remediations + Guardrails' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..\src\remediation\BackupManager.ps1')
        . (Join-Path $PSScriptRoot '..\src\remediation\RemediationCatalog.ps1')
        . (Join-Path $PSScriptRoot '..\src\remediation\FixRunner.ps1')

        function Invoke-Controlli { param($Catalogo, $Ambiente, $ControlId, $CartellaChecks) }
        if (-not (Get-Command -Name 'Get-NetFirewallProfile' -ErrorAction SilentlyContinue)) {
            function Get-NetFirewallProfile { param($Name, $ErrorAction) }
            function Set-NetFirewallProfile { param($Name, $Enabled, $DefaultInboundAction, $ErrorAction) }
        }
        if (-not (Get-Command -Name 'Get-MpPreference' -ErrorAction SilentlyContinue)) {
            function Get-MpPreference { param($ErrorAction) }
            function Set-MpPreference { param($PUAProtection, $EnableNetworkProtection, $EnableControlledFolderAccess, $DisableRealtimeMonitoring, $DisableBehaviorMonitoring, $DisableIOAVProtection, $AttackSurfaceReductionRules_Ids, $AttackSurfaceReductionRules_Actions, $ErrorAction) }
            function Add-MpPreference { param($AttackSurfaceReductionRules_Ids, $AttackSurfaceReductionRules_Actions, $ErrorAction) }
            function Remove-MpPreference { param($AttackSurfaceReductionRules_Ids, $ErrorAction) }
            function Update-MpSignature { param($ErrorAction) }
        }
        if (-not (Get-Command -Name 'Get-LocalUser' -ErrorAction SilentlyContinue)) {
            function Get-LocalUser { param($ErrorAction) }
            function Disable-LocalUser { param($SID, $ErrorAction) }
            function Enable-LocalUser { param($SID, $ErrorAction) }
            function Get-LocalGroupMember { param($SID, $ErrorAction) }
        }
        if (-not (Get-Command -Name 'Get-WindowsOptionalFeature' -ErrorAction SilentlyContinue)) {
            function Get-WindowsOptionalFeature { param($Online, $FeatureName, $ErrorAction) }
            function Disable-WindowsOptionalFeature { param($Online, $FeatureName, $NoRestart, $ErrorAction) }
            function Enable-WindowsOptionalFeature { param($Online, $FeatureName, $NoRestart, $ErrorAction) }
        }
        if (-not (Get-Command -Name 'Set-SmbServerConfiguration' -ErrorAction SilentlyContinue)) {
            function Set-SmbServerConfiguration { param($EnableSMB1Protocol, $Force, $ErrorAction) }
        }
    }

    It 'HOME-FW-001 enables all 3 firewall profiles with DefaultInboundAction Block and rolls back' {
        $backupDir = Join-Path $TestDrive 'fw001'
        Mock Test-IsAdministrator { return $true }
        Mock Get-NetFirewallProfile {
            param($Name)
            return [PSCustomObject]@{ Name = $Name; Enabled = $false; DefaultInboundAction = 'Allow' }
        }
        Mock Set-NetFirewallProfile { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-FW-001') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 1
        Should -Invoke Set-NetFirewallProfile -Times 3 -ParameterFilter {
            $Enabled -eq 'True' -and $DefaultInboundAction -eq 'Block'
        }

        $rb = Restore-RemediationBackup -BackupPath $res.BackupPath
        $rb.RestoredCount | Should -Be 3
        Should -Invoke Set-NetFirewallProfile -Times 3 -ParameterFilter {
            $Enabled -eq 'False' -and $DefaultInboundAction -eq 'Allow'
        }
    }

    It 'HOME-UAC-001, HOME-UAC-002, and HOME-UAC-003 enforce complete UAC elevation settings' {
        $backupDir = Join-Path $TestDrive 'uac_all'
        Mock Test-IsAdministrator { return $true }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            return [PSCustomObject]@{ EnableLUA = 0; ConsentPromptBehaviorAdmin = 0; PromptOnSecureDesktop = 0; EnableInstallerDetection = 0 }
        }
        Mock Get-Item -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $null }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-UAC-001', 'HOME-UAC-002', 'HOME-UAC-003') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 3

        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'EnableLUA' -and [int]$Value -eq 1 }
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'ConsentPromptBehaviorAdmin' -and [int]$Value -eq 5 }
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'PromptOnSecureDesktop' -and [int]$Value -eq 1 }
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'EnableInstallerDetection' -and [int]$Value -eq 1 }
    }

    It 'HOME-SYS-003 configures both Explorer SmartScreenEnabled String and AppHost EnableWebContentEvaluation DWord' {
        $backupDir = Join-Path $TestDrive 'sys003'
        Mock Test-IsAdministrator { return $true }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $false }
        Mock New-Item -ParameterFilter { $Path -like 'HK*' } { }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-SYS-003') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 1
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'SmartScreenEnabled' -and $Value -eq 'Warn' -and $PropertyType -eq 'String'
        }
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $Name -eq 'EnableWebContentEvaluation' -and [int]$Value -eq 1 -and $PropertyType -eq 'DWord'
        }
    }

    It 'HOME-NET-008 disables TLS 1.0/1.1 SCHANNEL keys and enables Dnscache EnableAutoDoh = 2' {
        $backupDir = Join-Path $TestDrive 'net008'
        Mock Test-IsAdministrator { return $true }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $false }
        Mock New-Item -ParameterFilter { $Path -like 'HK*' } { }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-NET-008') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 1
        Should -Invoke New-ItemProperty -Times 4 -ParameterFilter {
            $LiteralPath -like '*SCHANNEL\Protocols\TLS 1.*' -and $Name -eq 'Enabled' -and [int]$Value -eq 0
        }
        Should -Invoke New-ItemProperty -Times 4 -ParameterFilter {
            $LiteralPath -like '*SCHANNEL\Protocols\TLS 1.*' -and $Name -eq 'DisabledByDefault' -and [int]$Value -eq 1
        }
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $LiteralPath -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -and $Name -eq 'EnableAutoDoh' -and [int]$Value -eq 2
        }
    }

    It 'HOME-SEC-009 remediates permissive ExecutionPolicy scopes and restores original policies on rollback' {
        $backupDir = Join-Path $TestDrive 'sec009'
        Mock Test-IsAdministrator { return $true }
        Mock Get-ExecutionPolicy {
            return @(
                [PSCustomObject]@{ Scope = 'MachinePolicy'; ExecutionPolicy = 'Undefined' },
                [PSCustomObject]@{ Scope = 'UserPolicy';    ExecutionPolicy = 'Undefined' },
                [PSCustomObject]@{ Scope = 'CurrentUser';   ExecutionPolicy = 'Bypass' },
                [PSCustomObject]@{ Scope = 'LocalMachine';  ExecutionPolicy = 'Unrestricted' }
            )
        }
        Mock Set-ExecutionPolicy { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-SEC-009') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 1
        Should -Invoke Set-ExecutionPolicy -Times 1 -ParameterFilter { $Scope -eq 'LocalMachine' -and $ExecutionPolicy -eq 'RemoteSigned' }
        Should -Invoke Set-ExecutionPolicy -Times 1 -ParameterFilter { $Scope -eq 'CurrentUser'  -and $ExecutionPolicy -eq 'RemoteSigned' }

        $rb = Restore-RemediationBackup -BackupPath $res.BackupPath
        $rb.RestoredCount | Should -Be 2
        Should -Invoke Set-ExecutionPolicy -Times 1 -ParameterFilter { $Scope -eq 'LocalMachine' -and $ExecutionPolicy -eq 'Unrestricted' }
        Should -Invoke Set-ExecutionPolicy -Times 1 -ParameterFilter { $Scope -eq 'CurrentUser'  -and $ExecutionPolicy -eq 'Bypass' }
    }

    It 'HOME-ACC-001 and HOME-ACC-004 disable Guest account and enforce lockout threshold with full rollback' {
        $backupDir = Join-Path $TestDrive 'acc_safe'
        Mock Test-IsAdministrator { return $true }
        Mock Get-LocalUser {
            return @([PSCustomObject]@{ Name = 'Guest'; SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-501' }; Enabled = $true })
        }
        Mock Disable-LocalUser { }
        Mock Enable-LocalUser { }
        Mock Invoke-NetAccounts {
            param($Arguments)
            if ($null -eq $Arguments -or $Arguments.Count -eq 0) {
                return @(
                    'Lockout threshold:                    Never',
                    'Lockout duration (minutes):           30',
                    'Lockout observation window (minutes): 30'
                )
            }
            return @()
        }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-ACC-001', 'HOME-ACC-004') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 2
        Should -Invoke Disable-LocalUser -Times 1 -ParameterFilter { $SID -eq 'S-1-5-21-100-501' }
        Should -Invoke Invoke-NetAccounts -Times 1 -ParameterFilter { $Arguments -contains '/lockoutthreshold:5' }

        $rb = Restore-RemediationBackup -BackupPath $res.BackupPath
        $rb.RestoredCount | Should -Be 2
        Should -Invoke Enable-LocalUser -Times 1 -ParameterFilter { $SID -eq 'S-1-5-21-100-501' }
        Should -Invoke Invoke-NetAccounts -Times 1 -ParameterFilter { $Arguments -contains '/lockoutthreshold:0' }
    }

    It 'HOME-UPD-001, HOME-SYS-008, HOME-NET-005, HOME-AV-001, and HOME-AV-004 configure services, SMB signing, and Defender cleanly' {
        $backupDir = Join-Path $TestDrive 'tier1_misc'
        Mock Test-IsAdministrator { return $true }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            return [PSCustomObject]@{ Start = 4; RequireSecuritySignature = 0; NoAutoUpdate = 1 }
        }
        Mock Get-Item -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $null }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }
        Mock Get-Service { return [PSCustomObject]@{ Name = 'RemoteRegistry'; Status = 'Running' } }
        Mock Stop-Service { }
        Mock Get-MpPreference {
            return [PSCustomObject]@{ DisableRealtimeMonitoring = $true; DisableBehaviorMonitoring = $true; DisableIOAVProtection = $true }
        }
        Mock Set-MpPreference { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-UPD-001', 'HOME-SYS-008', 'HOME-NET-005', 'HOME-AV-001', 'HOME-AV-004') -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 5
        Should -Invoke Stop-Service -Times 1 -ParameterFilter { $Name -eq 'RemoteRegistry' }
        Should -Invoke New-ItemProperty -Times 2 -ParameterFilter { $Name -eq 'RequireSecuritySignature' -and [int]$Value -eq 1 }
        Should -Invoke Set-MpPreference -Times 1 -ParameterFilter { $DisableRealtimeMonitoring -eq $false }
        Should -Invoke Set-MpPreference -Times 1 -ParameterFilter { $DisableBehaviorMonitoring -eq $false }
        Should -Invoke Set-MpPreference -Times 1 -ParameterFilter { $DisableIOAVProtection -eq $false }
    }

    It 'Guardrails block HOME-RDP-001 during active RDP sessions and apply when outside RDP' {
        $backupDir = Join-Path $TestDrive 'rdp_guard'
        Mock Test-IsAdministrator { return $true }

        Mock Test-IsRdpSession { return $true }
        $blocked = Invoke-SecurityRemediation -ControlIds @('HOME-RDP-001') -BackupDirectory $backupDir
        $blocked.BlockedCount      | Should -Be 1
        $blocked.Results[0].Status | Should -Be 'Blocked'
        $blocked.Results[0].Message | Should -Match 'RDP session'

        Mock Test-IsRdpSession { return $false }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return [PSCustomObject]@{ fDenyTSConnections = 0 } }
        Mock Get-Item -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $null }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $applied = Invoke-SecurityRemediation -ControlIds @('HOME-RDP-001') -BackupDirectory $backupDir
        $applied.AppliedCount | Should -Be 1
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter { $Name -eq 'fDenyTSConnections' -and [int]$Value -eq 1 }
    }

    It 'Guardrails block HOME-NET-006 during active WinRM sessions and apply when outside WinRM' {
        $backupDir = Join-Path $TestDrive 'winrm_guard'
        Mock Test-IsAdministrator { return $true }

        Mock Test-IsWinRmSession { return $true }
        $blocked = Invoke-SecurityRemediation -ControlIds @('HOME-NET-006') -BackupDirectory $backupDir
        $blocked.BlockedCount      | Should -Be 1
        $blocked.Results[0].Status | Should -Be 'Blocked'
        $blocked.Results[0].Message | Should -Match 'WinRM'

        Mock Test-IsWinRmSession { return $false }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return [PSCustomObject]@{ Start = 2 } }
        Mock Get-Item -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $null }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }
        Mock Get-Service { return [PSCustomObject]@{ Name = 'WinRM'; Status = 'Running' } }
        Mock Stop-Service { }

        $applied = Invoke-SecurityRemediation -ControlIds @('HOME-NET-006') -BackupDirectory $backupDir
        $applied.AppliedCount | Should -Be 1
        Should -Invoke Stop-Service -Times 1 -ParameterFilter { $Name -eq 'WinRM' }
    }

    It 'HOME-SYS-004 enforces Test-HvciSupported guardrail and returns RebootRequired (not VerificationFailed) before reboot' {
        $backupDir = Join-Path $TestDrive 'hvci_guard'
        $fakeCatalog  = [PSCustomObject]@{ controls = @() }
        $fakeAmbiente = [PSCustomObject]@{ Edition = 'Pro' }

        Mock Test-IsAdministrator { return $true }
        Mock Test-HvciSupported { return $false }
        $blocked = Invoke-SecurityRemediation -ControlIds @('HOME-SYS-004') -Catalogo $fakeCatalog -Ambiente $fakeAmbiente -BackupDirectory $backupDir
        $blocked.Results[0].Status  | Should -Be 'Blocked'
        $blocked.Results[0].Message | Should -Match 'HVCI'

        Mock Test-HvciSupported { return $true }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $false }
        Mock New-Item -ParameterFilter { $Path -like 'HK*' } { }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }
        Mock Invoke-Controlli {
            return @([PSCustomObject]@{ control_id = 'HOME-SYS-004'; status = 'fallito'; observed = 'HVCI not running until reboot'; expected = ''; evidence = $null; error = $null; duration_ms = 2 })
        }

        $rebootRes = Invoke-SecurityRemediation -ControlIds @('HOME-SYS-004') -Catalogo $fakeCatalog -Ambiente $fakeAmbiente -BackupDirectory $backupDir
        $rebootRes.RebootRequiredCount | Should -Be 1
        $rebootRes.FailedCount         | Should -Be 0
        $rebootRes.Results[0].Status   | Should -Be 'RebootRequired'
    }

    It 'HOME-NET-001 and HOME-AV-011 apply SMBv1 removal and ASR rules with rollback support' {
        $backupDir = Join-Path $TestDrive 'tier2_net_asr'
        Mock Test-IsAdministrator { return $true }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $false }
        Mock New-Item -ParameterFilter { $Path -like 'HK*' } { }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }
        Mock Get-WindowsOptionalFeature { return [PSCustomObject]@{ FeatureName = 'SMB1Protocol'; State = 'Enabled' } }
        Mock Disable-WindowsOptionalFeature { }
        Mock Enable-WindowsOptionalFeature { }
        Mock Set-SmbServerConfiguration { }
        Mock Get-MpPreference { return [PSCustomObject]@{ AttackSurfaceReductionRules_Ids = @(); AttackSurfaceReductionRules_Actions = @() } }
        Mock Add-MpPreference { }
        Mock Remove-MpPreference { }

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-NET-001', 'HOME-AV-011') -BackupDirectory $backupDir
        $res.RebootRequiredCount | Should -Be 1
        $res.AppliedCount        | Should -Be 1
        Should -Invoke Disable-WindowsOptionalFeature -Times 1 -ParameterFilter { $FeatureName -eq 'SMB1Protocol' }
        Should -Invoke Add-MpPreference -Times 1

        $rb = Restore-RemediationBackup -BackupPath $res.BackupPath
        $rb.RestoredCount | Should -Be 3
        Should -Invoke Remove-MpPreference -Times 1
        Should -Invoke Enable-WindowsOptionalFeature -Times 1 -ParameterFilter { $FeatureName -eq 'SMB1Protocol' }
    }
}

Describe 'Phase 4 Tier 3 Evidence-Driven Dynamic Fixes' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..\src\remediation\BackupManager.ps1')
        . (Join-Path $PSScriptRoot '..\src\remediation\RemediationCatalog.ps1')
        . (Join-Path $PSScriptRoot '..\src\remediation\FixRunner.ps1')

        function Invoke-Controlli { param($Catalogo, $Ambiente, $ControlId, $CartellaChecks) }
        if (-not (Get-Command -Name 'Get-LocalUser' -ErrorAction SilentlyContinue)) {
            function Get-LocalUser { param($ErrorAction) }
            function Disable-LocalUser { param($SID, $ErrorAction) }
            function Enable-LocalUser { param($SID, $ErrorAction) }
            function Get-LocalGroupMember { param($SID, $ErrorAction) }
        }
    }

    It 'HOME-NET-009 switches insecure SSIDs from ScanResults Evidence to manual, rejects unsafe SSIDs, and rolls back to auto' {
        $backupDir = Join-Path $TestDrive 'net009_dyn'
        Mock Test-IsAdministrator { return $true }
        Mock Invoke-NetshWlan { }

        $scanResults = @(
            [PSCustomObject]@{
                control_id = 'HOME-NET-009'
                status     = 'fallito'
                evidence   = @{
                    InsecureProfiles = @(
                        [PSCustomObject]@{ ProfileName = 'CafeFree'; ConnectionMode = 'auto' }
                    )
                }
            }
        )

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-NET-009') -ScanResults $scanResults -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 1
        Should -Invoke Invoke-NetshWlan -Times 1 -ParameterFilter {
            ($Arguments -contains 'name=CafeFree') -and ($Arguments -contains 'connectionmode=manual')
        }

        $rb = Restore-RemediationBackup -BackupPath $res.BackupPath
        $rb.RestoredCount | Should -Be 1
        Should -Invoke Invoke-NetshWlan -Times 1 -ParameterFilter {
            ($Arguments -contains 'name=CafeFree') -and ($Arguments -contains 'connectionmode=auto')
        }

        { Set-WifiProfileManualWithBackup -ProfileName 'Bad";whoami' } | Should -Throw '*unsafe characters*'
    }

    It 'HOME-ACC-002 blocks when only the built-in admin exists and disables SID -500 when another enabled admin is present' {
        $backupDir = Join-Path $TestDrive 'acc002_dyn'
        Mock Test-IsAdministrator { return $true }

        # Single-admin case: only built-in -500 enabled
        Mock Get-LocalUser {
            return @(
                [PSCustomObject]@{ Name = 'Administrator'; SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-500' }; Enabled = $true },
                [PSCustomObject]@{ Name = 'BackupAdmin';   SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-1001' }; Enabled = $false }
            )
        }
        Mock Get-LocalGroupMember {
            return @(
                [PSCustomObject]@{ Name = 'PC\Administrator'; SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-500' }; ObjectClass = 'User' },
                [PSCustomObject]@{ Name = 'PC\BackupAdmin';   SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-1001' }; ObjectClass = 'User' }
            )
        }

        $blockedRes = Invoke-SecurityRemediation -ControlIds @('HOME-ACC-002') -BackupDirectory $backupDir
        $blockedRes.BlockedCount      | Should -Be 1
        $blockedRes.Results[0].Status | Should -Be 'Blocked'
        $blockedRes.Results[0].Message | Should -Match 'Lockout prevention'

        # Two-admin case: built-in -500 plus another enabled admin -1001
        Mock Get-LocalUser {
            return @(
                [PSCustomObject]@{ Name = 'Administrator'; SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-500' }; Enabled = $true },
                [PSCustomObject]@{ Name = 'PersonalAdmin'; SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-1001' }; Enabled = $true }
            )
        }
        Mock Get-LocalGroupMember {
            return @(
                [PSCustomObject]@{ Name = 'PC\Administrator'; SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-500' }; ObjectClass = 'User' },
                [PSCustomObject]@{ Name = 'PC\PersonalAdmin'; SID = [PSCustomObject]@{ Value = 'S-1-5-21-100-1001' }; ObjectClass = 'User' }
            )
        }
        Mock Disable-LocalUser { }
        Mock Enable-LocalUser { }

        $okRes = Invoke-SecurityRemediation -ControlIds @('HOME-ACC-002') -BackupDirectory $backupDir
        $okRes.AppliedCount | Should -Be 1
        Should -Invoke Disable-LocalUser -Times 1 -ParameterFilter { $SID -eq 'S-1-5-21-100-500' }

        $rb = Restore-RemediationBackup -BackupPath $okRes.BackupPath
        $rb.RestoredCount | Should -Be 1
        Should -Invoke Enable-LocalUser -Times 1 -ParameterFilter { $SID -eq 'S-1-5-21-100-500' }
    }

    It 'HOME-FIL-009 quotes only the executable path up to .exe, preserves arguments and ExpandString, and rolls back' {
        ConvertTo-QuotedServicePath -PathName 'C:\Program Files\My App\svc.exe -run helper.exe' | Should -Be '"C:\Program Files\My App\svc.exe" -run helper.exe'
        ConvertTo-QuotedServicePath -PathName '"C:\Program Files\My App\svc.exe" -run' | Should -Be $null
        ConvertTo-QuotedServicePath -PathName 'C:\Windows\System32\svchost.exe -k netsvcs' | Should -Be $null

        $backupDir = Join-Path $TestDrive 'fil009_dyn'
        Mock Test-IsAdministrator { return $true }
        Mock Test-Path -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } { return $true }
        Mock Get-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            return [PSCustomObject]@{ ImagePath = 'C:\Program Files\My App\svc.exe -run' }
        }
        Mock Get-Item -ParameterFilter { $LiteralPath -like 'HK*' -or $Path -like 'HK*' } {
            $mockReg = [PSCustomObject]@{}
            Add-Member -InputObject $mockReg -MemberType ScriptMethod -Name 'GetValueKind' -Value { param($n) return 'ExpandString' }
            return $mockReg
        }
        Mock New-ItemProperty -ParameterFilter { $LiteralPath -like 'HK*' } { }

        $scanResults = @(
            [PSCustomObject]@{
                control_id = 'HOME-FIL-009'
                status     = 'fallito'
                evidence   = @{
                    VulnerableServices = @('MyAppSvc (C:\Program Files\My App\svc.exe -run)')
                }
            }
        )

        $res = Invoke-SecurityRemediation -ControlIds @('HOME-FIL-009') -ScanResults $scanResults -BackupDirectory $backupDir
        $res.AppliedCount | Should -Be 1
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $LiteralPath -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\MyAppSvc' -and
            $Name -eq 'ImagePath' -and
            $Value -eq '"C:\Program Files\My App\svc.exe" -run' -and
            $PropertyType -eq 'ExpandString'
        }

        $rb = Restore-RemediationBackup -BackupPath $res.BackupPath
        $rb.RestoredCount | Should -Be 1
        Should -Invoke New-ItemProperty -Times 1 -ParameterFilter {
            $LiteralPath -eq 'HKLM:\SYSTEM\CurrentControlSet\Services\MyAppSvc' -and
            $Name -eq 'ImagePath' -and
            $Value -eq 'C:\Program Files\My App\svc.exe -run' -and
            $PropertyType -eq 'ExpandString'
        }
    }
}
