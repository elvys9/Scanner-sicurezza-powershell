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

    It 'Registers all 10 Phase 1 AutoSafe controls with valid catalog IDs, Rollback support, and Apply scriptblocks' {
        $autoSafeIds = @(Get-AutoSafeControlIds)
        $autoSafeIds.Count | Should -Be 10

        $expectedPhase1 = @(
            'HOME-SYS-001', 'HOME-SYS-002', 'HOME-SYS-007',
            'HOME-NET-002', 'HOME-NET-003', 'HOME-NET-007',
            'HOME-SEC-003', 'HOME-AV-005', 'HOME-AV-010', 'HOME-PRV-001'
        )
        foreach ($expectedId in $expectedPhase1) {
            ($autoSafeIds -contains $expectedId) | Should -Be $true
        }

        foreach ($id in $autoSafeIds) {
            ($script:mainIds -contains $id) | Should -Be $true
            $def = Get-RemediationDefinition -ControlId $id
            $def.FixMode           | Should -Be 'AutoSafe'
            $def.Phase             | Should -Be 1
            $def.RollbackSupported | Should -Be $true
            $def.RequiresReboot    | Should -Be $false
            @($def.PreviewCommands).Count | Should -BeGreaterThan 0
            ($def.Apply -is [scriptblock]) | Should -Be $true

            if ($id -eq 'HOME-SYS-001') {
                $def.RequiresAdmin | Should -Be $false
            }
            else {
                $def.RequiresAdmin | Should -Be $true
            }
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
