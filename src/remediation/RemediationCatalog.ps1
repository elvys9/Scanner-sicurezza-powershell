<#
.SYNOPSIS
    Deterministic remediation catalog for Windows 11 Security Scanner.

.DESCRIPTION
    Defines curated, idempotent, pre-tested PowerShell remediations and manual Windows
    Settings deep-links keyed by catalog Control ID. Phase 1 registers the first 10
    zero-risk AutoSafe controls plus Manual guidance entries with native URIs.
#>

Set-StrictMode -Version 2

function Get-RemediationCatalog {
    <#
    .SYNOPSIS
        Returns an ordered dictionary of supported remediation definitions keyed by Control ID.
    #>
    [CmdletBinding()]
    param()

    $catalog = [ordered]@{
        'HOME-SYS-001' = [PSCustomObject]@{
            ControlId         = 'HOME-SYS-001'
            FixMode           = 'AutoSafe'
            Phase             = 1
            RequiresAdmin     = $false
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Show known file extensions in File Explorer (HideFileExt = 0).'
            PreviewCommands   = @(
                'Set-ItemProperty -LiteralPath ''HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'' -Name ''HideFileExt'' -Value 0'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup `
                    -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' `
                    -Name 'HideFileExt' `
                    -Value 0 `
                    -PropertyType 'DWord' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-SYS-001'
            }
        }

        'HOME-SYS-002' = [PSCustomObject]@{
            ControlId         = 'HOME-SYS-002'
            FixMode           = 'AutoSafe'
            Phase             = 1
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Disable AutoRun and AutoPlay for removable USB drives.'
            PreviewCommands   = @(
                'New-Item -Path ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'' -Force | Out-Null',
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'' -Name ''NoDriveTypeAutoRun'' -Value 255 -PropertyType DWord -Force',
                'New-Item -Path ''HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'' -Force | Out-Null',
                'New-ItemProperty -LiteralPath ''HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'' -Name ''DisableAutoplay'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup `
                    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' `
                    -Name 'NoDriveTypeAutoRun' `
                    -Value 255 `
                    -PropertyType 'DWord' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-SYS-002'

                Set-RegistryValueWithBackup `
                    -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers' `
                    -Name 'DisableAutoplay' `
                    -Value 1 `
                    -PropertyType 'DWord' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-SYS-002'
            }
        }

        'HOME-SYS-007' = [PSCustomObject]@{
            ControlId         = 'HOME-SYS-007'
            FixMode           = 'AutoSafe'
            Phase             = 1
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Disable Windows Remote Assistance (fAllowToGetHelp = 0).'
            PreviewCommands   = @(
                'New-Item -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'' -Force | Out-Null',
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'' -Name ''fAllowToGetHelp'' -Value 0 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup `
                    -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance' `
                    -Name 'fAllowToGetHelp' `
                    -Value 0 `
                    -PropertyType 'DWord' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-SYS-007'
            }
        }

        'HOME-NET-002' = [PSCustomObject]@{
            ControlId         = 'HOME-NET-002'
            FixMode           = 'AutoSafe'
            Phase             = 1
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Disable NetBIOS over TCP/IP (NetbiosOptions = 2) on all NetBT interfaces.'
            PreviewCommands   = @(
                'Get-ChildItem -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'' | ForEach-Object { New-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\$($_.PSChildName)" -Name ''NetbiosOptions'' -Value 2 -PropertyType DWord -Force }'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                $basePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
                $subKeys = @(Get-ChildItem -LiteralPath $basePath -ErrorAction Stop)
                if ($subKeys.Count -eq 0) {
                    throw 'No NetBT TCP/IP interfaces found in registry'
                }

                foreach ($subKey in $subKeys) {
                    $targetPath = "$basePath\$($subKey.PSChildName)"
                    Set-RegistryValueWithBackup `
                        -Path $targetPath `
                        -Name 'NetbiosOptions' `
                        -Value 2 `
                        -PropertyType 'DWord' `
                        -BackupSession $BackupSession `
                        -ControlId 'HOME-NET-002'
                }
            }
        }

        'HOME-NET-003' = [PSCustomObject]@{
            ControlId         = 'HOME-NET-003'
            FixMode           = 'AutoSafe'
            Phase             = 1
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Disable LLMNR multicast name resolution via DNSClient policy (EnableMulticast = 0).'
            PreviewCommands   = @(
                'New-Item -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'' -Force | Out-Null',
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'' -Name ''EnableMulticast'' -Value 0 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup `
                    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' `
                    -Name 'EnableMulticast' `
                    -Value 0 `
                    -PropertyType 'DWord' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-NET-003'
            }
        }

        'HOME-NET-007' = [PSCustomObject]@{
            ControlId         = 'HOME-NET-007'
            FixMode           = 'AutoSafe'
            Phase             = 1
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Disable WPAD automatic proxy discovery (DisableWpad = 1).'
            PreviewCommands   = @(
                'New-Item -Path ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad'' -Force | Out-Null',
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad'' -Name ''DisableWpad'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup `
                    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad' `
                    -Name 'DisableWpad' `
                    -Value 1 `
                    -PropertyType 'DWord' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-NET-007'
            }
        }

        'HOME-SEC-003' = [PSCustomObject]@{
            ControlId         = 'HOME-SEC-003'
            FixMode           = 'AutoSafe'
            Phase             = 1
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enable PowerShell Script Block Logging (EnableScriptBlockLogging = 1).'
            PreviewCommands   = @(
                'New-Item -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'' -Force | Out-Null',
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'' -Name ''EnableScriptBlockLogging'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup `
                    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
                    -Name 'EnableScriptBlockLogging' `
                    -Value 1 `
                    -PropertyType 'DWord' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-SEC-003'
            }
        }

        'HOME-AV-005' = [PSCustomObject]@{
            ControlId         = 'HOME-AV-005'
            FixMode           = 'AutoSafe'
            Phase             = 1
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enable Microsoft Defender PUA blocking (PUAProtection = Enabled).'
            PreviewCommands   = @(
                'Set-MpPreference -PUAProtection Enabled'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-DefenderPreferenceWithBackup `
                    -PropertyName 'PUAProtection' `
                    -TargetValue 'Enabled' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-AV-005'
            }
        }

        'HOME-AV-010' = [PSCustomObject]@{
            ControlId         = 'HOME-AV-010'
            FixMode           = 'AutoSafe'
            Phase             = 1
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enable Microsoft Defender Network Protection in Block mode (EnableNetworkProtection = Enabled).'
            PreviewCommands   = @(
                'Set-MpPreference -EnableNetworkProtection Enabled'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-DefenderPreferenceWithBackup `
                    -PropertyName 'EnableNetworkProtection' `
                    -TargetValue 'Enabled' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-AV-010'
            }
        }

        'HOME-PRV-001' = [PSCustomObject]@{
            ControlId         = 'HOME-PRV-001'
            FixMode           = 'AutoSafe'
            Phase             = 1
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Restrict Windows diagnostic telemetry to minimum required data (AllowTelemetry = 1).'
            PreviewCommands   = @(
                'New-Item -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'' -Force | Out-Null',
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'' -Name ''AllowTelemetry'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup `
                    -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection' `
                    -Name 'AllowTelemetry' `
                    -Value 1 `
                    -PropertyType 'DWord' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-PRV-001'
            }
        }

        # === MANUAL / DEEP-LINK CONTROLS ===
        'HOME-ACC-003' = [PSCustomObject]@{
            ControlId         = 'HOME-ACC-003'
            FixMode           = 'Manual'
            Phase             = 1
            RequiresAdmin     = $false
            RequiresReboot    = $false
            RollbackSupported = $false
            Summary           = 'Set a strong account password or Windows Hello PIN interactively in Windows Settings.'
            PreviewCommands   = @()
            SettingsUri       = 'ms-settings:signinoptions'
            Apply             = $null
        }

        'HOME-ENC-001' = [PSCustomObject]@{
            ControlId         = 'HOME-ENC-001'
            FixMode           = 'Manual'
            Phase             = 1
            RequiresAdmin     = $false
            RequiresReboot    = $false
            RollbackSupported = $false
            Summary           = 'Enable BitLocker or Device Encryption in Windows Settings after backing up the recovery key.'
            PreviewCommands   = @()
            SettingsUri       = 'ms-settings:deviceencryption'
            Apply             = $null
        }

        'HOME-AV-003' = [PSCustomObject]@{
            ControlId         = 'HOME-AV-003'
            FixMode           = 'Manual'
            Phase             = 1
            RequiresAdmin     = $false
            RequiresReboot    = $false
            RollbackSupported = $false
            Summary           = 'Review and quarantine active threats in Windows Security.'
            PreviewCommands   = @()
            SettingsUri       = 'windowsdefender://threat'
            Apply             = $null
        }

        'HOME-AV-006' = [PSCustomObject]@{
            ControlId         = 'HOME-AV-006'
            FixMode           = 'Manual'
            Phase             = 1
            RequiresAdmin     = $false
            RequiresReboot    = $false
            RollbackSupported = $false
            Summary           = 'Enable Tamper Protection interactively inside Windows Security (cannot be enabled by PowerShell).'
            PreviewCommands   = @()
            SettingsUri       = 'windowsdefender://threatsettings'
            Apply             = $null
        }

        'HOME-SEC-001' = [PSCustomObject]@{
            ControlId         = 'HOME-SEC-001'
            FixMode           = 'Manual'
            Phase             = 1
            RequiresAdmin     = $false
            RequiresReboot    = $true
            RollbackSupported = $false
            Summary           = 'Enable UEFI Secure Boot inside motherboard firmware settings.'
            PreviewCommands   = @()
            SettingsUri       = $null
            Apply             = $null
        }

        'HOME-SEC-007' = [PSCustomObject]@{
            ControlId         = 'HOME-SEC-007'
            FixMode           = 'Manual'
            Phase             = 1
            RequiresAdmin     = $false
            RequiresReboot    = $false
            RollbackSupported = $false
            Summary           = 'Inspect Smart App Control status in Windows Security (OS policy can only be enabled on clean install).'
            PreviewCommands   = @()
            SettingsUri       = 'windowsdefender://appbrowser'
            Apply             = $null
        }

        'HOME-SEC-008' = [PSCustomObject]@{
            ControlId         = 'HOME-SEC-008'
            FixMode           = 'Manual'
            Phase             = 1
            RequiresAdmin     = $false
            RequiresReboot    = $true
            RollbackSupported = $false
            Summary           = 'Enable hardware TPM 2.0 (Intel PTT / AMD fTPM) inside motherboard UEFI/BIOS settings.'
            PreviewCommands   = @()
            SettingsUri       = $null
            Apply             = $null
        }
    }

    return $catalog
}

function Get-RemediationDefinition {
    <#
    .SYNOPSIS
        Looks up a single remediation definition by Control ID (returns $null when unsupported).

    .PARAMETER ControlId
        Catalog control identifier (e.g., 'HOME-NET-003').
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ControlId
    )

    $catalog = Get-RemediationCatalog
    $normalized = $ControlId.Trim().ToUpperInvariant()

    if ($catalog.Contains($normalized)) {
        return $catalog[$normalized]
    }

    return $null
}

function Get-AutoSafeControlIds {
    <#
    .SYNOPSIS
        Returns all Control IDs currently registered with FixMode = 'AutoSafe'.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $catalog = Get-RemediationCatalog
    $ids = @()
    foreach ($entry in $catalog.Values) {
        if ($entry.FixMode -eq 'AutoSafe') {
            $ids += [string]$entry.ControlId
        }
    }

    return @($ids)
}
