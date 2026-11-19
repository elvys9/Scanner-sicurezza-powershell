<#
.SYNOPSIS
    Deterministic remediation catalog for Windows 11 Security Scanner.

.DESCRIPTION
    Defines curated, idempotent, pre-tested PowerShell remediations and manual Windows
    Settings deep-links keyed by catalog Control ID:
    - Tier 1 (AutoSafe): 29 safe, immediate controls
    - Tier 2 (AutoReboot): 11 hardening controls requiring reboot or runtime guardrails
    - Tier 3 (Guided): 3 evidence-driven surgical controls (Wi-Fi AutoConnect, Built-in Admin, Unquoted Services)
    - Manual: 7 hardware/UEFI/UI-only controls with native Windows Settings deep-links
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

        # === TIER 1 REMAINING AUTOSAFE CONTROLS (PHASE 3 - TOTAL 29 AUTOSAFE) ===
        'HOME-FW-001' = [PSCustomObject]@{
            ControlId         = 'HOME-FW-001'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enable Windows Defender Firewall across Domain, Private, and Public profiles with DefaultInboundAction Block.'
            PreviewCommands   = @(
                'Set-NetFirewallProfile -Name Domain,Private,Public -Enabled True -DefaultInboundAction Block'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-FirewallProfileWithBackup `
                    -Profiles @('Domain', 'Private', 'Public') `
                    -Enabled 'True' `
                    -DefaultInboundAction 'Block' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-FW-001'
            }
        }

        'HOME-UAC-001' = [PSCustomObject]@{
            ControlId         = 'HOME-UAC-001'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enable User Account Control (EnableLUA = 1).'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'' -Name ''EnableLUA'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup `
                    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                    -Name 'EnableLUA' `
                    -Value 1 `
                    -PropertyType 'DWord' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-UAC-001'
            }
        }

        'HOME-UAC-002' = [PSCustomObject]@{
            ControlId         = 'HOME-UAC-002'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Require UAC elevation prompts on Secure Desktop (ConsentPromptBehaviorAdmin = 5, PromptOnSecureDesktop = 1).'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'' -Name ''ConsentPromptBehaviorAdmin'' -Value 5 -PropertyType DWord -Force',
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'' -Name ''PromptOnSecureDesktop'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                $uacKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                Set-RegistryValueWithBackup -Path $uacKey -Name 'ConsentPromptBehaviorAdmin' -Value 5 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-UAC-002'
                Set-RegistryValueWithBackup -Path $uacKey -Name 'PromptOnSecureDesktop' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-UAC-002'
            }
        }

        'HOME-UAC-003' = [PSCustomObject]@{
            ControlId         = 'HOME-UAC-003'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enable UAC application installer detection (EnableInstallerDetection = 1).'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'' -Name ''EnableInstallerDetection'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup `
                    -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
                    -Name 'EnableInstallerDetection' `
                    -Value 1 `
                    -PropertyType 'DWord' `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-UAC-003'
            }
        }

        'HOME-ACC-001' = [PSCustomObject]@{
            ControlId         = 'HOME-ACC-001'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Disable the built-in Guest account (SID -501).'
            PreviewCommands   = @(
                'Get-LocalUser | Where-Object { $_.SID.Value -like ''*-501'' } | Disable-LocalUser'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Disable-LocalUserWithBackup -SidSuffix '-501' -BackupSession $BackupSession -ControlId 'HOME-ACC-001'
            }
        }

        'HOME-ACC-004' = [PSCustomObject]@{
            ControlId         = 'HOME-ACC-004'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enable account lockout threshold (5 attempts, 15 minute lockout duration/window).'
            PreviewCommands   = @(
                'net.exe accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-AccountLockoutPolicyWithBackup -Threshold 5 -Duration 15 -Window 15 -BackupSession $BackupSession -ControlId 'HOME-ACC-004'
            }
        }

        'HOME-UPD-001' = [PSCustomObject]@{
            ControlId         = 'HOME-UPD-001'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Ensure Windows Update service (wuauserv) is Manual (Start = 3) and NoAutoUpdate policy is disabled.'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv'' -Name ''Start'' -Value 3 -PropertyType DWord -Force',
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'' -Name ''NoAutoUpdate'' -Value 0 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-ServiceStartupWithBackup -ServiceName 'wuauserv' -TargetStart 3 -BackupSession $BackupSession -ControlId 'HOME-UPD-001'
                Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Value 0 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-UPD-001'
            }
        }

        'HOME-AV-001' = [PSCustomObject]@{
            ControlId         = 'HOME-AV-001'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enable Microsoft Defender real-time antivirus protection (DisableRealtimeMonitoring = $false).'
            PreviewCommands   = @(
                'Set-MpPreference -DisableRealtimeMonitoring $false'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-DefenderPreferenceWithBackup -PropertyName 'DisableRealtimeMonitoring' -TargetValue $false -BackupSession $BackupSession -ControlId 'HOME-AV-001'
            }
        }

        'HOME-AV-002' = [PSCustomObject]@{
            ControlId         = 'HOME-AV-002'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $false
            Summary           = 'Update Windows Defender antivirus threat signatures via Update-MpSignature.'
            PreviewCommands   = @(
                'Update-MpSignature'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Update-MpSignature -ErrorAction Stop
            }
        }

        'HOME-AV-004' = [PSCustomObject]@{
            ControlId         = 'HOME-AV-004'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enable Windows Defender Behavior Monitoring and Downloaded File Scanning (IOAV).'
            PreviewCommands   = @(
                'Set-MpPreference -DisableBehaviorMonitoring $false',
                'Set-MpPreference -DisableIOAVProtection $false'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-DefenderPreferenceWithBackup -PropertyName 'DisableBehaviorMonitoring' -TargetValue $false -BackupSession $BackupSession -ControlId 'HOME-AV-004'
                Set-DefenderPreferenceWithBackup -PropertyName 'DisableIOAVProtection' -TargetValue $false -BackupSession $BackupSession -ControlId 'HOME-AV-004'
            }
        }

        'HOME-SYS-003' = [PSCustomObject]@{
            ControlId         = 'HOME-SYS-003'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enable Microsoft Defender SmartScreen for Explorer apps/files and Web Content Evaluation.'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'' -Name ''SmartScreenEnabled'' -Value ''Warn'' -PropertyType String -Force',
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'' -Name ''EnableWebContentEvaluation'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer' -Name 'SmartScreenEnabled' -Value 'Warn' -PropertyType 'String' -BackupSession $BackupSession -ControlId 'HOME-SYS-003'
                Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost' -Name 'EnableWebContentEvaluation' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-SYS-003'
            }
        }

        'HOME-SYS-005' = [PSCustomObject]@{
            ControlId         = 'HOME-SYS-005'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Restrict anonymous enumeration of SAM accounts (RestrictAnonymousSAM = 1).'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'' -Name ''RestrictAnonymousSAM'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RestrictAnonymousSAM' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-SYS-005'
            }
        }

        'HOME-SYS-006' = [PSCustomObject]@{
            ControlId         = 'HOME-SYS-006'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Disable WDigest cleartext credential caching in memory (UseLogonCredential = 0).'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'' -Name ''UseLogonCredential'' -Value 0 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name 'UseLogonCredential' -Value 0 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-SYS-006'
            }
        }

        'HOME-SYS-008' = [PSCustomObject]@{
            ControlId         = 'HOME-SYS-008'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Stop and disable the Remote Registry service (RemoteRegistry Start = 4).'
            PreviewCommands   = @(
                'Stop-Service -Name ''RemoteRegistry'' -Force -ErrorAction SilentlyContinue',
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry'' -Name ''Start'' -Value 4 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-ServiceStartupWithBackup -ServiceName 'RemoteRegistry' -TargetStart 4 -StopService -BackupSession $BackupSession -ControlId 'HOME-SYS-008'
            }
        }

        'HOME-SYS-009' = [PSCustomObject]@{
            ControlId         = 'HOME-SYS-009'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Disable Windows Script Host (WSH) execution of .vbs/.js scripts (Enabled = 0).'
            PreviewCommands   = @(
                'New-Item -Path ''HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'' -Force | Out-Null',
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'' -Name ''Enabled'' -Value 0 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings' -Name 'Enabled' -Value 0 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-SYS-009'
            }
        }

        'HOME-SYS-010' = [PSCustomObject]@{
            ControlId         = 'HOME-SYS-010'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enforce PrintNightmare administrator-only printer driver installation (RestrictDriverInstallationToAdministrators = 1).'
            PreviewCommands   = @(
                'New-Item -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'' -Force | Out-Null',
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'' -Name ''RestrictDriverInstallationToAdministrators'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint' -Name 'RestrictDriverInstallationToAdministrators' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-SYS-010'
            }
        }

        'HOME-NET-005' = [PSCustomObject]@{
            ControlId         = 'HOME-NET-005'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enforce mandatory SMB digital signing on both SMB Server and SMB Client.'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'' -Name ''RequireSecuritySignature'' -Value 1 -PropertyType DWord -Force',
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'' -Name ''RequireSecuritySignature'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'RequireSecuritySignature' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-NET-005'
                Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name 'RequireSecuritySignature' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-NET-005'
            }
        }

        'HOME-NET-008' = [PSCustomObject]@{
            ControlId         = 'HOME-NET-008'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Disable legacy TLS 1.0/1.1 protocols in SCHANNEL and enable automatic DNS over HTTPS (EnableAutoDoh = 2).'
            PreviewCommands   = @(
                'foreach ($sub in ''TLS 1.0\Client'',''TLS 1.0\Server'',''TLS 1.1\Client'',''TLS 1.1\Server'') { $p = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\$sub"; New-Item -Path $p -Force | Out-Null; New-ItemProperty -LiteralPath $p -Name Enabled -Value 0 -PropertyType DWord -Force; New-ItemProperty -LiteralPath $p -Name DisabledByDefault -Value 1 -PropertyType DWord -Force }',
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'' -Name ''EnableAutoDoh'' -Value 2 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                $schannelBase = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
                foreach ($sub in @('TLS 1.0\Client', 'TLS 1.0\Server', 'TLS 1.1\Client', 'TLS 1.1\Server')) {
                    $subPath = "$schannelBase\$sub"
                    Set-RegistryValueWithBackup -Path $subPath -Name 'Enabled' -Value 0 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-NET-008'
                    Set-RegistryValueWithBackup -Path $subPath -Name 'DisabledByDefault' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-NET-008'
                }
                Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters' -Name 'EnableAutoDoh' -Value 2 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-NET-008'
            }
        }

        'HOME-SEC-009' = [PSCustomObject]@{
            ControlId         = 'HOME-SEC-009'
            FixMode           = 'AutoSafe'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Replace insecure Unrestricted/Bypass ExecutionPolicy scopes with RemoteSigned.'
            PreviewCommands   = @(
                'Set-ExecutionPolicy -Scope LocalMachine -ExecutionPolicy RemoteSigned -Force',
                'Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                $policies = @(Get-ExecutionPolicy -List -ErrorAction Stop)
                $policyMap = @{}
                foreach ($entry in $policies) {
                    $policyMap[[string]$entry.Scope] = [string]$entry.ExecutionPolicy
                }

                foreach ($gpoScope in @('MachinePolicy', 'UserPolicy')) {
                    if ($policyMap.ContainsKey($gpoScope) -and $policyMap[$gpoScope] -in @('Unrestricted', 'Bypass')) {
                        throw "ExecutionPolicy scope '$gpoScope=$($policyMap[$gpoScope])' is enforced by Group Policy and cannot be overridden locally."
                    }
                }

                $updatedAny = $false
                foreach ($targetScope in @('LocalMachine', 'CurrentUser')) {
                    if ($policyMap.ContainsKey($targetScope) -and $policyMap[$targetScope] -in @('Unrestricted', 'Bypass')) {
                        Set-ExecutionPolicyWithBackup -Scope $targetScope -ExecutionPolicy 'RemoteSigned' -BackupSession $BackupSession -ControlId 'HOME-SEC-009'
                        $updatedAny = $true
                    }
                }

                if (-not $updatedAny) {
                    Set-ExecutionPolicyWithBackup -Scope 'LocalMachine' -ExecutionPolicy 'RemoteSigned' -BackupSession $BackupSession -ControlId 'HOME-SEC-009'
                }
            }
        }

        # === TIER 2 AUTOREBOOT / GUARDRAIL CONTROLS (PHASE 3 - 11 CONTROLS) ===
        'HOME-SEC-002' = [PSCustomObject]@{
            ControlId         = 'HOME-SEC-002'
            FixMode           = 'AutoReboot'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $true
            RollbackSupported = $true
            Summary           = 'Enable Local Security Authority (LSA) Protection (RunAsPPL = 1). Requires reboot.'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'' -Name ''RunAsPPL'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'RunAsPPL' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-SEC-002'
            }
        }

        'HOME-SEC-006' = [PSCustomObject]@{
            ControlId         = 'HOME-SEC-006'
            FixMode           = 'AutoReboot'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $true
            RollbackSupported = $true
            Summary           = 'Enable Microsoft Vulnerable Driver Blocklist against BYOVD attacks. Requires reboot.'
            PreviewCommands   = @(
                'New-Item -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'' -Force | Out-Null',
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config'' -Name ''VulnerableDriverBlocklistEnable'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' -Name 'VulnerableDriverBlocklistEnable' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-SEC-006'
            }
        }

        'HOME-NET-001' = [PSCustomObject]@{
            ControlId         = 'HOME-NET-001'
            FixMode           = 'AutoReboot'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $true
            RollbackSupported = $true
            Summary           = 'Disable legacy SMBv1 protocol and optional feature. Requires reboot.'
            PreviewCommands   = @(
                'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force',
                'Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name 'SMB1' -Value 0 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-NET-001'
                Disable-OptionalFeatureWithBackup -FeatureName 'SMB1Protocol' -BackupSession $BackupSession -ControlId 'HOME-NET-001'
                if ($null -ne (Get-Command -Name 'Set-SmbServerConfiguration' -ErrorAction SilentlyContinue)) {
                    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force -ErrorAction SilentlyContinue
                }
            }
        }

        'HOME-SYS-004' = [PSCustomObject]@{
            ControlId         = 'HOME-SYS-004'
            FixMode           = 'AutoReboot'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $true
            RollbackSupported = $true
            Summary           = 'Enable Core Isolation / Memory Integrity (HVCI = 1). Guarded by hardware VBS check; requires reboot.'
            PreviewCommands   = @(
                'New-Item -Path ''HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'' -Force | Out-Null',
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'' -Name ''Enabled'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name 'Enabled' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-SYS-004'
            }
        }

        'HOME-AV-009' = [PSCustomObject]@{
            ControlId         = 'HOME-AV-009'
            FixMode           = 'AutoReboot'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enable Controlled Folder Access ransomware protection (verify third-party app access).'
            PreviewCommands   = @(
                'Set-MpPreference -EnableControlledFolderAccess Enabled'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-DefenderPreferenceWithBackup -PropertyName 'EnableControlledFolderAccess' -TargetValue 'Enabled' -BackupSession $BackupSession -ControlId 'HOME-AV-009'
            }
        }

        'HOME-AV-011' = [PSCustomObject]@{
            ControlId         = 'HOME-AV-011'
            FixMode           = 'AutoReboot'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Enable core Attack Surface Reduction (ASR) rules blocking LSASS credential theft and obfuscated scripts.'
            PreviewCommands   = @(
                'Add-MpPreference -AttackSurfaceReductionRules_Ids ''9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'',''5beb7efe-fd9a-4556-801d-275e5ffc04cc'' -AttackSurfaceReductionRules_Actions Enabled,Enabled'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-DefenderAsrRulesWithBackup `
                    -RuleIds @('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', '5beb7efe-fd9a-4556-801d-275e5ffc04cc') `
                    -Actions @('Enabled', 'Enabled') `
                    -BackupSession $BackupSession `
                    -ControlId 'HOME-AV-011'
            }
        }

        'HOME-RDP-001' = [PSCustomObject]@{
            ControlId         = 'HOME-RDP-001'
            FixMode           = 'AutoReboot'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Disable Remote Desktop connections (fDenyTSConnections = 1). Guarded against locking out active RDP sessions.'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'' -Name ''fDenyTSConnections'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-RDP-001'
            }
        }

        'HOME-NET-006' = [PSCustomObject]@{
            ControlId         = 'HOME-NET-006'
            FixMode           = 'AutoReboot'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Stop and disable WinRM service (ports 5985/5986). Guarded against interrupting active WinRM remote sessions.'
            PreviewCommands   = @(
                'Stop-Service -Name ''WinRM'' -Force',
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Services\WinRM'' -Name ''Start'' -Value 4 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-ServiceStartupWithBackup -ServiceName 'WinRM' -TargetStart 4 -StopService -BackupSession $BackupSession -ControlId 'HOME-NET-006'
            }
        }

        'HOME-UAC-004' = [PSCustomObject]@{
            ControlId         = 'HOME-UAC-004'
            FixMode           = 'AutoReboot'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $true
            RollbackSupported = $true
            Summary           = 'Enable Windows 11 24H2/25H2+ just-in-time Administrator Protection (TypeOfAdminApprovalMode = 2). Requires reboot.'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'' -Name ''TypeOfAdminApprovalMode'' -Value 2 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'TypeOfAdminApprovalMode' -Value 2 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-UAC-004'
            }
        }

        'HOME-SEC-011' = [PSCustomObject]@{
            ControlId         = 'HOME-SEC-011'
            FixMode           = 'AutoReboot'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $true
            RollbackSupported = $true
            Summary           = 'Remove insecure Kernel DMA Protection override (DeviceEnumerationPolicy = 1). Hardware IOMMU must also be enabled in BIOS.'
            PreviewCommands   = @(
                'New-Item -Path ''HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'' -Force | Out-Null',
                'New-ItemProperty -LiteralPath ''HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'' -Name ''DeviceEnumerationPolicy'' -Value 1 -PropertyType DWord -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-RegistryValueWithBackup -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection' -Name 'DeviceEnumerationPolicy' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-SEC-011'
                $dmaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity'
                if (Test-Path -LiteralPath $dmaKey) {
                    $dmaProps = Get-ItemProperty -LiteralPath $dmaKey -ErrorAction SilentlyContinue
                    if ($null -ne $dmaProps -and $null -ne $dmaProps.PSObject.Properties['DeviceEnumerationPolicy'] -and [int]$dmaProps.DeviceEnumerationPolicy -eq 2) {
                        Set-RegistryValueWithBackup -Path $dmaKey -Name 'DeviceEnumerationPolicy' -Value 1 -PropertyType 'DWord' -BackupSession $BackupSession -ControlId 'HOME-SEC-011'
                    }
                }
            }
        }

        'HOME-SEC-010' = [PSCustomObject]@{
            ControlId         = 'HOME-SEC-010'
            FixMode           = 'AutoReboot'
            Phase             = 3
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Restore EventLog service Automatic startup (Start = 2) and start the service (historical Event 1102 alerts remain audit evidence).'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Services\EventLog'' -Name ''Start'' -Value 2 -PropertyType DWord -Force',
                'Start-Service -Name ''EventLog'''
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Set-ServiceStartupWithBackup -ServiceName 'EventLog' -TargetStart 2 -StartService -BackupSession $BackupSession -ControlId 'HOME-SEC-010'
            }
        }

        # === TIER 3 EVIDENCE-DRIVEN DYNAMIC CONTROLS (PHASE 4 - 3 GUIDED CONTROLS) ===
        'HOME-NET-009' = [PSCustomObject]@{
            ControlId         = 'HOME-NET-009'
            FixMode           = 'Guided'
            Phase             = 4
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Switch detected insecure Wi-Fi profiles from AutoConnect to manual connection mode using scan Evidence.'
            PreviewCommands   = @(
                'netsh.exe wlan set profileparameter name="<InsecureSSID>" connectionmode=manual'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                $ev = if ($null -ne $Context -and $null -ne $Context.PSObject.Properties['Evidence']) { $Context.Evidence } else { $null }
                $profiles = @()
                if ($ev -is [hashtable] -and $ev.ContainsKey('InsecureProfiles')) {
                    $profiles = @($ev['InsecureProfiles'])
                }
                elseif ($null -ne $ev -and $null -ne $ev.PSObject.Properties['InsecureProfiles']) {
                    $profiles = @($ev.InsecureProfiles)
                }

                $ssids = @()
                foreach ($p in $profiles) {
                    if ($null -eq $p) { continue }
                    $ssid = ''
                    if ($p -is [string]) {
                        $ssid = $p
                    }
                    elseif ($p -is [hashtable]) {
                        if ($p.ContainsKey('ProfileName')) { $ssid = [string]$p['ProfileName'] }
                        elseif ($p.ContainsKey('Name')) { $ssid = [string]$p['Name'] }
                        elseif ($p.ContainsKey('SSID')) { $ssid = [string]$p['SSID'] }
                    }
                    elseif ($null -ne $p.PSObject.Properties['ProfileName'] -and -not [string]::IsNullOrWhiteSpace([string]$p.ProfileName)) {
                        $ssid = [string]$p.ProfileName
                    }
                    elseif ($null -ne $p.PSObject.Properties['Name'] -and -not [string]::IsNullOrWhiteSpace([string]$p.Name)) {
                        $ssid = [string]$p.Name
                    }
                    elseif ($null -ne $p.PSObject.Properties['SSID'] -and -not [string]::IsNullOrWhiteSpace([string]$p.SSID)) {
                        $ssid = [string]$p.SSID
                    }

                    $trimmedSsid = $ssid.Trim()
                    if ($trimmedSsid -ne '' -and ($ssids -notcontains $trimmedSsid)) {
                        $ssids += $trimmedSsid
                    }
                }

                if ($ssids.Count -eq 0) {
                    throw 'No insecure AutoConnect Wi-Fi profile names found in scan Evidence.'
                }

                foreach ($ssidName in $ssids) {
                    Set-WifiProfileManualWithBackup -ProfileName $ssidName -BackupSession $BackupSession -ControlId 'HOME-NET-009'
                }
            }
        }

        'HOME-ACC-002' = [PSCustomObject]@{
            ControlId         = 'HOME-ACC-002'
            FixMode           = 'Guided'
            Phase             = 4
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Disable the built-in local Administrator account (SID -500) only after verifying another enabled local admin exists.'
            PreviewCommands   = @(
                'Get-LocalUser | Where-Object { $_.SID.Value -like ''*-500'' } | Disable-LocalUser'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                Disable-LocalUserWithBackup -SidSuffix '-500' -BackupSession $BackupSession -ControlId 'HOME-ACC-002'
            }
        }

        'HOME-FIL-009' = [PSCustomObject]@{
            ControlId         = 'HOME-FIL-009'
            FixMode           = 'Guided'
            Phase             = 4
            RequiresAdmin     = $true
            RequiresReboot    = $false
            RollbackSupported = $true
            Summary           = 'Quote unquoted third-party Windows service executable paths reported in scan Evidence while keeping arguments outside quotes.'
            PreviewCommands   = @(
                'New-ItemProperty -LiteralPath ''HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName>'' -Name ''ImagePath'' -Value ''"C:\Program Files\...\service.exe" -args'' -PropertyType ExpandString -Force'
            )
            SettingsUri       = $null
            Apply             = {
                param($BackupSession, $Context)
                $ev = if ($null -ne $Context -and $null -ne $Context.PSObject.Properties['Evidence']) { $Context.Evidence } else { $null }
                $vulnList = @()
                if ($ev -is [hashtable] -and $ev.ContainsKey('VulnerableServices')) {
                    $vulnList = @($ev['VulnerableServices'])
                }
                elseif ($null -ne $ev -and $null -ne $ev.PSObject.Properties['VulnerableServices']) {
                    $vulnList = @($ev.VulnerableServices)
                }

                if ($vulnList.Count -eq 0) {
                    throw 'No vulnerable unquoted service entries found in scan Evidence.'
                }

                $fixedAny = $false
                foreach ($entry in $vulnList) {
                    $svcName = ''
                    $rawPath = ''

                    if ($entry -is [string]) {
                        if ($entry -match '^([^\s(]+)\s*\((.+)\)$') {
                            $svcName = $Matches[1].Trim()
                            $rawPath = $Matches[2].Trim()
                        }
                    }
                    elseif ($null -ne $entry) {
                        if ($entry -is [hashtable]) {
                            $svcName = [string]$entry['Name']
                            $rawPath = [string]$entry['PathName']
                        }
                        else {
                            if ($null -ne $entry.PSObject.Properties['Name']) { $svcName = [string]$entry.Name }
                            if ($null -ne $entry.PSObject.Properties['PathName']) { $rawPath = [string]$entry.PathName }
                        }
                    }

                    if ([string]::IsNullOrWhiteSpace($svcName) -or ($svcName -notmatch '^[A-Za-z0-9_\-\.\s]+$')) {
                        continue
                    }

                    $quotedPath = ConvertTo-QuotedServicePath -PathName $rawPath
                    if ([string]::IsNullOrWhiteSpace($quotedPath)) {
                        continue
                    }

                    $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName"
                    $snap = Backup-RegistryValueState -Path $svcRegPath -Name 'ImagePath'
                    $propType = if ($snap.ValueExisted -and (-not [string]::IsNullOrWhiteSpace([string]$snap.ValueType))) {
                        [string]$snap.ValueType
                    }
                    else {
                        'ExpandString'
                    }

                    Set-RegistryValueWithBackup -Path $svcRegPath -Name 'ImagePath' -Value $quotedPath -PropertyType $propType -BackupSession $BackupSession -ControlId 'HOME-FIL-009'
                    $fixedAny = $true
                }

                if (-not $fixedAny) {
                    throw 'No unquoted service paths matched safe executable quoting rules.'
                }
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

function Get-AutoRebootControlIds {
    <#
    .SYNOPSIS
        Returns all Control IDs currently registered with FixMode = 'AutoReboot'.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $catalog = Get-RemediationCatalog
    $ids = @()
    foreach ($entry in $catalog.Values) {
        if ($entry.FixMode -eq 'AutoReboot') {
            $ids += [string]$entry.ControlId
        }
    }

    return @($ids)
}

function Get-GuidedControlIds {
    <#
    .SYNOPSIS
        Returns all Control IDs currently registered with FixMode = 'Guided'.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    $catalog = Get-RemediationCatalog
    $ids = @()
    foreach ($entry in $catalog.Values) {
        if ($entry.FixMode -eq 'Guided') {
            $ids += [string]$entry.ControlId
        }
    }

    return @($ids)
}
