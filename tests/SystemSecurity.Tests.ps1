<#
.SYNOPSIS
    Test Pester 5 per i controlli di sistema (SystemSecurity.ps1) e per il
    pacchetto autonomo stile winutil (dist/scanner-win11.ps1).
#>

Set-StrictMode -Version 2

Describe 'Controlli SystemSecurity (HOME-UPD-001, HOME-ENC-001, HOME-PRV-001, HOME-SEC-001..003)' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\SystemSecurity.ps1'
        . $percorsoModulo

        function Get-Tpm { }
        $controlloDummy = [PSCustomObject]@{ id = 'HOME-SYS-TEST' }
    }

    Context 'Test-WindowsUpdateEnabled (HOME-UPD-001)' {

        It 'Restituisce superato quando wuauserv ha Start != 4 e NoAutoUpdate != 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ Start = 3; NoAutoUpdate = 0 }
            }
            $res = Test-WindowsUpdateEnabled -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando il servizio wuauserv e disabilitato (Start = 4)' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ Start = 4 }
            }
            $res = Test-WindowsUpdateEnabled -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-TelemetryMinimum (HOME-PRV-001)' {

        It 'Restituisce superato quando AllowTelemetry <= 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ AllowTelemetry = 1 }
            }
            $res = Test-TelemetryMinimum -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando AllowTelemetry > 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ AllowTelemetry = 3 }
            }
            $res = Test-TelemetryMinimum -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-SecureBoot (HOME-SEC-001)' {

        It 'Restituisce superato quando UEFISecureBootEnabled = 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ UEFISecureBootEnabled = 1 }
            }
            $res = Test-SecureBoot -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando UEFISecureBootEnabled = 0' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ UEFISecureBootEnabled = 0 }
            }
            $res = Test-SecureBoot -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-LsaProtection (HOME-SEC-002)' {

        It 'Restituisce superato quando RunAsPPL >= 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ RunAsPPL = 2; RunAsPPLBoot = 2 }
            }
            $res = Test-LsaProtection -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando RunAsPPL e RunAsPPLBoot sono 0' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ RunAsPPL = 0; RunAsPPLBoot = 0 }
            }
            $res = Test-LsaProtection -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-PsScriptBlockLogging (HOME-SEC-003)' {

        It 'Restituisce superato quando EnableScriptBlockLogging = 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ EnableScriptBlockLogging = 1 }
            }
            $res = Test-PsScriptBlockLogging -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando la policy non esiste' {
            Mock Test-Path { return $false }
            $res = Test-PsScriptBlockLogging -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Nuovi controlli impostazioni di sistema Windows (HOME-SYS-001..005, HOME-UPD-002)' {

        It 'Test-FileExtensionsVisible: superato quando HideFileExt = 0' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty { return [PSCustomObject]@{ HideFileExt = 0 } }
            $res = Test-FileExtensionsVisible -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Test-FileExtensionsVisible: fallito quando HideFileExt = 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty { return [PSCustomObject]@{ HideFileExt = 1 } }
            $res = Test-FileExtensionsVisible -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
        }

        It 'Test-AutorunDisabled: superato quando DisableAutoplay = 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty { return [PSCustomObject]@{ DisableAutoplay = 1; NoDriveTypeAutoRun = 0 } }
            $res = Test-AutorunDisabled -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Test-SmartScreenEnabled: superato quando SmartScreenEnabled = Warn e EnableWebContentEvaluation = 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty { return [PSCustomObject]@{ SmartScreenEnabled = 'Warn'; EnableWebContentEvaluation = 1 } }
            $res = Test-SmartScreenEnabled -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Test-MemoryIntegrityEnabled: superato quando Win32_DeviceGuard riporta VBS=2 e SecurityServicesRunning contiene 2' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty { return [PSCustomObject]@{ Enabled = 1 } }
            Mock Get-CimInstance {
                return [PSCustomObject]@{
                    VirtualizationBasedSecurityStatus = 2
                    SecurityServicesRunning           = @(1, 2)
                }
            }
            $res = Test-MemoryIntegrityEnabled -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Test-MemoryIntegrityEnabled: fallito quando Win32_DeviceGuard riporta che HVCI non e in esecuzione nonostante Enabled = 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty { return [PSCustomObject]@{ Enabled = 1 } }
            Mock Get-CimInstance {
                return [PSCustomObject]@{
                    VirtualizationBasedSecurityStatus = 1
                    SecurityServicesRunning           = @()
                }
            }
            $res = Test-MemoryIntegrityEnabled -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
        }

        It 'Test-AnonymousSamRestricted: superato quando RestrictAnonymousSAM = 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty { return [PSCustomObject]@{ RestrictAnonymousSAM = 1 } }
            $res = Test-AnonymousSamRestricted -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Test-WindowsUpdateAuthenticServer: superato quando nessun WUServer esterno e impostato' {
            Mock Test-Path { return $false }
            $res = Test-WindowsUpdateAuthenticServer -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Test-UacSecureElevation (HOME-UAC-002): superato quando ConsentPromptBehaviorAdmin = 2 e PromptOnSecureDesktop = 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ ConsentPromptBehaviorAdmin = 2; PromptOnSecureDesktop = 1 }
            }
            $res = Test-UacSecureElevation -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Test-UacSecureElevation (HOME-UAC-002): fallito quando PromptOnSecureDesktop = 0' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ ConsentPromptBehaviorAdmin = 5; PromptOnSecureDesktop = 0 }
            }
            $res = Test-UacSecureElevation -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
        }

        It 'Test-SmartAppControl (HOME-SEC-007): superato quando VerifiedAndReputablePolicyState e 1 (Enforced) o 2 (Evaluation)' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty { return [PSCustomObject]@{ VerifiedAndReputablePolicyState = 1 } }
            $res1 = Test-SmartAppControl -Controllo $controlloDummy
            $res1.Status | Should -Be 'superato'

            Mock Get-ItemProperty { return [PSCustomObject]@{ VerifiedAndReputablePolicyState = 2 } }
            $res2 = Test-SmartAppControl -Controllo $controlloDummy
            $res2.Status | Should -Be 'superato'
        }

        It 'Test-SmartAppControl (HOME-SEC-007): fallito quando VerifiedAndReputablePolicyState = 0' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty { return [PSCustomObject]@{ VerifiedAndReputablePolicyState = 0 } }
            $res = Test-SmartAppControl -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
        }

        It 'Test-Tpm20Ready (HOME-SEC-008): superato quando TpmPresent = True e TpmReady = True' {
            Mock Get-Tpm {
                return [PSCustomObject]@{ TpmPresent = $true; TpmReady = $true }
            }
            $res = Test-Tpm20Ready -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Test-Tpm20Ready (HOME-SEC-008): fallito quando TpmReady = False' {
            Mock Get-Tpm {
                return [PSCustomObject]@{ TpmPresent = $true; TpmReady = $false }
            }
            $res = Test-Tpm20Ready -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
        }

        It 'Test-WshDisabled (HOME-SYS-009): superato quando Enabled = 0' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty { return [PSCustomObject]@{ Enabled = 0 } }
            $res = Test-WshDisabled -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Test-WshDisabled (HOME-SYS-009): fallito quando Enabled = 1' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty { return [PSCustomObject]@{ Enabled = 1 } }
            $res = Test-WshDisabled -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
        }

        It 'Test-PowerShellExecutionPolicySecure (HOME-SEC-009): superato quando gli scope sono RemoteSigned' {
            Mock Get-ExecutionPolicy {
                return @(
                    [PSCustomObject]@{ Scope = 'MachinePolicy'; ExecutionPolicy = 'Undefined' }
                    [PSCustomObject]@{ Scope = 'UserPolicy';    ExecutionPolicy = 'Undefined' }
                    [PSCustomObject]@{ Scope = 'Process';       ExecutionPolicy = 'Bypass' }
                    [PSCustomObject]@{ Scope = 'CurrentUser';   ExecutionPolicy = 'Undefined' }
                    [PSCustomObject]@{ Scope = 'LocalMachine';  ExecutionPolicy = 'RemoteSigned' }
                )
            }
            $res = Test-PowerShellExecutionPolicySecure -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Test-PowerShellExecutionPolicySecure (HOME-SEC-009): fallito quando LocalMachine o CurrentUser e Unrestricted o Bypass' {
            Mock Get-ExecutionPolicy {
                return @(
                    [PSCustomObject]@{ Scope = 'LocalMachine'; ExecutionPolicy = 'Unrestricted' }
                    [PSCustomObject]@{ Scope = 'CurrentUser';  ExecutionPolicy = 'Bypass' }
                )
            }
            $res = Test-PowerShellExecutionPolicySecure -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-AdministratorProtection (HOME-UAC-004)' {
        It 'Restituisce superato quando TypeOfAdminApprovalMode e impostato a 2 (just-in-time)' {
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ TypeOfAdminApprovalMode = 2 }
            }
            $res = Test-AdministratorProtection -Controllo $controlloDummy -Ambiente ([PSCustomObject]@{ Build = '26100.1' })
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando TypeOfAdminApprovalMode e 1 (legacy)' {
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ TypeOfAdminApprovalMode = 1 }
            }
            $res = Test-AdministratorProtection -Controllo $controlloDummy -Ambiente ([PSCustomObject]@{ Build = '26100.1' })
            $res.Status | Should -Be 'fallito'
        }

        It 'Restituisce fallito quando TypeOfAdminApprovalMode e assente su build 26100+' {
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ EnableLUA = 1 }
            }
            $res = Test-AdministratorProtection -Controllo $controlloDummy -Ambiente ([PSCustomObject]@{ Build = '26100.1' })
            $res.Status | Should -Be 'fallito'
        }

        It 'Restituisce sconosciuto quando TypeOfAdminApprovalMode e assente su build precedente a 26100' {
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ EnableLUA = 1 }
            }
            $res = Test-AdministratorProtection -Controllo $controlloDummy -Ambiente ([PSCustomObject]@{ Build = '22631.1' })
            $res.Status | Should -Be 'sconosciuto'
        }

        It 'Restituisce sconosciuto in caso di SecurityException' {
            Mock Get-ItemProperty {
                throw [System.Security.SecurityException]::new('Access is denied')
            }
            $res = Test-AdministratorProtection -Controllo $controlloDummy -Ambiente ([PSCustomObject]@{ Build = '26100.1' })
            $res.Status | Should -Be 'sconosciuto'
        }
    }

    Context 'Test-EventLogIntegrity (HOME-SEC-010)' {
        It 'Returns superato when EventLog service is running and no Event ID 1102 is found' {
            Mock Get-Service {
                return [PSCustomObject]@{ Name = 'EventLog'; Status = 'Running'; StartType = 'Automatic' }
            }
            Mock Get-WinEvent {
                throw [System.Exception]::new('No events were found that match the specified selection criteria.')
            }
            $res = Test-EventLogIntegrity -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
            $res.Evidence.Event1102Count | Should -Be 0
        }

        It 'Returns fallito when EventLog service is stopped or disabled' {
            Mock Get-Service {
                return [PSCustomObject]@{ Name = 'EventLog'; Status = 'Stopped'; StartType = 'Disabled' }
            }
            $res = Test-EventLogIntegrity -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
            $res.Observed | Should -Match 'EventLog'
        }

        It 'Returns fallito when Security log clearing Event ID 1102 is detected' {
            Mock Get-Service {
                return [PSCustomObject]@{ Name = 'EventLog'; Status = 'Running'; StartType = 'Automatic' }
            }
            Mock Get-WinEvent {
                return @(
                    [PSCustomObject]@{ Id = 1102; TimeCreated = (Get-Date).AddDays(-1) }
                )
            }
            $res = Test-EventLogIntegrity -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
            $res.Evidence.Event1102Count | Should -Be 1
            $res.Observed | Should -Match '1102'
        }

        It 'Returns sconosciuto when querying Security log fails with Access is denied' {
            Mock Get-Service {
                return [PSCustomObject]@{ Name = 'EventLog'; Status = 'Running'; StartType = 'Automatic' }
            }
            Mock Get-WinEvent {
                throw [System.UnauthorizedAccessException]::new('Attempted to perform an unauthorized operation.')
            }
            $res = Test-EventLogIntegrity -Controllo $controlloDummy
            $res.Status | Should -Be 'sconosciuto'
            $res.Observed | Should -Match 'Administrator privileges'
        }
    }

    Context 'Test-PrintNightmareProtection (HOME-SYS-010)' {
        It 'Returns superato when Print Spooler service is Disabled' {
            Mock Get-Service {
                return [PSCustomObject]@{ Name = 'Spooler'; Status = 'Stopped'; StartType = 'Disabled' }
            }
            $res = Test-PrintNightmareProtection -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
            $res.Observed | Should -Match 'disabled'
        }

        It 'Returns fallito when Spooler is running and RestrictDriverInstallationToAdministrators = 0' {
            Mock Get-Service {
                return [PSCustomObject]@{ Name = 'Spooler'; Status = 'Running'; StartType = 'Automatic' }
            }
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ RestrictDriverInstallationToAdministrators = 0 }
            }
            $res = Test-PrintNightmareProtection -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
            $res.Observed | Should -Match 'RestrictDriverInstallationToAdministrators = 0'
        }

        It 'Returns superato when Spooler is running and RestrictDriverInstallationToAdministrators = 1' {
            Mock Get-Service {
                return [PSCustomObject]@{ Name = 'Spooler'; Status = 'Running'; StartType = 'Automatic' }
            }
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ RestrictDriverInstallationToAdministrators = 1 }
            }
            $res = Test-PrintNightmareProtection -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Returns superato on Windows 11 default when PointAndPrint policy key is absent' {
            Mock Get-Service {
                return [PSCustomObject]@{ Name = 'Spooler'; Status = 'Running'; StartType = 'Automatic' }
            }
            Mock Test-Path { return $false }
            $res = Test-PrintNightmareProtection -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
            $res.Observed | Should -Match 'default'
        }
    }

    Context 'Test-KernelDmaProtection (HOME-SEC-011)' {
        It 'Returns superato when Win32_DeviceGuard AvailableSecurityProperties contains 3' {
            Mock Test-Path { return $false }
            Mock Get-CimInstance {
                return [PSCustomObject]@{ AvailableSecurityProperties = @(1, 2, 3) }
            }
            $res = Test-KernelDmaProtection -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Returns sconosciuto when hardware or VM does not expose DMA Protection' {
            Mock Test-Path { return $false }
            Mock Get-CimInstance {
                return [PSCustomObject]@{ AvailableSecurityProperties = @(1, 2) }
            }
            $res = Test-KernelDmaProtection -Controllo $controlloDummy
            $res.Status | Should -Be 'sconosciuto'
            $res.Observed | Should -Match 'not supported'
        }

        It 'Returns fallito when DeviceEnumerationPolicy is explicitly set to 2' {
            Mock Test-Path { return $true } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
            }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ DeviceEnumerationPolicy = 2 }
            } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
            }
            $res = Test-KernelDmaProtection -Controllo $controlloDummy
            $res.Status | Should -Be 'fallito'
            $res.Observed | Should -Match 'DeviceEnumerationPolicy = 2'
        }
    }
}

Describe 'Copertura completa dei 64 controlli e script singolo stile winutil' {

    It 'Tutti i 64 controlli in catalog/home_profile.json hanno un check implementato (registry o command_ref)' {
        $percorsoJson = Join-Path $PSScriptRoot '..\catalog\home_profile.json'
        $cat = Get-Content -LiteralPath $percorsoJson -Raw -Encoding UTF8 | ConvertFrom-Json

        @($cat.controls).Count | Should -Be 64
        foreach ($c in $cat.controls) {
            $haReg = ($null -ne $c.check.PSObject.Properties['registry'] -and $null -ne $c.check.registry)
            $haCmd = ($null -ne $c.check.PSObject.Properties['command_ref'] -and (-not [string]::IsNullOrWhiteSpace($c.check.command_ref)))
            ($haReg -or $haCmd) | Should -Be $true -Because "Il controllo $($c.id) deve avere un check implementato"
        }
    }

    It 'Lo script autonomo dist/scanner-win11.ps1 esiste ed e compatibile con Invoke-Expression (irm | iex)' {
        $percorsoDist = Join-Path $PSScriptRoot '..\dist\scanner-win11.ps1'
        Test-Path -LiteralPath $percorsoDist | Should -Be $true

        $bytes = [System.IO.File]::ReadAllBytes($percorsoDist)
        $haBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
        $haBom | Should -Be $false -Because "Per funzionare con irm | iex non deve avere il carattere BOM iniziale"

        $testo = [System.IO.File]::ReadAllText($percorsoDist)
        $erroriParse = $null
        [void][System.Management.Automation.Language.Parser]::ParseInput($testo, [ref]$null, [ref]$erroriParse)
        @($erroriParse).Count | Should -Be 0
    }
}
