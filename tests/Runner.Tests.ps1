<#
.SYNOPSIS
    Pester 5 tests for the Runner module.
#>

Set-StrictMode -Version 2

Describe 'Invoke-Controlli' {

    BeforeAll {
        $percorsoCore = Join-Path $PSScriptRoot '..\src\core'
        . (Join-Path $percorsoCore 'Catalog.ps1')
        . (Join-Path $percorsoCore 'Runner.ps1')
        . (Join-Path $percorsoCore 'Checks\Registry.ps1')
        . (Join-Path $percorsoCore 'Checks\Firewall.ps1')
        . (Join-Path $percorsoCore 'Checks\Accounts.ps1')

        $percorsoChecks = Join-Path $PSScriptRoot '..\src\core\Checks'
        $ambienteHome = [PSCustomObject]@{
            Edition   = 'Home'
            EditionId = 'Core'
            Build     = '22631.1234'
            Language  = 'en-US'
            IsAdmin   = $true
            PsVersion = '5.1.22621.1234'
        }
        $ambientePro = [PSCustomObject]@{
            Edition   = 'Pro'
            EditionId = 'Professional'
            Build     = '22631.1234'
            Language  = 'en-US'
            IsAdmin   = $true
            PsVersion = '5.1.22621.1234'
        }
    }

    Context 'Execution of core vertical slice controls' {

        It 'Executes three controls without fatal errors' {
            Mock Get-NetFirewallProfile {
                return @(
                    [PSCustomObject]@{ Name = 'Domain';  Enabled = $true }
                    [PSCustomObject]@{ Name = 'Private'; Enabled = $true }
                    [PSCustomObject]@{ Name = 'Public';  Enabled = $true }
                )
            }
            Mock Get-LocalUser {
                return @(
                    [PSCustomObject]@{
                        Name    = 'Guest'
                        SID     = [PSCustomObject]@{ Value = 'S-1-5-21-123-456-789-501' }
                        Enabled = $false
                    }
                )
            }
            Mock Test-Path { return $true } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ EnableLUA = 1 }
            } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -and $Name -eq 'EnableLUA'
            }

            $catalogo = [PSCustomObject]@{
                schema_version = '0.2'
                controls = @(
                    [PSCustomObject]@{
                        id = 'HOME-FW-001'
                        title = 'Firewall'
                        editions = @('Home', 'Pro')
                        check = [PSCustomObject]@{
                            command_ref = 'Firewall.ps1#Test-FirewallProfiles'
                        }
                    }
                    [PSCustomObject]@{
                        id = 'HOME-UAC-001'
                        title = 'UAC'
                        editions = @('Home', 'Pro')
                        check = [PSCustomObject]@{
                            registry = [PSCustomObject]@{
                                path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                                name = 'EnableLUA'
                                operator = 'eq'
                                value = 1
                            }
                        }
                    }
                    [PSCustomObject]@{
                        id = 'HOME-ACC-001'
                        title = 'Guest'
                        editions = @('Home', 'Pro')
                        check = [PSCustomObject]@{
                            command_ref = 'Accounts.ps1#Test-GuestAccount'
                        }
                    }
                )
            }

            $risultati = Invoke-Controlli -Catalogo $catalogo -Ambiente $ambienteHome -CartellaChecks $percorsoChecks
            $risultati.Count | Should -Be 3
            foreach ($r in $risultati) {
                $r.status | Should -BeIn @('superato', 'fallito', 'sconosciuto', 'non_applicabile', 'errore')
            }
        }
    }

    Context 'Not applicable edition' {

        It 'Returns non_applicabile when edition is not covered' {
            $catalogo = [PSCustomObject]@{
                schema_version = '0.2'
                controls = @(
                    [PSCustomObject]@{
                        id = 'HOME-RDP-001'
                        title = 'RDP'
                        editions = @('Pro')
                        check = [PSCustomObject]@{
                            registry = [PSCustomObject]@{
                                path = 'HKLM:\SOFTWARE\Test'
                                name = 'Test'
                                operator = 'eq'
                                value = 1
                            }
                        }
                    }
                )
            }

            $risultati = Invoke-Controlli -Catalogo $catalogo -Ambiente $ambienteHome -CartellaChecks $percorsoChecks
            $risultati.Count | Should -Be 1
            $risultati[0].status | Should -Be 'non_applicabile'
        }
    }

    Context 'Error isolation' {

        It 'A throwing control does not halt subsequent controls' {
            Mock Get-NetFirewallProfile {
                throw [System.InvalidOperationException]::new("Simulated error")
            }
            Mock Get-LocalUser {
                return @(
                    [PSCustomObject]@{
                        Name    = 'Guest'
                        SID     = [PSCustomObject]@{ Value = 'S-1-5-21-123-456-789-501' }
                        Enabled = $false
                    }
                )
            }

            $catalogo = [PSCustomObject]@{
                schema_version = '0.2'
                controls = @(
                    [PSCustomObject]@{
                        id = 'HOME-FW-001'
                        title = 'Firewall'
                        editions = @('Home', 'Pro')
                        check = [PSCustomObject]@{
                            command_ref = 'Firewall.ps1#Test-FirewallProfiles'
                        }
                    }
                    [PSCustomObject]@{
                        id = 'HOME-ACC-001'
                        title = 'Guest'
                        editions = @('Home', 'Pro')
                        check = [PSCustomObject]@{
                            command_ref = 'Accounts.ps1#Test-GuestAccount'
                        }
                    }
                )
            }

            $risultati = Invoke-Controlli -Catalogo $catalogo -Ambiente $ambienteHome -CartellaChecks $percorsoChecks
            $risultati.Count | Should -Be 2
            $risultati[0].status | Should -Be 'errore'
            $risultati[1].status | Should -Be 'superato'
        }
    }

    Context 'ControlId filter' {

        It 'Executes only the specified control IDs' {
            Mock Get-LocalUser {
                return @(
                    [PSCustomObject]@{
                        Name    = 'Guest'
                        SID     = [PSCustomObject]@{ Value = 'S-1-5-21-123-456-789-501' }
                        Enabled = $false
                    }
                )
            }

            $catalogo = [PSCustomObject]@{
                schema_version = '0.2'
                controls = @(
                    [PSCustomObject]@{
                        id = 'HOME-FW-001'
                        title = 'Firewall'
                        editions = @('Home', 'Pro')
                        check = [PSCustomObject]@{
                            command_ref = 'Firewall.ps1#Test-FirewallProfiles'
                        }
                    }
                    [PSCustomObject]@{
                        id = 'HOME-ACC-001'
                        title = 'Guest'
                        editions = @('Home', 'Pro')
                        check = [PSCustomObject]@{
                            command_ref = 'Accounts.ps1#Test-GuestAccount'
                        }
                    }
                )
            }

            $risultati = Invoke-Controlli -Catalogo $catalogo -Ambiente $ambienteHome -CartellaChecks $percorsoChecks -ControlId @('HOME-ACC-001')
            $risultati.Count | Should -Be 1
            $risultati[0].control_id | Should -Be 'HOME-ACC-001'
        }
    }

    Context 'Unimplemented control' {

        It 'Returns sconosciuto for controls without a check definition' {
            $catalogo = [PSCustomObject]@{
                schema_version = '0.2'
                controls = @(
                    [PSCustomObject]@{
                        id = 'HOME-UPD-001'
                        title = 'Updates'
                        editions = @('Home', 'Pro')
                        check = [PSCustomObject]@{}
                    }
                )
            }

            $risultati = Invoke-Controlli -Catalogo $catalogo -Ambiente $ambienteHome -CartellaChecks $percorsoChecks
            $risultati.Count | Should -Be 1
            $risultati[0].status | Should -Be 'sconosciuto'
            $risultati[0].observed | Should -Match 'not yet implemented'
        }
    }
}
