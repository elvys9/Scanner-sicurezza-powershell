<#
.SYNOPSIS
    Test Pester 5 per il Runner.
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
            Language  = 'it-IT'
            IsAdmin   = $true
            PsVersion = '5.1.22621.1234'
        }
        $ambientePro = [PSCustomObject]@{
            Edition   = 'Pro'
            EditionId = 'Professional'
            Build     = '22631.1234'
            Language  = 'it-IT'
            IsAdmin   = $true
            PsVersion = '5.1.22621.1234'
        }
    }

    Context 'Esecuzione dei tre controlli della fetta' {

        It 'Esegue i tre controlli senza errori fatali' {
            # Mock per firewall
            Mock Get-NetFirewallProfile {
                return @(
                    [PSCustomObject]@{ Name = 'Domain';  Enabled = $true }
                    [PSCustomObject]@{ Name = 'Private'; Enabled = $true }
                    [PSCustomObject]@{ Name = 'Public';  Enabled = $true }
                )
            }
            # Mock per Guest
            Mock Get-LocalUser {
                return @(
                    [PSCustomObject]@{
                        Name    = 'Guest'
                        SID     = [PSCustomObject]@{ Value = 'S-1-5-21-123-456-789-501' }
                        Enabled = $false
                    }
                )
            }
            # Mock per UAC (registro reale con chiave di test)
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

    Context 'Edizione non applicabile' {

        It 'Restituisce non_applicabile per edizione non coperta' {
            $catalogo = [PSCustomObject]@{
                schema_version = '0.2'
                controls = @(
                    [PSCustomObject]@{
                        id = 'HOME-RDP-001'
                        title = 'RDP'
                        editions = @('Pro')  # Solo Pro
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

    Context 'Isolamento errori' {

        It 'Un controllo che lancia eccezione non ferma gli altri' {
            Mock Get-NetFirewallProfile {
                throw [System.InvalidOperationException]::new("Errore simulato")
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
            # Il primo controllo ha un errore, il secondo no
            $risultati.Count | Should -Be 2
            $risultati[0].status | Should -Be 'errore'
            $risultati[1].status | Should -Be 'superato'
        }
    }

    Context 'Filtro per ControlId' {

        It 'Esegue solo i controlli specificati' {
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

    Context 'Controllo non implementato' {

        It 'Restituisce sconosciuto per controlli senza check definito' {
            $catalogo = [PSCustomObject]@{
                schema_version = '0.2'
                controls = @(
                    [PSCustomObject]@{
                        id = 'HOME-UPD-001'
                        title = 'Aggiornamenti'
                        editions = @('Home', 'Pro')
                        check = [PSCustomObject]@{}  # Vuoto
                    }
                )
            }

            $risultati = Invoke-Controlli -Catalogo $catalogo -Ambiente $ambienteHome -CartellaChecks $percorsoChecks
            $risultati.Count | Should -Be 1
            $risultati[0].status | Should -Be 'sconosciuto'
            $risultati[0].observed | Should -Match 'non ancora implementato'
        }
    }
}
