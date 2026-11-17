<#
.SYNOPSIS
    Test Pester 5 per il controllo Firewall (Firewall.ps1).
#>

Set-StrictMode -Version 2

Describe 'Test-FirewallProfiles' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Firewall.ps1'
        . $percorsoModulo

        $controlloFittizio = [PSCustomObject]@{
            id = 'HOME-FW-001'
            check = [PSCustomObject]@{
                command_ref = 'Firewall.ps1#Test-FirewallProfiles'
            }
        }
        $ambienteFittizio = [PSCustomObject]@{
            Edition = 'Home'
            IsAdmin = $true
        }
    }

    Context 'Tutti i profili attivi (superato)' {

        It 'Restituisce superato quando tutti i profili sono attivi' {
            Mock Get-NetFirewallProfile {
                return @(
                    [PSCustomObject]@{ Name = 'Domain';  Enabled = $true }
                    [PSCustomObject]@{ Name = 'Private'; Enabled = $true }
                    [PSCustomObject]@{ Name = 'Public';  Enabled = $true }
                )
            }

            $risultato = Test-FirewallProfiles -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'superato'
        }
    }

    Context 'Un profilo disattivo (fallito)' {

        It 'Restituisce fallito quando un profilo e disattivo' {
            Mock Get-NetFirewallProfile {
                return @(
                    [PSCustomObject]@{ Name = 'Domain';  Enabled = $true }
                    [PSCustomObject]@{ Name = 'Private'; Enabled = $true }
                    [PSCustomObject]@{ Name = 'Public';  Enabled = $false }
                )
            }

            $risultato = Test-FirewallProfiles -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'fallito'
            $risultato.Observed | Should -Match 'Public'
        }
    }

    Context 'Tutti i profili disattivi (fallito)' {

        It 'Restituisce fallito quando tutti i profili sono disattivi' {
            Mock Get-NetFirewallProfile {
                return @(
                    [PSCustomObject]@{ Name = 'Domain';  Enabled = $false }
                    [PSCustomObject]@{ Name = 'Private'; Enabled = $false }
                    [PSCustomObject]@{ Name = 'Public';  Enabled = $false }
                )
            }

            $risultato = Test-FirewallProfiles -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'fallito'
        }
    }

    Context 'Cmdlet non disponibile (sconosciuto)' {

        It 'Restituisce sconosciuto se Get-NetFirewallProfile non esiste' {
            Mock Get-NetFirewallProfile {
                throw [System.Management.Automation.CommandNotFoundException]::new(
                    "Il termine 'Get-NetFirewallProfile' non e' riconosciuto."
                )
            }

            $risultato = Test-FirewallProfiles -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'sconosciuto'
        }
    }

    Context 'Eccezione generica (errore)' {

        It 'Restituisce errore per eccezioni non previste' {
            Mock Get-NetFirewallProfile {
                throw [System.InvalidOperationException]::new("Errore imprevisto")
            }

            $risultato = Test-FirewallProfiles -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'errore'
            $risultato.Error | Should -Not -BeNullOrEmpty
        }
    }
}
