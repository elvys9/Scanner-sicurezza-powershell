<#
.SYNOPSIS
    Test Pester 5 per il controllo Account Guest (Accounts.ps1).
#>

Set-StrictMode -Version 2

Describe 'Test-GuestAccount' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Accounts.ps1'
        . $percorsoModulo

        $controlloFittizio = [PSCustomObject]@{
            id = 'HOME-ACC-001'
            check = [PSCustomObject]@{
                command_ref = 'Accounts.ps1#Test-GuestAccount'
            }
        }
        $ambienteFittizio = [PSCustomObject]@{
            Edition = 'Home'
            IsAdmin = $true
        }
    }

    Context 'Guest disabilitato (superato)' {

        It 'Restituisce superato quando Guest e disabilitato' {
            Mock Get-LocalUser {
                return @(
                    [PSCustomObject]@{
                        Name    = 'Ospite'
                        SID     = [PSCustomObject]@{ Value = 'S-1-5-21-1234567890-1234567890-1234567890-501' }
                        Enabled = $false
                    }
                    [PSCustomObject]@{
                        Name    = 'Utente1'
                        SID     = [PSCustomObject]@{ Value = 'S-1-5-21-1234567890-1234567890-1234567890-1001' }
                        Enabled = $true
                    }
                )
            }

            $risultato = Test-GuestAccount -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'superato'
        }
    }

    Context 'Guest abilitato (fallito)' {

        It 'Restituisce fallito quando Guest e abilitato' {
            Mock Get-LocalUser {
                return @(
                    [PSCustomObject]@{
                        Name    = 'Guest'
                        SID     = [PSCustomObject]@{ Value = 'S-1-5-21-9999999999-9999999999-9999999999-501' }
                        Enabled = $true
                    }
                )
            }

            $risultato = Test-GuestAccount -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'fallito'
            $risultato.Observed | Should -Match 'abilitato'
        }
    }

    Context 'Account non trovato (sconosciuto)' {

        It 'Restituisce sconosciuto se nessun SID -501' {
            Mock Get-LocalUser {
                return @(
                    [PSCustomObject]@{
                        Name    = 'Utente1'
                        SID     = [PSCustomObject]@{ Value = 'S-1-5-21-1234567890-1234567890-1234567890-1001' }
                        Enabled = $true
                    }
                )
            }

            $risultato = Test-GuestAccount -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'sconosciuto'
        }
    }

    Context 'Cmdlet non disponibile (sconosciuto)' {

        It 'Restituisce sconosciuto se Get-LocalUser non esiste' {
            Mock Get-LocalUser {
                throw [System.Management.Automation.CommandNotFoundException]::new(
                    "Il termine 'Get-LocalUser' non e' riconosciuto."
                )
            }

            $risultato = Test-GuestAccount -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'sconosciuto'
        }
    }

    Context 'Eccezione generica (errore)' {

        It 'Restituisce errore per eccezioni non previste' {
            Mock Get-LocalUser {
                throw [System.InvalidOperationException]::new("Errore imprevisto nel modulo")
            }

            $risultato = Test-GuestAccount -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'errore'
            $risultato.Error | Should -Not -BeNullOrEmpty
        }
    }
}
