<#
.SYNOPSIS
    Test Pester 5 per i controlli sugli account locali (Accounts.ps1):
    HOME-ACC-001 (Guest), HOME-ACC-002 (Administrator), HOME-ACC-003 (PasswordRequired).
#>

Set-StrictMode -Version 2

Describe 'Test-GuestAccount (HOME-ACC-001)' {

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

Describe 'Test-AdminAccount (HOME-ACC-002)' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Accounts.ps1'
        . $percorsoModulo

        $controlloAdmin = [PSCustomObject]@{ id = 'HOME-ACC-002' }
        $ambiente = [PSCustomObject]@{ Edition = 'Home'; IsAdmin = $true }
    }

    It 'Restituisce superato quando Administrator predefinito (-500) e disabilitato' {
        Mock Get-LocalUser {
            return @(
                [PSCustomObject]@{
                    Name    = 'Administrator'
                    SID     = [PSCustomObject]@{ Value = 'S-1-5-21-111-222-333-500' }
                    Enabled = $false
                }
            )
        }
        $res = Test-AdminAccount -Controllo $controlloAdmin -Ambiente $ambiente
        $res.Status | Should -Be 'superato'
    }

    It 'Restituisce fallito quando Administrator predefinito (-500) e abilitato' {
        Mock Get-LocalUser {
            return @(
                [PSCustomObject]@{
                    Name    = 'Administrator'
                    SID     = [PSCustomObject]@{ Value = 'S-1-5-21-111-222-333-500' }
                    Enabled = $true
                }
            )
        }
        $res = Test-AdminAccount -Controllo $controlloAdmin -Ambiente $ambiente
        $res.Status | Should -Be 'fallito'
    }

    It 'Restituisce sconosciuto se nessun account con SID -500 viene trovato' {
        Mock Get-LocalUser { return @() }
        $res = Test-AdminAccount -Controllo $controlloAdmin -Ambiente $ambiente
        $res.Status | Should -Be 'sconosciuto'
    }
}

Describe 'Test-AccountsPasswordRequired (HOME-ACC-003)' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Accounts.ps1'
        . $percorsoModulo

        $controlloPwd = [PSCustomObject]@{ id = 'HOME-ACC-003' }
        $ambiente = [PSCustomObject]@{ Edition = 'Pro'; IsAdmin = $true }
    }

    It 'Restituisce superato se tutti gli account attivi richiedono una password' {
        Mock Get-LocalUser {
            return @(
                [PSCustomObject]@{
                    Name             = 'UtenteSicuro'
                    SID              = [PSCustomObject]@{ Value = 'S-1-5-21-111-1001' }
                    Enabled          = $true
                    PasswordRequired = $true
                }
                [PSCustomObject]@{
                    Name             = 'Guest'
                    SID              = [PSCustomObject]@{ Value = 'S-1-5-21-111-501' }
                    Enabled          = $false
                    PasswordRequired = $false
                }
            )
        }
        $res = Test-AccountsPasswordRequired -Controllo $controlloPwd -Ambiente $ambiente
        $res.Status | Should -Be 'superato'
    }

    It 'Restituisce fallito se un account attivo ha PasswordRequired = False' {
        Mock Get-LocalUser {
            return @(
                [PSCustomObject]@{
                    Name             = 'UtenteSenzaPwd'
                    SID              = [PSCustomObject]@{ Value = 'S-1-5-21-111-1002' }
                    Enabled          = $true
                    PasswordRequired = $false
                }
            )
        }
        $res = Test-AccountsPasswordRequired -Controllo $controlloPwd -Ambiente $ambiente
        $res.Status   | Should -Be 'fallito'
        $res.Observed | Should -Match 'UtenteSenzaPwd'
    }
}
