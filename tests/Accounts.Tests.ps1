<#
.SYNOPSIS
    Pester 5 tests for local account checks (Accounts.ps1):
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

    Context 'Guest disabled (passed)' {
        It 'Returns superato when Guest is disabled' {
            Mock Get-LocalUser {
                return @(
                    [PSCustomObject]@{
                        Name    = 'Guest'
                        SID     = [PSCustomObject]@{ Value = 'S-1-5-21-1234567890-1234567890-1234567890-501' }
                        Enabled = $false
                    }
                    [PSCustomObject]@{
                        Name    = 'User1'
                        SID     = [PSCustomObject]@{ Value = 'S-1-5-21-1234567890-1234567890-1234567890-1001' }
                        Enabled = $true
                    }
                )
            }

            $risultato = Test-GuestAccount -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'superato'
        }
    }

    Context 'Guest enabled (failed)' {
        It 'Returns fallito when Guest is enabled' {
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
            $risultato.Observed | Should -Match 'enabled'
        }
    }

    Context 'Account not found (unknown)' {
        It 'Returns sconosciuto when no SID -501 exists' {
            Mock Get-LocalUser {
                return @(
                    [PSCustomObject]@{
                        Name    = 'User1'
                        SID     = [PSCustomObject]@{ Value = 'S-1-5-21-1234567890-1234567890-1234567890-1001' }
                        Enabled = $true
                    }
                )
            }

            $risultato = Test-GuestAccount -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'sconosciuto'
        }
    }

    Context 'Cmdlet unavailable (fallback & unknown)' {
        It 'Returns sconosciuto when Get-LocalUser is not recognized and fallback returns empty' {
            Mock Get-LocalUser {
                throw [System.Management.Automation.CommandNotFoundException]::new(
                    "The term 'Get-LocalUser' is not recognized as the name of a cmdlet."
                )
            }
            Mock Test-FallbackUtentiLocali { return @() }

            $risultato = Test-GuestAccount -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'sconosciuto'
        }

        It 'Uses Test-FallbackUtentiLocali and returns superato when Get-LocalUser is unavailable' {
            Mock Get-LocalUser {
                throw [System.Management.Automation.CommandNotFoundException]::new(
                    "The term 'Get-LocalUser' is not recognized as the name of a cmdlet."
                )
            }
            Mock Test-FallbackUtentiLocali {
                return @(
                    [PSCustomObject]@{
                        Name    = 'Guest'
                        SID     = [PSCustomObject]@{ Value = 'S-1-5-21-1234567890-1234567890-1234567890-501' }
                        Enabled = $false
                    }
                )
            }

            $risultato = Test-GuestAccount -Controllo $controlloFittizio -Ambiente $ambienteFittizio
            $risultato.Status | Should -Be 'superato'
        }
    }

    Context 'Unexpected exception (error)' {
        It 'Returns errore for unhandled exceptions' {
            Mock Get-LocalUser {
                throw [System.InvalidOperationException]::new("Unexpected module error")
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

    It 'Returns superato when built-in Administrator (-500) is disabled' {
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

    It 'Returns fallito when built-in Administrator (-500) is enabled' {
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

    It 'Returns sconosciuto when no account with SID -500 is found' {
        Mock Get-LocalUser { return @() }
        $res = Test-AdminAccount -Controllo $controlloAdmin -Ambiente $ambiente
        $res.Status | Should -Be 'sconosciuto'
    }

    It 'Uses Test-FallbackUtentiLocali and returns superato when Get-LocalUser is unavailable' {
        Mock Get-LocalUser {
            throw [System.Management.Automation.CommandNotFoundException]::new(
                "The term 'Get-LocalUser' is not recognized as the name of a cmdlet."
            )
        }
        Mock Test-FallbackUtentiLocali {
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
}

Describe 'Test-AccountsPasswordRequired (HOME-ACC-003)' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Accounts.ps1'
        . $percorsoModulo

        $controlloPwd = [PSCustomObject]@{ id = 'HOME-ACC-003' }
        $ambiente = [PSCustomObject]@{ Edition = 'Pro'; IsAdmin = $true }
    }

    It 'Returns superato when all active accounts require a password' {
        Mock Get-LocalUser {
            return @(
                [PSCustomObject]@{
                    Name             = 'SecureUser'
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

    It 'Returns fallito when an active local account has PasswordRequired = False' {
        Mock Get-LocalUser {
            return @(
                [PSCustomObject]@{
                    Name             = 'NoPasswordUser'
                    SID              = [PSCustomObject]@{ Value = 'S-1-5-21-111-1002' }
                    Enabled          = $true
                    PasswordRequired = $false
                }
            )
        }
        $res = Test-AccountsPasswordRequired -Controllo $controlloPwd -Ambiente $ambiente
        $res.Status   | Should -Be 'fallito'
        $res.Observed | Should -Match 'NoPasswordUser'
    }

    It 'Returns superato (no false positive) when PasswordRequired = False but PrincipalSource = MicrosoftAccount' {
        Mock Get-LocalUser {
            return @(
                [PSCustomObject]@{
                    Name             = 'MicrosoftHelloUser'
                    SID              = [PSCustomObject]@{ Value = 'S-1-5-21-111-1003' }
                    Enabled          = $true
                    PasswordRequired = $false
                    PrincipalSource  = 'MicrosoftAccount'
                }
            )
        }
        $res = Test-AccountsPasswordRequired -Controllo $controlloPwd -Ambiente $ambiente
        $res.Status   | Should -Be 'superato'
        $res.Observed | Should -Match 'MicrosoftHelloUser'
    }

    It 'Uses Test-FallbackUtentiLocali and returns superato when Get-LocalUser is unavailable' {
        Mock Get-LocalUser {
            throw [System.Management.Automation.CommandNotFoundException]::new(
                "The term 'Get-LocalUser' is not recognized as the name of a cmdlet."
            )
        }
        Mock Test-FallbackUtentiLocali {
            return @(
                [PSCustomObject]@{
                    Name             = 'MicrosoftHelloUser'
                    SID              = [PSCustomObject]@{ Value = 'S-1-5-21-111-1003' }
                    Enabled          = $true
                    PasswordRequired = $false
                    PrincipalSource  = 'MicrosoftAccount'
                }
            )
        }
        $res = Test-AccountsPasswordRequired -Controllo $controlloPwd -Ambiente $ambiente
        $res.Status   | Should -Be 'superato'
        $res.Observed | Should -Match 'MicrosoftHelloUser'
    }
}
