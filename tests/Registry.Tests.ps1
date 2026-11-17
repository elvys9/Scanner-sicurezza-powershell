<#
.SYNOPSIS
    Test Pester 5 per il valutatore generico di registro (Registry.ps1).
#>

Set-StrictMode -Version 2

Describe 'Test-RegistryValue' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Registry.ps1'
        . $percorsoModulo
    }

    Context 'Operatore eq - valore corretto (superato)' {

        It 'Restituisce superato quando il valore corrisponde' {
            # Simula una chiave di registro esistente
            Mock Test-Path { return $true } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test\Chiave'
            }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ ValoreTest = 1 }
            } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test\Chiave' -and $Name -eq 'ValoreTest'
            }

            $check = [PSCustomObject]@{
                path     = 'HKLM:\SOFTWARE\Test\Chiave'
                name     = 'ValoreTest'
                operator = 'eq'
                value    = 1
            }

            $risultato = Test-RegistryValue -RegistryCheck $check
            $risultato.Status | Should -Be 'superato'
        }
    }

    Context 'Operatore eq - valore errato (fallito)' {

        It 'Restituisce fallito quando il valore non corrisponde' {
            Mock Test-Path { return $true } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test\Chiave'
            }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ ValoreTest = 0 }
            } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test\Chiave' -and $Name -eq 'ValoreTest'
            }

            $check = [PSCustomObject]@{
                path     = 'HKLM:\SOFTWARE\Test\Chiave'
                name     = 'ValoreTest'
                operator = 'eq'
                value    = 1
            }

            $risultato = Test-RegistryValue -RegistryCheck $check
            $risultato.Status | Should -Be 'fallito'
        }
    }

    Context 'Operatore ge (superato)' {

        It 'Restituisce superato per ge quando il valore e maggiore o uguale' {
            Mock Test-Path { return $true } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test\Chiave'
            }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ ValoreTest = 5 }
            } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test\Chiave' -and $Name -eq 'ValoreTest'
            }

            $check = [PSCustomObject]@{
                path     = 'HKLM:\SOFTWARE\Test\Chiave'
                name     = 'ValoreTest'
                operator = 'ge'
                value    = 3
            }

            $risultato = Test-RegistryValue -RegistryCheck $check
            $risultato.Status | Should -Be 'superato'
        }
    }

    Context 'Operatore exists' {

        It 'Restituisce superato quando il valore esiste' {
            Mock Test-Path { return $true } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test\Chiave'
            }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{ ValoreTest = 'qualcosa' }
            } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test\Chiave' -and $Name -eq 'ValoreTest'
            }

            $check = [PSCustomObject]@{
                path     = 'HKLM:\SOFTWARE\Test\Chiave'
                name     = 'ValoreTest'
                operator = 'exists'
                value    = $null
            }

            $risultato = Test-RegistryValue -RegistryCheck $check
            $risultato.Status | Should -Be 'superato'
        }
    }

    Context 'Chiave non trovata (sconosciuto)' {

        It 'Restituisce sconosciuto se la chiave di registro non esiste' {
            Mock Test-Path { return $false } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Inesistente'
            }

            $check = [PSCustomObject]@{
                path     = 'HKLM:\SOFTWARE\Inesistente'
                name     = 'Valore'
                operator = 'eq'
                value    = 1
            }

            $risultato = Test-RegistryValue -RegistryCheck $check
            $risultato.Status | Should -Be 'sconosciuto'
        }
    }

    Context 'Valore non trovato nella chiave (sconosciuto)' {

        It 'Restituisce sconosciuto se il valore non esiste nella chiave' {
            Mock Test-Path { return $true } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test\Chiave'
            }
            Mock Get-ItemProperty {
                throw [System.Management.Automation.ItemNotFoundException]::new(
                    "Proprieta' non trovata"
                )
            } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test\Chiave' -and $Name -eq 'ValoreInesistente'
            }

            $check = [PSCustomObject]@{
                path     = 'HKLM:\SOFTWARE\Test\Chiave'
                name     = 'ValoreInesistente'
                operator = 'eq'
                value    = 1
            }

            $risultato = Test-RegistryValue -RegistryCheck $check
            $risultato.Status | Should -Be 'sconosciuto'
        }
    }

    Context 'Accesso negato (sconosciuto)' {

        It 'Restituisce sconosciuto per SecurityException' {
            Mock Test-Path { return $true } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test\Protetta'
            }
            Mock Get-ItemProperty {
                throw [System.Security.SecurityException]::new("Accesso negato")
            } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Test\Protetta' -and $Name -eq 'Valore'
            }

            $check = [PSCustomObject]@{
                path     = 'HKLM:\SOFTWARE\Test\Protetta'
                name     = 'Valore'
                operator = 'eq'
                value    = 1
            }

            $risultato = Test-RegistryValue -RegistryCheck $check
            $risultato.Status | Should -Be 'sconosciuto'
        }
    }

    Context 'Operatore notexists - chiave non presente (superato)' {

        It 'Restituisce superato per notexists se la chiave non esiste' {
            Mock Test-Path { return $false } -ParameterFilter {
                $LiteralPath -eq 'HKLM:\SOFTWARE\Rimossa'
            }

            $check = [PSCustomObject]@{
                path     = 'HKLM:\SOFTWARE\Rimossa'
                name     = 'Valore'
                operator = 'notexists'
                value    = $null
            }

            $risultato = Test-RegistryValue -RegistryCheck $check
            $risultato.Status | Should -Be 'superato'
        }
    }
}
