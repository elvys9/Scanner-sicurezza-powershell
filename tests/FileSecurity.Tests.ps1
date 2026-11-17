<#
.SYNOPSIS
    Test Pester 5 per i controlli sui file sospetti, persistenza avvio e file hosts (FileSecurity.ps1):
    HOME-FIL-001, HOME-FIL-002, HOME-FIL-003.
#>

Set-StrictMode -Version 2

Describe 'Controlli FileSecurity (HOME-FIL-001, HOME-FIL-002, HOME-FIL-003)' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\FileSecurity.ps1'
        . $percorsoModulo

        $controlloDummy = [PSCustomObject]@{ id = 'HOME-FIL-TEST' }
    }

    Context 'Test-SuspiciousDoubleExtensionFiles (HOME-FIL-001)' {

        It 'Restituisce superato quando non ci sono file con doppia estensione sospetta' {
            $cartellaSicura = Join-Path $TestDrive 'CartellaSicura'
            [void][System.IO.Directory]::CreateDirectory($cartellaSicura)
            [System.IO.File]::WriteAllText((Join-Path $cartellaSicura 'documento.pdf'), 'ok')
            [System.IO.File]::WriteAllText((Join-Path $cartellaSicura 'immagine.png'), 'ok')

            $res = Test-SuspiciousDoubleExtensionFiles -Controllo $controlloDummy -CartelleDaControllare @($cartellaSicura)
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando rileva un file camuffato con doppia estensione (es. fattura.pdf.exe)' {
            $cartellaInfetta = Join-Path $TestDrive 'CartellaInfetta'
            [void][System.IO.Directory]::CreateDirectory($cartellaInfetta)
            [System.IO.File]::WriteAllText((Join-Path $cartellaInfetta 'fattura_urgente.pdf.exe'), 'fake')

            $res = Test-SuspiciousDoubleExtensionFiles -Controllo $controlloDummy -CartelleDaControllare @($cartellaInfetta)
            $res.Status   | Should -Be 'fallito'
            $res.Observed | Should -Match 'fattura_urgente\.pdf\.exe'
        }
    }

    Context 'Test-StartupPersistenceEntries (HOME-FIL-002)' {

        It 'Restituisce superato quando le voci di avvio automatico sono normali' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{
                    OneDrive = '"C:\Program Files\Microsoft OneDrive\OneDrive.exe" /background'
                }
            }

            $res = Test-StartupPersistenceEntries -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando una voce Run usa powershell -enc o punta a Temp' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{
                    MalwareUpdater = 'powershell.exe -w hidden -enc SQBFAFgA'
                }
            }

            $res = Test-StartupPersistenceEntries -Controllo $controlloDummy
            $res.Status   | Should -Be 'fallito'
            $res.Observed | Should -Match 'MalwareUpdater'
        }
    }

    Context 'Test-HostsFileIntegrity (HOME-FIL-003)' {

        It 'Restituisce superato su un file hosts pulito' {
            $fileHostsPulito = Join-Path $TestDrive 'hosts_pulito'
            $testoPulito = @"
# Commento standard Microsoft
127.0.0.1       localhost
::1             localhost
"@
            [System.IO.File]::WriteAllText($fileHostsPulito, $testoPulito)

            $res = Test-HostsFileIntegrity -Controllo $controlloDummy -PercorsoHosts $fileHostsPulito
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito se il file hosts dirotta domini di sicurezza o Windows Update' {
            $fileHostsManomesso = Join-Path $TestDrive 'hosts_manomesso'
            $testoManomesso = @"
127.0.0.1       localhost
0.0.0.0         www.virustotal.com
127.0.0.1       update.microsoft.com
"@
            [System.IO.File]::WriteAllText($fileHostsManomesso, $testoManomesso)

            $res = Test-HostsFileIntegrity -Controllo $controlloDummy -PercorsoHosts $fileHostsManomesso
            $res.Status   | Should -Be 'fallito'
            $res.Observed | Should -Match 'virustotal\.com'
        }
    }
}
