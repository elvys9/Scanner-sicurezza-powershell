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

    Context 'Test-WmiEventSubscriptions (HOME-FIL-007)' {
        It 'Restituisce superato se e presente solo la sottoscrizione predefinita SCM Event Log Filter' {
            Mock Get-CimInstance {
                param($Namespace, $ClassName)
                switch ($ClassName) {
                    '__EventFilter' { return @([PSCustomObject]@{ Name = 'SCM Event Log Filter'; Query = 'SELECT * FROM MSFT_SCMEventLogEvent' }) }
                    'CommandLineEventConsumer' { return @() }
                    'ActiveScriptEventConsumer' { return @() }
                    '__FilterToConsumerBinding' { return @([PSCustomObject]@{ Filter = '__EventFilter.Name="SCM Event Log Filter"'; Consumer = 'NTEventLogEventConsumer.Name="SCM Event Log Consumer"' }) }
                }
            }
            $res = Test-WmiEventSubscriptions -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito se rileva un CommandLineEventConsumer sospetto' {
            Mock Get-CimInstance {
                param($Namespace, $ClassName)
                switch ($ClassName) {
                    '__EventFilter' { return @([PSCustomObject]@{ Name = 'EvilFilter'; Query = 'SELECT * FROM __InstanceCreationEvent' }) }
                    'CommandLineEventConsumer' { return @([PSCustomObject]@{ Name = 'EvilConsumer'; CommandLineTemplate = 'powershell.exe -enc AAAA' }) }
                    'ActiveScriptEventConsumer' { return @() }
                    '__FilterToConsumerBinding' { return @([PSCustomObject]@{ Filter = '__EventFilter.Name="EvilFilter"'; Consumer = 'CommandLineEventConsumer.Name="EvilConsumer"' }) }
                }
            }
            $res = Test-WmiEventSubscriptions -Controllo $controlloDummy
            $res.Status   | Should -Be 'fallito'
            $res.Observed | Should -Match 'EvilConsumer'
        }

        It 'Restituisce sconosciuto se Get-CimInstance solleva Access is denied' {
            Mock Get-CimInstance {
                throw [System.UnauthorizedAccessException]::new('Access is denied')
            }
            $res = Test-WmiEventSubscriptions -Controllo $controlloDummy
            $res.Status | Should -Be 'sconosciuto'
        }
    }

    Context 'Test-BrowserForcedExtensions (HOME-FIL-008)' {
        It 'Restituisce superato se nessuna chiave ExtensionInstallForcelist e presente' {
            Mock Test-Path { return $false }
            $res = Test-BrowserForcedExtensions -Controllo $controlloDummy
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito se rileva una estensione forzata in ExtensionInstallForcelist' {
            Mock Test-Path {
                param($LiteralPath)
                return ($LiteralPath -eq 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist')
            }
            Mock Get-ItemProperty {
                return [PSCustomObject]@{
                    '1'        = 'abcdefghijklmnopabcdefghijklmnop;https://clients2.google.com/service/update2/crx'
                    PSPath     = 'Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist'
                    PSProvider = 'Registry'
                }
            }
            $res = Test-BrowserForcedExtensions -Controllo $controlloDummy
            $res.Status   | Should -Be 'fallito'
            $res.Observed | Should -Match 'abcdefghijklmnop'
        }

        It 'Restituisce sconosciuto in caso di SecurityException durante la lettura delle policy' {
            Mock Test-Path { return $true }
            Mock Get-ItemProperty {
                throw [System.Security.SecurityException]::new('Access is denied')
            }
            $res = Test-BrowserForcedExtensions -Controllo $controlloDummy
            $res.Status | Should -Be 'sconosciuto'
        }
    }
}
