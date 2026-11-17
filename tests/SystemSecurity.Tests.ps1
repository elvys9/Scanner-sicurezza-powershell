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
}

Describe 'Copertura completa dei 18 controlli e script singolo stile winutil' {

    It 'Tutti i 18 controlli in catalog/home_profile.json hanno un check implementato (registry o command_ref)' {
        $percorsoJson = Join-Path $PSScriptRoot '..\catalog\home_profile.json'
        $cat = Get-Content -LiteralPath $percorsoJson -Raw -Encoding UTF8 | ConvertFrom-Json

        @($cat.controls).Count | Should -Be 18
        foreach ($c in $cat.controls) {
            $haReg = ($null -ne $c.check.PSObject.Properties['registry'] -and $null -ne $c.check.registry)
            $haCmd = ($null -ne $c.check.PSObject.Properties['command_ref'] -and (-not [string]::IsNullOrWhiteSpace($c.check.command_ref)))
            ($haReg -or $haCmd) | Should -Be $true -Because "Il controllo $($c.id) deve avere un check implementato"
        }
    }

    It 'Lo script autonomo dist/scanner-win11.ps1 esiste ed e salvato in UTF-8 con BOM' {
        $percorsoDist = Join-Path $PSScriptRoot '..\dist\scanner-win11.ps1'
        Test-Path -LiteralPath $percorsoDist | Should -Be $true

        $bytes = [System.IO.File]::ReadAllBytes($percorsoDist)
        $haBom = ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
        $haBom | Should -Be $true
    }
}
