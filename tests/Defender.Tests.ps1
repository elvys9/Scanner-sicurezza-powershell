<#
.SYNOPSIS
    Test Pester 5 per i controlli Windows Defender (Defender.ps1):
    HOME-AV-001 (Protezione in tempo reale) e HOME-AV-002 (Firme aggiornate).
#>

Set-StrictMode -Version 2

Describe 'Test-DefenderRealtime (HOME-AV-001)' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Defender.ps1'
        . $percorsoModulo

        function Get-MpComputerStatus { }
        $controllo = [PSCustomObject]@{ id = 'HOME-AV-001' }
    }

    It 'Restituisce superato quando AntivirusEnabled e RealTimeProtectionEnabled sono True' {
        Mock Get-MpComputerStatus {
            return [PSCustomObject]@{
                AntivirusEnabled          = $true
                RealTimeProtectionEnabled = $true
            }
        }
        $res = Test-DefenderRealtime -Controllo $controllo
        $res.Status | Should -Be 'superato'
    }

    It 'Restituisce fallito quando RealTimeProtectionEnabled e False' {
        Mock Get-MpComputerStatus {
            return [PSCustomObject]@{
                AntivirusEnabled          = $true
                RealTimeProtectionEnabled = $false
            }
        }
        $res = Test-DefenderRealtime -Controllo $controllo
        $res.Status | Should -Be 'fallito'
    }
}

Describe 'Test-DefenderSignatures (HOME-AV-002)' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Defender.ps1'
        . $percorsoModulo

        function Get-MpComputerStatus { }
        $controllo = [PSCustomObject]@{ id = 'HOME-AV-002' }
    }

    It 'Restituisce superato quando AntivirusSignatureAge e <= 7 giorni' {
        Mock Get-MpComputerStatus {
            return [PSCustomObject]@{ AntivirusSignatureAge = 2 }
        }
        $res = Test-DefenderSignatures -Controllo $controllo
        $res.Status | Should -Be 'superato'
    }

    It 'Restituisce fallito quando AntivirusSignatureAge e > 7 giorni' {
        Mock Get-MpComputerStatus {
            return [PSCustomObject]@{ AntivirusSignatureAge = 14 }
        }
        $res = Test-DefenderSignatures -Controllo $controllo
        $res.Status   | Should -Be 'fallito'
        $res.Observed | Should -Match '14 giorni'
    }
}
