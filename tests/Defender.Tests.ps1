<#
.SYNOPSIS
    Test Pester 5 per i controlli Windows Defender (Defender.ps1):
    HOME-AV-001 .. HOME-AV-008.
#>

Set-StrictMode -Version 2

Describe 'Controlli Windows Defender (HOME-AV-001 .. HOME-AV-008)' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Defender.ps1'
        . $percorsoModulo

        function Get-MpComputerStatus { }
        function Get-MpPreference { }
        function Get-MpThreatDetection { }
        function Get-MpThreat { }

        $controllo = [PSCustomObject]@{ id = 'HOME-AV-TEST' }
    }

    Context 'Test-DefenderRealtime (HOME-AV-001)' {
        It 'Restituisce superato quando AntivirusEnabled e RealTimeProtectionEnabled sono True' {
            Mock Get-MpComputerStatus {
                return [PSCustomObject]@{ AntivirusEnabled = $true; RealTimeProtectionEnabled = $true }
            }
            $res = Test-DefenderRealtime -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando RealTimeProtectionEnabled e False' {
            Mock Get-MpComputerStatus {
                return [PSCustomObject]@{ AntivirusEnabled = $true; RealTimeProtectionEnabled = $false }
            }
            $res = Test-DefenderRealtime -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-DefenderSignatures (HOME-AV-002)' {
        It 'Restituisce superato quando AntivirusSignatureAge e <= 7 giorni' {
            Mock Get-MpComputerStatus { return [PSCustomObject]@{ AntivirusSignatureAge = 2 } }
            $res = Test-DefenderSignatures -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando AntivirusSignatureAge e > 7 giorni' {
            Mock Get-MpComputerStatus { return [PSCustomObject]@{ AntivirusSignatureAge = 14 } }
            $res = Test-DefenderSignatures -Controllo $controllo
            $res.Status   | Should -Be 'fallito'
            $res.Observed | Should -Match '14 giorni'
        }
    }

    Context 'Test-DefenderNoActiveThreats (HOME-AV-003)' {
        It 'Restituisce superato quando non ci sono minacce attive' {
            Mock Get-MpThreatDetection { return @() }
            Mock Get-MpThreat { return @() }
            $res = Test-DefenderNoActiveThreats -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando esiste una minaccia attiva' {
            Mock Get-MpThreatDetection { return @([PSCustomObject]@{ ThreatID = 1 }) }
            Mock Get-MpThreat {
                return @([PSCustomObject]@{ ThreatName = 'Trojan:Win32/Test'; IsActive = $true })
            }
            $res = Test-DefenderNoActiveThreats -Controllo $controllo
            $res.Status   | Should -Be 'fallito'
            $res.Observed | Should -Match 'Trojan:Win32/Test'
        }
    }

    Context 'Test-DefenderBehaviorAndIoav (HOME-AV-004)' {
        It 'Restituisce superato quando BehaviorMonitor e IOAV sono True' {
            Mock Get-MpComputerStatus {
                return [PSCustomObject]@{ BehaviorMonitorEnabled = $true; IoavProtectionEnabled = $true }
            }
            $res = Test-DefenderBehaviorAndIoav -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando BehaviorMonitor e False' {
            Mock Get-MpComputerStatus {
                return [PSCustomObject]@{ BehaviorMonitorEnabled = $false; IoavProtectionEnabled = $true }
            }
            $res = Test-DefenderBehaviorAndIoav -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-DefenderPuaProtection (HOME-AV-005)' {
        It 'Restituisce superato quando PUAProtection = 1' {
            Mock Get-MpPreference { return [PSCustomObject]@{ PUAProtection = 1 } }
            $res = Test-DefenderPuaProtection -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando PUAProtection = 0 o 2' {
            Mock Get-MpPreference { return [PSCustomObject]@{ PUAProtection = 0 } }
            $res = Test-DefenderPuaProtection -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-DefenderTamperAndCloud (HOME-AV-006)' {
        It 'Restituisce superato quando IsTamperProtected = True e MAPSReporting >= 1' {
            Mock Get-MpComputerStatus { return [PSCustomObject]@{ IsTamperProtected = $true } }
            Mock Get-MpPreference { return [PSCustomObject]@{ MAPSReporting = 2 } }
            $res = Test-DefenderTamperAndCloud -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando IsTamperProtected = False' {
            Mock Get-MpComputerStatus { return [PSCustomObject]@{ IsTamperProtected = $false } }
            Mock Get-MpPreference { return [PSCustomObject]@{ MAPSReporting = 2 } }
            $res = Test-DefenderTamperAndCloud -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-DefenderRecentScan (HOME-AV-007)' {
        It 'Restituisce superato quando QuickScanAge <= 14' {
            Mock Get-MpComputerStatus { return [PSCustomObject]@{ QuickScanAge = 3; FullScanAge = 4294967295 } }
            $res = Test-DefenderRecentScan -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito quando nessuna scansione e stata eseguita negli ultimi 14 giorni' {
            Mock Get-MpComputerStatus { return [PSCustomObject]@{ QuickScanAge = 30; FullScanAge = 4294967295 } }
            $res = Test-DefenderRecentScan -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-DefenderSafeExclusions (HOME-AV-008)' {
        It 'Restituisce superato quando non ci sono esclusioni pericolose' {
            Mock Get-MpPreference {
                return [PSCustomObject]@{ ExclusionPath = @(); ExclusionExtension = @() }
            }
            $res = Test-DefenderSafeExclusions -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Restituisce fallito se e esclusa C:\ o l estensione .exe' {
            Mock Get-MpPreference {
                return [PSCustomObject]@{ ExclusionPath = @('C:\'); ExclusionExtension = @('.exe') }
            }
            $res = Test-DefenderSafeExclusions -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }

        It 'Restituisce sconosciuto se non si hanno privilegi admin per vedere le esclusioni' {
            Mock Get-MpPreference {
                return [PSCustomObject]@{
                    ExclusionPath      = @('N/A: Must be an administrator to view exclusions')
                    ExclusionExtension = @()
                }
            }
            $res = Test-DefenderSafeExclusions -Controllo $controllo
            $res.Status | Should -Be 'sconosciuto'
        }
    }
}
