<#
.SYNOPSIS
    Pester 5 tests for Windows Defender checks (Defender.ps1):
    HOME-AV-001 .. HOME-AV-011.
#>

Set-StrictMode -Version 2

Describe 'Windows Defender Checks (HOME-AV-001 .. HOME-AV-011)' {

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
        It 'Returns superato when AntivirusEnabled and RealTimeProtectionEnabled are True' {
            Mock Get-MpComputerStatus {
                return [PSCustomObject]@{ AntivirusEnabled = $true; RealTimeProtectionEnabled = $true }
            }
            $res = Test-DefenderRealtime -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Returns fallito when RealTimeProtectionEnabled is False' {
            Mock Get-MpComputerStatus {
                return [PSCustomObject]@{ AntivirusEnabled = $true; RealTimeProtectionEnabled = $false }
            }
            $res = Test-DefenderRealtime -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-DefenderSignatures (HOME-AV-002)' {
        It 'Returns superato when AntivirusSignatureAge is <= 7 days' {
            Mock Get-MpComputerStatus { return [PSCustomObject]@{ AntivirusSignatureAge = 2 } }
            $res = Test-DefenderSignatures -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Returns fallito when AntivirusSignatureAge is > 7 days' {
            Mock Get-MpComputerStatus { return [PSCustomObject]@{ AntivirusSignatureAge = 14 } }
            $res = Test-DefenderSignatures -Controllo $controllo
            $res.Status   | Should -Be 'fallito'
            $res.Observed | Should -Match '14 days'
        }
    }

    Context 'Test-DefenderNoActiveThreats (HOME-AV-003)' {
        It 'Returns superato when there are no active threats' {
            Mock Get-MpThreatDetection { return @() }
            Mock Get-MpThreat { return @() }
            $res = Test-DefenderNoActiveThreats -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Returns fallito when an active threat exists' {
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
        It 'Returns superato when BehaviorMonitor and IOAV are True' {
            Mock Get-MpComputerStatus {
                return [PSCustomObject]@{ BehaviorMonitorEnabled = $true; IoavProtectionEnabled = $true }
            }
            $res = Test-DefenderBehaviorAndIoav -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Returns fallito when BehaviorMonitor is False' {
            Mock Get-MpComputerStatus {
                return [PSCustomObject]@{ BehaviorMonitorEnabled = $false; IoavProtectionEnabled = $true }
            }
            $res = Test-DefenderBehaviorAndIoav -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-DefenderPuaProtection (HOME-AV-005)' {
        It 'Returns superato when PUAProtection = 1' {
            Mock Get-MpPreference { return [PSCustomObject]@{ PUAProtection = 1 } }
            $res = Test-DefenderPuaProtection -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Returns fallito when PUAProtection = 0 or 2' {
            Mock Get-MpPreference { return [PSCustomObject]@{ PUAProtection = 0 } }
            $res = Test-DefenderPuaProtection -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-DefenderTamperAndCloud (HOME-AV-006)' {
        It 'Returns superato when IsTamperProtected = True and MAPSReporting >= 1' {
            Mock Get-MpComputerStatus { return [PSCustomObject]@{ IsTamperProtected = $true } }
            Mock Get-MpPreference { return [PSCustomObject]@{ MAPSReporting = 2 } }
            $res = Test-DefenderTamperAndCloud -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Returns fallito when IsTamperProtected = False' {
            Mock Get-MpComputerStatus { return [PSCustomObject]@{ IsTamperProtected = $false } }
            Mock Get-MpPreference { return [PSCustomObject]@{ MAPSReporting = 2 } }
            $res = Test-DefenderTamperAndCloud -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-DefenderRecentScan (HOME-AV-007)' {
        It 'Returns superato when QuickScanAge <= 14' {
            Mock Get-MpComputerStatus { return [PSCustomObject]@{ QuickScanAge = 3; FullScanAge = 4294967295 } }
            $res = Test-DefenderRecentScan -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Returns fallito when no scan completed within the last 14 days' {
            Mock Get-MpComputerStatus { return [PSCustomObject]@{ QuickScanAge = 30; FullScanAge = 4294967295 } }
            $res = Test-DefenderRecentScan -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }
    }

    Context 'Test-DefenderSafeExclusions (HOME-AV-008)' {
        It 'Returns superato when no dangerous exclusions exist' {
            Mock Get-MpPreference {
                return [PSCustomObject]@{ ExclusionPath = @(); ExclusionExtension = @() }
            }
            $res = Test-DefenderSafeExclusions -Controllo $controllo
            $res.Status | Should -Be 'superato'
        }

        It 'Returns fallito when C:\ or .exe extension is excluded' {
            Mock Get-MpPreference {
                return [PSCustomObject]@{ ExclusionPath = @('C:\'); ExclusionExtension = @('.exe') }
            }
            $res = Test-DefenderSafeExclusions -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }

        It 'Returns sconosciuto when admin privileges are required to view exclusions' {
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

    Context 'Test-DefenderAsrRules (HOME-AV-011)' {

        It 'Returns superato when ASR rules (LSASS and Obfuscated Scripts) are active in Block (1) or Warn (6)' {
            Mock Get-MpPreference {
                return [PSCustomObject]@{
                    AttackSurfaceReductionRules_Ids     = @('9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', '5beb7efe-fd9a-4556-801d-275e5ffc04cc')
                    AttackSurfaceReductionRules_Actions = @(1, 6)
                }
            }
            $res = Test-DefenderAsrRules -Controllo $controllo
            $res.Status | Should -Be 'superato'
            $res.Evidence.LsassProtected | Should -Be $true
            $res.Evidence.ScriptsProtected | Should -Be $true
        }

        It 'Returns fallito when no ASR rule is active in Block or Warn mode' {
            Mock Get-MpPreference {
                return [PSCustomObject]@{
                    AttackSurfaceReductionRules_Ids     = @()
                    AttackSurfaceReductionRules_Actions = @()
                }
            }
            $res = Test-DefenderAsrRules -Controllo $controllo
            $res.Status | Should -Be 'fallito'
        }
    }
}
