<#
.SYNOPSIS
    Test Pester 5 per i controlli di Rete (Network.ps1):
    HOME-NET-001 (SMBv1) e HOME-NET-002 (NetBIOS).
#>

Set-StrictMode -Version 2

Describe 'Test-Smb1Disabled (HOME-NET-001)' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Network.ps1'
        . $percorsoModulo

        function Get-SmbServerConfiguration { }
        $controllo = [PSCustomObject]@{ id = 'HOME-NET-001' }
    }

    It 'Restituisce superato quando EnableSMB1Protocol e False' {
        Mock Get-SmbServerConfiguration {
            return [PSCustomObject]@{ EnableSMB1Protocol = $false }
        }
        $res = Test-Smb1Disabled -Controllo $controllo
        $res.Status | Should -Be 'superato'
    }

    It 'Restituisce fallito quando EnableSMB1Protocol e True' {
        Mock Get-SmbServerConfiguration {
            return [PSCustomObject]@{ EnableSMB1Protocol = $true }
        }
        $res = Test-Smb1Disabled -Controllo $controllo
        $res.Status | Should -Be 'fallito'
    }
}

Describe 'Test-NetbiosDisabled (HOME-NET-002)' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Network.ps1'
        . $percorsoModulo

        $controllo = [PSCustomObject]@{ id = 'HOME-NET-002' }
    }

    It 'Restituisce superato quando tutte le interfacce hanno NetbiosOptions = 2' {
        Mock Test-Path { return $true }
        Mock Get-ChildItem {
            return @(
                [PSCustomObject]@{ PSChildName = 'Tcpip_1'; PSPath = 'HKLM:\NetBT\Tcpip_1' }
                [PSCustomObject]@{ PSChildName = 'Tcpip_2'; PSPath = 'HKLM:\NetBT\Tcpip_2' }
            )
        }
        Mock Get-ItemProperty {
            return [PSCustomObject]@{ NetbiosOptions = 2 }
        }

        $res = Test-NetbiosDisabled -Controllo $controllo
        $res.Status | Should -Be 'superato'
    }

    It 'Restituisce fallito quando almeno una interfaccia ha NetbiosOptions != 2' {
        Mock Test-Path { return $true }
        Mock Get-ChildItem {
            return @(
                [PSCustomObject]@{ PSChildName = 'Tcpip_1'; PSPath = 'HKLM:\NetBT\Tcpip_1' }
            )
        }
        Mock Get-ItemProperty {
            return [PSCustomObject]@{ NetbiosOptions = 0 }
        }

        $res = Test-NetbiosDisabled -Controllo $controllo
        $res.Status | Should -Be 'fallito'
    }
}

Describe 'Test-LlmnrDisabled (HOME-NET-003)' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Network.ps1'
        . $percorsoModulo

        $controllo = [PSCustomObject]@{ id = 'HOME-NET-003' }
    }

    It 'Restituisce superato quando EnableMulticast = 0' {
        Mock Test-Path { return $true }
        Mock Get-ItemProperty { return [PSCustomObject]@{ EnableMulticast = 0 } }
        $res = Test-LlmnrDisabled -Controllo $controllo
        $res.Status | Should -Be 'superato'
    }

    It 'Restituisce fallito quando la policy non e configurata o EnableMulticast = 1' {
        Mock Test-Path { return $false }
        $res = Test-LlmnrDisabled -Controllo $controllo
        $res.Status | Should -Be 'fallito'
    }
}
