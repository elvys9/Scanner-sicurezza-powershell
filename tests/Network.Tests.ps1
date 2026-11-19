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

Describe 'Test-LegacyTlsAndDoh (HOME-NET-008)' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Checks\Network.ps1'
        . $percorsoModulo

        function Get-DnsClientDohServerAddress { }
        $controllo = [PSCustomObject]@{ id = 'HOME-NET-008' }
    }

    It 'Restituisce superato quando TLS 1.0/1.1 non sono abilitati e DoH e attivo' {
        Mock Test-Path { return $true }
        Mock Get-ItemProperty {
            return [PSCustomObject]@{ Enabled = 0; EnableAutoDoh = 2 }
        }
        Mock Get-DnsClientDohServerAddress {
            return @([PSCustomObject]@{ ServerAddress = '1.1.1.1' })
        }

        $res = Test-LegacyTlsAndDoh -Controllo $controllo
        $res.Status | Should -Be 'superato'
    }

    It 'Restituisce fallito quando TLS 1.0 o TLS 1.1 e forzatamente abilitato (Enabled = 1)' {
        Mock Test-Path { return $true }
        Mock Get-ItemProperty {
            return [PSCustomObject]@{ Enabled = 1; EnableAutoDoh = 2 }
        }

        $res = Test-LegacyTlsAndDoh -Controllo $controllo
        $res.Status | Should -Be 'fallito'
        $res.Observed | Should -Match 'TLS 1\.0'
    }
}

Describe 'Test-InsecureWifiProfiles (HOME-NET-009)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..\src\core\Checks\Network.ps1')
        $controllo = [PSCustomObject]@{ id = 'HOME-NET-009'; category = 'Network'; severity = 'medio' }
    }

    It 'Passes when no saved Wi-Fi profile directory exists on the system' {
        $missingDir = Join-Path $TestDrive 'NoWlansvcProfiles'
        $res = Test-InsecureWifiProfiles -Controllo $controllo -ProfilesPath $missingDir

        $res.Status   | Should -Be 'superato'
        $res.Observed | Should -Match 'No saved Wi-Fi profiles found'
    }

    It 'Passes when saved AutoConnect Wi-Fi profiles use strong WPA2/WPA3 AES encryption' {
        $ifaceDir = Join-Path $TestDrive 'WifiSecure\Interfaces\{11111111-1111-1111-1111-111111111111}'
        New-Item -ItemType Directory -Path $ifaceDir -Force | Out-Null

        @'
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>HomeSecure5G</name>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
'@ | Set-Content -LiteralPath (Join-Path $ifaceDir 'HomeSecure5G.xml') -Encoding UTF8

        $res = Test-InsecureWifiProfiles -Controllo $controllo -ProfilesPath (Join-Path $TestDrive 'WifiSecure\Interfaces')
        $res.Status | Should -Be 'superato'
        $res.Evidence.ScannedProfiles | Should -Be 1
        @($res.Evidence.InsecureProfiles).Count | Should -Be 0
    }

    It 'Fails when an open or WEP/TKIP Wi-Fi profile is configured for AutoConnect' {
        $ifaceDir = Join-Path $TestDrive 'WifiInsecure\Interfaces\{22222222-2222-2222-2222-222222222222}'
        New-Item -ItemType Directory -Path $ifaceDir -Force | Out-Null

        @'
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>CafeFree</name>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
'@ | Set-Content -LiteralPath (Join-Path $ifaceDir 'CafeFree.xml') -Encoding UTF8

        @'
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>LegacyRouter</name>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPAPSK</authentication>
                <encryption>TKIP</encryption>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
'@ | Set-Content -LiteralPath (Join-Path $ifaceDir 'LegacyRouter.xml') -Encoding UTF8

        $res = Test-InsecureWifiProfiles -Controllo $controllo -ProfilesPath (Join-Path $TestDrive 'WifiInsecure\Interfaces')
        $res.Status   | Should -Be 'fallito'
        $res.Observed | Should -Match 'CafeFree'
        $res.Observed | Should -Match 'LegacyRouter'
        @($res.Evidence.InsecureProfiles).Count | Should -Be 2
    }

    It 'Passes when an open Wi-Fi profile uses manual connectionMode instead of auto' {
        $ifaceDir = Join-Path $TestDrive 'WifiManual\Interfaces\{33333333-3333-3333-3333-333333333333}'
        New-Item -ItemType Directory -Path $ifaceDir -Force | Out-Null

        @'
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>AirportGuest</name>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
'@ | Set-Content -LiteralPath (Join-Path $ifaceDir 'AirportGuest.xml') -Encoding UTF8

        $res = Test-InsecureWifiProfiles -Controllo $controllo -ProfilesPath (Join-Path $TestDrive 'WifiManual\Interfaces')
        $res.Status | Should -Be 'superato'
        @($res.Evidence.InsecureProfiles).Count | Should -Be 0
    }

    It 'Returns unknown status when access to saved Wi-Fi XML files is denied' {
        Mock Test-Path { return $true }
        Mock Get-ChildItem { throw [System.UnauthorizedAccessException]::new('Access to the path is denied.') }

        $res = Test-InsecureWifiProfiles -Controllo $controllo -ProfilesPath 'C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces'
        $res.Status   | Should -Be 'sconosciuto'
        $res.Observed | Should -Match 'Administrator privileges'
    }
}

Describe 'Test-HighRiskListeningPorts (HOME-NET-010)' {
    BeforeAll {
        . (Join-Path $PSScriptRoot '..\src\core\Checks\Network.ps1')
        $controllo = [PSCustomObject]@{ id = 'HOME-NET-010'; category = 'Network'; severity = 'alto' }
        function Get-NetTCPConnection { param($State, $ErrorAction) }
    }

    It 'Passes when only loopback high-risk ports or standard/excluded ports (such as RPC 135) are listening' {
        Mock Get-NetTCPConnection {
            return @(
                [PSCustomObject]@{ LocalAddress = '127.0.0.1'; LocalPort = 6379; OwningProcess = 1001 }
                [PSCustomObject]@{ LocalAddress = '::1';       LocalPort = 5900; OwningProcess = 1002 }
                [PSCustomObject]@{ LocalAddress = '0.0.0.0';   LocalPort = 135;  OwningProcess = 800  }
                [PSCustomObject]@{ LocalAddress = '0.0.0.0';   LocalPort = 443;  OwningProcess = 4    }
            )
        }

        $res = Test-HighRiskListeningPorts -Controllo $controllo
        $res.Status | Should -Be 'superato'
        $res.Evidence.ExposedCount | Should -Be 0
    }

    It 'Fails when high-risk ports such as 23 or 5900 listen on 0.0.0.0' {
        Mock Get-NetTCPConnection {
            return @(
                [PSCustomObject]@{ LocalAddress = '0.0.0.0'; LocalPort = 5900; OwningProcess = 4242 }
                [PSCustomObject]@{ LocalAddress = '::';      LocalPort = 23;   OwningProcess = 4243 }
            )
        }
        Mock Get-Process {
            if ($Id -eq 4242) { return [PSCustomObject]@{ ProcessName = 'tvnserver' } }
            if ($Id -eq 4243) { return [PSCustomObject]@{ ProcessName = 'tlntsvr' } }
            return $null
        }

        $res = Test-HighRiskListeningPorts -Controllo $controllo
        $res.Status   | Should -Be 'fallito'
        $res.Observed | Should -Match '5900/VNC'
        $res.Observed | Should -Match '23/Telnet'
        $res.Observed | Should -Match 'tvnserver'
        $res.Evidence.ExposedCount | Should -Be 2
        $res.Evidence.ExposedPorts[0].LocalPort    | Should -Be 23
        $res.Evidence.ExposedPorts[1].LocalAddress | Should -Be '0.0.0.0'
        $res.Evidence.ExposedPorts[1].PID          | Should -Be 4242
    }

    It 'Returns unknown status when Get-NetTCPConnection is unavailable' {
        Mock Get-NetTCPConnection {
            throw [System.Management.Automation.CommandNotFoundException]::new("The term 'Get-NetTCPConnection' is not recognized as the name of a cmdlet.")
        }

        $res = Test-HighRiskListeningPorts -Controllo $controllo
        $res.Status   | Should -Be 'sconosciuto'
        $res.Observed | Should -Match 'unavailable'
    }
}
