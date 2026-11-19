<#
.SYNOPSIS
    Network protocol and exposure security controls.

.DESCRIPTION
    Implements read-only checks for:
    - HOME-NET-001: SMBv1 protocol disabled (Test-Smb1Disabled)
    - HOME-NET-002: NetBIOS over TCP/IP disabled (Test-NetbiosDisabled)
    - HOME-NET-003: LLMNR multicast name resolution disabled (Test-LlmnrDisabled)
    - HOME-NET-004: No non-standard SMB shares exposed (Test-CondivisioniSmbPericolose)
    - HOME-NET-005: Mandatory SMB signing enabled (Test-FirmaSmbObbligatoria)
    - HOME-NET-006: WinRM service disabled/stopped (Test-WinRmDisabilitatoOSicuro)
    - HOME-NET-007: WPAD auto-discovery disabled (Test-WpadDisabilitato)
    - HOME-NET-008: Legacy TLS 1.0/1.1 disabled and DoH supported (Test-LegacyTlsAndDoh)
    - HOME-NET-009: No insecure Wi-Fi profiles configured for AutoConnect (Test-InsecureWifiProfiles)
    - HOME-NET-010: No high-risk TCP ports exposed on all interfaces (Test-HighRiskListeningPorts)
    Never modifies system state.
#>

Set-StrictMode -Version 2

function Test-Smb1Disabled {
    <#
    .SYNOPSIS
        Verifies that the legacy SMBv1 protocol is disabled.
    .PARAMETER Controllo
        Control object from the catalog.
    .PARAMETER Ambiente
        Environment object (from Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject with properties: Status, Observed, Expected, Evidence, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "SMBv1 protocol disabled (EnableSMB1Protocol = False)"
        Evidence = $null
        Error    = $null
    }

    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
        $smb1Attivo = [bool]$smbConfig.EnableSMB1Protocol

        $risultato.Evidence = @{
            EnableSMB1Protocol = $smb1Attivo
            Source             = 'Get-SmbServerConfiguration'
        }

        if (-not $smb1Attivo) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "SMBv1 disabled"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "SMBv1 enabled (EnableSMB1Protocol = True)"
        }
    }
    catch {
        # Registry fallback (LanmanServer\Parameters and mrxsmb10 driver)
        try {
            $percorsoLanman = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            $percorsoMrx    = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'

            if (Test-Path -LiteralPath $percorsoLanman) {
                $propLanman = Get-ItemProperty -LiteralPath $percorsoLanman -ErrorAction Stop
                if ($null -ne $propLanman.PSObject.Properties['SMB1'] -and $null -ne $propLanman.SMB1) {
                    $valSmb1 = [int]$propLanman.SMB1
                    $risultato.Evidence = @{ SMB1Registry = $valSmb1; Source = 'LanmanServerRegistry' }
                    if ($valSmb1 -eq 0) {
                        $risultato.Status   = 'superato'
                        $risultato.Observed = "SMBv1 disabled via registry (SMB1 = 0)"
                    }
                    else {
                        $risultato.Status   = 'fallito'
                        $risultato.Observed = "SMBv1 enabled via registry (SMB1 = $valSmb1)"
                    }
                    return $risultato
                }
            }

            # If mrxsmb10 driver is absent or has Start = 4 (Disabled), SMBv1 is inactive
            if (-not (Test-Path -LiteralPath $percorsoMrx)) {
                $risultato.Evidence = @{ MrxSmb10Present = $false; Source = 'ServiceRegistry' }
                $risultato.Status   = 'superato'
                $risultato.Observed = "SMBv1 driver (mrxsmb10) is not installed on the system"
                return $risultato
            }
            else {
                $propMrx = Get-ItemProperty -LiteralPath $percorsoMrx -ErrorAction Stop
                $startVal = if ($null -ne $propMrx.PSObject.Properties['Start']) { [int]$propMrx.Start } else { 3 }
                $risultato.Evidence = @{ MrxSmb10Present = $true; Start = $startVal; Source = 'ServiceRegistry' }
                if ($startVal -eq 4) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "SMBv1 driver disabled (Start = 4)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "SMBv1 driver present and not disabled (Start = $startVal)"
                }
                return $risultato
            }
        }
        catch {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Unable to determine SMBv1 status"
            $risultato.Error    = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-NetbiosDisabled {
    <#
    .SYNOPSIS
        Verifies that NetBIOS over TCP/IP is disabled (NetbiosOptions = 2) on network interfaces.
    .PARAMETER Controllo
        Control object from the catalog.
    .PARAMETER Ambiente
        Environment object (from Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject with properties: Status, Observed, Expected, Evidence, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "NetbiosOptions = 2 (Disabled) on all TCP/IP interfaces"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoInterfacce = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        if (-not (Test-Path -LiteralPath $percorsoInterfacce)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "NetBT Interfaces registry key not found"
            return $risultato
        }

        $sottoChiavi = @(Get-ChildItem -LiteralPath $percorsoInterfacce -ErrorAction Stop)
        if ($sottoChiavi.Count -eq 0) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "No TCP/IP interfaces found under NetBT"
            return $risultato
        }

        $interfacceNonDisabilitate = @()
        $dettaglioInterfacce = @{}

        foreach ($chiave in $sottoChiavi) {
            $nomeIf = $chiave.PSChildName
            $propIf = Get-ItemProperty -LiteralPath $chiave.PSPath -ErrorAction Stop
            $opzione = if ($null -ne $propIf.PSObject.Properties['NetbiosOptions'] -and $null -ne $propIf.NetbiosOptions) {
                [int]$propIf.NetbiosOptions
            }
            else {
                0
            }

            $dettaglioInterfacce[$nomeIf] = $opzione
            if ($opzione -ne 2) {
                $interfacceNonDisabilitate += "$nomeIf (NetbiosOptions=$opzione)"
            }
        }

        $risultato.Evidence = $dettaglioInterfacce

        if ($interfacceNonDisabilitate.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "NetBIOS disabled (NetbiosOptions=2) on all $($sottoChiavi.Count) interfaces"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "NetBIOS enabled or default on $($interfacceNonDisabilitate.Count)/$($sottoChiavi.Count) interfaces"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Access denied to NetBT registry key"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-LlmnrDisabled {
    <#
    .SYNOPSIS
        Verifies that LLMNR (Link-Local Multicast Name Resolution) is disabled (EnableMulticast = 0).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "EnableMulticast = 0 in HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoDns = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        if (-not (Test-Path -LiteralPath $percorsoDns)) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "DNSClient policy not configured (LLMNR active by default)"
            $risultato.Evidence = @{ Path = $percorsoDns; KeyExists = $false }
            return $risultato
        }

        $propDns = Get-ItemProperty -LiteralPath $percorsoDns -ErrorAction Stop
        $valore = if ($null -ne $propDns.PSObject.Properties['EnableMulticast'] -and $null -ne $propDns.EnableMulticast) {
            [int]$propDns.EnableMulticast
        }
        else {
            1
        }

        $risultato.Evidence = @{
            Path            = $percorsoDns
            EnableMulticast = $valore
        }

        if ($valore -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "LLMNR disabled (EnableMulticast = 0)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "LLMNR enabled (EnableMulticast = $valore)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Access denied to DNSClient registry key"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-CondivisioniSmbPericolose {
    <#
    .SYNOPSIS
        Verifies that no non-standard user SMB network shares are exposed
        (excluding default administrative shares ADMIN$, C$, IPC$, print$) (HOME-NET-004).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "0 unprotected or unnecessary user SMB shares"
        Evidence = $null
        Error    = $null
    }

    try {
        $shares = @(Get-SmbShare -ErrorAction Stop)
        $nonStandard = @()
        foreach ($s in $shares) {
            $nome = [string]$s.Name
            if ($nome -notmatch '^(ADMIN\$|IPC\$|print\$|[A-Za-z]\$)$') {
                $nonStandard += "$nome ($($s.Path))"
            }
        }

        $risultato.Evidence = @{
            TotalShares       = $shares.Count
            NonStandardShares = $nonStandard
        }

        if ($nonStandard.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "No non-standard shared folders exposed on the network"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Network shared folders detected ($($nonStandard.Count)): $($nonStandard -join '; ')"
        }
    }
    catch {
        # Registry fallback (HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares)
        try {
            $chiaveShares = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares'
            if (Test-Path -LiteralPath $chiaveShares -ErrorAction SilentlyContinue) {
                $propShares = Get-ItemProperty -LiteralPath $chiaveShares -ErrorAction Stop
                $nonStdReg = @()
                foreach ($p in $propShares.PSObject.Properties) {
                    if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
                    if ($p.Name -notmatch '^(ADMIN\$|IPC\$|print\$|[A-Za-z]\$)$') {
                        $nonStdReg += $p.Name
                    }
                }
                $risultato.Evidence = @{ NonStandardShares = $nonStdReg; Source = 'Registry' }
                if ($nonStdReg.Count -eq 0) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "No non-standard shared folders found in LanmanServer registry"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "Shared folders detected ($($nonStdReg.Count)): $($nonStdReg -join ', ')"
                }
                return $risultato
            }
        }
        catch { }

        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to inspect SMB shares"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-FirmaSmbObbligatoria {
    <#
    .SYNOPSIS
        Verifies that mandatory SMB packet signing (RequireSecuritySignature = 1) is enabled
        to mitigate Man-in-the-Middle and NTLM Relay attacks on local networks (HOME-NET-005).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "RequireSecuritySignature = 1 on both SMB Server and Client"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaveSrv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        $chiaveWrk = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'

        $reqSrv = 0
        $reqWrk = 0

        if (Test-Path -LiteralPath $chiaveSrv) {
            $pSrv = Get-ItemProperty -LiteralPath $chiaveSrv -ErrorAction SilentlyContinue
            if ($null -ne $pSrv -and $null -ne $pSrv.PSObject.Properties['RequireSecuritySignature']) {
                $reqSrv = [int]$pSrv.RequireSecuritySignature
            }
        }
        if (Test-Path -LiteralPath $chiaveWrk) {
            $pWrk = Get-ItemProperty -LiteralPath $chiaveWrk -ErrorAction SilentlyContinue
            if ($null -ne $pWrk -and $null -ne $pWrk.PSObject.Properties['RequireSecuritySignature']) {
                $reqWrk = [int]$pWrk.RequireSecuritySignature
            }
        }

        $risultato.Evidence = @{
            ServerRequireSecuritySignature      = $reqSrv
            WorkstationRequireSecuritySignature = $reqWrk
        }

        if ($reqSrv -eq 1 -and $reqWrk -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Mandatory SMB signing enabled on Server and Client (1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "SMB signing not enforced (Server=$reqSrv, Client=$reqWrk)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-WinRmDisabilitatoOSicuro {
    <#
    .SYNOPSIS
        Verifies that the Windows Remote Management (WinRM / PowerShell Remoting) service is stopped
        so remote management ports 5985/5986 are not exposed (HOME-NET-006).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "WinRM service stopped"
        Evidence = $null
        Error    = $null
    }

    try {
        $srv = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
        if ($null -eq $srv) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "WinRM service not present"
            return $risultato
        }

        $statoSrv = [string]$srv.Status
        $risultato.Evidence = @{
            ServiceName = 'WinRM'
            Status      = $statoSrv
        }

        if ($statoSrv -ne 'Running') {
            $risultato.Status   = 'superato'
            $risultato.Observed = "WinRM service stopped ($statoSrv)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "WinRM service is running (remote port 5985 active)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-WpadDisabilitato {
    <#
    .SYNOPSIS
        Verifies that Web Proxy Auto-Discovery (WPAD) is disabled to prevent
        web traffic interception attacks on local/Wi-Fi networks (HOME-NET-007).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "DisableWpad = 1 or WinHttpAutoProxySvc service disabled"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaveWpad = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad'
        $disableWpad = 0
        if (Test-Path -LiteralPath $chiaveWpad) {
            $propWpad = Get-ItemProperty -LiteralPath $chiaveWpad -ErrorAction SilentlyContinue
            if ($null -ne $propWpad -and $null -ne $propWpad.PSObject.Properties['DisableWpad']) {
                $disableWpad = [int]$propWpad.DisableWpad
            }
        }

        $chiaveSvc = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc'
        $startSvc = 3
        if (Test-Path -LiteralPath $chiaveSvc) {
            $propSvc = Get-ItemProperty -LiteralPath $chiaveSvc -ErrorAction SilentlyContinue
            if ($null -ne $propSvc -and $null -ne $propSvc.PSObject.Properties['Start']) {
                $startSvc = [int]$propSvc.Start
            }
        }

        $risultato.Evidence = @{
            DisableWpad           = $disableWpad
            WinHttpAutoProxyStart = $startSvc
        }

        if ($disableWpad -eq 1 -or $startSvc -eq 4) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "WPAD disabled (DisableWpad=$disableWpad, ServiceStart=$startSvc)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "WPAD active (DisableWpad=$disableWpad, ServiceStart=$startSvc)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-LegacyTlsAndDoh {
    <#
    .SYNOPSIS
        Verifies that deprecated TLS 1.0 and TLS 1.1 protocols are not enabled in SCHANNEL
        and checks DNS over HTTPS (DoH) support (HOME-NET-008).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "TLS 1.0/1.1 not enabled (Enabled != 1) and DNS over HTTPS (DoH) support present"
        Evidence = $null
        Error    = $null
    }

    try {
        $baseSchannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
        $sottoChiaviTls = @(
            'TLS 1.0\Client',
            'TLS 1.0\Server',
            'TLS 1.1\Client',
            'TLS 1.1\Server'
        )

        $tlsLegacyAttivi = @()
        foreach ($sub in $sottoChiaviTls) {
            $percorsoTls = Join-Path $baseSchannel $sub
            if (Test-Path -LiteralPath $percorsoTls -ErrorAction SilentlyContinue) {
                $propTls = Get-ItemProperty -LiteralPath $percorsoTls -ErrorAction SilentlyContinue
                if ($null -ne $propTls -and $null -ne $propTls.PSObject.Properties['Enabled'] -and $null -ne $propTls.Enabled) {
                    $valEn = [int]$propTls.Enabled
                    if ($valEn -eq 1) {
                        $tlsLegacyAttivi += "$sub (Enabled=1)"
                    }
                }
            }
        }

        # Check DNS over HTTPS (DoH) configuration
        $chiaveDnsCache = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
        $autoDoh = 0
        if (Test-Path -LiteralPath $chiaveDnsCache -ErrorAction SilentlyContinue) {
            $propDns = Get-ItemProperty -LiteralPath $chiaveDnsCache -ErrorAction SilentlyContinue
            if ($null -ne $propDns -and $null -ne $propDns.PSObject.Properties['EnableAutoDoh'] -and $null -ne $propDns.EnableAutoDoh) {
                $autoDoh = [int]$propDns.EnableAutoDoh
            }
        }

        $dohServerCount = 0
        try {
            if (Get-Command -Name 'Get-DnsClientDohServerAddress' -ErrorAction SilentlyContinue) {
                $dohServers = @(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)
                $dohServerCount = $dohServers.Count
            }
        }
        catch { }

        $dohConfigurato = ($autoDoh -ge 1) -or ($dohServerCount -gt 0)

        $risultato.Evidence = @{
            LegacyTlsEnabled = $tlsLegacyAttivi
            EnableAutoDoh    = $autoDoh
            DohServersCount  = $dohServerCount
            DohConfigured    = $dohConfigurato
        }

        if ($tlsLegacyAttivi.Count -gt 0) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Legacy cryptographic protocols enabled: $($tlsLegacyAttivi -join ', ')"
        }
        elseif (-not $dohConfigurato) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "TLS 1.0/1.1 disabled, but DNS over HTTPS (DoH) is not configured (EnableAutoDoh=$autoDoh)"
        }
        else {
            $risultato.Status   = 'superato'
            $risultato.Observed = "TLS 1.0/1.1 disabled and DNS over HTTPS (DoH) support active (EnableAutoDoh=$autoDoh, DohServers=$dohServerCount)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-InsecureWifiProfiles {
    <#
    .SYNOPSIS
        Verifies that no saved Wi-Fi profile with insecure authentication or encryption
        is configured for automatic connection (HOME-NET-009).

    .DESCRIPTION
        Reads saved WLAN profile XML files directly in read-only mode without relying
        on localized netsh output. Flags a profile only when connectionMode is 'auto'
        AND either authentication is insecure (open, shared, WEP, WPA, WPAPSK) or
        encryption is insecure (none, WEP, TKIP).

    .PARAMETER Controllo
        Catalog control object metadata for HOME-NET-009.

    .PARAMETER Ambiente
        Optional shared host environment snapshot object.

    .PARAMETER ProfilesPath
        Optional path to the WLAN XML profiles directory (defaults to the standard Windows path).
        Primarily intended for deterministic unit testing.

    .EXAMPLE
        Test-InsecureWifiProfiles -Controllo $control
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [string]$ProfilesPath = 'C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces'
    )

    $result = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = 'No insecure Wi-Fi profiles (open, shared, WEP, WPA, WPAPSK, or TKIP) configured with AutoConnect enabled'
        Evidence = $null
        Error    = $null
    }

    $insecureAuthValues = @('open', 'shared', 'WEP', 'WPA', 'WPAPSK')
    $insecureEncValues  = @('none', 'WEP', 'TKIP')

    try {
        if (-not (Test-Path -LiteralPath $ProfilesPath -ErrorAction Stop)) {
            $result.Status   = 'superato'
            $result.Observed = 'No saved Wi-Fi profiles found on this system.'
            $result.Evidence = [PSCustomObject]@{
                ProfilesPath    = $ProfilesPath
                DirectoryExists = $false
                ScannedProfiles = 0
                InsecureProfiles = @()
            }
            return $result
        }

        $profileFiles = @(Get-ChildItem -LiteralPath $ProfilesPath -Filter '*.xml' -File -Recurse -ErrorAction Stop)
        if ($profileFiles.Count -eq 0) {
            $result.Status   = 'superato'
            $result.Observed = 'No saved Wi-Fi profiles found on this system.'
            $result.Evidence = [PSCustomObject]@{
                ProfilesPath     = $ProfilesPath
                DirectoryExists  = $true
                ScannedProfiles  = 0
                InsecureProfiles = @()
            }
            return $result
        }

        $scannedCount = 0
        $insecureProfiles = @()

        foreach ($profileFile in $profileFiles) {
            $rawXml = Get-Content -LiteralPath $profileFile.FullName -Raw -ErrorAction Stop
            if ([string]::IsNullOrWhiteSpace($rawXml)) {
                continue
            }

            $xmlDoc = $null
            try {
                $xmlDoc = [xml]$rawXml
            }
            catch {
                # Skip malformed or non-WLAN XML files cleanly without failing the entire audit
                continue
            }

            $root = $xmlDoc.DocumentElement
            if ($null -eq $root) {
                continue
            }

            $scannedCount++

            $profileName    = if ($null -ne $root['name']) { ([string]$root['name'].InnerText).Trim() } else { $profileFile.BaseName }
            $connectionMode = if ($null -ne $root['connectionMode']) { ([string]$root['connectionMode'].InnerText).Trim() } else { '' }

            $authNode = $null
            $msmNode = $root['MSM']
            if ($null -ne $msmNode) {
                $securityNode = $msmNode['security']
                if ($null -ne $securityNode) {
                    $authNode = $securityNode['authEncryption']
                }
            }

            $authentication = if ($null -ne $authNode -and $null -ne $authNode['authentication']) { ([string]$authNode['authentication'].InnerText).Trim() } else { '' }
            $encryption     = if ($null -ne $authNode -and $null -ne $authNode['encryption'])     { ([string]$authNode['encryption'].InnerText).Trim() }     else { '' }

            $isAutoConnect   = ($connectionMode -eq 'auto')
            $hasInsecureAuth = ($insecureAuthValues -contains $authentication)
            $hasInsecureEnc  = ($insecureEncValues -contains $encryption)

            if ($isAutoConnect -and ($hasInsecureAuth -or $hasInsecureEnc)) {
                $insecureProfiles += [PSCustomObject]@{
                    ProfileName    = $profileName
                    ConnectionMode = $connectionMode
                    Authentication = $authentication
                    Encryption     = $encryption
                    FileName       = $profileFile.Name
                }
            }
        }

        if ($insecureProfiles.Count -gt 0) {
            $summaryList = @($insecureProfiles | ForEach-Object {
                "$($_.ProfileName) (Auth=$($_.Authentication), Enc=$($_.Encryption), Mode=$($_.ConnectionMode))"
            }) -join '; '

            $result.Status   = 'fallito'
            $result.Observed = "Insecure AutoConnect Wi-Fi profile(s) detected: $summaryList"
            $result.Evidence = [PSCustomObject]@{
                ProfilesPath     = $ProfilesPath
                ScannedProfiles  = $scannedCount
                InsecureProfiles = @($insecureProfiles)
            }
        }
        elseif ($scannedCount -eq 0) {
            $result.Status   = 'superato'
            $result.Observed = 'No saved Wi-Fi profiles found on this system.'
            $result.Evidence = [PSCustomObject]@{
                ProfilesPath     = $ProfilesPath
                ScannedProfiles  = 0
                InsecureProfiles = @()
            }
        }
        else {
            $result.Status   = 'superato'
            $result.Observed = "All $scannedCount saved Wi-Fi profile(s) use strong authentication/encryption or manual connection mode."
            $result.Evidence = [PSCustomObject]@{
                ProfilesPath     = $ProfilesPath
                ScannedProfiles  = $scannedCount
                InsecureProfiles = @()
            }
        }
    }
    catch {
        $exception = $_.Exception
        if (
            ($exception -is [System.UnauthorizedAccessException]) -or
            ($exception -is [System.Security.SecurityException]) -or
            ($exception.Message -match '(?i)access.*denied|unauthorized')
        ) {
            $result.Status   = 'sconosciuto'
            $result.Observed = 'Administrator privileges are required to inspect saved Wi-Fi profile XML files'
            $result.Error    = $exception.Message
        }
        else {
            $result.Status = 'errore'
            $result.Error  = $exception.Message
        }
    }

    return $result
}

function Test-HighRiskListeningPorts {
    <#
    .SYNOPSIS
        Verifies that high-risk remote access, legacy, or backdoor TCP ports are not
        listening on exposed (non-loopback) network interfaces (HOME-NET-010).

    .DESCRIPTION
        Queries listening TCP sockets via Get-NetTCPConnection in read-only mode, strictly
        excluding loopback bindings (127.0.0.1, ::1, and 127.*). Evaluates exposed sockets
        against a closed allow-free high-risk port table (21, 23, 69, 139, 1433, 3389,
        4444, 5900, 5985, 5986, 6379) while deliberately excluding RPC port 135 to prevent
        false positives on standard Windows hosts. Resolves owning process names cleanly.

    .PARAMETER Controllo
        Catalog control object metadata for HOME-NET-010.

    .PARAMETER Ambiente
        Optional shared host environment snapshot object.

    .EXAMPLE
        Test-HighRiskListeningPorts -Controllo $control
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $result = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = 'No high-risk TCP ports listening on exposed (non-loopback) network interfaces'
        Evidence = $null
        Error    = $null
    }

    # Strict closed set of high-risk exposed TCP ports (deliberately excludes RPC 135)
    $highRiskPorts = @{
        21   = 'FTP'
        23   = 'Telnet'
        69   = 'TFTP'
        139  = 'NetBIOS Session'
        1433 = 'MS SQL Server'
        3389 = 'RDP'
        4444 = 'Reverse Shell / Metasploit'
        5900 = 'VNC'
        5985 = 'WinRM HTTP'
        5986 = 'WinRM HTTPS'
        6379 = 'Redis'
    }

    try {
        if ($null -eq (Get-Command -Name 'Get-NetTCPConnection' -ErrorAction SilentlyContinue)) {
            $result.Status   = 'sconosciuto'
            $result.Observed = 'Get-NetTCPConnection cmdlet is unavailable on this system.'
            return $result
        }

        $listeningConnections = @(Get-NetTCPConnection -State Listen -ErrorAction Stop)
        $exposedFindings = @()

        foreach ($conn in $listeningConnections) {
            if ($null -eq $conn) {
                continue
            }

            $localAddr = if ($null -ne $conn.PSObject.Properties['LocalAddress'] -and $null -ne $conn.LocalAddress) {
                ([string]$conn.LocalAddress).Trim()
            }
            else {
                ''
            }

            if ([string]::IsNullOrWhiteSpace($localAddr)) {
                continue
            }

            # Strip optional IPv6 scope identifier before loopback comparison
            $normalizedAddr = ($localAddr -split '%')[0]
            if (
                ($normalizedAddr -eq '127.0.0.1') -or
                ($normalizedAddr -like '127.*') -or
                ($normalizedAddr -eq '::1') -or
                ($normalizedAddr -eq '::ffff:127.0.0.1') -or
                ($normalizedAddr -eq 'localhost')
            ) {
                continue
            }

            $localPort = if ($null -ne $conn.PSObject.Properties['LocalPort'] -and $null -ne $conn.LocalPort) {
                [int]$conn.LocalPort
            }
            else {
                0
            }

            if ($highRiskPorts.ContainsKey($localPort)) {
                $owningPid = $null
                $processName = 'Unknown'

                if ($null -ne $conn.PSObject.Properties['OwningProcess'] -and $null -ne $conn.OwningProcess) {
                    $owningPid = [int]$conn.OwningProcess
                    if ($owningPid -gt 0) {
                        $proc = Get-Process -Id $owningPid -ErrorAction SilentlyContinue
                        if ($null -ne $proc -and $null -ne $proc.PSObject.Properties['ProcessName'] -and -not [string]::IsNullOrWhiteSpace($proc.ProcessName)) {
                            $processName = [string]$proc.ProcessName
                        }
                    }
                    elseif ($owningPid -eq 0) {
                        $processName = 'Idle'
                    }
                }

                $exposedFindings += [PSCustomObject]@{
                    LocalAddress  = $localAddr
                    LocalPort     = $localPort
                    ProtocolLabel = $highRiskPorts[$localPort]
                    PID           = $owningPid
                    ProcessName   = $processName
                }
            }
        }

        if ($exposedFindings.Count -gt 0) {
            $sortedFindings = @($exposedFindings | Sort-Object -Property LocalPort, LocalAddress)
            $summaryList = @($sortedFindings | ForEach-Object {
                "$($_.LocalPort)/$($_.ProtocolLabel) ($($_.LocalAddress), Process=$($_.ProcessName), PID=$($_.PID))"
            }) -join '; '

            $result.Status   = 'fallito'
            $result.Observed = "High-risk TCP port(s) exposed on non-loopback interfaces: $summaryList"
            $result.Evidence = [PSCustomObject]@{
                ExposedCount = $sortedFindings.Count
                ExposedPorts = @($sortedFindings)
            }
        }
        else {
            $result.Status   = 'superato'
            $result.Observed = 'No high-risk TCP ports are listening on exposed network interfaces.'
            $result.Evidence = [PSCustomObject]@{
                ExposedCount = 0
                ExposedPorts = @()
                CheckedPorts = @($highRiskPorts.Keys | Sort-Object)
            }
        }
    }
    catch {
        $exception = $_.Exception
        if (
            ($exception -is [System.Management.Automation.CommandNotFoundException]) -or
            ($exception -is [System.NotSupportedException]) -or
            ($exception.Message -match '(?i)not recognized|unavailable|not available|NetTCPIP|not supported')
        ) {
            $result.Status   = 'sconosciuto'
            $result.Observed = 'Get-NetTCPConnection cmdlet is unavailable on this system.'
            $result.Error    = $exception.Message
        }
        else {
            $result.Status = 'errore'
            $result.Error  = $exception.Message
        }
    }

    return $result
}
