<#
.SYNOPSIS
    Controlli di sicurezza relativi ai protocolli di rete (SMBv1 e NetBIOS).

.DESCRIPTION
    Contiene i controlli per:
    - HOME-NET-001: Protocollo SMBv1 disabilitato (Test-Smb1Disabled)
    - HOME-NET-002: NetBIOS su TCP/IP disabilitato (Test-NetbiosDisabled)
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-Smb1Disabled {
    <#
    .SYNOPSIS
        Verifica che il protocollo SMBv1 sia disabilitato.
    .PARAMETER Controllo
        L'oggetto controllo dal catalogo.
    .PARAMETER Ambiente
        L'oggetto ambiente (da Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject con proprieta': Status, Observed, Expected, Evidence, Error.
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
        Expected = "Protocollo SMBv1 disabilitato (EnableSMB1Protocol = False)"
        Evidence = $null
        Error    = $null
    }

    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
        $smb1Attivo = [bool]$smbConfig.EnableSMB1Protocol

        $risultato.Evidence = @{
            EnableSMB1Protocol = $smb1Attivo
            Fonte              = 'Get-SmbServerConfiguration'
        }

        if (-not $smb1Attivo) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "SMBv1 disabilitato"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "SMBv1 abilitato (EnableSMB1Protocol = True)"
        }
    }
    catch {
        # Fallback su registro (LanmanServer\Parameters e driver mrxsmb10)
        try {
            $percorsoLanman = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            $percorsoMrx    = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'

            if (Test-Path -LiteralPath $percorsoLanman) {
                $propLanman = Get-ItemProperty -LiteralPath $percorsoLanman -ErrorAction Stop
                if ($null -ne $propLanman.PSObject.Properties['SMB1'] -and $null -ne $propLanman.SMB1) {
                    $valSmb1 = [int]$propLanman.SMB1
                    $risultato.Evidence = @{ SMB1Registry = $valSmb1; Fonte = 'LanmanServerRegistry' }
                    if ($valSmb1 -eq 0) {
                        $risultato.Status   = 'superato'
                        $risultato.Observed = "SMBv1 disabilitato da registro (SMB1 = 0)"
                    }
                    else {
                        $risultato.Status   = 'fallito'
                        $risultato.Observed = "SMBv1 abilitato da registro (SMB1 = $valSmb1)"
                    }
                    return $risultato
                }
            }

            # Se il driver client/server mrxsmb10 non e' installato o ha Start = 4 (Disabled), SMBv1 non e' attivo
            if (-not (Test-Path -LiteralPath $percorsoMrx)) {
                $risultato.Evidence = @{ MrxSmb10Presente = $false; Fonte = 'ServiceRegistry' }
                $risultato.Status   = 'superato'
                $risultato.Observed = "Driver SMBv1 (mrxsmb10) non installato sul sistema"
                return $risultato
            }
            else {
                $propMrx = Get-ItemProperty -LiteralPath $percorsoMrx -ErrorAction Stop
                $startVal = if ($null -ne $propMrx.PSObject.Properties['Start']) { [int]$propMrx.Start } else { 3 }
                $risultato.Evidence = @{ MrxSmb10Presente = $true; Start = $startVal; Fonte = 'ServiceRegistry' }
                if ($startVal -eq 4) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Driver SMBv1 disabilitato (Start = 4)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "Driver SMBv1 presente e non disabilitato (Start = $startVal)"
                }
                return $risultato
            }
        }
        catch {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Impossibile determinare lo stato di SMBv1"
            $risultato.Error    = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-NetbiosDisabled {
    <#
    .SYNOPSIS
        Verifica che NetBIOS su TCP/IP sia disabilitato (NetbiosOptions = 2) sulle interfacce.
    .PARAMETER Controllo
        L'oggetto controllo dal catalogo.
    .PARAMETER Ambiente
        L'oggetto ambiente (da Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject con proprieta': Status, Observed, Expected, Evidence, Error.
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
        Expected = "NetbiosOptions = 2 (Disabilitato) su tutte le interfacce TCP/IP"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoInterfacce = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        if (-not (Test-Path -LiteralPath $percorsoInterfacce)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Chiave di registro NetBT Interfaces non trovata"
            return $risultato
        }

        $sottoChiavi = @(Get-ChildItem -LiteralPath $percorsoInterfacce -ErrorAction Stop)
        if ($sottoChiavi.Count -eq 0) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Nessuna interfaccia TCP/IP trovata in NetBT"
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
            $risultato.Observed = "NetBIOS disabilitato (NetbiosOptions=2) su tutte le $($sottoChiavi.Count) interfacce"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "NetBIOS attivo o predefinito su $($interfacceNonDisabilitate.Count)/$($sottoChiavi.Count) interfacce"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave di registro NetBT"
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
        Verifica che il protocollo LLMNR (Link-Local Multicast Name Resolution) sia disabilitato (EnableMulticast = 0).
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
            $risultato.Observed = "Policy DNSClient non configurata (LLMNR attivo per impostazione predefinita)"
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
            $risultato.Observed = "LLMNR disabilitato (EnableMulticast = 0)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "LLMNR abilitato (EnableMulticast = $valore)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave DNSClient"
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
        Verifica che non vi siano condivisioni di rete (SMB Shares) utente non standard esposte
        (escludendo le condivisioni di sistema ADMIN$, C$, IPC$, print$) (HOME-NET-004).
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
        Expected = "0 condivisioni SMB utente non protette o non necessarie"
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
            TotaleShares      = $shares.Count
            SharesNonStandard = $nonStandard
        }

        if ($nonStandard.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna cartella condivisa non standard esposta in rete"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Cartelle condivise in rete rilevate ($($nonStandard.Count)): $($nonStandard -join '; ')"
        }
    }
    catch {
        # Fallback su registro (HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares)
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
                $risultato.Evidence = @{ SharesNonStandard = $nonStdReg; Fonte = 'Registry' }
                if ($nonStdReg.Count -eq 0) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Nessuna cartella condivisa non standard rilevata nel registro LanmanServer"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "Cartelle condivise rilevate ($($nonStdReg.Count)): $($nonStdReg -join ', ')"
                }
                return $risultato
            }
        }
        catch { }

        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per verificare le condivisioni SMB"
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
        Verifica che la firma digitale dei pacchetti SMB (RequireSecuritySignature = 1) sia attiva
        per prevenire attacchi Man-in-the-Middle e NTLM Relay sulla rete locale (HOME-NET-005).
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
        Expected = "RequireSecuritySignature = 1 su Server e Client SMB"
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
            $risultato.Observed = "Firma SMB obbligatoria attiva su Server e Client (1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Firma SMB non obbligatoria (Server=$reqSrv, Client=$reqWrk)"
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
        Verifica che il servizio Windows Remote Management (WinRM / PowerShell Remoting) sia fermo
        per non esporre le porte 5985/5986 sulla rete (HOME-NET-006).
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
        Expected = "Servizio WinRM fermo (Stopped)"
        Evidence = $null
        Error    = $null
    }

    try {
        $srv = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
        if ($null -eq $srv) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Servizio WinRM non presente"
            return $risultato
        }

        $statoSrv = [string]$srv.Status
        $risultato.Evidence = @{
            ServiceName = 'WinRM'
            Status      = $statoSrv
        }

        if ($statoSrv -ne 'Running') {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Servizio WinRM fermo ($statoSrv)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Servizio WinRM in esecuzione (Running - porta remota 5985 attiva)"
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
        Verifica che il protocollo WPAD (Web Proxy Auto-Discovery) sia disabilitato per prevenire
        attacchi di intercettazione del traffico web su reti locali/Wi-Fi (HOME-NET-007).
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
        Expected = "DisableWpad = 1 oppure servizio WinHttpAutoProxySvc disabilitato"
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
            DisableWpad            = $disableWpad
            WinHttpAutoProxyStart  = $startSvc
        }

        if ($disableWpad -eq 1 -or $startSvc -eq 4) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "WPAD disabilitato (DisableWpad=$disableWpad, ServiceStart=$startSvc)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "WPAD attivo (DisableWpad=$disableWpad, ServiceStart=$startSvc)"
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
        Verifica che i protocolli crittografici obsoleti TLS 1.0 e TLS 1.1 non siano abilitati in SCHANNEL
        e controlla la configurazione di DNS over HTTPS (DoH) (HOME-NET-008).
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
        Expected = "TLS 1.0/1.1 non abilitati (Enabled != 1) e supporto DNS over HTTPS (DoH) presente"
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

        # Verifica configurazione DNS over HTTPS (DoH)
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
            $risultato.Observed = "Protocolli crittografici obsoleti abilitati: $($tlsLegacyAttivi -join ', ')"
        }
        elseif (-not $dohConfigurato) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "TLS 1.0/1.1 disabilitati, ma DNS over HTTPS (DoH) non configurato (EnableAutoDoh=$autoDoh)"
        }
        else {
            $risultato.Status   = 'superato'
            $risultato.Observed = "TLS 1.0/1.1 disabilitati e supporto DNS over HTTPS (DoH) attivo (EnableAutoDoh=$autoDoh, ServerDoH=$dohServerCount)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}
