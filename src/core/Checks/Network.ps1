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
