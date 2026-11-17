<#
.SYNOPSIS
    Controlli di sicurezza relativi a Windows Defender Antivirus.

.DESCRIPTION
    Contiene i controlli per:
    - HOME-AV-001: Protezione in tempo reale attiva (Test-DefenderRealtime)
    - HOME-AV-002: Definizioni antivirus aggiornate negli ultimi 7 giorni (Test-DefenderSignatures)
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-DefenderRealtime {
    <#
    .SYNOPSIS
        Verifica che la protezione in tempo reale di Windows Defender sia attiva.
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
        Expected = "AntivirusEnabled = True e RealTimeProtectionEnabled = True"
        Evidence = $null
        Error    = $null
    }

    try {
        $statoMp = Get-MpComputerStatus -ErrorAction Stop
        $avAttivo = [bool]$statoMp.AntivirusEnabled
        $rtAttivo = [bool]$statoMp.RealTimeProtectionEnabled

        $risultato.Evidence = @{
            AntivirusEnabled          = $avAttivo
            RealTimeProtectionEnabled = $rtAttivo
            Fonte                     = 'Get-MpComputerStatus'
        }

        if ($avAttivo -and $rtAttivo) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Protezione in tempo reale e antivirus attivi"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "AntivirusEnabled=$avAttivo, RealTimeProtectionEnabled=$rtAttivo"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpComputerStatus non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        # Fallback su lettura del registro di Windows Defender se CIM non e' raggiungibile
        try {
            $regDef = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
            $regRt  = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'
            if (Test-Path -LiteralPath $regDef) {
                $propDef = Get-ItemProperty -LiteralPath $regDef -ErrorAction Stop
                $disAv = if ($null -ne $propDef.PSObject.Properties['DisableAntiVirus']) { [int]$propDef.DisableAntiVirus } else { 0 }
                $disAs = if ($null -ne $propDef.PSObject.Properties['DisableAntiSpyware']) { [int]$propDef.DisableAntiSpyware } else { 0 }
                $disRt = 0
                if (Test-Path -LiteralPath $regRt) {
                    $propRt = Get-ItemProperty -LiteralPath $regRt -ErrorAction SilentlyContinue
                    if ($null -ne $propRt -and $null -ne $propRt.PSObject.Properties['DisableRealtimeMonitoring'] -and $null -ne $propRt.DisableRealtimeMonitoring) {
                        $disRt = [int]$propRt.DisableRealtimeMonitoring
                    }
                }

                $risultato.Evidence = @{
                    DisableAntiVirus          = $disAv
                    DisableAntiSpyware        = $disAs
                    DisableRealtimeMonitoring = $disRt
                    Fonte                     = 'RegistryFallback'
                }

                if ($disAv -eq 0 -and $disAs -eq 0 -and $disRt -eq 0) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Protezione in tempo reale attiva (rilevato da registro)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "Protezione disattivata nel registro (DisableRealtimeMonitoring=$disRt)"
                }
                return $risultato
            }
        }
        catch {
            # Ignora errore fallback e gestisci sotto
        }

        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per interrogare Windows Defender"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderSignatures {
    <#
    .SYNOPSIS
        Verifica che le definizioni di Windows Defender siano aggiornate (<= 7 giorni).
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
        Expected = "Eta' definizioni antivirus <= 7 giorni"
        Evidence = $null
        Error    = $null
    }

    try {
        $statoMp = Get-MpComputerStatus -ErrorAction Stop
        $etaGiorni = [int]$statoMp.AntivirusSignatureAge

        $risultato.Evidence = @{
            AntivirusSignatureAge = $etaGiorni
            Fonte                 = 'Get-MpComputerStatus'
        }

        if ($etaGiorni -le 7) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Definizioni aggiornate ($etaGiorni giorni fa)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Definizioni obsolete ($etaGiorni giorni fa, soglia massima: 7 giorni)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpComputerStatus non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        # Fallback su registro Signature Updates
        try {
            $regSig = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates'
            if (Test-Path -LiteralPath $regSig) {
                $propSig = Get-ItemProperty -LiteralPath $regSig -ErrorAction Stop
                if ($null -ne $propSig.PSObject.Properties['SignaturesLastUpdated'] -and $null -ne $propSig.SignaturesLastUpdated) {
                    $bytes = [byte[]]$propSig.SignaturesLastUpdated
                    if ($bytes.Length -ge 8) {
                        $fileTime = [System.BitConverter]::ToInt64($bytes, 0)
                        if ($fileTime -gt 0) {
                            $dataAgg = [datetime]::FromFileTimeUtc($fileTime)
                            $giorni = [int][math]::Floor(((Get-Date).ToUniversalTime() - $dataAgg).TotalDays)
                            if ($giorni -lt 0) { $giorni = 0 }

                            $risultato.Evidence = @{
                                AntivirusSignatureAge = $giorni
                                LastUpdatedUtc        = $dataAgg.ToString('o')
                                Fonte                 = 'RegistryFallback'
                            }
                            if ($giorni -le 7) {
                                $risultato.Status   = 'superato'
                                $risultato.Observed = "Definizioni aggiornate ($giorni giorni fa)"
                            }
                            else {
                                $risultato.Status   = 'fallito'
                                $risultato.Observed = "Definizioni obsolete ($giorni giorni fa)"
                            }
                            return $risultato
                        }
                    }
                }
            }
        }
        catch {
            # Ignora errore fallback
        }

        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per verificare le firme di Windows Defender"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}
