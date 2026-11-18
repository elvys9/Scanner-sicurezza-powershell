<#
.SYNOPSIS
    Controlli di sicurezza relativi a Windows Defender Antivirus e protezione minacce.

.DESCRIPTION
    Contiene i controlli per:
    - HOME-AV-001: Protezione in tempo reale attiva (Test-DefenderRealtime)
    - HOME-AV-002: Definizioni antivirus aggiornate negli ultimi 7 giorni (Test-DefenderSignatures)
    - HOME-AV-003: Nessuna minaccia attiva o rilevata sui file (Test-DefenderNoActiveThreats)
    - HOME-AV-004: Scansione file scaricati (IOAV) e monitoraggio comportamentale attivi (Test-DefenderBehaviorAndIoav)
    - HOME-AV-005: Protezione da applicazioni potenzialmente indesiderate PUA attiva (Test-DefenderPuaProtection)
    - HOME-AV-006: Protezione antimanomissione (Tamper Protection) e Cloud MAPS attive (Test-DefenderTamperAndCloud)
    - HOME-AV-007: Scansione antivirus eseguita negli ultimi 14 giorni (Test-DefenderRecentScan)
    - HOME-AV-008: Nessuna esclusione pericolosa in Windows Defender (Test-DefenderSafeExclusions)
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-DefenderRealtime {
    <#
    .SYNOPSIS
        Verifica che la protezione in tempo reale di Windows Defender sia attiva.
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
        catch { }

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
        catch { }

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

function Test-DefenderNoActiveThreats {
    <#
    .SYNOPSIS
        Verifica che Windows Defender non abbia rilevato minacce o malware attivi sui file.
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
        Expected = "0 minacce attive rilevate da Windows Defender"
        Evidence = $null
        Error    = $null
    }

    try {
        $rilevamenti = @(Get-MpThreatDetection -ErrorAction Stop)
        $minacceCat  = @(Get-MpThreat -ErrorAction SilentlyContinue)

        $minacceAttive = @()
        foreach ($m in $minacceCat) {
            if ($null -ne $m.PSObject.Properties['IsActive'] -and $m.IsActive) {
                $nomeMinaccia = if ($null -ne $m.PSObject.Properties['ThreatName']) { [string]$m.ThreatName } else { 'Minaccia' }
                $minacceAttive += $nomeMinaccia
            }
        }

        $risultato.Evidence = @{
            TotaleRilevamentiStorici = $rilevamenti.Count
            MinacceAttiveCount       = $minacceAttive.Count
            MinacceAttive            = $minacceAttive
        }

        if ($minacceAttive.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna minaccia attiva presente sul sistema (0 minacce attive)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevate $($minacceAttive.Count) minacce attive: $($minacceAttive -join ', ')"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpThreatDetection non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per interrogare il catalogo minacce di Defender"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderBehaviorAndIoav {
    <#
    .SYNOPSIS
        Verifica che il monitoraggio comportamentale e la scansione dei file scaricati (IOAV) siano attivi.
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
        Expected = "BehaviorMonitorEnabled = True e IoavProtectionEnabled = True"
        Evidence = $null
        Error    = $null
    }

    try {
        $statoMp = Get-MpComputerStatus -ErrorAction Stop
        $behav = [bool]$statoMp.BehaviorMonitorEnabled
        $ioav  = [bool]$statoMp.IoavProtectionEnabled

        $risultato.Evidence = @{
            BehaviorMonitorEnabled = $behav
            IoavProtectionEnabled  = $ioav
        }

        if ($behav -and $ioav) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Monitoraggio comportamentale e scansione file scaricati attivi"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "BehaviorMonitorEnabled=$behav, IoavProtectionEnabled=$ioav"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpComputerStatus non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
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

function Test-DefenderPuaProtection {
    <#
    .SYNOPSIS
        Verifica che il blocco delle applicazioni potenzialmente indesiderate (PUAProtection = 1) sia attivo.
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
        Expected = "PUAProtection = 1 (Blocco attivo)"
        Evidence = $null
        Error    = $null
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $pua = [int]$pref.PUAProtection

        $risultato.Evidence = @{
            PUAProtection = $pua
        }

        if ($pua -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Protezione PUA attiva in modalita' blocco (PUAProtection = 1)"
        }
        elseif ($pua -eq 2) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Protezione PUA solo in modalita' audit, non blocca i file (PUAProtection = 2)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Protezione PUA disattivata (PUAProtection = $pua)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpPreference non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per leggere le preferenze PUA di Defender"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderTamperAndCloud {
    <#
    .SYNOPSIS
        Verifica che la protezione antimanomissione (IsTamperProtected) e la protezione Cloud (MAPSReporting) siano attive.
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
        Expected = "IsTamperProtected = True e MAPSReporting >= 1"
        Evidence = $null
        Error    = $null
    }

    try {
        $statoMp = Get-MpComputerStatus -ErrorAction Stop
        $pref    = Get-MpPreference -ErrorAction Stop

        $tamper = [bool]$statoMp.IsTamperProtected
        $maps   = [int]$pref.MAPSReporting

        $risultato.Evidence = @{
            IsTamperProtected = $tamper
            MAPSReporting     = $maps
        }

        if ($tamper -and ($maps -ge 1)) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Tamper Protection attiva e Cloud MAPS abilitato (livello $maps)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "IsTamperProtected=$tamper, MAPSReporting=$maps"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet di Windows Defender non disponibili"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per verificare Tamper Protection e Cloud MAPS"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderRecentScan {
    <#
    .SYNOPSIS
        Verifica che una scansione antivirus (rapida o completa) sia stata eseguita negli ultimi 14 giorni.
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
        Expected = "Scansione rapida o completa eseguita negli ultimi 14 giorni"
        Evidence = $null
        Error    = $null
    }

    try {
        $statoMp = Get-MpComputerStatus -ErrorAction Stop
        $quickAge = [uint32]$statoMp.QuickScanAge
        $fullAge  = [uint32]$statoMp.FullScanAge

        $risultato.Evidence = @{
            QuickScanAge = $quickAge
            FullScanAge  = $fullAge
        }

        $minAge = if ($quickAge -lt $fullAge) { $quickAge } else { $fullAge }

        if ($minAge -le 14) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Ultima scansione eseguita $minAge giorni fa"
        }
        elseif ($minAge -eq [uint32]::MaxValue) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Nessuna scansione periodica registrata di recente"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Ultima scansione risale a $minAge giorni fa (soglia consigliata: <= 14 giorni)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpComputerStatus non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per verificare la data dell'ultima scansione"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderSafeExclusions {
    <#
    .SYNOPSIS
        Verifica che non vi siano esclusioni pericolose (es. C:\, Downloads, .exe, .ps1) in Windows Defender.
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
        Expected = "Nessuna cartella critica o estensione eseguibile esclusa da Windows Defender"
        Evidence = $null
        Error    = $null
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $paths = @()
        if ($null -ne $pref.ExclusionPath) {
            $paths = @($pref.ExclusionPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
        $exts = @()
        if ($null -ne $pref.ExclusionExtension) {
            $exts = @($pref.ExclusionExtension | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        # Se non si e' amministratori, Defender restituisce il messaggio "N/A: Must be an administrator..."
        if (($paths.Count -gt 0 -and $paths[0] -match 'Must be an administrator|amministratore') -or
            ($exts.Count -gt 0 -and $exts[0] -match 'Must be an administrator|amministratore')) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Richiede privilegi di amministratore per leggere l'elenco delle esclusioni di Defender"
            $risultato.Evidence = @{ RichiedeAdmin = $true }
            return $risultato
        }

        $esclusioniPericolose = @()
        foreach ($p in $paths) {
            $pNorm = $p.TrimEnd('\')
            if ($pNorm -match '^[A-Za-z]:$' -or
                $pNorm -match '(?i)\\Windows$' -or
                $pNorm -match '(?i)\\Users$' -or
                $pNorm -match '(?i)\\Downloads$' -or
                $pNorm -match '(?i)\\Temp$' -or
                $pNorm -match '(?i)\\AppData$') {
                $esclusioniPericolose += "Percorso: $p"
            }
        }

        foreach ($e in $exts) {
            $eNorm = $e.Trim().TrimStart('.').ToLowerInvariant()
            if ($eNorm -in @('exe', 'dll', 'ps1', 'bat', 'cmd', 'vbs', 'js', 'scr', 'hta', 'msi', '*')) {
                $esclusioniPericolose += "Estensione: .$eNorm"
            }
        }

        $risultato.Evidence = @{
            ExclusionPathCount      = $paths.Count
            ExclusionExtensionCount = $exts.Count
            EsclusioniPericolose    = $esclusioniPericolose
        }

        if ($esclusioniPericolose.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna esclusione critica trovata ($($paths.Count) percorsi, $($exts.Count) estensioni)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Esclusioni ad alto rischio rilevate: $($esclusioniPericolose -join '; ')"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpPreference non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per verificare le esclusioni di Windows Defender"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderRansomwareCartelle {
    <#
    .SYNOPSIS
        Verifica che l'Accesso alle cartelle controllato (Controlled Folder Access anti-ransomware) sia attivo (HOME-AV-009).
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
        Expected = "EnableControlledFolderAccess = 1 (Blocco anti-ransomware attivo)"
        Evidence = $null
        Error    = $null
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $cfa  = [int]$pref.EnableControlledFolderAccess

        $risultato.Evidence = @{
            EnableControlledFolderAccess = $cfa
        }

        if ($cfa -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Protezione ransomware (Accesso alle cartelle controllato) attiva (1)"
        }
        elseif ($cfa -eq 2) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Accesso alle cartelle controllato solo in modalita' audit (2)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Accesso alle cartelle controllato disattivato ($cfa)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpPreference non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per leggere EnableControlledFolderAccess"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderNetworkProtection {
    <#
    .SYNOPSIS
        Verifica che la Protezione di rete di Microsoft Defender Exploit Guard (EnableNetworkProtection = 1) sia attiva (HOME-AV-010).
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
        Expected = "EnableNetworkProtection = 1 (Blocco domini malevoli attivo)"
        Evidence = $null
        Error    = $null
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $netP = [int]$pref.EnableNetworkProtection

        $risultato.Evidence = @{
            EnableNetworkProtection = $netP
        }

        if ($netP -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Protezione di rete Defender Exploit Guard attiva in modalita' blocco (1)"
        }
        elseif ($netP -eq 2) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Protezione di rete solo in modalita' audit (2)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Protezione di rete disattivata ($netP)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpPreference non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per leggere EnableNetworkProtection"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}
