<#
.SYNOPSIS
    Controlli di sicurezza sui file locali, avvio automatico (persistenza) e file hosts.

.DESCRIPTION
    Contiene i controlli in sola lettura per:
    - HOME-FIL-001: Scansione file sospetti con doppia estensione in Download, Desktop e Temp (Test-SuspiciousDoubleExtensionFiles)
    - HOME-FIL-002: Verifica voci di avvio automatico (Run/RunOnce) contro persistenza malware (Test-StartupPersistenceEntries)
    - HOME-FIL-003: Integrita' del file hosts di Windows contro dirottamenti DNS (Test-HostsFileIntegrity)
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-SuspiciousDoubleExtensionFiles {
    <#
    .SYNOPSIS
        Scansiona in sola lettura le cartelle Download, Desktop e Temp alla ricerca di file
        eseguibili camuffati con doppia estensione (es. documento.pdf.exe, foto.jpg.scr).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [string[]]$CartelleDaControllare = @()
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "0 file eseguibili camuffati con doppia estensione in Download, Desktop e Temp"
        Evidence = $null
        Error    = $null
    }

    try {
        if ($null -eq $CartelleDaControllare -or $CartelleDaControllare.Count -eq 0) {
            $profiloUtente = [Environment]::GetFolderPath('UserProfile')
            $CartelleDaControllare = @(
                (Join-Path $profiloUtente 'Downloads'),
                (Join-Path $profiloUtente 'Desktop'),
                [System.IO.Path]::GetTempPath()
            )
        }

        # Pattern doppia estensione: (estensione documento/media/archivio) seguita da (estensione eseguibile/script)
        $patternDoppiaEstensione = '(?i)\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf|jpg|jpeg|png|gif|bmp|mp3|mp4|avi|zip|rar|7z)\.(exe|scr|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|hta|com|pif)$'

        $fileSospetti   = @()
        $totaleAnalizzati = 0

        foreach ($cartella in $CartelleDaControllare) {
            if ([string]::IsNullOrWhiteSpace($cartella)) { continue }
            if (-not (Test-Path -LiteralPath $cartella)) { continue }

            $elementi = @(Get-ChildItem -LiteralPath $cartella -File -ErrorAction SilentlyContinue | Select-Object -First 1000)
            foreach ($file in $elementi) {
                $totaleAnalizzati++
                if ($file.Name -match $patternDoppiaEstensione) {
                    $fileSospetti += $file.FullName
                }
            }
        }

        $risultato.Evidence = @{
            CartelleAnalizzate = $CartelleDaControllare
            FileAnalizzati     = $totaleAnalizzati
            FileSospetti       = $fileSospetti
        }

        if ($fileSospetti.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessun file con doppia estensione sospetta rilevato ($totaleAnalizzati file controllati)"
        }
        else {
            $risultato.Status   = 'fallito'
            $nomiBrevi = @($fileSospetti | ForEach-Object { Split-Path -Leaf $_ })
            $risultato.Observed = "Trovati $($fileSospetti.Count) file sospetti con doppia estensione: $($nomiBrevi -join ', ')"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-StartupPersistenceEntries {
    <#
    .SYNOPSIS
        Analizza le chiavi di avvio automatico (Run / RunOnce) alla ricerca di comandi
        sospetti (esecuzione da Temp, PowerShell offuscato -enc, mshta, wscript).
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
        Expected = "Nessuna voce di avvio automatico sospetta o offuscata nelle chiavi Run/RunOnce"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaviRun = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        )

        $patternSospetto = '(?i)(-enc|-EncodedCommand|-w\s+hidden|-WindowStyle\s+Hidden|mshta\.exe|wscript\.exe|cscript\.exe|regsvr32\.exe\s+/s|\\AppData\\Local\\Temp\\|\\Windows\\Temp\\)'

        $vociTotali   = @()
        $vociSospette = @()

        foreach ($percorso in $chiaviRun) {
            if (-not (Test-Path -LiteralPath $percorso)) { continue }

            $prop = Get-ItemProperty -LiteralPath $percorso -ErrorAction SilentlyContinue
            if ($null -eq $prop) { continue }

            foreach ($p in $prop.PSObject.Properties) {
                if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                    continue
                }
                $valoreCmd = [string]$p.Value
                $voceDesc  = "$($p.Name) = $valoreCmd"
                $vociTotali += $voceDesc

                if ($valoreCmd -match $patternSospetto) {
                    $vociSospette += "$($p.Name) ($percorso)"
                }
            }
        }

        $risultato.Evidence = @{
            TotaleVociRun = $vociTotali.Count
            VociSospette  = $vociSospette
        }

        if ($vociSospette.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna voce sospetta rilevata tra i $($vociTotali.Count) programmi in avvio automatico"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevate $($vociSospette.Count) voci di avvio automatico sospette: $($vociSospette -join '; ')"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-HostsFileIntegrity {
    <#
    .SYNOPSIS
        Verifica che il file hosts di Windows non contenga dirottamenti di domini di sicurezza
        o Windows Update.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [string]$PercorsoHosts = ''
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Nessun dirottamento di domini Microsoft o antivirus nel file hosts"
        Evidence = $null
        Error    = $null
    }

    try {
        if ([string]::IsNullOrWhiteSpace($PercorsoHosts)) {
            $sysRoot = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }
            $PercorsoHosts = Join-Path $sysRoot 'System32\drivers\etc\hosts'
        }

        if (-not (Test-Path -LiteralPath $PercorsoHosts)) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "File hosts non presente (nessun dirottamento attivo)"
            return $risultato
        }

        $righe = @(Get-Content -LiteralPath $PercorsoHosts -Encoding UTF8 -ErrorAction Stop)
        $righeAttive = @()
        $righeSospette = @()

        $patternDominiSensibili = '(?i)(windowsupdate\.com|update\.microsoft\.com|microsoft\.com|defender|virustotal\.com|malwarebytes\.com|kaspersky|bitdefender|avast|Norton|mcafee)'

        foreach ($riga in $righe) {
            $trimmed = $riga.Trim()
            if ($trimmed -eq '' -or $trimmed.StartsWith('#')) {
                continue
            }
            # Ignora le voci standard di localhost
            if ($trimmed -match '^(127\.0\.0\.1|::1)\s+localhost(\s|$)') {
                continue
            }
            $righeAttive += $trimmed
            if ($trimmed -match $patternDominiSensibili) {
                $righeSospette += $trimmed
            }
        }

        $risultato.Evidence = @{
            Percorso            = $PercorsoHosts
            VociPersonalizzate  = $righeAttive.Count
            DirottamentiSospetti= $righeSospette
        }

        if ($righeSospette.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "File hosts integro ($($righeAttive.Count) voci personalizzate, 0 dirottamenti di sicurezza)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevati $($righeSospette.Count) dirottamenti sospetti nel file hosts: $($righeSospette -join '; ')"
        }
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato in lettura al file hosts"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}
