<#
.SYNOPSIS
    Controlli di sicurezza sui file locali, avvio automatico (persistenza), task pianificati, IFEO e file hosts.

.DESCRIPTION
    Contiene i controlli in sola lettura per:
    - HOME-FIL-001: Scansione file sospetti con doppia estensione in Download, Desktop e Temp (Test-SuspiciousDoubleExtensionFiles)
    - HOME-FIL-002: Verifica voci di avvio automatico (Run/RunOnce) contro persistenza malware (Test-StartupPersistenceEntries)
    - HOME-FIL-003: Integrita' del file hosts di Windows contro dirottamenti DNS (Test-HostsFileIntegrity)
    - HOME-FIL-004: Verifica Attivita' pianificate (Scheduled Tasks) contro comandi offuscati (Test-TaskPianificatiSospetti)
    - HOME-FIL-005: Verifica assenza dirottamenti IFEO Debugger (Sticky Keys / TaskMgr / Defender) (Test-HijackingIFEO)
    - HOME-FIL-006: Scansione cartelle Esecuzione automatica (Startup) contro script sospetti (Test-CartellaStartupUtente)
    - HOME-FIL-007: Verifica assenza persistenza fileless via WMI Event Subscriptions (Test-WmiEventSubscriptions)
    - HOME-FIL-008: Verifica assenza estensioni browser forzate da policy Chrome/Edge (Test-BrowserForcedExtensions)
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

        $patternDoppiaEstensione = '(?i)\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf|jpg|jpeg|png|gif|bmp|mp3|mp4|avi|zip|rar|7z)\.(exe|scr|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|hta|com|pif)$'

        $fileSospetti     = @()
        $totaleAnalizzati = 0

        foreach ($cartella in $CartelleDaControllare) {
            if ([string]::IsNullOrWhiteSpace($cartella)) { continue }
            if (-not (Test-Path -LiteralPath $cartella -ErrorAction SilentlyContinue)) { continue }

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
        $righeAttive   = @()
        $righeSospette = @()

        $patternDominiSensibili = '(?i)(windowsupdate\.com|update\.microsoft\.com|microsoft\.com|defender|virustotal\.com|malwarebytes\.com|kaspersky|bitdefender|avast|Norton|mcafee)'

        foreach ($riga in $righe) {
            $trimmed = $riga.Trim()
            if ($trimmed -eq '' -or $trimmed.StartsWith('#')) {
                continue
            }
            if ($trimmed -match '^(127\.0\.0\.1|::1)\s+localhost(\s|$)') {
                continue
            }
            $righeAttive += $trimmed
            if ($trimmed -match $patternDominiSensibili) {
                $righeSospette += $trimmed
            }
        }

        $risultato.Evidence = @{
            Percorso             = $PercorsoHosts
            VociPersonalizzate   = $righeAttive.Count
            DirottamentiSospetti = $righeSospette
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

function Test-TaskPianificatiSospetti {
    <#
    .SYNOPSIS
        Analizza le Attivita' pianificate (Scheduled Tasks) alla ricerca di persistenza malware
        (esecuzione da Temp/Users\Public, PowerShell offuscato -enc, mshta, regsvr32, certutil) (HOME-FIL-004).
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
        Expected = "0 attivita' pianificate sospette o offuscate"
        Evidence = $null
        Error    = $null
    }

    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' })
        $patternCmdSospetto = '(?i)(-enc\b|-EncodedCommand|FromBase64String|DownloadString|mshta\.exe|certutil\.exe.*-urlcache|regsvr32\.exe.*scrobj|\\AppData\\Local\\Temp\\|\\Users\\Public\\)'

        $sospetti = @()
        foreach ($t in $tasks) {
            foreach ($act in $t.Actions) {
                $exe = if ($null -ne $act.PSObject.Properties['Execute']) { [string]$act.Execute } else { '' }
                $arg = if ($null -ne $act.PSObject.Properties['Arguments']) { [string]$act.Arguments } else { '' }
                $combinato = "$exe $arg".Trim()
                if ($combinato -match $patternCmdSospetto) {
                    $sospetti += "$($t.TaskName) ($combinato)"
                }
            }
        }

        $risultato.Evidence = @{
            TaskAnalizzati = $tasks.Count
            TaskSospetti   = $sospetti
        }

        if ($sospetti.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna attivita' pianificata sospetta rilevata ($($tasks.Count) task non-Microsoft verificati)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevate $($sospetti.Count) attivita' pianificate sospette: $($sospetti -join '; ')"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-ScheduledTask non disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi di amministratore richiesti per ispezionare tutte le Attivita' pianificate"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-HijackingIFEO {
    <#
    .SYNOPSIS
        Verifica che non vi siano dirottamenti di eseguibili di sistema o accessibilita'
        (Sticky Keys sethc.exe, utilman.exe, taskmgr.exe, MsMpEng.exe) tramite IFEO Debugger (HOME-FIL-005).
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
        Expected = "Nessun Debugger IFEO malevolo su eseguibili di sistema o accessibilita'"
        Evidence = $null
        Error    = $null
    }

    try {
        $baseIfeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        $eseguibiliCritici = @(
            'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe',
            'displayswitch.exe', 'atbroker.exe', 'taskmgr.exe', 'MsMpEng.exe',
            'MpCmdRun.exe', 'SecHealthUI.exe', 'regedit.exe', 'powershell.exe'
        )

        $dirottati = @()
        foreach ($exeName in $eseguibiliCritici) {
            $chiaveExe = Join-Path $baseIfeo $exeName
            if (Test-Path -LiteralPath $chiaveExe -ErrorAction SilentlyContinue) {
                $prop = Get-ItemProperty -LiteralPath $chiaveExe -Name 'Debugger' -ErrorAction SilentlyContinue
                if ($null -ne $prop -and $null -ne $prop.PSObject.Properties['Debugger'] -and (-not [string]::IsNullOrWhiteSpace([string]$prop.Debugger))) {
                    $dirottati += "$exeName -> $($prop.Debugger)"
                }
            }
        }

        $risultato.Evidence = @{
            EseguibiliControllati = $eseguibiliCritici.Count
            DirottamentiIFEO      = $dirottati
        }

        if ($dirottati.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessun dirottamento IFEO rilevato sugli eseguibili critici di sistema ($($eseguibiliCritici.Count) controllati)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevati dirottamenti IFEO sospetti: $($dirottati -join '; ')"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-CartellaStartupUtente {
    <#
    .SYNOPSIS
        Scansiona le cartelle di Esecuzione automatica (Startup utente e comune) alla ricerca di
        script o eseguibili sospetti (.vbs, .js, .bat, .cmd, .ps1, .hta, .scr) (HOME-FIL-006).
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
        Expected = "0 script o eseguibili sospetti nelle cartelle Startup"
        Evidence = $null
        Error    = $null
    }

    try {
        $cartelleStartup = @(
            [Environment]::GetFolderPath('Startup'),
            [Environment]::GetFolderPath('CommonStartup')
        )

        $patternScriptSospetto = '(?i)\.(vbs|vbe|js|jse|wsf|wsh|hta|bat|cmd|ps1|scr|pif)$'
        $trovati = @()
        $totFile = 0

        foreach ($dir in $cartelleStartup) {
            if ([string]::IsNullOrWhiteSpace($dir) -or (-not (Test-Path -LiteralPath $dir -ErrorAction SilentlyContinue))) { continue }
            $files = @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)
            foreach ($f in $files) {
                if ($f.Name -eq 'desktop.ini') { continue }
                $totFile++
                if ($f.Name -match $patternScriptSospetto) {
                    $trovati += $f.FullName
                }
            }
        }

        $risultato.Evidence = @{
            FileTotaliStartup = $totFile
            ScriptSospetti    = $trovati
        }

        if ($trovati.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuno script sospetto nelle cartelle Esecuzione automatica ($totFile elementi presenti)"
        }
        else {
            $risultato.Status   = 'fallito'
            $nomi = @($trovati | ForEach-Object { Split-Path -Leaf $_ })
            $risultato.Observed = "Rilevati script/eseguibili sospetti in Startup: $($nomi -join ', ')"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-WmiEventSubscriptions {
    <#
    .SYNOPSIS
        Verifica che non siano presenti sottoscrizioni WMI persistenti malevole
        (persistenza fileless tramite __EventFilter, CommandLineEventConsumer,
        ActiveScriptEventConsumer e __FilterToConsumerBinding in root\subscription) (HOME-FIL-007).
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
        Expected = "0 sottoscrizioni WMI persistenti sospette (CommandLineEventConsumer / ActiveScriptEventConsumer)"
        Evidence = $null
        Error    = $null
    }

    try {
        $filtri          = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop)
        $cmdConsumers    = @(Get-CimInstance -Namespace 'root\subscription' -ClassName 'CommandLineEventConsumer' -ErrorAction Stop)
        $scriptConsumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName 'ActiveScriptEventConsumer' -ErrorAction Stop)
        $bindings        = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop)

        $elementiSospetti = @()
        $filtriLegittimi = @('SCM Event Log Filter')

        foreach ($c in $cmdConsumers) {
            $nomeC  = if ($null -ne $c.PSObject.Properties['Name'] -and $null -ne $c.Name) { [string]$c.Name } else { 'ConsumerSenzaNome' }
            $cmdTpl = if ($null -ne $c.PSObject.Properties['CommandLineTemplate'] -and $null -ne $c.CommandLineTemplate) { [string]$c.CommandLineTemplate } else { '' }
            if ($cmdTpl.Length -gt 120) {
                $cmdTpl = $cmdTpl.Substring(0, 117) + '...'
            }
            $elementiSospetti += "CommandLineEventConsumer: $nomeC ($cmdTpl)"
        }

        foreach ($s in $scriptConsumers) {
            $nomeS  = if ($null -ne $s.PSObject.Properties['Name'] -and $null -ne $s.Name) { [string]$s.Name } else { 'ScriptConsumerSenzaNome' }
            $scrTxt = if ($null -ne $s.PSObject.Properties['ScriptText'] -and $null -ne $s.ScriptText) { [string]$s.ScriptText } else { '' }
            if ($scrTxt.Length -gt 120) {
                $scrTxt = $scrTxt.Substring(0, 117) + '...'
            }
            $elementiSospetti += "ActiveScriptEventConsumer: $nomeS ($scrTxt)"
        }

        foreach ($f in $filtri) {
            $fNome = if ($null -ne $f.PSObject.Properties['Name'] -and $null -ne $f.Name) { [string]$f.Name } else { '' }
            if ($filtriLegittimi -contains $fNome) { continue }
            $fQuery = if ($null -ne $f.PSObject.Properties['Query'] -and $null -ne $f.Query) { [string]$f.Query } else { '' }
            if ($fQuery.Length -gt 120) {
                $fQuery = $fQuery.Substring(0, 117) + '...'
            }
            if (($cmdConsumers.Count -gt 0 -or $scriptConsumers.Count -gt 0) -or
                ($fQuery -match '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|Win32_ProcessStartTrace)')) {
                $elementiSospetti += "EventFilter: $fNome ($fQuery)"
            }
        }

        $bindingsNonStandard = 0
        foreach ($b in $bindings) {
            $bFilt = if ($null -ne $b.PSObject.Properties['Filter'] -and $null -ne $b.Filter) { [string]$b.Filter } else { '' }
            $bCons = if ($null -ne $b.PSObject.Properties['Consumer'] -and $null -ne $b.Consumer) { [string]$b.Consumer } else { '' }
            if (($bFilt -match 'SCM Event Log Filter') -and ($bCons -match 'NTEventLogEventConsumer')) {
                continue
            }
            $bindingsNonStandard++
        }

        $risultato.Evidence = @{
            EventFiltersCount          = $filtri.Count
            CommandLineConsumersCount  = $cmdConsumers.Count
            ActiveScriptConsumersCount = $scriptConsumers.Count
            BindingsCount              = $bindings.Count
            NonStandardBindingsCount   = $bindingsNonStandard
            ElementiSospetti           = $elementiSospetti
        }

        if ($elementiSospetti.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna sottoscrizione WMI persistente sospetta rilevata in root\subscription"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevate $($elementiSospetti.Count) sottoscrizioni WMI sospette: $($elementiSospetti -join '; ')"
        }
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Privilegi insufficienti per interrogare il namespace WMI root\subscription"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|CIM resource|Unauthorized') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per interrogare il namespace WMI root\subscription"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-BrowserForcedExtensions {
    <#
    .SYNOPSIS
        Verifica che non vi siano estensioni browser forzate tramite policy di registro
        (ExtensionInstallForcelist su Google Chrome o Microsoft Edge) (HOME-FIL-008).
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
        Expected = "Nessuna estensione browser forzata da policy (ExtensionInstallForcelist vuota o assente)"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaviBrowser = @(
            @{ Browser = 'Chrome'; Hive = 'HKLM'; Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist' },
            @{ Browser = 'Chrome'; Hive = 'HKCU'; Path = 'HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist' },
            @{ Browser = 'Edge';   Hive = 'HKLM'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist' },
            @{ Browser = 'Edge';   Hive = 'HKCU'; Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist' }
        )

        $estensioniForzate = @()
        $chiaviTrovate     = @()

        foreach ($voce in $chiaviBrowser) {
            if (-not (Test-Path -LiteralPath $voce.Path -ErrorAction SilentlyContinue)) {
                continue
            }
            $chiaviTrovate += $voce.Path
            $prop = Get-ItemProperty -LiteralPath $voce.Path -ErrorAction Stop
            if ($null -eq $prop) { continue }

            foreach ($p in $prop.PSObject.Properties) {
                if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                    continue
                }
                $valEst = [string]$p.Value
                if (-not [string]::IsNullOrWhiteSpace($valEst)) {
                    $estensioniForzate += "$($voce.Browser) ($($voce.Hive)): $valEst"
                }
            }
        }

        $risultato.Evidence = @{
            ChiaviVerificate  = $chiaviBrowser.Count
            ChiaviEsistenti   = $chiaviTrovate
            EstensioniForzate = $estensioniForzate
            TotaleRilevate    = $estensioniForzate.Count
        }

        if ($estensioniForzate.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna estensione browser forzata da policy rilevata su Chrome o Edge"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevate $($estensioniForzate.Count) estensioni browser forzate da policy: $($estensioniForzate -join '; ')"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alle chiavi di policy del browser"
        $risultato.Error    = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alle chiavi di policy del browser"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|SecurityException') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Accesso negato alle chiavi di policy del browser"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}
