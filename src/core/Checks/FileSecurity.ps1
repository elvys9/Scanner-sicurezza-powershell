<#
.SYNOPSIS
    Local file security, startup persistence, Scheduled Tasks, IFEO, hosts file, WMI, and browser policy checks.

.DESCRIPTION
    Implements read-only checks for:
    - HOME-FIL-001: Disguised double-extension executables in Downloads, Desktop, and Temp (Test-SuspiciousDoubleExtensionFiles)
    - HOME-FIL-002: Suspicious or obfuscated Startup Run/RunOnce registry entries (Test-StartupPersistenceEntries)
    - HOME-FIL-003: Windows hosts file integrity against DNS hijacking (Test-HostsFileIntegrity)
    - HOME-FIL-004: Suspicious or obfuscated Scheduled Tasks (Test-TaskPianificatiSospetti)
    - HOME-FIL-005: IFEO Debugger hijacking on critical executables (Test-HijackingIFEO)
    - HOME-FIL-006: Suspicious scripts or executables in Startup folders (Test-CartellaStartupUtente)
    - HOME-FIL-007: Fileless persistence via WMI Event Subscriptions (Test-WmiEventSubscriptions)
    - HOME-FIL-008: Policy-forced Chrome/Edge browser extensions (Test-BrowserForcedExtensions)
    Never modifies system state.
#>

Set-StrictMode -Version 2

function Test-SuspiciousDoubleExtensionFiles {
    <#
    .SYNOPSIS
        Performs a read-only scan of Downloads, Desktop, and Temp directories for
        disguised double-extension executables (e.g., invoice.pdf.exe, photo.jpg.scr).
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
        Expected = "0 disguised double-extension executables in Downloads, Desktop, and Temp"
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
            ScannedFolders  = $CartelleDaControllare
            ScannedFiles    = $totaleAnalizzati
            SuspiciousFiles = $fileSospetti
        }

        if ($fileSospetti.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "No suspicious double-extension files found ($totaleAnalizzati files scanned)"
        }
        else {
            $risultato.Status   = 'fallito'
            $nomiBrevi = @($fileSospetti | ForEach-Object { Split-Path -Leaf $_ })
            $risultato.Observed = "Found $($fileSospetti.Count) suspicious double-extension files: $($nomiBrevi -join ', ')"
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
        Inspects Startup registry keys (Run / RunOnce) for suspicious commands
        (execution from Temp, obfuscated PowerShell -enc, mshta, wscript).
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
        Expected = "No suspicious or obfuscated startup entries in Run/RunOnce keys"
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
            TotalRunEntries   = $vociTotali.Count
            SuspiciousEntries = $vociSospette
        }

        if ($vociSospette.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "No suspicious startup entries detected across $($vociTotali.Count) Run/RunOnce entries"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Detected $($vociSospette.Count) suspicious startup entries: $($vociSospette -join '; ')"
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
        Verifies that the Windows hosts file does not hijack security or Windows Update domains.
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
        Expected = "No hijacking of Microsoft or antivirus domains in the hosts file"
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
            $risultato.Observed = "Hosts file not present (no active redirections)"
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
            Path                = $PercorsoHosts
            CustomEntriesCount  = $righeAttive.Count
            SuspiciousRedirects = $righeSospette
        }

        if ($righeSospette.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Hosts file intact ($($righeAttive.Count) custom entries, 0 security hijacks)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Detected $($righeSospette.Count) suspicious hosts redirections: $($righeSospette -join '; ')"
        }
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Access denied while reading the hosts file"
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
        Audits non-Microsoft Scheduled Tasks for malware persistence indicators
        (execution from Temp/Users\Public, obfuscated PowerShell -enc, mshta, regsvr32, certutil) (HOME-FIL-004).
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
        Expected = "0 suspicious or obfuscated Scheduled Tasks"
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
            AnalyzedTasks   = $tasks.Count
            SuspiciousTasks = $sospetti
        }

        if ($sospetti.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "No suspicious scheduled tasks detected ($($tasks.Count) non-Microsoft tasks inspected)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Detected $($sospetti.Count) suspicious scheduled tasks: $($sospetti -join '; ')"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-ScheduledTask is not available"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Administrator privileges required to inspect all Scheduled Tasks"
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
        Verifies that no critical system or accessibility executables (sethc.exe, utilman.exe,
        taskmgr.exe, MsMpEng.exe) have an IFEO Debugger hijack configured (HOME-FIL-005).
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
        Expected = "No malicious IFEO Debugger values on critical system or accessibility executables"
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
            CheckedExecutables = $eseguibiliCritici.Count
            IfeoHijacks        = $dirottati
        }

        if ($dirottati.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "No IFEO hijacking detected on critical system executables ($($eseguibiliCritici.Count) checked)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Suspicious IFEO hijacks detected: $($dirottati -join '; ')"
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
        Scans user and common Startup folders for suspicious scripts or executables
        (.vbs, .js, .bat, .cmd, .ps1, .hta, .scr) (HOME-FIL-006).
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
        Expected = "0 suspicious scripts or executables in Startup folders"
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
            TotalStartupFiles = $totFile
            SuspiciousScripts = $trovati
        }

        if ($trovati.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "No suspicious scripts in Startup folders ($totFile items checked)"
        }
        else {
            $risultato.Status   = 'fallito'
            $nomi = @($trovati | ForEach-Object { Split-Path -Leaf $_ })
            $risultato.Observed = "Suspicious scripts/executables detected in Startup: $($nomi -join ', ')"
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
        Verifies that no malicious permanent WMI event subscriptions exist
        (fileless persistence via __EventFilter, CommandLineEventConsumer,
        ActiveScriptEventConsumer, and __FilterToConsumerBinding in root\subscription) (HOME-FIL-007).
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
        Expected = "0 suspicious permanent WMI subscriptions (CommandLineEventConsumer / ActiveScriptEventConsumer)"
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
            $nomeC  = if ($null -ne $c.PSObject.Properties['Name'] -and $null -ne $c.Name) { [string]$c.Name } else { 'UnnamedConsumer' }
            $cmdTpl = if ($null -ne $c.PSObject.Properties['CommandLineTemplate'] -and $null -ne $c.CommandLineTemplate) { [string]$c.CommandLineTemplate } else { '' }
            if ($cmdTpl.Length -gt 120) {
                $cmdTpl = $cmdTpl.Substring(0, 117) + '...'
            }
            $elementiSospetti += "CommandLineEventConsumer: $nomeC ($cmdTpl)"
        }

        foreach ($s in $scriptConsumers) {
            $nomeS  = if ($null -ne $s.PSObject.Properties['Name'] -and $null -ne $s.Name) { [string]$s.Name } else { 'UnnamedScriptConsumer' }
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
            SuspiciousItems            = $elementiSospetti
        }

        if ($elementiSospetti.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "No suspicious permanent WMI subscriptions detected in root\subscription"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Detected $($elementiSospetti.Count) suspicious WMI subscriptions: $($elementiSospetti -join '; ')"
        }
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Insufficient privileges to query WMI namespace root\subscription"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|CIM resource|Unauthorized') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to query WMI namespace root\subscription"
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
        Verifies that no browser extensions are force-installed via registry policy
        (ExtensionInstallForcelist for Google Chrome or Microsoft Edge) (HOME-FIL-008).
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
        Expected = "No policy-forced browser extensions (ExtensionInstallForcelist empty or absent)"
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
            CheckedKeys      = $chiaviBrowser.Count
            ExistingKeys     = $chiaviTrovate
            ForcedExtensions = $estensioniForzate
            TotalDetected    = $estensioniForzate.Count
        }

        if ($estensioniForzate.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "No policy-forced browser extensions detected for Chrome or Edge"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Detected $($estensioniForzate.Count) policy-forced browser extensions: $($estensioniForzate -join '; ')"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Access denied to browser policy registry keys"
        $risultato.Error    = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Access denied to browser policy registry keys"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|SecurityException') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Access denied to browser policy registry keys"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}
