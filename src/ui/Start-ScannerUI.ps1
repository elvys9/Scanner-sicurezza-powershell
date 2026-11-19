<#
.SYNOPSIS
    Launches the WPF graphical user interface (or SSH console TUI) for the Windows 11 Security Scanner.

.DESCRIPTION
    Loads the XAML layout from src/ui/MainWindow.xaml via XamlReader,
    binds controls via FindName, manages Dark/Light themes, trilingual
    localization (IT / EN / DE), filters, details panel, JSON/HTML export,
    opt-in WinUtil-style remediation / rollback, and asynchronous Runspace execution.
    The audit phase operates strictly in read-only mode via src/core.
#>

Set-StrictMode -Version 2

function Update-TemaFinestra {
    <#
    .SYNOPSIS
        Applies the Dark or Light theme color dictionary to the window resources.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Finestra,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Chiaro', 'Scuro')]
        [string]$Tema
    )

    $convertitore = New-Object System.Windows.Media.BrushConverter

    if ($Tema -eq 'Scuro') {
        $mappaColori = @{
            'BgPrimary'        = '#0B0F19'
            'BgSurface'        = '#111827'
            'BgElevated'       = '#1E293B'
            'BgHeader'         = '#060911'
            'TextHeader'       = '#F8FAFC'
            'BgSubtle'         = '#0F172A'
            'BgInput'          = '#0F172A'
            'BgAlternating'    = '#131C2E'
            'SelectedRowBg'    = '#1E3A8A'
            'SelectedRowFg'    = '#FFFFFF'
            'HoverRowBg'       = '#1E293B'
            'TextPrimary'      = '#F1F5F9'
            'TextSecondary'    = '#94A3B8'
            'BorderSubtle'     = '#1E293B'
            'BorderStrong'     = '#334155'
            'AccentBrush'      = '#3B82F6'
            'AccentText'       = '#FFFFFF'
            'PassBg'           = '#064E3B'
            'PassFg'           = '#6EE7B7'
            'PassBorder'       = '#10B981'
            'FailBg'           = '#7F1D1D'
            'FailFg'           = '#FCA5A5'
            'FailBorder'       = '#EF4444'
            'UnknownBg'        = '#1E293B'
            'UnknownFg'        = '#CBD5E1'
            'UnknownBorder'    = '#64748B'
            'NaBg'             = '#0F172A'
            'NaFg'             = '#94A3B8'
            'NaBorder'         = '#475569'
            'ErrorBg'          = '#7C2D12'
            'ErrorFg'          = '#FDBA74'
            'ErrorBorder'      = '#F97316'
            'WarnBannerBg'     = '#451A03'
            'WarnBannerFg'     = '#FDE68A'
            'WarnBannerBorder' = '#D97706'
        }
    }
    else {
        $mappaColori = @{
            'BgPrimary'        = '#F1F5F9'
            'BgSurface'        = '#FFFFFF'
            'BgElevated'       = '#F8FAFC'
            'BgHeader'         = '#0F172A'
            'TextHeader'       = '#F8FAFC'
            'BgSubtle'         = '#F8FAFC'
            'BgInput'          = '#FFFFFF'
            'BgAlternating'    = '#F8FAFC'
            'SelectedRowBg'    = '#DBEAFE'
            'SelectedRowFg'    = '#1E3A8A'
            'HoverRowBg'       = '#EFF6FF'
            'TextPrimary'      = '#0F172A'
            'TextSecondary'    = '#475569'
            'BorderSubtle'     = '#E2E8F0'
            'BorderStrong'     = '#CBD5E1'
            'AccentBrush'      = '#2563EB'
            'AccentText'       = '#FFFFFF'
            'PassBg'           = '#ECFDF5'
            'PassFg'           = '#065F46'
            'PassBorder'       = '#10B981'
            'FailBg'           = '#FEF2F2'
            'FailFg'           = '#991B1B'
            'FailBorder'       = '#EF4444'
            'UnknownBg'        = '#F1F5F9'
            'UnknownFg'        = '#334155'
            'UnknownBorder'    = '#64748B'
            'NaBg'             = '#F8FAFC'
            'NaFg'             = '#64748B'
            'NaBorder'         = '#94A3B8'
            'ErrorBg'          = '#FFF7ED'
            'ErrorFg'          = '#9A3412'
            'ErrorBorder'      = '#F97316'
            'WarnBannerBg'     = '#FFFBEB'
            'WarnBannerFg'     = '#92400E'
            'WarnBannerBorder' = '#F59E0B'
        }
    }

    foreach ($chiave in $mappaColori.Keys) {
        $pennello = $convertitore.ConvertFromString($mappaColori[$chiave])
        $Finestra.Resources[$chiave] = $pennello
    }
}

function Test-SessioneTerminaleSsh {
    <#
    .SYNOPSIS
        Rileva se PowerShell e' in esecuzione all'interno di una sessione SSH o in Sessione 0
        priva di desktop grafico interattivo (dove una finestra WPF rimarrebbe invisibile/bloccata).
    #>
    [CmdletBinding()]
    param()

    if (-not [string]::IsNullOrWhiteSpace($env:SSH_CONNECTION) -or
        -not [string]::IsNullOrWhiteSpace($env:SSH_CLIENT) -or
        -not [string]::IsNullOrWhiteSpace($env:SSH_TTY)) {
        return $true
    }

    try {
        if (-not [Environment]::UserInteractive) {
            return $true
        }
        $procCorr = Get-Process -Id $PID -ErrorAction SilentlyContinue
        if ($null -ne $procCorr -and $procCorr.SessionId -eq 0) {
            return $true
        }
        # Verifica se il processo padre o antenato e' sshd
        $currPid = $PID
        for ($depth = 0; $depth -lt 4; $depth++) {
            $wmiProc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $currPid" -ErrorAction SilentlyContinue
            if ($null -eq $wmiProc) { break }
            if ($wmiProc.Name -match '^(sshd|ssh-shellhost)(\.exe)?$') {
                return $true
            }
            $parentId = [int]$wmiProc.ParentProcessId
            if ($parentId -le 0 -or $parentId -eq $currPid) { break }
            $pObj = Get-Process -Id $parentId -ErrorAction SilentlyContinue
            if ($null -ne $pObj -and $pObj.ProcessName -match '^(sshd|ssh-shellhost)$') {
                return $true
            }
            $currPid = $parentId
        }
    }
    catch { }

    return $false
}

function Show-ScannerConsoleUI {
    <#
    .SYNOPSIS
        Interfaccia interattiva da terminale (TUI / CLI) per sessioni SSH o console senza GUI.
        Supporta scansione in tempo reale dei 50 controlli, tabella colorata, ispezione dettagli,
        Resoconto IA con Ollama (con auto-setup sulla VM), cambio lingua (IT/EN/DE) ed export JSON/HTML.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Catalogo,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Ambiente,

        [Parameter(Mandatory = $false)]
        [string]$PercorsoProgetto = '',

        [Parameter(Mandatory = $false)]
        [string[]]$ControlId = @(),

        [Parameter(Mandatory = $false)]
        [string]$VersioneTool = '0.2.0',

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$LinguaIniziale = 'IT',

        [Parameter(Mandatory = $false)]
        [switch]$NonInterattivo
    )

    $lingua = $LinguaIniziale
    $percorsoChecks = if ($PercorsoProgetto) { Join-Path $PercorsoProgetto 'src\core\Checks' } else { '' }
    $totaleCat = @($Catalogo.controls).Count
    $risultatiGrezzi = @()
    $elementiVista   = @()

    $eseguiScansioneConsole = {
        $lblAvvio = switch ($lingua) {
            'EN' { "Running security audit ($totaleCat deterministic controls) in read-only mode..." }
            'DE' { "Sicherheitspruefung wird ausgefuehrt ($totaleCat deterministische Pruefungen, schreibgeschuetzt)..." }
            default { "Esecuzione scansione di sicurezza ($totaleCat controlli deterministici) in sola lettura..." }
        }
        Write-Host ""
        Write-Host "================================================================================" -ForegroundColor DarkCyan
        Write-Host "  $lblAvvio" -ForegroundColor Cyan
        Write-Host "================================================================================" -ForegroundColor DarkCyan

        $onProg = {
            param($idx, $tot, $res)
            $simbolo = switch ($res.status) {
                'superato'        { '[OK]' }
                'fallito'         { '[X] ' }
                'sconosciuto'     { '[?] ' }
                'non_applicabile' { '[-] ' }
                default           { '[!] ' }
            }
            $colore = switch ($res.status) {
                'superato'        { 'Green' }
                'fallito'         { 'Red' }
                'sconosciuto'     { 'Yellow' }
                'non_applicabile' { 'DarkGray' }
                default           { 'Magenta' }
            }
            $pct = if ($tot -gt 0) { [int](($idx * 100) / $tot) } else { 100 }
            $barra = ('#' * [int]($pct / 5)).PadRight(20, '.')
            Write-Host ("  [{0,2}/{1,2}] [{2}] {3} {4}" -f $idx, $tot, $barra, $simbolo, $res.control_id) -ForegroundColor $colore
        }

        $paramRun = @{
            Catalogo       = $Catalogo
            Ambiente       = $Ambiente
            CartellaChecks = $percorsoChecks
            OnProgress     = $onProg
        }
        if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
            $paramRun['ControlId'] = $ControlId
        }

        $script:ConsoleRisultatiGrezzi = Invoke-Controlli @paramRun
        $script:ConsoleElementiVista   = @(ConvertTo-RisultatiVista -Risultati $script:ConsoleRisultatiGrezzi -Catalogo $Catalogo -Lingua $lingua)
    }

    $mostraRiepilogoETabella = {
        $script:ConsoleElementiVista = @(ConvertTo-RisultatiVista -Risultati $script:ConsoleRisultatiGrezzi -Catalogo $Catalogo -Lingua $lingua)
        $cnt = Measure-ConteggiRisultati -Elementi $script:ConsoleRisultatiGrezzi

        $titoloBanner = switch ($lingua) {
            'EN' { "WINDOWS 11 SECURITY SCANNER (SSH / TERMINAL MODE - READ-ONLY)" }
            'DE' { "WINDOWS 11 SICHERHEITSSCANNER (SSH / TERMINAL-MODUS - NUR LESEN)" }
            default { "SCANNER SICUREZZA WINDOWS 11 (MODALITA' TERMINALE SSH - SOLA LETTURA)" }
        }
        $adminTxt = if ($Ambiente.IsAdmin) {
            switch ($lingua) { 'EN' { 'Yes' } 'DE' { 'Ja' } default { 'Si' } }
        } else {
            switch ($lingua) { 'DE' { 'Nein (Eingeschraenkt)' } 'EN' { 'No (Limited)' } default { 'No (Limitato)' } }
        }

        Write-Host ""
        Write-Host "================================================================================" -ForegroundColor Blue
        Write-Host "  $titoloBanner" -ForegroundColor White
        Write-Host "  OS: Windows 11 $($Ambiente.Edition) ($($Ambiente.Build)) | Admin: $adminTxt | Lang: [$lingua]" -ForegroundColor Gray
        Write-Host "================================================================================" -ForegroundColor Blue

        if (-not $Ambiente.IsAdmin) {
            $warnAdm = switch ($lingua) {
                'EN' { "  [!] Non-Admin SSH session: some checks report 'Unknown'. Connect as an Admin user for full results." }
                'DE' { "  [!] SSH-Sitzung ohne Admin-Rechte: Einige Pruefungen melden 'Unbekannt'." }
                default { "  [!] Sessione SSH non amministrativa: alcuni controlli risultano 'Sconosciuto'." }
            }
            Write-Host $warnAdm -ForegroundColor Yellow
        }

        # Contatori KPI colorati
        Write-Host ""
        switch ($lingua) {
            'EN' {
                Write-Host "  [OK] $($cnt.superato) Passed   " -NoNewline -ForegroundColor Green
                Write-Host "[X] $($cnt.fallito) Failed   " -NoNewline -ForegroundColor Red
                Write-Host "[?] $($cnt.sconosciuto) Unknown   " -NoNewline -ForegroundColor Yellow
                Write-Host "[-] $($cnt.non_applicabile) N/A   " -NoNewline -ForegroundColor DarkGray
                Write-Host "[!] $($cnt.errore) Errors" -ForegroundColor Magenta
            }
            'DE' {
                Write-Host "  [OK] $($cnt.superato) Bestanden   " -NoNewline -ForegroundColor Green
                Write-Host "[X] $($cnt.fallito) Fehlgeschlagen   " -NoNewline -ForegroundColor Red
                Write-Host "[?] $($cnt.sconosciuto) Unbekannt   " -NoNewline -ForegroundColor Yellow
                Write-Host "[-] $($cnt.non_applicabile) N/Z   " -NoNewline -ForegroundColor DarkGray
                Write-Host "[!] $($cnt.errore) Fehler" -ForegroundColor Magenta
            }
            default {
                Write-Host "  [OK] $($cnt.superato) Superati   " -NoNewline -ForegroundColor Green
                Write-Host "[X] $($cnt.fallito) Falliti   " -NoNewline -ForegroundColor Red
                Write-Host "[?] $($cnt.sconosciuto) Sconosciuti   " -NoNewline -ForegroundColor Yellow
                Write-Host "[-] $($cnt.non_applicabile) N/A   " -NoNewline -ForegroundColor DarkGray
                Write-Host "[!] $($cnt.errore) Errori" -ForegroundColor Magenta
            }
        }
        Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray

        $hdr = switch ($lingua) {
            'EN' { ("{0,-16} {1,-10} {2,-18} {3,-14} {4}" -f "STATUS", "SEVERITY", "CATEGORY", "ID", "SECURITY CONTROL") }
            'DE' { ("{0,-18} {1,-10} {2,-21} {3,-14} {4}" -f "STATUS", "SCHWERE", "KATEGORIE", "ID", "SICHERHEITSPRUEFUNG") }
            default { ("{0,-16} {1,-10} {2,-20} {3,-14} {4}" -f "STATO", "GRAVITA'", "CATEGORIA", "ID", "CONTROLLO") }
        }
        Write-Host "  $hdr" -ForegroundColor Cyan
        Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray

        foreach ($el in $script:ConsoleElementiVista) {
            $colRiga = switch ($el.Status) {
                'superato'        { 'Green' }
                'fallito'         { 'Red' }
                'sconosciuto'     { 'Yellow' }
                'non_applicabile' { 'DarkGray' }
                default           { 'Magenta' }
            }
            $catTronc = if ($el.Category.Length -gt 18) { $el.Category.Substring(0, 17) + '.' } else { $el.Category }
            $titTronc = if ($el.Title.Length -gt 48) { $el.Title.Substring(0, 45) + '...' } else { $el.Title }
            $rigaTxt = ("  {0,-16} {1,-10} {2,-18} {3,-14} {4}" -f $el.StatusLabel, $el.SeverityLabel, $catTronc, $el.ControlId, $titTronc)
            Write-Host $rigaTxt -ForegroundColor $colRiga
        }
        Write-Host "================================================================================" -ForegroundColor Blue
    }

    # Esegui la scansione iniziale
    & $eseguiScansioneConsole
    & $mostraRiepilogoETabella

    if ($NonInterattivo) {
        return
    }

    # Loop Menu Interattivo da Terminale SSH
    $continuaLoop = $true
    while ($continuaLoop) {
        Write-Host ""
        switch ($lingua) {
            'EN' {
                Write-Host "  SSH INTERACTIVE MENU (Active Language: [*] EN English):" -ForegroundColor Cyan
                Write-Host "  [1] Inspect all FAILED controls (details & remediation commands)" -ForegroundColor White
                Write-Host "  [2] Generate FULL PC AI SECURITY REPORT (Local Ollama / Auto-Setup)" -ForegroundColor Magenta
                Write-Host "  [3] Inspect or explain a specific control by ID (e.g. HOME-ENC-001)" -ForegroundColor White
                Write-Host "  [4] Switch Language: [IT Italiano] / [EN English] / [DE Deutsch]" -ForegroundColor Yellow
                Write-Host "  [5] Export JSON & HTML reports to disk" -ForegroundColor Green
                Write-Host "  [R] Re-run security scan ($totaleCat controls)" -ForegroundColor Gray
                Write-Host "  [Q] Quit" -ForegroundColor Gray
                $promptScelta = "  Select an option (1-5, R, Q)"
            }
            'DE' {
                Write-Host "  INTERAKTIVES SSH-MENUE (Aktive Sprache: [*] DE Deutsch):" -ForegroundColor Cyan
                Write-Host "  [1] Alle FEHLGESCHLAGENEN Pruefungen anzeigen (Details & Befehle)" -ForegroundColor White
                Write-Host "  [2] VOLLSTAENDIGEN KI-SICHERHEITSBERICHT erstellen (Lokales Ollama)" -ForegroundColor Magenta
                Write-Host "  [3] Einzelne Pruefung per ID untersuchen/erklaeren (z. B. HOME-ENC-001)" -ForegroundColor White
                Write-Host "  [4] Sprache wechseln: [IT Italiano] / [EN English] / [DE Deutsch]" -ForegroundColor Yellow
                Write-Host "  [5] JSON- & HTML-Berichte auf Festplatte exportieren" -ForegroundColor Green
                Write-Host "  [R] Sicherheitsscan erneut starten ($totaleCat Pruefungen)" -ForegroundColor Gray
                Write-Host "  [Q] Beenden" -ForegroundColor Gray
                $promptScelta = "  Option waehlen (1-5, R, Q)"
            }
            default {
                Write-Host "  MENU INTERATTIVO TERMINALE SSH (Lingua attiva: [*] IT Italiano):" -ForegroundColor Cyan
                Write-Host "  [1] Mostra dettagli e comandi di correzione di tutti i controlli FALLITI" -ForegroundColor White
                Write-Host "  [2] Genera RESOCONTO COMPLETO IA (Ollama locale / Auto-Setup VM)" -ForegroundColor Magenta
                Write-Host "  [3] Ispeziona o spiega con IA un controllo specifico tramite ID (es. HOME-ENC-001)" -ForegroundColor White
                Write-Host "  [4] Cambia Lingua: [IT Italiano] / [EN English] / [DE Deutsch]" -ForegroundColor Yellow
                Write-Host "  [5] Esporta report JSON e HTML su disco" -ForegroundColor Green
                Write-Host "  [R] Riesegui la scansione ($totaleCat controlli)" -ForegroundColor Gray
                Write-Host "  [Q] Esci" -ForegroundColor Gray
                $promptScelta = "  Scegli un'opzione (1-5, R, Q)"
            }
        }

        $scelta = Read-Host $promptScelta
        if ($null -eq $scelta) { break }
        $sceltaNorm = $scelta.Trim().ToUpperInvariant()

        switch ($sceltaNorm) {
            '1' {
                $falliti = @($script:ConsoleElementiVista | Where-Object { $_.Status -eq 'fallito' })
                if ($falliti.Count -eq 0) {
                    $msgZero = switch ($lingua) {
                        'EN' { "  [OK] No failed controls found!" }
                        'DE' { "  [OK] Keine fehlgeschlagenen Pruefungen gefunden!" }
                        default { "  [OK] Nessun controllo fallito rilevato!" }
                    }
                    Write-Host $msgZero -ForegroundColor Green
                }
                else {
                    foreach ($f in $falliti) {
                        $det = Format-DettaglioControllo -Elemento $f -Modalita 'Semplice' -Lingua $lingua
                        Write-Host ""
                        Write-Host "  ----------------------------------------------------------------------------" -ForegroundColor DarkRed
                        Write-Host "  $($det.StatusLabel) | [$($det.SeverityLabel)] $($det.ControlId) - $($det.Title)" -ForegroundColor Red
                        Write-Host "  Observed: $($det.ValoreOsservato)" -ForegroundColor Yellow
                        Write-Host "  Expected: $($det.ValoreAtteso)" -ForegroundColor Gray
                        Write-Host "  Why:      $($det.TestoSpiegazione)" -ForegroundColor White
                        Write-Host "  Fix:      $($det.TestoRimedio)" -ForegroundColor Cyan
                        if ($det.HaComando) {
                            Write-Host "  Command:  $($det.ComandoRimedio)" -ForegroundColor Green
                        }
                    }
                }
            }
            '2' {
                $cnt = Measure-ConteggiRisultati -Elementi $script:ConsoleRisultatiGrezzi
                $promptRes   = Format-PromptResocontoOllama -ElementiVista $script:ConsoleElementiVista -Conteggi $cnt -Ambiente $Ambiente -Lingua $lingua
                $fallbackRes = Format-ResocontoLocaleScansione -ElementiVista $script:ConsoleElementiVista -Conteggi $cnt -Ambiente $Ambiente -Lingua $lingua

                $cbStatoConsole = {
                    param([string]$msg)
                    Write-Host "  [Ollama] $msg" -ForegroundColor DarkCyan
                }
                Write-Host ""
                $esitoIa = Invoke-RichiestaOllama -Prompt $promptRes -Modello 'qwen2.5:0.5b' -Endpoint 'http://127.0.0.1:11434' -TestoFallbackLocale $fallbackRes -AutoProvision $true -Lingua $lingua -OnStatus $cbStatoConsole
                Write-Host ""
                Write-Host "================================================================================" -ForegroundColor Magenta
                Write-Host "  $($esitoIa.Sorgente)" -ForegroundColor Cyan
                Write-Host "================================================================================" -ForegroundColor Magenta
                Write-Host $esitoIa.Risposta -ForegroundColor White
                Write-Host "================================================================================" -ForegroundColor Magenta
            }
            '3' {
                $msgAskId = switch ($lingua) {
                    'EN' { "  Enter Control ID (e.g. HOME-ENC-001, HOME-AV-009)" }
                    'DE' { "  Pruefungs-ID eingeben (z. B. HOME-ENC-001, HOME-AV-009)" }
                    default { "  Inserisci l'ID del controllo (es. HOME-ENC-001, HOME-AV-009)" }
                }
                $idCercato = (Read-Host $msgAskId).Trim().ToUpperInvariant()
                $elTrovato = $script:ConsoleElementiVista | Where-Object { $_.ControlId.ToUpperInvariant() -eq $idCercato } | Select-Object -First 1
                if ($null -eq $elTrovato) {
                    Write-Host "  [!] ID '$idCercato' non trovato." -ForegroundColor Yellow
                }
                else {
                    $det = Format-DettaglioControllo -Elemento $elTrovato -Modalita 'Semplice' -Lingua $lingua
                    $promptCtrl  = Format-PromptControlloOllama -Dettaglio $det -Ambiente $Ambiente -Lingua $lingua
                    $fallbackLoc = Format-AnalisiLocaleControllo -Dettaglio $det -Ambiente $Ambiente -Lingua $lingua
                    $esitoCtrl = Invoke-RichiestaOllama -Prompt $promptCtrl -Modello 'qwen2.5:0.5b' -Endpoint 'http://127.0.0.1:11434' -TestoFallbackLocale $fallbackLoc -AutoProvision $true -Lingua $lingua
                    Write-Host ""
                    Write-Host $esitoCtrl.Risposta -ForegroundColor White
                }
            }
            '4' {
                $sceltaLang = (Read-Host "  Choose language / Lingua / Sprache (IT / EN / DE)").Trim().ToUpperInvariant()
                if ($sceltaLang -in @('IT', 'EN', 'DE')) {
                    $lingua = $sceltaLang
                }
                else {
                    $lingua = switch ($lingua) { 'IT' { 'EN' } 'EN' { 'DE' } default { 'IT' } }
                }
                & $mostraRiepilogoETabella
            }
            '5' {
                $dirOut = (Get-Location).Path
                $fileJson = Join-Path $dirOut (Get-NomeFileExport -Estensione 'json')
                $fileHtml = Join-Path $dirOut (Get-NomeFileExport -Estensione 'html')
                $rep = New-Report -Risultati $script:ConsoleRisultatiGrezzi -Ambiente $Ambiente -Catalogo $Catalogo -VersioneTool $VersioneTool
                Export-ReportJson -Report $rep -PercorsoFile $fileJson
                Export-ReportHtml -Report $rep -Catalogo $Catalogo -PercorsoFile $fileHtml
                Write-Host "  [OK] JSON: $fileJson" -ForegroundColor Green
                Write-Host "  [OK] HTML: $fileHtml" -ForegroundColor Green
            }
            'R' {
                & $eseguiScansioneConsole
                & $mostraRiepilogoETabella
            }
            'Q' {
                $continuaLoop = $false
            }
            default {
                & $mostraRiepilogoETabella
            }
        }
    }
}

function Start-ScannerUI {
    <#
    .SYNOPSIS
        Costruisce e mostra la finestra WPF dello scanner di sicurezza.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Catalogo,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Ambiente,

        [Parameter(Mandatory = $false)]
        [string]$PercorsoProgetto = '',

        [Parameter(Mandatory = $false)]
        [string]$ContenutoXaml = '',

        [Parameter(Mandatory = $false)]
        [string[]]$ControlId = @(),

        [Parameter(Mandatory = $false)]
        [string]$VersioneTool = '0.1.0',

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$LinguaIniziale = 'IT'
    )

    # Se lo script viene eseguito in una sessione SSH o priva di desktop interattivo,
    # passa automaticamente alla modalita' interattiva da terminale (TUI / Console)
    if (Test-SessioneTerminaleSsh) {
        Show-ScannerConsoleUI -Catalogo $Catalogo -Ambiente $Ambiente -PercorsoProgetto $PercorsoProgetto -ControlId $ControlId -VersioneTool $VersioneTool -LinguaIniziale $LinguaIniziale
        return
    }

    # Verifica che il thread corrente sia STA (obbligatorio per WPF)
    if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne [System.Threading.ApartmentState]::STA) {
        throw "La modalita' grafica WPF richiede un thread STA (avviare PowerShell con -STA)."
    }

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

    $percorsoUi          = if ($PercorsoProgetto) { Join-Path $PercorsoProgetto 'src\ui' } else { '' }
    $percorsoCore        = if ($PercorsoProgetto) { Join-Path $PercorsoProgetto 'src\core' } else { '' }
    $percorsoChecks      = if ($percorsoCore) { Join-Path $percorsoCore 'Checks' } else { '' }
    $percorsoRemediation = if ($PercorsoProgetto) { Join-Path $PercorsoProgetto 'src\remediation' } else { '' }

    if ([string]::IsNullOrWhiteSpace($ContenutoXaml)) {
        $percorsoXaml = Join-Path $percorsoUi 'MainWindow.xaml'
        if (-not (Test-Path -LiteralPath $percorsoXaml)) {
            throw "File XAML dell'interfaccia non trovato: $percorsoXaml"
        }
        $ContenutoXaml = Get-Content -LiteralPath $percorsoXaml -Raw -Encoding UTF8
    }

    # Carica il contenuto XAML con XamlReader
    [xml]$xmlXaml = $ContenutoXaml
    $lettoreXml = New-Object System.Xml.XmlNodeReader($xmlXaml)
    $finestra = [System.Windows.Markup.XamlReader]::Load($lettoreXml)

    # Riferimenti ai controlli tramite FindName
    $ctrl = @{
        TxtTitoloApp           = $finestra.FindName('TxtTitoloApp')
        TxtBadgeSolaLettura    = $finestra.FindName('TxtBadgeSolaLettura')
        TxtSottotitoloApp      = $finestra.FindName('TxtSottotitoloApp')
        TxtAmbienteInfo        = $finestra.FindName('TxtAmbienteInfo')
        LblLinguaAttiva        = $finestra.FindName('LblLinguaAttiva')
        BtnLinguaIT            = $finestra.FindName('BtnLinguaIT')
        BtnLinguaEN            = $finestra.FindName('BtnLinguaEN')
        BtnLinguaDE            = $finestra.FindName('BtnLinguaDE')
        BtnLingua              = $finestra.FindName('BtnLingua')
        BtnTema                = $finestra.FindName('BtnTema')
        BannerNonAdmin         = $finestra.FindName('BannerNonAdmin')
        TxtBannerNonAdmin      = $finestra.FindName('TxtBannerNonAdmin')
        BtnRiavviaAdmin        = $finestra.FindName('BtnRiavviaAdmin')
        BannerErrore           = $finestra.FindName('BannerErrore')
        TxtBannerErrore        = $finestra.FindName('TxtBannerErrore')
        BtnAvvia               = $finestra.FindName('BtnAvvia')
        BtnAnnulla             = $finestra.FindName('BtnAnnulla')
        ProgressScansione      = $finestra.FindName('ProgressScansione')
        TxtProgresso           = $finestra.FindName('TxtProgresso')
        TxtCountSuperati       = $finestra.FindName('TxtCountSuperati')
        TxtCountFalliti        = $finestra.FindName('TxtCountFalliti')
        TxtCountSconosciuti    = $finestra.FindName('TxtCountSconosciuti')
        TxtCountNonApplicabili = $finestra.FindName('TxtCountNonApplicabili')
        TxtCountErrori         = $finestra.FindName('TxtCountErrori')
        LblFiltroStato         = $finestra.FindName('LblFiltroStato')
        LblFiltroGravita       = $finestra.FindName('LblFiltroGravita')
        LblFiltroCategoria     = $finestra.FindName('LblFiltroCategoria')
        LblFiltroCerca         = $finestra.FindName('LblFiltroCerca')
        CmbFiltroStato         = $finestra.FindName('CmbFiltroStato')
        CmbFiltroGravita       = $finestra.FindName('CmbFiltroGravita')
        CmbFiltroCategoria     = $finestra.FindName('CmbFiltroCategoria')
        TxtRicerca             = $finestra.FindName('TxtRicerca')
        BtnResetFiltri         = $finestra.FindName('BtnResetFiltri')
        GridRisultati          = $finestra.FindName('GridRisultati')
        ColStato               = $finestra.FindName('ColStato')
        ColGravita             = $finestra.FindName('ColGravita')
        ColCategoria           = $finestra.FindName('ColCategoria')
        ColId                  = $finestra.FindName('ColId')
        ColControllo           = $finestra.FindName('ColControllo')
        PanelGuidaVuota        = $finestra.FindName('PanelGuidaVuota')
        TxtMessaggioGuida      = $finestra.FindName('TxtMessaggioGuida')
        TxtSottotitoloGuida    = $finestra.FindName('TxtSottotitoloGuida')
        TxtDettaglioTitolo     = $finestra.FindName('TxtDettaglioTitolo')
        TxtDettaglioSottotitolo= $finestra.FindName('TxtDettaglioSottotitolo')
        BtnModoSemplice        = $finestra.FindName('BtnModoSemplice')
        BtnModoTecnico         = $finestra.FindName('BtnModoTecnico')
        TxtTitoloSpiegazione   = $finestra.FindName('TxtTitoloSpiegazione')
        TxtDettaglioSpiegazione= $finestra.FindName('TxtDettaglioSpiegazione')
        BannerDettaglioErrore  = $finestra.FindName('BannerDettaglioErrore')
        TxtDettaglioErrore     = $finestra.FindName('TxtDettaglioErrore')
        LblValoreAtteso        = $finestra.FindName('LblValoreAtteso')
        LblValoreOsservato     = $finestra.FindName('LblValoreOsservato')
        TxtDettaglioAtteso     = $finestra.FindName('TxtDettaglioAtteso')
        TxtDettaglioOsservato  = $finestra.FindName('TxtDettaglioOsservato')
        LblComeCorreggere      = $finestra.FindName('LblComeCorreggere')
        TxtDettaglioRimedio    = $finestra.FindName('TxtDettaglioRimedio')
        PanelComandoRimedio    = $finestra.FindName('PanelComandoRimedio')
        LblComandoRif          = $finestra.FindName('LblComandoRif')
        TxtComandoRimedio      = $finestra.FindName('TxtComandoRimedio')
        BtnCopiaComando        = $finestra.FindName('BtnCopiaComando')
        TxtFeedbackCopia       = $finestra.FindName('TxtFeedbackCopia')
        PanelAzioneRapidaDettaglio = $finestra.FindName('PanelAzioneRapidaDettaglio')
        BtnRiparaSingolo       = $finestra.FindName('BtnRiparaSingolo')
        BtnApriImpostazioni    = $finestra.FindName('BtnApriImpostazioni')
        TxtEsitoFixDettaglio   = $finestra.FindName('TxtEsitoFixDettaglio')
        LblNoteRischi          = $finestra.FindName('LblNoteRischi')
        TxtDettaglioRischi     = $finestra.FindName('TxtDettaglioRischi')
        BtnNavScansione        = $finestra.FindName('BtnNavScansione')
        BtnNavIA               = $finestra.FindName('BtnNavIA')
        BtnNavAutoFix          = $finestra.FindName('BtnNavAutoFix')
        BtnTornaScansione      = $finestra.FindName('BtnTornaScansione')
        GridPaginaScansione    = $finestra.FindName('GridPaginaScansione')
        GridPaginaIA           = $finestra.FindName('GridPaginaIA')
        GridPaginaAutoFix      = $finestra.FindName('GridPaginaAutoFix')
        LblAutoFixPresetTitle  = $finestra.FindName('LblAutoFixPresetTitle')
        BtnSelezionaFixSicuri  = $finestra.FindName('BtnSelezionaFixSicuri')
        BtnDeselezionaTuttiFix = $finestra.FindName('BtnDeselezionaTuttiFix')
        TxtConteggioSelezionati = $finestra.FindName('TxtConteggioSelezionati')
        LblAutoFixSicurezzaTitle = $finestra.FindName('LblAutoFixSicurezzaTitle')
        ChkCreaRestorePoint    = $finestra.FindName('ChkCreaRestorePoint')
        TxtChkCreaRestorePoint = $finestra.FindName('TxtChkCreaRestorePoint')
        TxtInfoBackupPath      = $finestra.FindName('TxtInfoBackupPath')
        BtnAnteprimaComandi    = $finestra.FindName('BtnAnteprimaComandi')
        BtnEsportaScriptFix    = $finestra.FindName('BtnEsportaScriptFix')
        BtnApplicaFixSelezionati = $finestra.FindName('BtnApplicaFixSelezionati')
        LblAutoFixRollbackTitle = $finestra.FindName('LblAutoFixRollbackTitle')
        TxtUltimoBackup        = $finestra.FindName('TxtUltimoBackup')
        BtnRollbackUltimo      = $finestra.FindName('BtnRollbackUltimo')
        LblAutoFixListaTitle   = $finestra.FindName('LblAutoFixListaTitle')
        BtnTornaDaAutoFix      = $finestra.FindName('BtnTornaDaAutoFix')
        ListAutoFixControlli   = $finestra.FindName('ListAutoFixControlli')
        PanelAutoFixVuoto      = $finestra.FindName('PanelAutoFixVuoto')
        TxtAutoFixVuoto        = $finestra.FindName('TxtAutoFixVuoto')
        LblAutoFixLogTitle     = $finestra.FindName('LblAutoFixLogTitle')
        TxtStatoAutoFix        = $finestra.FindName('TxtStatoAutoFix')
        TxtLogAutoFix          = $finestra.FindName('TxtLogAutoFix')
        LblMotoreIaTitle       = $finestra.FindName('LblMotoreIaTitle')
        LblIndirizzoOllama     = $finestra.FindName('LblIndirizzoOllama')
        TxtEndpointOllama      = $finestra.FindName('TxtEndpointOllama')
        LblModelloOllama       = $finestra.FindName('LblModelloOllama')
        CmbModelloOllama       = $finestra.FindName('CmbModelloOllama')
        ChkAutoInstallaOllama  = $finestra.FindName('ChkAutoInstallaOllama')
        TxtChkAutoInstalla     = $finestra.FindName('TxtChkAutoInstalla')
        BtnVerificaOllama      = $finestra.FindName('BtnVerificaOllama')
        LblGeneraAnalisiTitle  = $finestra.FindName('LblGeneraAnalisiTitle')
        BtnSpiegaLLM           = $finestra.FindName('BtnSpiegaLLM')
        BtnResocontoLLM        = $finestra.FindName('BtnResocontoLLM')
        BtnSpiegaControlloTab  = $finestra.FindName('BtnSpiegaControlloTab')
        BtnResocontoTab        = $finestra.FindName('BtnResocontoTab')
        LblCriticitaRilevate   = $finestra.FindName('LblCriticitaRilevate')
        LblTitoloResocontoIA   = $finestra.FindName('LblTitoloResocontoIA')
        BtnCopiaRispostaLLM    = $finestra.FindName('BtnCopiaRispostaLLM')
        ListFallitiIA          = $finestra.FindName('ListFallitiIA')
        TxtStatoLLM            = $finestra.FindName('TxtStatoLLM')
        TxtRispostaLLM         = $finestra.FindName('TxtRispostaLLM')
        BtnEsportaJson         = $finestra.FindName('BtnEsportaJson')
        BtnEsportaHtml         = $finestra.FindName('BtnEsportaHtml')
        ChkSalvaLogTecnico     = $finestra.FindName('ChkSalvaLogTecnico')
        TxtRiepilogoFooter     = $finestra.FindName('TxtRiepilogoFooter')
        TxtDisclaimerPermanente= $finestra.FindName('TxtDisclaimerPermanente')
    }

    # Stato interno dell'interfaccia (Tema Scuro Fluent predefinito)
    $totaleControlli = @($Catalogo.controls).Count
    $statoUI = @{
        LinguaCorrente      = $LinguaIniziale
        TemaCorrente        = 'Scuro'
        PaginaCorrente      = 'Scansione'
        ModalitaDettaglio   = 'Semplice'
        RisultatiGrezzi     = @()
        ElementiVista       = @()
        ElementoSelezionato = $null
        ScansioneInCorso    = $false
        UltimaModalitaIA    = 'Resoconto'
        SyncRunspace        = $null
        PsInstance          = $null
        Runspace            = $null
        ElementiAutoFix     = @()
        UltimoBackupPath    = $null
        FixInCorso          = $false
        EsitiFixPerId       = @{}
        UriImpostazioniCorr = $null
    }

    if ($null -ne (Get-Command -Name 'Get-DefaultBackupDirectory' -ErrorAction SilentlyContinue)) {
        try {
            $dirBackupsInit = Get-DefaultBackupDirectory
            if ([System.IO.Directory]::Exists($dirBackupsInit)) {
                $ultimoFileBackup = Get-ChildItem -LiteralPath $dirBackupsInit -Filter 'rollback_*.json' -File -ErrorAction SilentlyContinue | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1
                if ($null -ne $ultimoFileBackup) {
                    $statoUI.UltimoBackupPath = $ultimoFileBackup.FullName
                }
            }
        }
        catch { }
    }

    Update-TemaFinestra -Finestra $finestra -Tema $statoUI.TemaCorrente
    $ctrl.ProgressScansione.Maximum = if ($totaleControlli -gt 0) { $totaleControlli } else { 1 }

    # Banner giallo se non avviato come amministratore
    if (-not $Ambiente.IsAdmin) {
        $ctrl.BannerNonAdmin.Visibility = [System.Windows.Visibility]::Visible
    }

    $convBrush = New-Object System.Windows.Media.BrushConverter

    # Aggiorna l'evidenziazione visiva del selettore lingua [IT | EN | DE] e delle schede di navigazione
    $aggiornaStileSelettori = {
        $mappaBtnLingua = @{
            'IT' = @{ Btn = $ctrl.BtnLinguaIT; Label = 'IT Italiano' }
            'EN' = @{ Btn = $ctrl.BtnLinguaEN; Label = 'EN English' }
            'DE' = @{ Btn = $ctrl.BtnLinguaDE; Label = 'DE Deutsch' }
        }
        foreach ($cod in @('IT', 'EN', 'DE')) {
            $b = $mappaBtnLingua[$cod].Btn
            $lblBase = $mappaBtnLingua[$cod].Label
            if ($statoUI.LinguaCorrente -eq $cod) {
                $b.Content    = "[*] $lblBase"
                $b.Background = $convBrush.ConvertFromString('#2563EB')
                $b.Foreground = $convBrush.ConvertFromString('#FFFFFF')
                $b.FontWeight = [System.Windows.FontWeights]::Bold
            }
            else {
                $b.Content    = $lblBase
                $b.Background = $convBrush.ConvertFromString('Transparent')
                $b.Foreground = $convBrush.ConvertFromString('#94A3B8')
                $b.FontWeight = [System.Windows.FontWeights]::SemiBold
            }
        }

        # Evidenzia la scheda pagina attiva (Tab 1 vs Tab 2 vs Tab 3)
        if ($statoUI.PaginaCorrente -eq 'IA') {
            $ctrl.BtnNavIA.Background        = $convBrush.ConvertFromString('#7C3AED')
            $ctrl.BtnNavIA.Foreground        = $convBrush.ConvertFromString('#FFFFFF')
            $ctrl.BtnNavIA.FontWeight        = [System.Windows.FontWeights]::Bold
            $ctrl.BtnNavScansione.Background = $convBrush.ConvertFromString('Transparent')
            $ctrl.BtnNavScansione.Foreground = $finestra.Resources['TextSecondary']
            $ctrl.BtnNavScansione.FontWeight = [System.Windows.FontWeights]::SemiBold
            $ctrl.BtnNavAutoFix.Background   = $convBrush.ConvertFromString('Transparent')
            $ctrl.BtnNavAutoFix.Foreground   = $finestra.Resources['TextSecondary']
            $ctrl.BtnNavAutoFix.FontWeight   = [System.Windows.FontWeights]::SemiBold
        }
        elseif ($statoUI.PaginaCorrente -eq 'AutoFix') {
            $ctrl.BtnNavAutoFix.Background   = $convBrush.ConvertFromString('#059669')
            $ctrl.BtnNavAutoFix.Foreground   = $convBrush.ConvertFromString('#FFFFFF')
            $ctrl.BtnNavAutoFix.FontWeight   = [System.Windows.FontWeights]::Bold
            $ctrl.BtnNavScansione.Background = $convBrush.ConvertFromString('Transparent')
            $ctrl.BtnNavScansione.Foreground = $finestra.Resources['TextSecondary']
            $ctrl.BtnNavScansione.FontWeight = [System.Windows.FontWeights]::SemiBold
            $ctrl.BtnNavIA.Background        = $convBrush.ConvertFromString('Transparent')
            $ctrl.BtnNavIA.Foreground        = $finestra.Resources['TextSecondary']
            $ctrl.BtnNavIA.FontWeight        = [System.Windows.FontWeights]::SemiBold
        }
        else {
            $ctrl.BtnNavScansione.Background = $convBrush.ConvertFromString('#2563EB')
            $ctrl.BtnNavScansione.Foreground = $convBrush.ConvertFromString('#FFFFFF')
            $ctrl.BtnNavScansione.FontWeight = [System.Windows.FontWeights]::Bold
            $ctrl.BtnNavIA.Background        = $convBrush.ConvertFromString('Transparent')
            $ctrl.BtnNavIA.Foreground        = $finestra.Resources['TextSecondary']
            $ctrl.BtnNavIA.FontWeight        = [System.Windows.FontWeights]::SemiBold
            $ctrl.BtnNavAutoFix.Background   = $convBrush.ConvertFromString('Transparent')
            $ctrl.BtnNavAutoFix.Foreground   = $finestra.Resources['TextSecondary']
            $ctrl.BtnNavAutoFix.FontWeight   = [System.Windows.FontWeights]::SemiBold
        }
    }

    # Funzione helper per ripopolare i filtri ComboBox nella lingua corrente (IT / EN / DE)
    $aggiornaFiltriComboLingua = {
        $lang = $statoUI.LinguaCorrente

        $idxStato = if ($ctrl.CmbFiltroStato.SelectedIndex -ge 0) { $ctrl.CmbFiltroStato.SelectedIndex } else { 0 }
        $idxGrav  = if ($ctrl.CmbFiltroGravita.SelectedIndex -ge 0) { $ctrl.CmbFiltroGravita.SelectedIndex } else { 0 }
        $idxCat   = if ($ctrl.CmbFiltroCategoria.SelectedIndex -ge 0) { $ctrl.CmbFiltroCategoria.SelectedIndex } else { 0 }

        $vociStato = switch ($lang) {
            'EN' { @('All', 'Failed', 'Passed', 'Unknown', 'N/A', 'Error') }
            'DE' { @('Alle', 'Fehlgeschlagen', 'Bestanden', 'Unbekannt', 'N/Z', 'Fehler') }
            default { @('Tutti', 'Fallito', 'Superato', 'Sconosciuto', 'Non_Applicabile', 'Errore') }
        }

        $vociGrav = switch ($lang) {
            'EN' { @('All', 'Critical', 'High', 'Medium', 'Low', 'Info') }
            'DE' { @('Alle', 'Kritisch', 'Hoch', 'Mittel', 'Niedrig', 'Info') }
            default { @('Tutte', 'Critico', 'Alto', 'Medio', 'Basso', 'Informativo') }
        }

        $ctrl.CmbFiltroStato.Items.Clear()
        foreach ($v in $vociStato) {
            $item = New-Object System.Windows.Controls.ComboBoxItem
            $item.Content = $v
            [void]$ctrl.CmbFiltroStato.Items.Add($item)
        }
        $ctrl.CmbFiltroStato.SelectedIndex = [Math]::Min($idxStato, $vociStato.Count - 1)

        $ctrl.CmbFiltroGravita.Items.Clear()
        foreach ($v in $vociGrav) {
            $item = New-Object System.Windows.Controls.ComboBoxItem
            $item.Content = $v
            [void]$ctrl.CmbFiltroGravita.Items.Add($item)
        }
        $ctrl.CmbFiltroGravita.SelectedIndex = [Math]::Min($idxGrav, $vociGrav.Count - 1)

        # Popola categorie nella lingua corrente
        $categorieUniche = @()
        foreach ($c in $Catalogo.controls) {
            $cid = [string]$c.id
            $catVal = [string]$c.category
            if ($lang -eq 'EN' -and $script:TraduzioniControlliEN.ContainsKey($cid)) {
                $catVal = $script:TraduzioniControlliEN[$cid].cat
            }
            elseif ($lang -eq 'DE' -and $script:TraduzioniControlliDE.ContainsKey($cid)) {
                $catVal = $script:TraduzioniControlliDE[$cid].cat
            }
            if ($catVal -and ($categorieUniche -notcontains $catVal)) {
                $categorieUniche += $catVal
            }
        }

        $ctrl.CmbFiltroCategoria.Items.Clear()
        $itemTutte = New-Object System.Windows.Controls.ComboBoxItem
        $itemTutte.Content = switch ($lang) { 'EN' { 'All' } 'DE' { 'Alle' } default { 'Tutte' } }
        [void]$ctrl.CmbFiltroCategoria.Items.Add($itemTutte)

        foreach ($cat in ($categorieUniche | Sort-Object)) {
            $itemCat = New-Object System.Windows.Controls.ComboBoxItem
            $itemCat.Content = $cat
            [void]$ctrl.CmbFiltroCategoria.Items.Add($itemCat)
        }
        $ctrl.CmbFiltroCategoria.SelectedIndex = [Math]::Min($idxCat, $ctrl.CmbFiltroCategoria.Items.Count - 1)
    }

    # --- Funzioni di aggiornamento UI ---
    $aggiornaPannelloDettaglio = {
        $lang = $statoUI.LinguaCorrente
        $dettaglio = Format-DettaglioControllo -Elemento $statoUI.ElementoSelezionato -Modalita $statoUI.ModalitaDettaglio -Lingua $lang
        $ctrl.TxtDettaglioTitolo.Text = $dettaglio.Title

        switch ($lang) {
            'EN' {
                $ctrl.TxtDettaglioSottotitolo.Text = "ID: $($dettaglio.ControlId)  |  Status: $($dettaglio.StatusLabel)  |  Severity: $($dettaglio.SeverityLabel)  |  Category: $($dettaglio.Category)"
            }
            'DE' {
                $ctrl.TxtDettaglioSottotitolo.Text = "ID: $($dettaglio.ControlId)  |  Status: $($dettaglio.StatusLabel)  |  Schweregrad: $($dettaglio.SeverityLabel)  |  Kategorie: $($dettaglio.Category)"
            }
            default {
                $ctrl.TxtDettaglioSottotitolo.Text = "ID: $($dettaglio.ControlId)  |  Stato: $($dettaglio.StatusLabel)  |  Gravita': $($dettaglio.SeverityLabel)  |  Categoria: $($dettaglio.Category)"
            }
        }

        if ($statoUI.ModalitaDettaglio -eq 'Tecnico') {
            $ctrl.TxtTitoloSpiegazione.Text = switch ($lang) {
                'EN' { "Technical details & references" }
                'DE' { "Technische Details & Referenzen" }
                default { "Dettaglio tecnico e riferimenti" }
            }
            $ctrl.BtnModoTecnico.FontWeight  = [System.Windows.FontWeights]::Bold
            $ctrl.BtnModoSemplice.FontWeight = [System.Windows.FontWeights]::Normal
        }
        else {
            $ctrl.TxtTitoloSpiegazione.Text = switch ($lang) {
                'EN' { "Why it matters (simple explanation)" }
                'DE' { "Warum es wichtig ist (einfache Erklaerung)" }
                default { "Perche' conta (spiegazione semplice)" }
            }
            $ctrl.BtnModoSemplice.FontWeight = [System.Windows.FontWeights]::Bold
            $ctrl.BtnModoTecnico.FontWeight  = [System.Windows.FontWeights]::Normal
        }

        $ctrl.TxtDettaglioSpiegazione.Text = $dettaglio.TestoSpiegazione
        $ctrl.TxtDettaglioAtteso.Text      = $dettaglio.ValoreAtteso
        $ctrl.TxtDettaglioOsservato.Text   = $dettaglio.ValoreOsservato
        $ctrl.TxtDettaglioRimedio.Text     = $dettaglio.TestoRimedio
        $ctrl.TxtDettaglioRischi.Text      = $dettaglio.NoteRischi
        $ctrl.TxtFeedbackCopia.Visibility  = [System.Windows.Visibility]::Collapsed

        if ($null -ne $dettaglio.MessaggioErrore) {
            $ctrl.TxtDettaglioErrore.Text = $dettaglio.MessaggioErrore
            $ctrl.BannerDettaglioErrore.Visibility = [System.Windows.Visibility]::Visible
        }
        else {
            $ctrl.BannerDettaglioErrore.Visibility = [System.Windows.Visibility]::Collapsed
        }

        if ($dettaglio.HaComando) {
            $ctrl.TxtComandoRimedio.Text = $dettaglio.ComandoRimedio
            $ctrl.PanelComandoRimedio.Visibility = [System.Windows.Visibility]::Visible
        }
        else {
            $ctrl.TxtComandoRimedio.Text = ''
            $ctrl.PanelComandoRimedio.Visibility = [System.Windows.Visibility]::Collapsed
        }

        # Azioni rapide contestuali nel pannello dettagli (Auto-Fix 1-Click / Impostazioni Windows)
        $mostraRipara = $false
        $mostraUri    = $false
        $mostraEsito  = $false
        $statoUI.UriImpostazioniCorr = $null

        if ($dettaglio.Selezionato) {
            $defDet = $null
            if ($null -ne (Get-Command -Name 'Get-RemediationDefinition' -ErrorAction SilentlyContinue)) {
                $defDet = Get-RemediationDefinition -ControlId $dettaglio.ControlId
            }

            if ($null -ne $defDet -and $dettaglio.Status -eq 'fallito' -and ($defDet.FixMode -in @('AutoSafe', 'AutoReboot', 'Guided')) -and $null -ne $defDet.Apply) {
                $mostraRipara = $true
            }

            if ($null -ne $defDet -and (Test-SafeSettingsUri -Uri ([string]$defDet.SettingsUri))) {
                $statoUI.UriImpostazioniCorr = ([string]$defDet.SettingsUri).Trim()
                $mostraUri = $true
            }

            if ($statoUI.EsitiFixPerId.ContainsKey($dettaglio.ControlId)) {
                $esitoRecente = $statoUI.EsitiFixPerId[$dettaglio.ControlId]
                $msgRecente = Get-ValoreProprietaSicuro -Oggetto $esitoRecente -NomeProprieta 'Message' -ValorePredefinito ''
                if (-not [string]::IsNullOrWhiteSpace([string]$msgRecente)) {
                    $ctrl.TxtEsitoFixDettaglio.Text = "[$($esitoRecente.Status)] $msgRecente"
                    $mostraEsito = $true
                }
            }
        }

        $ctrl.BtnRiparaSingolo.Visibility        = if ($mostraRipara) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        $ctrl.BtnRiparaSingolo.IsEnabled         = (-not $statoUI.FixInCorso) -and (-not $statoUI.ScansioneInCorso)
        $ctrl.BtnApriImpostazioni.Visibility     = if ($mostraUri) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        $ctrl.TxtEsitoFixDettaglio.Visibility    = if ($mostraEsito) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
        $ctrl.PanelAzioneRapidaDettaglio.Visibility = if ($mostraRipara -or $mostraUri -or $mostraEsito) { [System.Windows.Visibility]::Visible } else { [System.Windows.Visibility]::Collapsed }
    }

    $aggiornaConteggioAutoFix = {
        $langAuto = $statoUI.LinguaCorrente
        $itemsAuto  = @($statoUI.ElementiAutoFix)
        $selAuto    = @($itemsAuto | Where-Object { $_.CanAutoFix -and $_.IsSelected })
        $nSel       = $selAuto.Count
        $nDispon    = @($itemsAuto | Where-Object { $_.CanAutoFix }).Count
        $nAutoSafe  = @($itemsAuto | Where-Object { $_.IsAutoSafe }).Count

        $ctrl.TxtConteggioSelezionati.Text = switch ($langAuto) {
            'EN' { "Selected: $nSel / $nDispon fixable ($nAutoSafe AutoSafe)" }
            'DE' { "Ausgewaehlt: $nSel / $nDispon behebbar ($nAutoSafe AutoSafe)" }
            default { "Selezionati: $nSel / $nDispon riparabili ($nAutoSafe AutoSafe)" }
        }

        $ctrl.BtnApplicaFixSelezionati.Content = switch ($langAuto) {
            'EN' { "Apply Selected Fixes ($nSel)" }
            'DE' { "Ausgewaehlte Korrekturen anwenden ($nSel)" }
            default { "Applica correzioni selezionate ($nSel)" }
        }

        $occupato = ($statoUI.FixInCorso -or $statoUI.ScansioneInCorso)
        $ctrl.BtnApplicaFixSelezionati.IsEnabled = (-not $occupato) -and ($nSel -gt 0)
        $ctrl.BtnAnteprimaComandi.IsEnabled      = (-not $occupato) -and ($nSel -gt 0 -or $nDispon -gt 0)
        $ctrl.BtnEsportaScriptFix.IsEnabled      = (-not $occupato) -and ($nSel -gt 0 -or $nDispon -gt 0)
        $ctrl.BtnSelezionaFixSicuri.IsEnabled    = (-not $occupato) -and ($nAutoSafe -gt 0)
        $ctrl.BtnDeselezionaTuttiFix.IsEnabled   = (-not $occupato) -and ($itemsAuto.Count -gt 0)
        $ctrl.BtnRollbackUltimo.IsEnabled        = (-not $occupato) -and (-not [string]::IsNullOrWhiteSpace($statoUI.UltimoBackupPath)) -and ([System.IO.File]::Exists($statoUI.UltimoBackupPath))

        if (-not [string]::IsNullOrWhiteSpace($statoUI.UltimoBackupPath) -and ([System.IO.File]::Exists($statoUI.UltimoBackupPath))) {
            $nomeFileBkp = Split-Path -Leaf $statoUI.UltimoBackupPath
            $ctrl.TxtUltimoBackup.Text = switch ($langAuto) {
                'EN' { "Latest backup: $nomeFileBkp" }
                'DE' { "Letzte Sicherung: $nomeFileBkp" }
                default { "Ultimo backup: $nomeFileBkp" }
            }
        }
        else {
            $ctrl.TxtUltimoBackup.Text = switch ($langAuto) {
                'EN' { "No remediation backup recorded yet." }
                'DE' { "Noch keine Sicherung vorhanden." }
                default { "Nessun backup di sessione disponibile." }
            }
        }
    }

    $aggiornaListaAutoFix = {
        $langAuto = $statoUI.LinguaCorrente
        $precedentiSelezionati = @{}
        foreach ($oldItem in @($statoUI.ElementiAutoFix)) {
            if ($null -ne $oldItem -and $oldItem.IsSelected) {
                $precedentiSelezionati[$oldItem.ControlId] = $true
            }
        }

        $nuoviAutoFix = @(ConvertTo-AutoFixItems -ElementiVista $statoUI.ElementiVista -Lingua $langAuto -EsitiFixPerId $statoUI.EsitiFixPerId)
        foreach ($nuovo in $nuoviAutoFix) {
            if ($nuovo.CanAutoFix -and $precedentiSelezionati.ContainsKey($nuovo.ControlId)) {
                $nuovo.IsSelected = $true
            }
        }

        $statoUI.ElementiAutoFix = $nuoviAutoFix
        $ctrl.ListAutoFixControlli.ItemsSource = $nuoviAutoFix

        if ($statoUI.ElementiVista.Count -eq 0) {
            $ctrl.TxtAutoFixVuoto.Text = switch ($langAuto) {
                'EN' { "Run the scan on Tab 1 first to populate failed controls available for Auto-Fix." }
                'DE' { "Fuehren Sie zuerst den Scan in Tab 1 aus, um fehlgeschlagene Pruefungen anzuzeigen." }
                default { "Esegui prima la scansione nella Scheda 1 per popolare la lista dei controlli falliti riparabili." }
            }
            $ctrl.PanelAutoFixVuoto.Visibility = [System.Windows.Visibility]::Visible
        }
        elseif ($nuoviAutoFix.Count -eq 0) {
            $ctrl.TxtAutoFixVuoto.Text = switch ($langAuto) {
                'EN' { "Great! No failed controls remain to remediate." }
                'DE' { "Ausgezeichnet! Es sind keine fehlgeschlagenen Pruefungen mehr offen." }
                default { "Ottimo! Non risultano controlli falliti da riparare." }
            }
            $ctrl.PanelAutoFixVuoto.Visibility = [System.Windows.Visibility]::Visible
        }
        else {
            $ctrl.PanelAutoFixVuoto.Visibility = [System.Windows.Visibility]::Collapsed
        }

        & $aggiornaConteggioAutoFix
    }

    $aggiornaConteggiERiepilogo = {
        $conteggi = Measure-ConteggiRisultati -Elementi $statoUI.RisultatiGrezzi
        $lang = $statoUI.LinguaCorrente

        switch ($lang) {
            'EN' {
                $ctrl.TxtCountSuperati.Text       = "[OK] $($conteggi.superato) Passed"
                $ctrl.TxtCountFalliti.Text        = "[X] $($conteggi.fallito) Failed"
                $ctrl.TxtCountSconosciuti.Text    = "[?] $($conteggi.sconosciuto) Unknown"
                $ctrl.TxtCountNonApplicabili.Text = "[-] $($conteggi.non_applicabile) N/A"
                $ctrl.TxtCountErrori.Text         = "[!] $($conteggi.errore) Errors"
                $ctrl.TxtRiepilogoFooter.Text     = "Summary: $($conteggi.totale) controls evaluated ($($conteggi.superato) passed, $($conteggi.fallito) failed, $($conteggi.sconosciuto) unknown)"
            }
            'DE' {
                $ctrl.TxtCountSuperati.Text       = "[OK] $($conteggi.superato) Bestanden"
                $ctrl.TxtCountFalliti.Text        = "[X] $($conteggi.fallito) Fehlgeschlagen"
                $ctrl.TxtCountSconosciuti.Text    = "[?] $($conteggi.sconosciuto) Unbekannt"
                $ctrl.TxtCountNonApplicabili.Text = "[-] $($conteggi.non_applicabile) N/Z"
                $ctrl.TxtCountErrori.Text         = "[!] $($conteggi.errore) Fehler"
                $ctrl.TxtRiepilogoFooter.Text     = "Zusammenfassung: $($conteggi.totale) Pruefungen ausgewertet ($($conteggi.superato) bestanden, $($conteggi.fallito) fehlgeschlagen, $($conteggi.sconosciuto) unbekannt)"
            }
            default {
                $ctrl.TxtCountSuperati.Text       = "[OK] $($conteggi.superato) Superati"
                $ctrl.TxtCountFalliti.Text        = "[X] $($conteggi.fallito) Falliti"
                $ctrl.TxtCountSconosciuti.Text    = "[?] $($conteggi.sconosciuto) Sconosciuti"
                $ctrl.TxtCountNonApplicabili.Text = "[-] $($conteggi.non_applicabile) Non applicabili"
                $ctrl.TxtCountErrori.Text         = "[!] $($conteggi.errore) Errori"
                $ctrl.TxtRiepilogoFooter.Text     = "Riepilogo calcolato dal codice: $($conteggi.totale) controlli valutati ($($conteggi.superato) superati, $($conteggi.fallito) falliti, $($conteggi.sconosciuto) sconosciuti)"
            }
        }

        if ($conteggi.errore -gt 0) {
            $ctrl.TxtBannerErrore.Text = switch ($lang) {
                'EN' { "Some controls ($($conteggi.errore)) returned an unexpected read error. Select the control for details or export the technical log." }
                'DE' { "Einige Pruefungen ($($conteggi.errore)) haben einen unerwarteten Lesefehler gemeldet. Waehlen Sie die Pruefung fuer Details oder exportieren Sie das technische Protokoll." }
                default { "Alcuni controlli ($($conteggi.errore)) hanno restituito un imprevisto durante la lettura. Seleziona il controllo per maggiori informazioni o esporta il log tecnico." }
            }
            $ctrl.BannerErrore.Visibility = [System.Windows.Visibility]::Visible
        }
        else {
            $ctrl.BannerErrore.Visibility = [System.Windows.Visibility]::Collapsed
        }
    }

    $applicaFiltriTabella = {
        $statoSel = if ($null -ne $ctrl.CmbFiltroStato.SelectedItem) { [string]$ctrl.CmbFiltroStato.SelectedItem.Content } else { 'Tutti' }
        $gravSel  = if ($null -ne $ctrl.CmbFiltroGravita.SelectedItem) { [string]$ctrl.CmbFiltroGravita.SelectedItem.Content } else { 'Tutte' }
        $catSel   = if ($null -ne $ctrl.CmbFiltroCategoria.SelectedItem) { [string]$ctrl.CmbFiltroCategoria.SelectedItem.Content } else { 'Tutte' }
        $ricerca  = $ctrl.TxtRicerca.Text

        $filtrati = @(Select-RisultatiVista -Elementi $statoUI.ElementiVista -Stato $statoSel -Gravita $gravSel -Categoria $catSel -TestoRicerca $ricerca)

        $idPrecedente = if ($null -ne $statoUI.ElementoSelezionato) { $statoUI.ElementoSelezionato.ControlId } else { $null }
        $ctrl.GridRisultati.ItemsSource = $filtrati

        if ($statoUI.ElementiVista.Count -eq 0) {
            $ctrl.PanelGuidaVuota.Visibility = [System.Windows.Visibility]::Visible
        }
        elseif ($filtrati.Count -eq 0) {
            $ctrl.TxtMessaggioGuida.Text = switch ($statoUI.LinguaCorrente) {
                'EN' { "No controls match the selected filters." }
                'DE' { "Keine Sicherheitspruefungen entsprechen den ausgewaehlten Filtern." }
                default { "Nessun controllo corrisponde ai filtri selezionati." }
            }
            $ctrl.PanelGuidaVuota.Visibility = [System.Windows.Visibility]::Visible
        }
        else {
            $ctrl.PanelGuidaVuota.Visibility = [System.Windows.Visibility]::Collapsed
            if ($null -ne $idPrecedente) {
                foreach ($item in $filtrati) {
                    if ($item.ControlId -eq $idPrecedente) {
                        $ctrl.GridRisultati.SelectedItem = $item
                        break
                    }
                }
            }
            if ($null -eq $ctrl.GridRisultati.SelectedItem -and $filtrati.Count -gt 0 -and (-not $statoUI.ScansioneInCorso)) {
                $ctrl.GridRisultati.SelectedIndex = 0
            }
        }
    }

    $aggiornaTestoPulsanteTema = {
        $lang = $statoUI.LinguaCorrente
        $isScuro = ($statoUI.TemaCorrente -eq 'Scuro')
        $ctrl.BtnTema.Content = switch ($lang) {
            'EN' { if ($isScuro) { "Active Theme: Dark" } else { "Active Theme: Light" } }
            'DE' { if ($isScuro) { "Design: Dunkel" }     else { "Design: Hell" } }
            default { if ($isScuro) { "Tema attivo: Scuro" } else { "Tema attivo: Chiaro" } }
        }
    }

    $applicaLinguaUI = {
        $lang = $statoUI.LinguaCorrente
        $testoAdmin = if ($Ambiente.IsAdmin) {
            switch ($lang) { 'EN' { 'Yes' } 'DE' { 'Ja' } default { 'Si' } }
        } else {
            switch ($lang) { 'DE' { 'Nein' } default { 'No' } }
        }
        $ctrl.TxtAmbienteInfo.Text = "Windows 11 $($Ambiente.Edition) $($Ambiente.Build) | Admin: $testoAdmin"

        & $aggiornaStileSelettori
        & $aggiornaTestoPulsanteTema

        if ($lang -eq 'EN') {
            $finestra.Title                        = "Windows 11 Security Scanner (Read-Only)"
            $ctrl.TxtTitoloApp.Text                = "Windows 11 Security Scanner"
            $ctrl.TxtBadgeSolaLettura.Text         = "READ-ONLY"
            $ctrl.TxtSottotitoloApp.Text           = "$totaleControlli Deterministic Controls + Local AI Security Advisor (Ollama)"
            $ctrl.LblLinguaAttiva.Text             = "Language:"
            $ctrl.TxtBannerNonAdmin.Text           = "[!] Non-administrative session: some controls will report 'Unknown'. Restart as Administrator for a complete audit."
            $ctrl.BtnRiavviaAdmin.Content          = "Restart as Administrator"
            $ctrl.BtnNavScansione.Content          = "1. Controls & Details"
            $ctrl.BtnNavIA.Content                 = "2. AI Security Advisor (Ollama)"
            $ctrl.BtnAvvia.Content                 = "Start Scan ($totaleControlli controls)"
            $ctrl.BtnAnnulla.Content               = "Cancel"
            $ctrl.BtnResocontoLLM.Content          = "Open AI Security Report"
            $ctrl.LblFiltroStato.Text              = "Status:"
            $ctrl.LblFiltroGravita.Text            = "Severity:"
            $ctrl.LblFiltroCategoria.Text          = "Category:"
            $ctrl.LblFiltroCerca.Text              = "Search:"
            $ctrl.BtnResetFiltri.Content           = "Reset Filters"
            $ctrl.ColStato.Header                  = "Status"
            $ctrl.ColGravita.Header                = "Severity"
            $ctrl.ColCategoria.Header              = "Category"
            $ctrl.ColId.Header                     = "ID"
            $ctrl.ColControllo.Header              = "Security Control"
            $ctrl.TxtSottotitoloGuida.Text         = "The scanner operates strictly in read-only mode and modifies no Windows settings."
            $ctrl.BtnModoSemplice.Content          = "Simple View"
            $ctrl.BtnModoTecnico.Content           = "Technical Details"
            $ctrl.BtnSpiegaLLM.Content             = "Explain with AI (Page 2)"
            $ctrl.LblValoreAtteso.Text             = "EXPECTED VALUE"
            $ctrl.LblValoreOsservato.Text          = "OBSERVED VALUE"
            $ctrl.LblComeCorreggere.Text           = "How to Remediate (Manual Instructions)"
            $ctrl.LblComandoRif.Text               = "REFERENCE COMMAND (NOT EXECUTED AUTOMATICALLY):"
            $ctrl.BtnCopiaComando.Content          = "Copy Command to Clipboard"
            $ctrl.TxtFeedbackCopia.Text            = "Copied!"
            $ctrl.LblNoteRischi.Text               = "Risk & Impact Notes"
            $ctrl.LblMotoreIaTitle.Text            = "LOCAL AI ENGINE (OLLAMA)"
            $ctrl.LblIndirizzoOllama.Text          = "Ollama Server Address:"
            $ctrl.LblModelloOllama.Text            = "Lightweight LLM Model:"
            $ctrl.TxtChkAutoInstalla.Text          = "If Ollama is missing on VM, silently auto-install and start it in background"
            $ctrl.BtnVerificaOllama.Content        = "Check / Auto-Setup Ollama"
            $ctrl.LblGeneraAnalisiTitle.Text       = "GENERATE ANALYSIS & ADVICE"
            $ctrl.BtnResocontoTab.Content          = "Generate Full PC Security Report"
            $ctrl.BtnSpiegaControlloTab.Content    = "Explain Selected Control"
            $ctrl.LblCriticitaRilevate.Text        = "DETECTED ISSUES (CLICK TO ANALYZE):"
            $ctrl.LblTitoloResocontoIA.Text        = "AI SECURITY REPORT & HARDENING PLAN"
            $ctrl.BtnCopiaRispostaLLM.Content      = "Copy AI Report"
            $ctrl.BtnTornaScansione.Content        = "Back to Controls Table"
            $ctrl.BtnEsportaJson.Content           = "Export JSON"
            $ctrl.BtnEsportaHtml.Content           = "Export HTML"
            $ctrl.ChkSalvaLogTecnico.Content       = "Include technical error log next to export"
            $ctrl.TxtDisclaimerPermanente.Text     = "Permanent Notice: This tool audits security configurations strictly in read-only mode. A compliant audit does not guarantee the absence of system compromise."
            $ctrl.BtnNavAutoFix.Content            = "3. Auto-Fix (WinUtil)"
            $ctrl.BtnRiparaSingolo.Content         = "Apply Auto-Fix (1-Click)"
            $ctrl.BtnApriImpostazioni.Content      = "Open Windows Settings"
            $ctrl.LblAutoFixPresetTitle.Text       = "QUICK SELECTION (WINUTIL STYLE)"
            $ctrl.BtnSelezionaFixSicuri.Content    = "Select Safe Fixes (AutoSafe)"
            $ctrl.BtnDeselezionaTuttiFix.Content   = "Deselect All"
            $ctrl.LblAutoFixSicurezzaTitle.Text    = "SAFETY, PREVIEW & APPLY"
            $ctrl.TxtChkCreaRestorePoint.Text      = "Create a Windows System Restore point before applying changes"
            $ctrl.TxtInfoBackupPath.Text           = "Automatic JSON state backup before every change."
            $ctrl.BtnAnteprimaComandi.Content      = "Preview Selected Commands"
            $ctrl.BtnEsportaScriptFix.Content      = "Export as .ps1 Script"
            $ctrl.LblAutoFixRollbackTitle.Text     = "ROLLBACK (1-CLICK RESTORE)"
            $ctrl.BtnRollbackUltimo.Content        = "Restore Last Changes (Rollback)"
            $ctrl.LblAutoFixListaTitle.Text        = "FAILED CONTROLS - DETERMINISTIC AUTO-FIX & MANUAL SETTINGS"
            $ctrl.BtnTornaDaAutoFix.Content        = "Back to Controls Table"
            $ctrl.LblAutoFixLogTitle.Text          = "COMMAND PREVIEW & REMEDIATION EXECUTION LOG"
        }
        elseif ($lang -eq 'DE') {
            $finestra.Title                        = "Windows 11 Sicherheitsscanner (Schreibgeschuetzt)"
            $ctrl.TxtTitoloApp.Text                = "Windows 11 Sicherheitsscanner"
            $ctrl.TxtBadgeSolaLettura.Text         = "NUR LESEN"
            $ctrl.TxtSottotitoloApp.Text           = "$totaleControlli Deterministische Pruefungen + Lokaler KI-Berater (Ollama)"
            $ctrl.LblLinguaAttiva.Text             = "Sprache:"
            $ctrl.TxtBannerNonAdmin.Text           = "[!] Sitzung ohne Administratorrechte: Einige Pruefungen melden 'Unbekannt'. Starten Sie als Administrator neu fuer eine vollstaendige Analyse."
            $ctrl.BtnRiavviaAdmin.Content          = "Als Administrator neustarten"
            $ctrl.BtnNavScansione.Content          = "1. Pruefungen & Details"
            $ctrl.BtnNavIA.Content                 = "2. KI-Sicherheitsberater (Ollama)"
            $ctrl.BtnAvvia.Content                 = "Scan starten ($totaleControlli Pruefungen)"
            $ctrl.BtnAnnulla.Content               = "Abbrechen"
            $ctrl.BtnResocontoLLM.Content          = "KI-Sicherheitsbericht oeffnen"
            $ctrl.LblFiltroStato.Text              = "Status:"
            $ctrl.LblFiltroGravita.Text            = "Schweregrad:"
            $ctrl.LblFiltroCategoria.Text          = "Kategorie:"
            $ctrl.LblFiltroCerca.Text              = "Suche:"
            $ctrl.BtnResetFiltri.Content           = "Filter zuruecksetzen"
            $ctrl.ColStato.Header                  = "Status"
            $ctrl.ColGravita.Header                = "Schweregrad"
            $ctrl.ColCategoria.Header              = "Kategorie"
            $ctrl.ColId.Header                     = "ID"
            $ctrl.ColControllo.Header              = "Sicherheitspruefung"
            $ctrl.TxtSottotitoloGuida.Text         = "Der Scanner arbeitet ausschliesslich schreibgeschuetzt und aendert keine Windows-Einstellungen."
            $ctrl.BtnModoSemplice.Content          = "Einfache Ansicht"
            $ctrl.BtnModoTecnico.Content           = "Technische Details"
            $ctrl.BtnSpiegaLLM.Content             = "Mit KI erklaeren (Seite 2)"
            $ctrl.LblValoreAtteso.Text             = "ERWARTETER WERT"
            $ctrl.LblValoreOsservato.Text          = "GEFUNDENER WERT"
            $ctrl.LblComeCorreggere.Text           = "Manuelle Behebung (Anleitung)"
            $ctrl.LblComandoRif.Text               = "REFERENZBEFEHL (WIRD NICHT AUTOMATISCH AUSGEFUEHRT):"
            $ctrl.BtnCopiaComando.Content          = "Befehl kopieren"
            $ctrl.TxtFeedbackCopia.Text            = "Kopiert!"
            $ctrl.LblNoteRischi.Text               = "Risiko- & Auswirkungshinweise"
            $ctrl.LblMotoreIaTitle.Text            = "LOKALE KI-ENGINE (OLLAMA)"
            $ctrl.LblIndirizzoOllama.Text          = "Ollama-Serveradresse:"
            $ctrl.LblModelloOllama.Text            = "Leichtes LLM-Modell:"
            $ctrl.TxtChkAutoInstalla.Text          = "Falls Ollama auf der VM fehlt, automatisch im Hintergrund installieren und starten"
            $ctrl.BtnVerificaOllama.Content        = "Ollama pruefen / Auto-Setup"
            $ctrl.LblGeneraAnalisiTitle.Text       = "ANALYSE & EMPFEHLUNGEN ERSTELLEN"
            $ctrl.BtnResocontoTab.Content          = "Vollstaendigen PC-Bericht erstellen"
            $ctrl.BtnSpiegaControlloTab.Content    = "Ausgewaehlte Pruefung erklaeren"
            $ctrl.LblCriticitaRilevate.Text        = "ERKANNTE PROBLEME (ZUM ANALYSIEREN KLICKEN):"
            $ctrl.LblTitoloResocontoIA.Text        = "KI-SICHERHEITSBERICHT & MASSNAHMENPLAN"
            $ctrl.BtnCopiaRispostaLLM.Content      = "KI-Bericht kopieren"
            $ctrl.BtnTornaScansione.Content        = "Zurueck zur Tabelle"
            $ctrl.BtnEsportaJson.Content           = "JSON exportieren"
            $ctrl.BtnEsportaHtml.Content           = "HTML exportieren"
            $ctrl.ChkSalvaLogTecnico.Content       = "Technisches Fehlerprotokoll neben dem Export speichern"
            $ctrl.TxtDisclaimerPermanente.Text     = "Dauerhafter Hinweis: Dieses Tool prueft Sicherheitskonfigurationen ausschliesslich schreibgeschuetzt. Ein konformes Audit garantiert nicht die Abwesenheit einer Kompromittierung."
            $ctrl.BtnNavAutoFix.Content            = "3. Auto-Fix (WinUtil)"
            $ctrl.BtnRiparaSingolo.Content         = "Auto-Fix anwenden (1-Klick)"
            $ctrl.BtnApriImpostazioni.Content      = "Windows-Einstellungen oeffnen"
            $ctrl.LblAutoFixPresetTitle.Text       = "SCHNELLAUSWAHL (WINUTIL-STIL)"
            $ctrl.BtnSelezionaFixSicuri.Content    = "Sichere Fixes waehlen (AutoSafe)"
            $ctrl.BtnDeselezionaTuttiFix.Content   = "Alle abwaehlen"
            $ctrl.LblAutoFixSicurezzaTitle.Text    = "SICHERHEIT, VORSCHAU & AUSFUEHRUNG"
            $ctrl.TxtChkCreaRestorePoint.Text      = "Vor den Aenderungen einen Windows-Wiederherstellungspunkt erstellen"
            $ctrl.TxtInfoBackupPath.Text           = "Automatische JSON-Sicherung vor jeder Aenderung."
            $ctrl.BtnAnteprimaComandi.Content      = "Ausgewaehlte Befehle anzeigen"
            $ctrl.BtnEsportaScriptFix.Content      = "Als .ps1-Skript exportieren"
            $ctrl.LblAutoFixRollbackTitle.Text     = "WIEDERHERSTELLUNG (1-KLICK-ROLLBACK)"
            $ctrl.BtnRollbackUltimo.Content        = "Letzte Aenderungen rueckgaengig machen"
            $ctrl.LblAutoFixListaTitle.Text        = "FEHLGESCHLAGENE PRUEFUNGEN - AUTO-FIX & MANUELLE EINSTELLUNGEN"
            $ctrl.BtnTornaDaAutoFix.Content        = "Zurueck zur Tabelle"
            $ctrl.LblAutoFixLogTitle.Text          = "BEFEHLSVORSCHAU & REMEDIATION-PROTOKOLL"
        }
        else {
            $finestra.Title                        = "Scanner Sicurezza Windows 11 (Sola Lettura)"
            $ctrl.TxtTitoloApp.Text                = "Scanner Sicurezza Windows 11"
            $ctrl.TxtBadgeSolaLettura.Text         = "SOLA LETTURA"
            $ctrl.TxtSottotitoloApp.Text           = "$totaleControlli Controlli Deterministici + Assistente IA Locale (Ollama)"
            $ctrl.LblLinguaAttiva.Text             = "Lingua:"
            $ctrl.TxtBannerNonAdmin.Text           = "[!] Sessione non amministrativa: alcuni controlli risulteranno 'Sconosciuto'. Riavvia come Amministratore per l'analisi completa."
            $ctrl.BtnRiavviaAdmin.Content          = "Riavvia come amministratore"
            $ctrl.BtnNavScansione.Content          = "1. Tabella Controlli & Dettagli"
            $ctrl.BtnNavIA.Content                 = "2. Assistente IA (Ollama)"
            $ctrl.BtnAvvia.Content                 = "Avvia scansione ($totaleControlli controlli)"
            $ctrl.BtnAnnulla.Content               = "Annulla"
            $ctrl.BtnResocontoLLM.Content          = "Apri Resoconto IA & Consigli"
            $ctrl.LblFiltroStato.Text              = "Stato:"
            $ctrl.LblFiltroGravita.Text            = "Gravita':"
            $ctrl.LblFiltroCategoria.Text          = "Categoria:"
            $ctrl.LblFiltroCerca.Text              = "Cerca:"
            $ctrl.BtnResetFiltri.Content           = "Reimposta filtri"
            $ctrl.ColStato.Header                  = "Stato"
            $ctrl.ColGravita.Header                = "Gravita'"
            $ctrl.ColCategoria.Header              = "Categoria"
            $ctrl.ColId.Header                     = "ID"
            $ctrl.ColControllo.Header              = "Controllo"
            $ctrl.TxtSottotitoloGuida.Text         = "Lo strumento opera esclusivamente in sola lettura e non modifica alcuna impostazione di Windows."
            $ctrl.BtnModoSemplice.Content          = "Spiegazione Semplice"
            $ctrl.BtnModoTecnico.Content           = "Dettagli Tecnici"
            $ctrl.BtnSpiegaLLM.Content             = "Spiega con IA (Pagina 2)"
            $ctrl.LblValoreAtteso.Text             = "VALORE ATTESO"
            $ctrl.LblValoreOsservato.Text          = "VALORE OSSERVATO"
            $ctrl.LblComeCorreggere.Text           = "Come correggere (istruzioni manuali)"
            $ctrl.LblComandoRif.Text               = "COMANDO DI RIFERIMENTO (NON ESEGUITO AUTOMATICAMENTE):"
            $ctrl.BtnCopiaComando.Content          = "Copia comando negli appunti"
            $ctrl.TxtFeedbackCopia.Text            = "Copiato!"
            $ctrl.LblNoteRischi.Text               = "Note sui rischi"
            $ctrl.LblMotoreIaTitle.Text            = "MOTORE IA LOCALE (OLLAMA)"
            $ctrl.LblIndirizzoOllama.Text          = "Indirizzo Server Ollama:"
            $ctrl.LblModelloOllama.Text            = "Modello LLM leggero:"
            $ctrl.TxtChkAutoInstalla.Text          = "Se Ollama manca sulla VM, installalo e avvialo automaticamente in background"
            $ctrl.BtnVerificaOllama.Content        = "Verifica / Auto-Configura Ollama"
            $ctrl.LblGeneraAnalisiTitle.Text       = "GENERA ANALISI E CONSIGLI"
            $ctrl.BtnResocontoTab.Content          = "Genera Resoconto Completo PC"
            $ctrl.BtnSpiegaControlloTab.Content    = "Spiega il Controllo Selezionato"
            $ctrl.LblCriticitaRilevate.Text        = "CRITICITA' RILEVATE (CLICCA PER ANALIZZARE):"
            $ctrl.LblTitoloResocontoIA.Text        = "RESOCONTO DI SICUREZZA & PIANO DI MIGLIORAMENTO IA"
            $ctrl.BtnCopiaRispostaLLM.Content      = "Copia Resoconto"
            $ctrl.BtnTornaScansione.Content        = "Torna alla Tabella Controlli"
            $ctrl.BtnEsportaJson.Content           = "Esporta JSON"
            $ctrl.BtnEsportaHtml.Content           = "Esporta HTML"
            $ctrl.ChkSalvaLogTecnico.Content       = "Includi file di log tecnico accanto all'export"
            $ctrl.TxtDisclaimerPermanente.Text     = "Avviso permanente: questo strumento verifica solo alcune configurazioni di sicurezza in sola lettura. Un audit conforme non dimostra l'assenza di compromissioni sul sistema."
            $ctrl.BtnNavAutoFix.Content            = "3. Auto-Fix (WinUtil)"
            $ctrl.BtnRiparaSingolo.Content         = "Applica Fix Automatico (1-Click)"
            $ctrl.BtnApriImpostazioni.Content      = "Apri in Impostazioni Windows"
            $ctrl.LblAutoFixPresetTitle.Text       = "SELEZIONE RAPIDA (STILE WINUTIL)"
            $ctrl.BtnSelezionaFixSicuri.Content    = "Seleziona Fix Sicuri (AutoSafe)"
            $ctrl.BtnDeselezionaTuttiFix.Content   = "Deseleziona tutti"
            $ctrl.LblAutoFixSicurezzaTitle.Text    = "SICUREZZA, ANTEPRIMA & ESECUZIONE"
            $ctrl.TxtChkCreaRestorePoint.Text      = "Crea un Punto di Ripristino Windows prima delle modifiche"
            $ctrl.TxtInfoBackupPath.Text           = "Backup JSON automatico attivo prima di ogni modifica."
            $ctrl.BtnAnteprimaComandi.Content      = "Anteprima comandi selezionati"
            $ctrl.BtnEsportaScriptFix.Content      = "Esporta come script .ps1"
            $ctrl.LblAutoFixRollbackTitle.Text     = "RIPRISTINO (ROLLBACK 1-CLICK)"
            $ctrl.BtnRollbackUltimo.Content        = "Ripristina ultime modifiche (Rollback)"
            $ctrl.LblAutoFixListaTitle.Text        = "CONTROLLI FALLITI - AUTO-FIX DETERMINISTICI & IMPOSTAZIONI MANUALI"
            $ctrl.BtnTornaDaAutoFix.Content        = "Torna alla Tabella Controlli"
            $ctrl.LblAutoFixLogTitle.Text          = "ANTEPRIMA COMANDI & LOG ESECUZIONE REMEDIATION"
        }

        & $aggiornaFiltriComboLingua

        if ($statoUI.RisultatiGrezzi.Count -eq 0) {
            if ($lang -eq 'EN') {
                $ctrl.TxtMessaggioGuida.Text = "Click 'Start Scan' to audit all $totaleControlli Windows 11 security controls."
                $ctrl.TxtProgresso.Text      = "Ready (0/$totaleControlli)"
                $ctrl.TxtStatoLLM.Text       = "Status: Ready (auto-connects or auto-installs Ollama on demand)"
                $ctrl.TxtRispostaLLM.Text    = "1. Run the PC scan using the 'Start Scan ($totaleControlli controls)' button at the top.`r`n2. Click 'Generate Full PC Security Report' on the left to get an executive summary, prioritized remediation plan, and hardening recommendations.`r`n3. On a VM without Ollama installed, leave the auto-install checkbox enabled: the tool will silently configure Ollama or provide an instant built-in expert analysis."
            }
            elseif ($lang -eq 'DE') {
                $ctrl.TxtMessaggioGuida.Text = "Klicken Sie auf 'Scan starten', um alle $totaleControlli Windows 11-Sicherheitspruefungen durchzufuehren."
                $ctrl.TxtProgresso.Text      = "Bereit (0/$totaleControlli)"
                $ctrl.TxtStatoLLM.Text       = "Status: Bereit (verbindet oder installiert Ollama bei Bedarf automatisch)"
                $ctrl.TxtRispostaLLM.Text    = "1. Starten Sie zuerst den PC-Scan ueber die Schaltflaeche 'Scan starten ($totaleControlli Pruefungen)' oben.`r`n2. Klicken Sie links auf 'Vollstaendigen PC-Bericht erstellen', um eine Zusammenfassung und einen priorisierten Massnahmenplan zu erhalten.`r`n3. Auf einer VM ohne Ollama lassen Sie das Kontrollkaestchen aktiviert: Das Tool richtet Ollama automatisch ein oder liefert sofort eine integrierte Expertenanalyse."
            }
            else {
                $ctrl.TxtMessaggioGuida.Text = "Premi 'Avvia scansione' per analizzare i $totaleControlli controlli di sicurezza del PC."
                $ctrl.TxtProgresso.Text      = "Pronto (0/$totaleControlli)"
                $ctrl.TxtStatoLLM.Text       = "Stato: Pronto (connessione o auto-installazione automatica al primo avvio)"
                $ctrl.TxtRispostaLLM.Text    = "1. Esegui prima la scansione del PC col pulsante 'Avvia scansione ($totaleControlli controlli)' in alto.`r`n2. Premi 'Genera Resoconto Completo PC' qui a sinistra per ricevere l'analisi di tutte le vulnerabilita' trovate e i consigli pratici di messa in sicurezza.`r`n3. Se sei su una Macchina Virtuale senza Ollama, lascia attiva la spunta a sinistra: il tool pensera' a tutto in automatico (oppure fornira' l'analisi immediata tramite il motore esperto integrato)."
            }
        }
        else {
            $nValutati = $statoUI.RisultatiGrezzi.Count
            $idSelPrec = if ($null -ne $statoUI.ElementoSelezionato) { $statoUI.ElementoSelezionato.ControlId } else { $null }

            # Rigenera gli elementi della vista nella lingua selezionata
            $statoUI.ElementiVista = @(ConvertTo-RisultatiVista -Risultati $statoUI.RisultatiGrezzi -Catalogo $Catalogo -Lingua $lang)
            if ($null -ne $idSelPrec) {
                foreach ($el in $statoUI.ElementiVista) {
                    if ($el.ControlId -eq $idSelPrec) {
                        $statoUI.ElementoSelezionato = $el
                        break
                    }
                }
            }

            if (-not $statoUI.ScansioneInCorso) {
                $ctrl.TxtProgresso.Text = switch ($lang) {
                    'EN' { "Completed ($nValutati/$nValutati)" }
                    'DE' { "Abgeschlossen ($nValutati/$nValutati)" }
                    default { "Completata ($nValutati/$nValutati)" }
                }
            }

            # Aggiorna la lista delle criticita' nella Pagina 2 (IA)
            $falliti = @($statoUI.ElementiVista | Where-Object { $_.Status -eq 'fallito' })
            $ctrl.ListFallitiIA.ItemsSource = $falliti
            if ($null -ne $statoUI.ElementoSelezionato -and $statoUI.ElementoSelezionato.Status -eq 'fallito') {
                $ctrl.ListFallitiIA.SelectedItem = $statoUI.ElementoSelezionato
            }

            # Aggiorna anche il testo del Resoconto IA nella lingua selezionata cosi' non resta mai nella lingua precedente
            if ($statoUI.UltimaModalitaIA -eq 'Controllo' -and $null -ne $statoUI.ElementoSelezionato) {
                $dettCorr = Format-DettaglioControllo -Elemento $statoUI.ElementoSelezionato -Modalita 'Semplice' -Lingua $lang
                $ctrl.TxtRispostaLLM.Text = Format-AnalisiLocaleControllo -Dettaglio $dettCorr -Ambiente $Ambiente -Lingua $lang
                $ctrl.TxtStatoLLM.Text    = switch ($lang) {
                    'EN' { "Completed: Instant Security Analysis ($($dettCorr.ControlId))" }
                    'DE' { "Abgeschlossen: Sicherheitsanalyse ($($dettCorr.ControlId))" }
                    default { "Completato: Analisi di Sicurezza ($($dettCorr.ControlId))" }
                }
            }
            else {
                $conteggiCorr = Measure-ConteggiRisultati -Elementi $statoUI.RisultatiGrezzi
                $ctrl.TxtRispostaLLM.Text = Format-ResocontoLocaleScansione -ElementiVista $statoUI.ElementiVista -Conteggi $conteggiCorr -Ambiente $Ambiente -Lingua $lang
                $ctrl.TxtStatoLLM.Text    = switch ($lang) {
                    'EN' { "Completed: Full PC Security Report (EN)" }
                    'DE' { "Abgeschlossen: Vollstaendiger PC-Sicherheitsbericht (DE)" }
                    default { "Completato: Resoconto Completo Sicurezza PC (IT)" }
                }
            }

            & $applicaFiltriTabella
        }

        & $aggiornaConteggiERiepilogo
        & $aggiornaPannelloDettaglio
        & $aggiornaListaAutoFix

        if (-not $statoUI.FixInCorso) {
            $ctrl.TxtStatoAutoFix.Text = switch ($lang) {
                'EN' { "Status: Ready" }
                'DE' { "Status: Bereit" }
                default { "Stato: Pronto" }
            }
        }
    }

    # --- Eventi Selettore Lingua Esplicito [IT | EN | DE] ---
    $ctrl.BtnLinguaIT.Add_Click({
        $statoUI.LinguaCorrente = 'IT'
        & $applicaLinguaUI
    })
    $ctrl.BtnLinguaEN.Add_Click({
        $statoUI.LinguaCorrente = 'EN'
        & $applicaLinguaUI
    })
    $ctrl.BtnLinguaDE.Add_Click({
        $statoUI.LinguaCorrente = 'DE'
        & $applicaLinguaUI
    })

    # --- Eventi Tema (Scuro <-> Chiaro) ---
    $ctrl.BtnTema.Add_Click({
        if ($statoUI.TemaCorrente -eq 'Chiaro') {
            $statoUI.TemaCorrente = 'Scuro'
        }
        else {
            $statoUI.TemaCorrente = 'Chiaro'
        }
        Update-TemaFinestra -Finestra $finestra -Tema $statoUI.TemaCorrente
        & $aggiornaStileSelettori
        & $aggiornaTestoPulsanteTema
    })

    # --- Evento Riavvia come Amministratore ---
    $ctrl.BtnRiavviaAdmin.Add_Click({
        $lang = $statoUI.LinguaCorrente
        try {
            $percorsoEntry = if ($PercorsoProgetto -and (Test-Path -LiteralPath (Join-Path $PercorsoProgetto 'src\Invoke-Scanner.ps1'))) {
                Join-Path $PercorsoProgetto 'src\Invoke-Scanner.ps1'
            }
            elseif (Get-Variable -Name 'PercorsoScriptAutonomo' -Scope Script -ErrorAction SilentlyContinue) {
                $script:PercorsoScriptAutonomo
            }
            else {
                ''
            }

            if (-not [string]::IsNullOrWhiteSpace($percorsoEntry) -and (Test-Path -LiteralPath $percorsoEntry)) {
                $argomenti = "-NoProfile -ExecutionPolicy Bypass -STA -File `"$percorsoEntry`" -Gui"
                if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
                    $argomenti += " -ControlId $($ControlId -join ',')"
                }
                Start-Process -FilePath 'powershell.exe' -ArgumentList $argomenti -Verb RunAs
                $finestra.Close()
            }
            elseif (Get-Variable -Name 'UrlScriptRemoto' -Scope Script -ErrorAction SilentlyContinue) {
                $argomentiRemoti = "-NoProfile -ExecutionPolicy Bypass -STA -Command `"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; irm '$($script:UrlScriptRemoto)' | iex`""
                Start-Process -FilePath 'powershell.exe' -ArgumentList $argomentiRemoti -Verb RunAs
                $finestra.Close()
            }
            else {
                $msg = switch ($lang) {
                    'EN' { "Launched from remote memory: open a new PowerShell window as Administrator and re-run the command." }
                    'DE' { "Aus dem Remote-Speicher gestartet: Oeffnen Sie ein neues PowerShell-Fenster als Administrator und fuehren Sie den Befehl erneut aus." }
                    default { "Avviato da memoria remota: apri una nuova finestra di PowerShell come Amministratore e riesegui il comando." }
                }
                [System.Windows.MessageBox]::Show($msg, $finestra.Title, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
            }
        }
        catch {
            $msgErr = switch ($lang) {
                'EN' { "Restart as Administrator was canceled or failed." }
                'DE' { "Neustart als Administrator wurde abgebrochen oder ist fehlgeschlagen." }
                default { "Riavvio come amministratore annullato o non riuscito." }
            }
            [System.Windows.MessageBox]::Show($msgErr, $finestra.Title, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
        }
    })

    # --- Eventi Filtri ---
    $ctrl.CmbFiltroStato.Add_SelectionChanged({ & $applicaFiltriTabella })
    $ctrl.CmbFiltroGravita.Add_SelectionChanged({ & $applicaFiltriTabella })
    $ctrl.CmbFiltroCategoria.Add_SelectionChanged({ & $applicaFiltriTabella })
    $ctrl.TxtRicerca.Add_TextChanged({ & $applicaFiltriTabella })

    $ctrl.BtnResetFiltri.Add_Click({
        $ctrl.CmbFiltroStato.SelectedIndex = 0
        $ctrl.CmbFiltroGravita.SelectedIndex = 0
        $ctrl.CmbFiltroCategoria.SelectedIndex = 0
        $ctrl.TxtRicerca.Text = ''
        & $applicaFiltriTabella
    })

    # --- Selezione riga nella tabella ---
    $ctrl.GridRisultati.Add_SelectionChanged({
        $statoUI.ElementoSelezionato = $ctrl.GridRisultati.SelectedItem
        & $aggiornaPannelloDettaglio
    })

    # --- Selettore Semplice / Tecnico ---
    $ctrl.BtnModoSemplice.Add_Click({
        $statoUI.ModalitaDettaglio = 'Semplice'
        & $aggiornaPannelloDettaglio
    })

    $ctrl.BtnModoTecnico.Add_Click({
        $statoUI.ModalitaDettaglio = 'Tecnico'
        & $aggiornaPannelloDettaglio
    })

    # --- Copia comando negli appunti ---
    $ctrl.BtnCopiaComando.Add_Click({
        $cmd = $ctrl.TxtComandoRimedio.Text
        if (-not [string]::IsNullOrWhiteSpace($cmd)) {
            [System.Windows.Clipboard]::SetText($cmd)
            $ctrl.TxtFeedbackCopia.Visibility = [System.Windows.Visibility]::Visible
        }
    })

    # --- Navigazione tra Pagina 1 (Scansione), Pagina 2 (IA) e Pagina 3 (Auto-Fix) ---
    $mostraPagina = {
        param([string]$NomePagina)
        $statoUI.PaginaCorrente = $NomePagina
        & $aggiornaStileSelettori

        if ($NomePagina -eq 'IA') {
            $ctrl.GridPaginaScansione.Visibility = [System.Windows.Visibility]::Collapsed
            $ctrl.GridPaginaAutoFix.Visibility   = [System.Windows.Visibility]::Collapsed
            $ctrl.GridPaginaIA.Visibility        = [System.Windows.Visibility]::Visible
            # Aggiorna la lista delle criticita' nella barra laterale della Pagina IA
            $falliti = @($statoUI.ElementiVista | Where-Object { $_.Status -eq 'fallito' })
            $ctrl.ListFallitiIA.ItemsSource = $falliti
            if ($null -ne $statoUI.ElementoSelezionato) {
                $ctrl.ListFallitiIA.SelectedItem = $statoUI.ElementoSelezionato
            }
            elseif ($falliti.Count -gt 0) {
                $ctrl.ListFallitiIA.SelectedIndex = 0
            }
        }
        elseif ($NomePagina -eq 'AutoFix') {
            $ctrl.GridPaginaScansione.Visibility = [System.Windows.Visibility]::Collapsed
            $ctrl.GridPaginaIA.Visibility        = [System.Windows.Visibility]::Collapsed
            $ctrl.GridPaginaAutoFix.Visibility   = [System.Windows.Visibility]::Visible
            & $aggiornaListaAutoFix
        }
        else {
            $ctrl.GridPaginaIA.Visibility        = [System.Windows.Visibility]::Collapsed
            $ctrl.GridPaginaAutoFix.Visibility   = [System.Windows.Visibility]::Collapsed
            $ctrl.GridPaginaScansione.Visibility = [System.Windows.Visibility]::Visible
        }
    }

    $ctrl.BtnNavScansione.Add_Click({ & $mostraPagina 'Scansione' })
    $ctrl.BtnTornaScansione.Add_Click({ & $mostraPagina 'Scansione' })
    $ctrl.BtnTornaDaAutoFix.Add_Click({ & $mostraPagina 'Scansione' })
    $ctrl.BtnNavIA.Add_Click({ & $mostraPagina 'IA' })
    $ctrl.BtnNavAutoFix.Add_Click({ & $mostraPagina 'AutoFix' })

    $apriSettingsUriSicuro = {
        param([string]$Uri)
        if (-not (Test-SafeSettingsUri -Uri $Uri)) {
            return
        }
        try {
            Start-Process -FilePath $Uri.Trim()
        }
        catch {
            [System.Windows.MessageBox]::Show($_.Exception.Message, $finestra.Title, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning) | Out-Null
        }
    }

    $ctrl.BtnApriImpostazioni.Add_Click({
        & $apriSettingsUriSicuro $statoUI.UriImpostazioniCorr
    })

    $ctrl.ListAutoFixControlli.AddHandler(
        [System.Windows.Controls.Primitives.ToggleButton]::CheckedEvent,
        [System.Windows.RoutedEventHandler]{ & $aggiornaConteggioAutoFix }
    )
    $ctrl.ListAutoFixControlli.AddHandler(
        [System.Windows.Controls.Primitives.ToggleButton]::UncheckedEvent,
        [System.Windows.RoutedEventHandler]{ & $aggiornaConteggioAutoFix }
    )
    $ctrl.ListAutoFixControlli.AddHandler(
        [System.Windows.Controls.Primitives.ButtonBase]::ClickEvent,
        [System.Windows.RoutedEventHandler]{
            param($sender, $e)
            $dep = $e.OriginalSource -as [System.Windows.DependencyObject]
            while ($null -ne $dep) {
                if ($dep -is [System.Windows.Controls.CheckBox] -or $dep -is [System.Windows.Controls.Primitives.ToggleButton]) {
                    return
                }
                if ($dep -is [System.Windows.Controls.Button]) {
                    $tagUri = [string]$dep.Tag
                    if (Test-SafeSettingsUri -Uri $tagUri) {
                        & $apriSettingsUriSicuro $tagUri
                    }
                    return
                }
                $dep = [System.Windows.Media.VisualTreeHelper]::GetParent($dep)
            }
        }
    )

    $ctrl.BtnSelezionaFixSicuri.Add_Click({
        foreach ($item in @($statoUI.ElementiAutoFix)) {
            if ($null -ne $item) {
                $item.IsSelected = [bool]$item.IsAutoSafe
            }
        }
        $ctrl.ListAutoFixControlli.Items.Refresh()
        & $aggiornaConteggioAutoFix
    })

    $ctrl.BtnDeselezionaTuttiFix.Add_Click({
        foreach ($item in @($statoUI.ElementiAutoFix)) {
            if ($null -ne $item) {
                $item.IsSelected = $false
            }
        }
        $ctrl.ListAutoFixControlli.Items.Refresh()
        & $aggiornaConteggioAutoFix
    })

    $getAutoFixTargetIds = {
        $sel = @($statoUI.ElementiAutoFix | Where-Object { $_.CanAutoFix -and $_.IsSelected } | ForEach-Object { $_.ControlId })
        if ($sel.Count -gt 0) {
            return $sel
        }
        return @($statoUI.ElementiAutoFix | Where-Object { $_.CanAutoFix } | ForEach-Object { $_.ControlId })
    }

    $ctrl.BtnAnteprimaComandi.Add_Click({
        if ($null -eq (Get-Command -Name 'Get-RemediationPreview' -ErrorAction SilentlyContinue)) {
            return
        }
        $targetIds = & $getAutoFixTargetIds
        if (@($targetIds).Count -eq 0) { return }
        $previews = @(Get-RemediationPreview -ControlIds $targetIds)
        $ctrl.TxtLogAutoFix.Text = Format-RemediationScriptExport -PreviewItems $previews -Lingua $statoUI.LinguaCorrente
        $ctrl.TxtStatoAutoFix.Text = switch ($statoUI.LinguaCorrente) {
            'EN' { "Preview generated for $(@($targetIds).Count) control(s)" }
            'DE' { "Vorschau fuer $(@($targetIds).Count) Pruefung(en) erstellt" }
            default { "Anteprima generata per $(@($targetIds).Count) controllo/i" }
        }
    })

    $ctrl.BtnEsportaScriptFix.Add_Click({
        if ($null -eq (Get-Command -Name 'Get-RemediationPreview' -ErrorAction SilentlyContinue)) {
            return
        }
        $lang = $statoUI.LinguaCorrente
        $targetIds = & $getAutoFixTargetIds
        if (@($targetIds).Count -eq 0) { return }
        $previews = @(Get-RemediationPreview -ControlIds $targetIds)
        $scriptTxt = Format-RemediationScriptExport -PreviewItems $previews -Lingua $lang

        $dialogo = New-Object Microsoft.Win32.SaveFileDialog
        $dialogo.Title      = switch ($lang) { 'EN' { "Export PowerShell Remediation Script" } 'DE' { "PowerShell-Skript exportieren" } default { "Esporta script PowerShell di remediation" } }
        $dialogo.Filter     = "PowerShell Script (*.ps1)|*.ps1"
        $dialogo.FileName   = (Get-NomeFileExport -Estensione 'ps1')
        $dialogo.DefaultExt = ".ps1"

        if ($dialogo.ShowDialog($finestra) -eq $true) {
            $utf8Bom = New-Object System.Text.UTF8Encoding($true)
            [System.IO.File]::WriteAllText($dialogo.FileName, $scriptTxt, $utf8Bom)
            $ctrl.TxtStatoAutoFix.Text = switch ($lang) {
                'EN' { "Exported script: $(Split-Path -Leaf $dialogo.FileName)" }
                'DE' { "Skript exportiert: $(Split-Path -Leaf $dialogo.FileName)" }
                default { "Script esportato: $(Split-Path -Leaf $dialogo.FileName)" }
            }
        }
    })

    $avviaRemediationAsincrona = {
        param([string[]]$IdsRichiesti)

        if ($statoUI.ScansioneInCorso -or $statoUI.FixInCorso) { return }
        if ($null -eq (Get-Command -Name 'Invoke-SecurityRemediation' -ErrorAction SilentlyContinue)) { return }

        $lang = $statoUI.LinguaCorrente
        $idsClean = @($IdsRichiesti | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
        if ($idsClean.Count -eq 0) { return }

        $previews = @(Get-RemediationPreview -ControlIds $idsClean)
        $richiedeAdminBatch = $false
        foreach ($p in $previews) {
            if ($p.RequiresAdmin -and ($p.FixMode -in @('AutoSafe', 'AutoReboot', 'Guided'))) {
                $richiedeAdminBatch = $true
                break
            }
        }

        if ($richiedeAdminBatch -and (-not $Ambiente.IsAdmin)) {
            $msgAdm = switch ($lang) {
                'EN' { "One or more selected fixes modify HKLM registry keys or Defender preferences and require Administrator privileges. Click 'Restart as Administrator' in the top warning banner first." }
                'DE' { "Mindestens eine ausgewaehlte Korrektur benoetigt Administratorrechte. Klicken Sie zuerst oben auf 'Als Administrator neustarten'." }
                default { "Uno o piu' fix selezionati modificano chiavi di sistema HKLM o preferenze di Defender e richiedono privilegi di Amministratore. Usa prima 'Riavvia come amministratore' nel banner in alto." }
            }
            [System.Windows.MessageBox]::Show($msgAdm, $finestra.Title, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Warning) | Out-Null
            return
        }

        $creaRp = ($ctrl.ChkCreaRestorePoint.IsChecked -eq $true)
        $msgConf = switch ($lang) {
            'EN' { "Apply $($idsClean.Count) remediation(s)?`r`nControls: $($idsClean -join ', ')`r`n`r`nA JSON rollback backup is saved automatically before modifying the system." }
            'DE' { "$($idsClean.Count) Korrektur(en) anwenden?`r`nPruefungen: $($idsClean -join ', ')`r`n`r`nVor den Aenderungen wird automatisch eine JSON-Rollback-Sicherung erstellt." }
            default { "Applicare $($idsClean.Count) correzione/i selezionate?`r`nControlli: $($idsClean -join ', ')`r`n`r`nVerrà salvato automaticamente un backup JSON per eventuale Rollback." }
        }
        $sceltaConf = [System.Windows.MessageBox]::Show($msgConf, $finestra.Title, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
        if ($sceltaConf -ne [System.Windows.MessageBoxResult]::Yes) {
            return
        }

        $statoUI.FixInCorso = $true
        & $aggiornaConteggioAutoFix
        & $aggiornaPannelloDettaglio
        $ctrl.BtnAvvia.IsEnabled = $false

        $ctrl.TxtLogAutoFix.Text = switch ($lang) {
            'EN' { "[Remediation started at $(Get-Date -Format 'HH:mm:ss')] Applying $($idsClean.Count) control(s)...`r`n" }
            'DE' { "[Behebung gestartet um $(Get-Date -Format 'HH:mm:ss')] Wende $($idsClean.Count) Korrektur(en) an...`r`n" }
            default { "[Remediation avviata alle $(Get-Date -Format 'HH:mm:ss')] Applicazione di $($idsClean.Count) controllo/i...`r`n" }
        }
        $ctrl.TxtStatoAutoFix.Text = switch ($lang) {
            'EN' { "Status: Applying fixes (0/$($idsClean.Count))..." }
            'DE' { "Status: Korrekturen werden angewendet (0/$($idsClean.Count))..." }
            default { "Stato: Applicazione fix in corso (0/$($idsClean.Count))..." }
        }

        $cbProgressoFix = [Action[int, int, object]]{
            param([int]$idx, [int]$tot, [object]$itemRes)
            $ctrl.TxtStatoAutoFix.Text = switch ($statoUI.LinguaCorrente) {
                'EN' { "Status: Applying & verifying ($idx/$tot)..." }
                'DE' { "Status: Anwenden & Pruefen ($idx/$tot)..." }
                default { "Stato: Applicazione e verifica ($idx/$tot)..." }
            }
            $riga = "[$idx/$tot] $($itemRes.ControlId) -> $($itemRes.Status) | $($itemRes.Message)"
            if (-not [string]::IsNullOrWhiteSpace([string]$itemRes.Error)) {
                $riga += " (Error: $($itemRes.Error))"
            }
            $ctrl.TxtLogAutoFix.AppendText("$riga`r`n")
            $ctrl.TxtLogAutoFix.ScrollToEnd()
        }

        $cbFineFix = [Action[object]]{
            param($payload)
            $langNow = $statoUI.LinguaCorrente
            $statoUI.FixInCorso = $false
            $ctrl.BtnAvvia.IsEnabled = $true

            $repFix = $payload.Report
            $errFatale = $payload.Error
            if ($null -ne $payload.Ps) { $payload.Ps.Dispose() }
            if ($null -ne $payload.Rs) { $payload.Rs.Close(); $payload.Rs.Dispose() }

            if (-not [string]::IsNullOrWhiteSpace([string]$errFatale)) {
                $ctrl.TxtLogAutoFix.AppendText("`r`n[ERROR] $errFatale`r`n")
                $ctrl.TxtStatoAutoFix.Text = switch ($langNow) {
                    'EN' { "Status: Remediation error" }
                    'DE' { "Status: Fehler bei der Behebung" }
                    default { "Stato: Errore durante la remediation" }
                }
            }
            elseif ($null -ne $repFix) {
                if (-not [string]::IsNullOrWhiteSpace([string]$repFix.BackupPath)) {
                    $statoUI.UltimoBackupPath = [string]$repFix.BackupPath
                }

                foreach ($rItem in @($repFix.Results)) {
                    if ($null -ne $rItem) {
                        $statoUI.EsitiFixPerId[$rItem.ControlId] = $rItem
                    }
                }

                $statoUI.RisultatiGrezzi = @(Update-RisultatiDopoFix -RisultatiGrezzi $statoUI.RisultatiGrezzi -FixResults @($repFix.Results))
                $idSelPrima = if ($null -ne $statoUI.ElementoSelezionato) { $statoUI.ElementoSelezionato.ControlId } else { $null }
                $statoUI.ElementiVista = @(ConvertTo-RisultatiVista -Risultati $statoUI.RisultatiGrezzi -Catalogo $Catalogo -Lingua $langNow)
                if ($null -ne $idSelPrima) {
                    foreach ($el in $statoUI.ElementiVista) {
                        if ($el.ControlId -eq $idSelPrima) {
                            $statoUI.ElementoSelezionato = $el
                            break
                        }
                    }
                }

                $fallitiAgg = @($statoUI.ElementiVista | Where-Object { $_.Status -eq 'fallito' })
                $ctrl.ListFallitiIA.ItemsSource = $fallitiAgg

                $ctrl.TxtLogAutoFix.AppendText("`r`n--- Summary: Fixed=$($repFix.FixedCount), RebootRequired=$($repFix.RebootRequiredCount), Blocked=$($repFix.BlockedCount), Failed=$($repFix.FailedCount) ---`r`n")
                if ($repFix.RestorePointCreated) {
                    $ctrl.TxtLogAutoFix.AppendText("System Restore Point: $($repFix.RestorePointMessage)`r`n")
                }
                if (-not [string]::IsNullOrWhiteSpace([string]$repFix.BackupPath)) {
                    $ctrl.TxtLogAutoFix.AppendText("Backup JSON: $($repFix.BackupPath)`r`n")
                }
                $ctrl.TxtLogAutoFix.ScrollToEnd()

                $ctrl.TxtStatoAutoFix.Text = switch ($langNow) {
                    'EN' { "Completed: $($repFix.FixedCount) fixed, $($repFix.RebootRequiredCount) reboot needed, $($repFix.BlockedCount) blocked, $($repFix.FailedCount) failed" }
                    'DE' { "Abgeschlossen: $($repFix.FixedCount) behoben, $($repFix.RebootRequiredCount) Neustart, $($repFix.BlockedCount) blockiert, $($repFix.FailedCount) fehlgeschlagen" }
                    default { "Completato: $($repFix.FixedCount) riparati, $($repFix.RebootRequiredCount) riavvio richiesto, $($repFix.BlockedCount) bloccati, $($repFix.FailedCount) falliti" }
                }
            }

            & $aggiornaConteggiERiepilogo
            & $applicaFiltriTabella
            & $aggiornaPannelloDettaglio
            & $aggiornaListaAutoFix
        }

        $issFix = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $nomiFnRem = @(
            'Get-DefaultBackupDirectory', 'New-RemediationBackupSession', 'Backup-RegistryValueState',
            'Backup-DefenderPreferenceState', 'Add-RemediationBackupEntry', 'Set-RegistryValueWithBackup',
            'Set-DefenderPreferenceWithBackup', 'Set-DefenderAsrRulesWithBackup', 'Invoke-NetAccounts',
            'Invoke-NetshWlan', 'Set-FirewallProfileWithBackup', 'Set-ServiceStartupWithBackup',
            'Set-ExecutionPolicyWithBackup', 'Disable-OptionalFeatureWithBackup', 'Set-AccountLockoutPolicyWithBackup',
            'Disable-LocalUserWithBackup', 'Set-WifiProfileManualWithBackup', 'ConvertTo-QuotedServicePath',
            'Save-RemediationBackupSession', 'New-ScannerRestorePoint', 'Restore-RemediationBackup',
            'Get-RemediationCatalog', 'Get-RemediationDefinition', 'Get-AutoSafeControlIds',
            'Get-AutoRebootControlIds', 'Get-GuidedControlIds', 'Test-IsAdministrator',
            'Test-IsRdpSession', 'Test-IsWinRmSession', 'Test-HvciSupported', 'Test-BuiltInAdminSafeToDisable',
            'Get-RemediationPreview', 'Invoke-SecurityRemediation', 'Invoke-Controlli', 'Test-RegistryValue'
        )
        foreach ($nomeFn in $nomiFnRem) {
            $fnObj = Get-Command -Name $nomeFn -ErrorAction SilentlyContinue
            if ($null -ne $fnObj) {
                [void]$issFix.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fnObj.Name, $fnObj.Definition)))
            }
        }
        foreach ($fnChk in @(Get-ChildItem Function:\Test-* -ErrorAction SilentlyContinue)) {
            [void]$issFix.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fnChk.Name, $fnChk.Definition)))
        }

        $rsFix = [runspacefactory]::CreateRunspace($issFix)
        $rsFix.ApartmentState = 'STA'
        $rsFix.ThreadOptions  = 'ReuseThread'
        $rsFix.Open()

        $psFix = [powershell]::Create()
        $psFix.Runspace = $rsFix

        $syncFix = [hashtable]::Synchronized(@{
            Finestra            = $finestra
            ControlIds          = $idsClean
            Catalogo            = $Catalogo
            Ambiente            = $Ambiente
            PercorsoChecks      = $percorsoChecks
            PercorsoCore        = $percorsoCore
            PercorsoRemediation = $percorsoRemediation
            ScanResults         = @($statoUI.RisultatiGrezzi)
            CreateRestorePoint  = $creaRp
            CallbackProgresso   = $cbProgressoFix
            CallbackFine        = $cbFineFix
            Ps                  = $psFix
            Rs                  = $rsFix
        })
        $rsFix.SessionStateProxy.SetVariable('SyncFix', $syncFix)

        [void]$psFix.AddScript({
            Set-StrictMode -Version 2
            $ErrorActionPreference = 'Stop'
            $rep = $null
            $errMsg = $null

            try {
                if (-not [string]::IsNullOrWhiteSpace($SyncFix.PercorsoCore) -and (Test-Path -LiteralPath $SyncFix.PercorsoCore)) {
                    . (Join-Path $SyncFix.PercorsoCore 'Runner.ps1')
                    . (Join-Path $SyncFix.PercorsoChecks 'Registry.ps1')
                    . (Join-Path $SyncFix.PercorsoChecks 'Firewall.ps1')
                    . (Join-Path $SyncFix.PercorsoChecks 'Accounts.ps1')
                    . (Join-Path $SyncFix.PercorsoChecks 'Defender.ps1')
                    . (Join-Path $SyncFix.PercorsoChecks 'FileSecurity.ps1')
                    . (Join-Path $SyncFix.PercorsoChecks 'Network.ps1')
                    . (Join-Path $SyncFix.PercorsoChecks 'SystemSecurity.ps1')
                }
                if (-not [string]::IsNullOrWhiteSpace($SyncFix.PercorsoRemediation) -and (Test-Path -LiteralPath $SyncFix.PercorsoRemediation)) {
                    . (Join-Path $SyncFix.PercorsoRemediation 'BackupManager.ps1')
                    . (Join-Path $SyncFix.PercorsoRemediation 'RemediationCatalog.ps1')
                    . (Join-Path $SyncFix.PercorsoRemediation 'FixRunner.ps1')
                }

                $onProgRem = {
                    param($idx, $tot, $itemRes)
                    [void]$SyncFix.Finestra.Dispatcher.Invoke(
                        [System.Windows.Threading.DispatcherPriority]::Background,
                        $SyncFix.CallbackProgresso,
                        $idx,
                        $tot,
                        $itemRes
                    )
                }

                $paramsRem = @{
                    ControlIds     = $SyncFix.ControlIds
                    Catalogo       = $SyncFix.Catalogo
                    Ambiente       = $SyncFix.Ambiente
                    CartellaChecks = $SyncFix.PercorsoChecks
                    ScanResults    = $SyncFix.ScanResults
                    OnProgress     = $onProgRem
                }
                if ($SyncFix.CreateRestorePoint) {
                    $paramsRem['CreateRestorePoint'] = $true
                }

                $rep = Invoke-SecurityRemediation @paramsRem
            }
            catch {
                $errMsg = $_.Exception.Message
            }
            finally {
                $payload = [PSCustomObject]@{
                    Report = $rep
                    Error  = $errMsg
                    Ps     = $SyncFix.Ps
                    Rs     = $SyncFix.Rs
                }
                [void]$SyncFix.Finestra.Dispatcher.BeginInvoke(
                    [System.Windows.Threading.DispatcherPriority]::Normal,
                    $SyncFix.CallbackFine,
                    $payload
                )
            }
        })
        [void]$psFix.BeginInvoke()
    }

    $ctrl.BtnApplicaFixSelezionati.Add_Click({
        $selIds = @($statoUI.ElementiAutoFix | Where-Object { $_.CanAutoFix -and $_.IsSelected } | ForEach-Object { $_.ControlId })
        & $avviaRemediationAsincrona $selIds
    })

    $ctrl.BtnRiparaSingolo.Add_Click({
        if ($null -eq $statoUI.ElementoSelezionato) { return }
        & $avviaRemediationAsincrona @($statoUI.ElementoSelezionato.ControlId)
    })

    $ctrl.BtnRollbackUltimo.Add_Click({
        if ($statoUI.ScansioneInCorso -or $statoUI.FixInCorso) { return }
        if ($null -eq (Get-Command -Name 'Restore-RemediationBackup' -ErrorAction SilentlyContinue)) { return }

        $backupPath = $statoUI.UltimoBackupPath
        if ([string]::IsNullOrWhiteSpace($backupPath) -or (-not [System.IO.File]::Exists($backupPath))) { return }

        $lang = $statoUI.LinguaCorrente
        $nomeBkp = Split-Path -Leaf $backupPath
        $msgRb = switch ($lang) {
            'EN' { "Restore original settings from backup '$nomeBkp'?" }
            'DE' { "Urspruengliche Einstellungen aus Sicherung '$nomeBkp' wiederherstellen?" }
            default { "Ripristinare le impostazioni originali dal backup '$nomeBkp'?" }
        }
        $sceltaRb = [System.Windows.MessageBox]::Show($msgRb, $finestra.Title, [System.Windows.MessageBoxButton]::YesNo, [System.Windows.MessageBoxImage]::Question)
        if ($sceltaRb -ne [System.Windows.MessageBoxResult]::Yes) {
            return
        }

        $statoUI.FixInCorso = $true
        & $aggiornaConteggioAutoFix
        & $aggiornaPannelloDettaglio
        $ctrl.BtnAvvia.IsEnabled = $false
        $ctrl.TxtStatoAutoFix.Text = switch ($lang) {
            'EN' { "Status: Rolling back from $nomeBkp..." }
            'DE' { "Status: Rollback aus $nomeBkp..." }
            default { "Stato: Ripristino in corso da $nomeBkp..." }
        }
        $ctrl.TxtLogAutoFix.AppendText("`r`n[Rollback started at $(Get-Date -Format 'HH:mm:ss')] File: $backupPath`r`n")

        $cbFineRb = [Action[object]]{
            param($payloadRb)
            $langNow = $statoUI.LinguaCorrente
            $statoUI.FixInCorso = $false
            $ctrl.BtnAvvia.IsEnabled = $true

            $rbRes = $payloadRb.RestoreResult
            $rechecks = @($payloadRb.Rechecks)
            $errMsg = $payloadRb.Error
            if ($null -ne $payloadRb.Ps) { $payloadRb.Ps.Dispose() }
            if ($null -ne $payloadRb.Rs) { $payloadRb.Rs.Close(); $payloadRb.Rs.Dispose() }

            if (-not [string]::IsNullOrWhiteSpace([string]$errMsg)) {
                $ctrl.TxtLogAutoFix.AppendText("[Rollback ERROR] $errMsg`r`n")
                $ctrl.TxtStatoAutoFix.Text = switch ($langNow) {
                    'EN' { "Status: Rollback failed" }
                    'DE' { "Status: Rollback fehlgeschlagen" }
                    default { "Stato: Rollback fallito" }
                }
            }
            elseif ($null -ne $rbRes) {
                foreach ($itemR in @($rbRes.Results)) {
                    $ctrl.TxtLogAutoFix.AppendText("[Rollback] $($itemR.ControlId) -> $($itemR.Target) | Restored=$($itemR.Restored) $($itemR.Error)`r`n")
                }
                if ($rechecks.Count -gt 0) {
                    $mappedFixes = @()
                    foreach ($rc in $rechecks) {
                        $statoUI.EsitiFixPerId[$rc.control_id] = [PSCustomObject]@{
                            Status  = 'RolledBack'
                            Message = "Rolled back ($($rc.status))"
                            Error   = $rc.error
                        }
                        $mappedFixes += [PSCustomObject]@{
                            ControlId         = $rc.control_id
                            PostCheckStatus   = $rc.status
                            PostCheckObserved = $rc.observed
                            Error             = $rc.error
                        }
                    }
                    $statoUI.RisultatiGrezzi = @(Update-RisultatiDopoFix -RisultatiGrezzi $statoUI.RisultatiGrezzi -FixResults $mappedFixes)
                    $statoUI.ElementiVista = @(ConvertTo-RisultatiVista -Risultati $statoUI.RisultatiGrezzi -Catalogo $Catalogo -Lingua $langNow)
                    $ctrl.ListFallitiIA.ItemsSource = @($statoUI.ElementiVista | Where-Object { $_.Status -eq 'fallito' })
                }

                $ctrl.TxtLogAutoFix.AppendText("--- Rollback completed: $($rbRes.RestoredCount)/$($rbRes.TotalEntries) entries restored ---`r`n")
                $ctrl.TxtLogAutoFix.ScrollToEnd()
                $ctrl.TxtStatoAutoFix.Text = switch ($langNow) {
                    'EN' { "Rollback completed: $($rbRes.RestoredCount)/$($rbRes.TotalEntries) restored" }
                    'DE' { "Rollback abgeschlossen: $($rbRes.RestoredCount)/$($rbRes.TotalEntries) wiederhergestellt" }
                    default { "Rollback completato: $($rbRes.RestoredCount)/$($rbRes.TotalEntries) voci ripristinate" }
                }
            }

            & $aggiornaConteggiERiepilogo
            & $applicaFiltriTabella
            & $aggiornaPannelloDettaglio
            & $aggiornaListaAutoFix
        }

        $issRb = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        foreach ($nomeFn in @('Restore-RemediationBackup', 'Invoke-NetAccounts', 'Invoke-NetshWlan', 'Invoke-Controlli', 'Test-RegistryValue')) {
            $fnObj = Get-Command -Name $nomeFn -ErrorAction SilentlyContinue
            if ($null -ne $fnObj) {
                [void]$issRb.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fnObj.Name, $fnObj.Definition)))
            }
        }
        foreach ($fnChk in @(Get-ChildItem Function:\Test-* -ErrorAction SilentlyContinue)) {
            [void]$issRb.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fnChk.Name, $fnChk.Definition)))
        }

        $rsRb = [runspacefactory]::CreateRunspace($issRb)
        $rsRb.ApartmentState = 'STA'
        $rsRb.ThreadOptions  = 'ReuseThread'
        $rsRb.Open()

        $psRb = [powershell]::Create()
        $psRb.Runspace = $rsRb

        $syncRb = [hashtable]::Synchronized(@{
            Finestra            = $finestra
            BackupPath          = $backupPath
            Catalogo            = $Catalogo
            Ambiente            = $Ambiente
            PercorsoChecks      = $percorsoChecks
            PercorsoCore        = $percorsoCore
            PercorsoRemediation = $percorsoRemediation
            CallbackFine        = $cbFineRb
            Ps                  = $psRb
            Rs                  = $rsRb
        })
        $rsRb.SessionStateProxy.SetVariable('SyncRb', $syncRb)

        [void]$psRb.AddScript({
            Set-StrictMode -Version 2
            $ErrorActionPreference = 'Stop'
            $rbResult = $null
            $rechecks = @()
            $errMsg   = $null

            try {
                if (-not [string]::IsNullOrWhiteSpace($SyncRb.PercorsoCore) -and (Test-Path -LiteralPath $SyncRb.PercorsoCore)) {
                    . (Join-Path $SyncRb.PercorsoCore 'Runner.ps1')
                    . (Join-Path $SyncRb.PercorsoChecks 'Registry.ps1')
                    . (Join-Path $SyncRb.PercorsoChecks 'Firewall.ps1')
                    . (Join-Path $SyncRb.PercorsoChecks 'Accounts.ps1')
                    . (Join-Path $SyncRb.PercorsoChecks 'Defender.ps1')
                    . (Join-Path $SyncRb.PercorsoChecks 'FileSecurity.ps1')
                    . (Join-Path $SyncRb.PercorsoChecks 'Network.ps1')
                    . (Join-Path $SyncRb.PercorsoChecks 'SystemSecurity.ps1')
                }
                if (-not [string]::IsNullOrWhiteSpace($SyncRb.PercorsoRemediation) -and (Test-Path -LiteralPath $SyncRb.PercorsoRemediation)) {
                    . (Join-Path $SyncRb.PercorsoRemediation 'BackupManager.ps1')
                }

                $rbResult = Restore-RemediationBackup -BackupPath $SyncRb.BackupPath
                $idsRestored = @($rbResult.Results | ForEach-Object { $_.ControlId } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
                if ($idsRestored.Count -gt 0 -and $null -ne $SyncRb.Catalogo -and $null -ne $SyncRb.Ambiente) {
                    $rechecks = @(Invoke-Controlli -Catalogo $SyncRb.Catalogo -Ambiente $SyncRb.Ambiente -ControlId $idsRestored -CartellaChecks $SyncRb.PercorsoChecks)
                }
            }
            catch {
                $errMsg = $_.Exception.Message
            }
            finally {
                $payload = [PSCustomObject]@{
                    RestoreResult = $rbResult
                    Rechecks      = @($rechecks)
                    Error         = $errMsg
                    Ps            = $SyncRb.Ps
                    Rs            = $SyncRb.Rs
                }
                [void]$SyncRb.Finestra.Dispatcher.BeginInvoke(
                    [System.Windows.Threading.DispatcherPriority]::Normal,
                    $SyncRb.CallbackFine,
                    $payload
                )
            }
        })
        [void]$psRb.BeginInvoke()
    })

    $ctrl.ListFallitiIA.Add_SelectionChanged({
        if ($null -ne $ctrl.ListFallitiIA.SelectedItem) {
            $statoUI.ElementoSelezionato = $ctrl.ListFallitiIA.SelectedItem
            & $aggiornaPannelloDettaglio
        }
    })

    # --- Funzione asincrona per eseguire una richiesta Ollama in un Runspace (con Auto-Provisioning sulla VM) ---
    $avviaRichiestaOllamaAsincrona = {
        param(
            [string]$PromptDaInviare,
            [string]$EtichettaOperazione,
            [string]$TestoFallback = ''
        )

        $lang = $statoUI.LinguaCorrente

        # Passa automaticamente alla Pagina 2 (Pagina dedicata Assistente IA)
        & $mostraPagina 'IA'

        $modelloScelto = $ctrl.CmbModelloOllama.Text
        if ([string]::IsNullOrWhiteSpace($modelloScelto)) {
            $modelloScelto = 'qwen2.5:0.5b'
        }

        $endpointScelto = $ctrl.TxtEndpointOllama.Text
        if ([string]::IsNullOrWhiteSpace($endpointScelto)) {
            $endpointScelto = 'http://127.0.0.1:11434'
        }

        $autoInstalla = ($ctrl.ChkAutoInstallaOllama.IsChecked -eq $true)

        $ctrl.BtnSpiegaLLM.IsEnabled          = $false
        $ctrl.BtnSpiegaControlloTab.IsEnabled = $false
        $ctrl.BtnResocontoLLM.IsEnabled       = $false
        $ctrl.BtnResocontoTab.IsEnabled       = $false
        $ctrl.BtnVerificaOllama.IsEnabled     = $false
        $ctrl.TxtStatoLLM.Text                = switch ($lang) {
            'EN' { "$EtichettaOperazione in progress ($modelloScelto)..." }
            'DE' { "$EtichettaOperazione laeuft ($modelloScelto)..." }
            default { "$EtichettaOperazione in corso ($modelloScelto)..." }
        }

        # Mostra subito l'analisi preliminare mentre Ollama genera (o si auto-installa sulla VM)
        if (-not [string]::IsNullOrWhiteSpace($TestoFallback)) {
            $bannerAttesa = switch ($lang) {
                'EN' { "[Connecting/Preparing Ollama ($modelloScelto) in background... Here is the immediate structured report:]" }
                'DE' { "[Verbindung/Vorbereitung von Ollama ($modelloScelto) im Hintergrund... Hier ist der sofortige strukturierte Bericht:]" }
                default { "[Connessione/Preparazione di Ollama ($modelloScelto) in corso in background... Ecco intanto il resoconto strutturato immediato:]" }
            }
            $ctrl.TxtRispostaLLM.Text = "$bannerAttesa`n`n$TestoFallback"
        }
        else {
            $ctrl.TxtRispostaLLM.Text = switch ($lang) {
                'EN' { "Processing with Ollama ($modelloScelto)... If you are on a VM without Ollama, the scanner is auto-configuring it in background." }
                'DE' { "Verarbeitung mit Ollama ($modelloScelto)... Auf einer VM ohne Ollama wird der Dienst automatisch im Hintergrund eingerichtet." }
                default { "Elaborazione in corso con Ollama ($modelloScelto)... Se ti trovi su una VM senza Ollama, lo scanner lo sta configurando automaticamente in background." }
            }
        }

        $callbackStatoLlm = [Action[string]]{
            param([string]$MsgStato)
            $ctrl.TxtStatoLLM.Text = $MsgStato
        }

        $callbackFineLlm = [Action[object]]{
            param($EsitoLlm)
            $langNow = $statoUI.LinguaCorrente
            $ctrl.BtnSpiegaLLM.IsEnabled          = $true
            $ctrl.BtnSpiegaControlloTab.IsEnabled = $true
            $ctrl.BtnResocontoTab.IsEnabled       = $true
            $ctrl.BtnVerificaOllama.IsEnabled     = $true
            if ($statoUI.RisultatiGrezzi.Count -gt 0) {
                $ctrl.BtnResocontoLLM.IsEnabled = $true
            }

            if ($EsitoLlm.Successo) {
                $sec = [math]::Round(($EsitoLlm.DurataMs / 1000.0), 1)
                $sorgente = if ($null -ne $EsitoLlm.PSObject.Properties['Sorgente']) { $EsitoLlm.Sorgente } else { $EsitoLlm.Modello }
                $ctrl.TxtStatoLLM.Text = switch ($langNow) {
                    'EN' { "Completed by: $sorgente (${sec}s)" }
                    'DE' { "Abgeschlossen von: $sorgente (${sec}s)" }
                    default { "Completato da: $sorgente (${sec}s)" }
                }
                $ctrl.TxtRispostaLLM.Text = $EsitoLlm.Risposta
            }
            else {
                $ctrl.TxtStatoLLM.Text = switch ($langNow) {
                    'EN' { "Status: $($EsitoLlm.Modello) unavailable" }
                    'DE' { "Status: $($EsitoLlm.Modello) nicht verfuegbar" }
                    default { "Stato: $($EsitoLlm.Modello) non disponibile" }
                }
                $ctrl.TxtRispostaLLM.Text = $EsitoLlm.Errore
            }
        }

        $syncLlm = [hashtable]::Synchronized(@{
            Finestra       = $finestra
            Prompt         = $PromptDaInviare
            Modello        = $modelloScelto
            Endpoint       = $endpointScelto
            Fallback       = $TestoFallback
            AutoProvision  = $autoInstalla
            Lingua         = $lang
            CallbackStato  = $callbackStatoLlm
            CallbackFine   = $callbackFineLlm
        })

        $issLlm = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $nomiFnOllama = @('Find-EseguibileOllamaLocale', 'Test-ConnessioneOllama', 'Initialize-AmbienteOllama', 'Invoke-RichiestaOllama')
        foreach ($nomeFn in $nomiFnOllama) {
            $fnObj = Get-Command -Name $nomeFn -ErrorAction SilentlyContinue
            if ($null -ne $fnObj) {
                $entryFn = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fnObj.Name, $fnObj.Definition)
                [void]$issLlm.Commands.Add($entryFn)
            }
        }

        $rsLlm = [runspacefactory]::CreateRunspace($issLlm)
        $rsLlm.ApartmentState = 'STA'
        $rsLlm.ThreadOptions  = 'ReuseThread'
        $rsLlm.Open()
        $rsLlm.SessionStateProxy.SetVariable('SyncLlm', $syncLlm)

        $psLlm = [powershell]::Create()
        $psLlm.Runspace = $rsLlm
        [void]$psLlm.AddScript({
            $onStatusBlock = {
                param([string]$statoMsg)
                [void]$SyncLlm.Finestra.Dispatcher.Invoke(
                    [System.Windows.Threading.DispatcherPriority]::Background,
                    $SyncLlm.CallbackStato,
                    $statoMsg
                )
            }
            $esito = Invoke-RichiestaOllama -Prompt $SyncLlm.Prompt -Modello $SyncLlm.Modello -Endpoint $SyncLlm.Endpoint -TestoFallbackLocale $SyncLlm.Fallback -AutoProvision $SyncLlm.AutoProvision -Lingua $SyncLlm.Lingua -OnStatus $onStatusBlock
            [void]$SyncLlm.Finestra.Dispatcher.Invoke(
                [System.Windows.Threading.DispatcherPriority]::Normal,
                $SyncLlm.CallbackFine,
                $esito
            )
        })
        [void]$psLlm.BeginInvoke()
    }

    # --- Pulsante Verifica / Auto-Configura Ollama in background ---
    $ctrl.BtnVerificaOllama.Add_Click({
        $lang = $statoUI.LinguaCorrente
        $endpointScelto = if ([string]::IsNullOrWhiteSpace($ctrl.TxtEndpointOllama.Text)) { 'http://127.0.0.1:11434' } else { $ctrl.TxtEndpointOllama.Text.Trim() }
        $autoInst = ($ctrl.ChkAutoInstallaOllama.IsChecked -eq $true)
        $ctrl.BtnVerificaOllama.IsEnabled = $false
        $ctrl.TxtStatoLLM.Text = switch ($lang) {
            'EN' { "Checking or auto-installing Ollama..." }
            'DE' { "Ollama wird geprueft oder automatisch installiert..." }
            default { "Verifica o installazione automatica di Ollama in corso..." }
        }

        $cbStato = [Action[string]]{ param([string]$m) $ctrl.TxtStatoLLM.Text = $m }
        $cbFine  = [Action[object]]{
            param($statoOll)
            $langNow = $statoUI.LinguaCorrente
            $ctrl.BtnVerificaOllama.IsEnabled = $true
            if ($statoOll.Disponibile) {
                $ctrl.TxtEndpointOllama.Text = $statoOll.Endpoint
                if ($statoOll.Modelli.Count -gt 0) {
                    $ctrl.CmbModelloOllama.Items.Clear()
                    foreach ($mod in $statoOll.Modelli) {
                        $itemM = New-Object System.Windows.Controls.ComboBoxItem
                        $itemM.Content = $mod
                        [void]$ctrl.CmbModelloOllama.Items.Add($itemM)
                    }
                    $ctrl.CmbModelloOllama.SelectedIndex = 0
                    $ctrl.TxtStatoLLM.Text = switch ($langNow) {
                        'EN' { "Ollama connected on $($statoOll.Endpoint)! Ready models: $($statoOll.Modelli -join ', ')" }
                        'DE' { "Ollama verbunden auf $($statoOll.Endpoint)! Bereite Modelle: $($statoOll.Modelli -join ', ')" }
                        default { "Ollama connesso su $($statoOll.Endpoint)! Modelli pronti: $($statoOll.Modelli -join ', ')" }
                    }
                }
                else {
                    $ctrl.TxtStatoLLM.Text = switch ($langNow) {
                        'EN' { "Ollama active on $($statoOll.Endpoint)! Model '$($ctrl.CmbModelloOllama.Text)' will be downloaded automatically on first analysis." }
                        'DE' { "Ollama aktiv auf $($statoOll.Endpoint)! Modell '$($ctrl.CmbModelloOllama.Text)' wird bei der ersten Analyse automatisch geladen." }
                        default { "Ollama attivo su $($statoOll.Endpoint)! Il modello '$($ctrl.CmbModelloOllama.Text)' verra' scaricato automaticamente alla prima analisi." }
                    }
                }
            }
            else {
                $ctrl.TxtStatoLLM.Text = switch ($langNow) {
                    'EN' { "Ollama unreachable: Built-in Expert Security Engine is active." }
                    'DE' { "Ollama nicht erreichbar: Integrierte Experten-Engine ist aktiv." }
                    default { "Ollama non raggiungibile: attivo il Motore Esperto Integrato." }
                }
            }
        }

        $syncCfg = [hashtable]::Synchronized(@{
            Finestra     = $finestra
            Endpoint     = $endpointScelto
            AutoInstalla = $autoInst
            CbStato      = $cbStato
            CbFine       = $cbFine
        })

        $issCfg = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        foreach ($nomeFn in @('Find-EseguibileOllamaLocale', 'Test-ConnessioneOllama', 'Initialize-AmbienteOllama')) {
            $fnObj = Get-Command -Name $nomeFn -ErrorAction SilentlyContinue
            if ($null -ne $fnObj) {
                [void]$issCfg.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fnObj.Name, $fnObj.Definition)))
            }
        }

        $rsCfg = [runspacefactory]::CreateRunspace($issCfg)
        $rsCfg.ApartmentState = 'STA'
        $rsCfg.ThreadOptions  = 'ReuseThread'
        $rsCfg.Open()
        $rsCfg.SessionStateProxy.SetVariable('SyncCfg', $syncCfg)

        $psCfg = [powershell]::Create()
        $psCfg.Runspace = $rsCfg
        [void]$psCfg.AddScript({
            $sbStato = {
                param([string]$msg)
                [void]$SyncCfg.Finestra.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, $SyncCfg.CbStato, $msg)
            }
            $esitoCfg = Initialize-AmbienteOllama -Endpoint $SyncCfg.Endpoint -AutoInstalla $SyncCfg.AutoInstalla -OnStatus $sbStato
            [void]$SyncCfg.Finestra.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Normal, $SyncCfg.CbFine, $esitoCfg)
        })
        [void]$psCfg.BeginInvoke()
    })

    # --- Azione: Spiega controllo selezionato ---
    $eseguiSpiegazioneControllo = {
        $lang = $statoUI.LinguaCorrente
        & $mostraPagina 'IA'
        if ($null -eq $statoUI.ElementoSelezionato) {
            $ctrl.TxtStatoLLM.Text = switch ($lang) {
                'EN' { "Please select a control from the 'Detected Issues' list on the left (or from the Controls Table) first." }
                'DE' { "Bitte waehlen Sie zuerst links in der Liste 'Erkannte Probleme' (oder in der Tabelle) eine Sicherheitspruefung aus." }
                default { "Seleziona prima un controllo dalla lista 'Criticita' rilevate' qui a sinistra (o dalla Tabella Controlli)." }
            }
            return
        }
        $statoUI.UltimaModalitaIA = 'Controllo'
        $dettaglio   = Format-DettaglioControllo -Elemento $statoUI.ElementoSelezionato -Modalita 'Semplice' -Lingua $lang
        $promptCtrl  = Format-PromptControlloOllama -Dettaglio $dettaglio -Ambiente $Ambiente -Lingua $lang
        $fallbackLoc = Format-AnalisiLocaleControllo -Dettaglio $dettaglio -Ambiente $Ambiente -Lingua $lang
        $lblOp       = switch ($lang) {
            'EN' { "Analyzing $($dettaglio.ControlId)" }
            'DE' { "Analyse von $($dettaglio.ControlId)" }
            default { "Analisi di $($dettaglio.ControlId)" }
        }
        & $avviaRichiestaOllamaAsincrona $promptCtrl $lblOp $fallbackLoc
    }

    # --- Azione: Genera Resoconto Completo della Scansione ---
    $eseguiResocontoScansione = {
        $lang = $statoUI.LinguaCorrente
        & $mostraPagina 'IA'
        if ($statoUI.ElementiVista.Count -eq 0) {
            $ctrl.TxtStatoLLM.Text = switch ($lang) {
                'EN' { "Click 'Start Scan' at the top first to collect PC security data." }
                'DE' { "Klicken Sie zuerst oben auf 'Scan starten', um die Sicherheitsdaten des PCs zu erfassen." }
                default { "Premi prima 'Avvia scansione' in alto per raccogliere i dati del PC." }
            }
            return
        }
        $statoUI.UltimaModalitaIA = 'Resoconto'
        $conteggi    = Measure-ConteggiRisultati -Elementi $statoUI.RisultatiGrezzi
        $promptRes   = Format-PromptResocontoOllama -ElementiVista $statoUI.ElementiVista -Conteggi $conteggi -Ambiente $Ambiente -Lingua $lang
        $fallbackRes = Format-ResocontoLocaleScansione -ElementiVista $statoUI.ElementiVista -Conteggi $conteggi -Ambiente $Ambiente -Lingua $lang
        $lblOp       = switch ($lang) {
            'EN' { "Generating Full PC Security Report" }
            'DE' { "Erstellung des PC-Sicherheitsberichts" }
            default { "Generazione Resoconto Sicurezza PC" }
        }
        & $avviaRichiestaOllamaAsincrona $promptRes $lblOp $fallbackRes
    }

    $ctrl.BtnSpiegaLLM.Add_Click($eseguiSpiegazioneControllo)
    $ctrl.BtnSpiegaControlloTab.Add_Click($eseguiSpiegazioneControllo)
    $ctrl.BtnResocontoLLM.Add_Click($eseguiResocontoScansione)
    $ctrl.BtnResocontoTab.Add_Click($eseguiResocontoScansione)

    $ctrl.BtnCopiaRispostaLLM.Add_Click({
        $lang = $statoUI.LinguaCorrente
        if (-not [string]::IsNullOrWhiteSpace($ctrl.TxtRispostaLLM.Text)) {
            [System.Windows.Clipboard]::SetText($ctrl.TxtRispostaLLM.Text)
            $ctrl.TxtStatoLLM.Text = switch ($lang) {
                'EN' { "AI Report copied to Windows clipboard!" }
                'DE' { "KI-Bericht in die Windows-Zwischenablage kopiert!" }
                default { "Resoconto copiato negli appunti di Windows!" }
            }
        }
    })

    # --- Avvia scansione in Runspace separato ---
    $ctrl.BtnAvvia.Add_Click({
        if ($statoUI.ScansioneInCorso) { return }
        $lang = $statoUI.LinguaCorrente

        $statoUI.ScansioneInCorso    = $true
        $statoUI.RisultatiGrezzi     = @()
        $statoUI.ElementiVista       = @()
        $statoUI.ElementoSelezionato = $null

        $ctrl.BtnAvvia.IsEnabled        = $false
        $ctrl.BtnAnnulla.IsEnabled      = $true
        $ctrl.BtnEsportaJson.IsEnabled  = $false
        $ctrl.BtnEsportaHtml.IsEnabled  = $false
        $ctrl.BannerErrore.Visibility   = [System.Windows.Visibility]::Collapsed
        $ctrl.ProgressScansione.Value   = 0
        $ctrl.TxtProgresso.Text         = switch ($lang) {
            'EN' { "Starting scan..." }
            'DE' { "Scan wird gestartet..." }
            default { "Avvio scansione..." }
        }
        $ctrl.TxtMessaggioGuida.Text    = switch ($lang) {
            'EN' { "Scan in progress... Results will appear as controls are evaluated." }
            'DE' { "Scan laeuft... Ergebnisse werden fortlaufend angezeigt." }
            default { "Scansione in corso... I risultati compariranno man mano." }
        }
        $ctrl.PanelGuidaVuota.Visibility = [System.Windows.Visibility]::Visible
        $ctrl.GridRisultati.ItemsSource = @()
        & $aggiornaConteggiERiepilogo
        & $aggiornaPannelloDettaglio

        # Callback invocato sul thread UI tramite Dispatcher per ogni controllo completato
        $callbackProgresso = [Action[int, int, object]]{
            param([int]$Indice, [int]$Totale, [object]$RisultatoSingolo)

            $langProg = $statoUI.LinguaCorrente
            $statoUI.RisultatiGrezzi += $RisultatoSingolo
            $statoUI.ElementiVista = @(ConvertTo-RisultatiVista -Risultati $statoUI.RisultatiGrezzi -Catalogo $Catalogo -Lingua $langProg)

            $ctrl.ProgressScansione.Maximum = if ($Totale -gt 0) { $Totale } else { 1 }
            $ctrl.ProgressScansione.Value   = $Indice
            $ctrl.TxtProgresso.Text         = switch ($langProg) {
                'EN' { "Progress: $Indice/$Totale" }
                'DE' { "Fortschritt: $Indice/$Totale" }
                default { "Avanzamento: $Indice/$Totale" }
            }

            & $aggiornaConteggiERiepilogo
            & $applicaFiltriTabella
        }

        # Callback invocato sul thread UI al termine (o annullamento) della scansione
        $callbackFine = [Action]{
            $langEnd = $statoUI.LinguaCorrente
            $statoUI.ScansioneInCorso   = $false
            $ctrl.BtnAvvia.IsEnabled    = $true
            $ctrl.BtnAnnulla.IsEnabled  = $false

            $nValutati = $statoUI.RisultatiGrezzi.Count
            if ($nValutati -gt 0) {
                $ctrl.BtnEsportaJson.IsEnabled  = $true
                $ctrl.BtnEsportaHtml.IsEnabled  = $true
                $ctrl.BtnResocontoLLM.IsEnabled = $true
            }

            if ($null -ne $statoUI.SyncRunspace -and $statoUI.SyncRunspace.ErroreFatale) {
                $ctrl.TxtBannerErrore.Text = switch ($langEnd) {
                    'EN' { "An error occurred during the scan execution. Please retry or export the technical log." }
                    'DE' { "Waehrend des Scans ist ein Fehler aufgetreten. Bitte versuchen Sie es erneut oder exportieren Sie das technische Protokoll." }
                    default { "Si e' verificato un problema durante l'esecuzione della scansione. Riprova o esporta il log tecnico." }
                }
                $ctrl.BannerErrore.Visibility = [System.Windows.Visibility]::Visible
                $ctrl.TxtProgresso.Text = switch ($langEnd) {
                    'EN' { "Stopped on error ($nValutati/$totaleControlli)" }
                    'DE' { "Wegen Fehler gestoppt ($nValutati/$totaleControlli)" }
                    default { "Interrotto per errore ($nValutati/$totaleControlli)" }
                }
            }
            elseif ($null -ne $statoUI.SyncRunspace -and $statoUI.SyncRunspace.AnnullaRichiesto) {
                $ctrl.TxtProgresso.Text = switch ($langEnd) {
                    'EN' { "Canceled ($nValutati/$totaleControlli)" }
                    'DE' { "Abgebrochen ($nValutati/$totaleControlli)" }
                    default { "Annullata ($nValutati/$totaleControlli)" }
                }
                if ($nValutati -eq 0) {
                    $ctrl.TxtMessaggioGuida.Text = switch ($langEnd) {
                        'EN' { "Scan canceled. Click 'Start Scan' to try again." }
                        'DE' { "Scan abgebrochen. Klicken Sie auf 'Scan starten', um es erneut zu versuchen." }
                        default { "Scansione annullata. Premi 'Avvia scansione' per riprovare." }
                    }
                }
            }
            else {
                $ctrl.TxtProgresso.Text = switch ($langEnd) {
                    'EN' { "Completed ($nValutati/$nValutati)" }
                    'DE' { "Abgeschlossen ($nValutati/$nValutati)" }
                    default { "Completata ($nValutati/$nValutati)" }
                }
            }

            & $aggiornaConteggiERiepilogo
            & $applicaFiltriTabella
            & $aggiornaListaAutoFix

            # Pulizia risorse Runspace
            if ($null -ne $statoUI.PsInstance) {
                $statoUI.PsInstance.Dispose()
                $statoUI.PsInstance = $null
            }
            if ($null -ne $statoUI.Runspace) {
                $statoUI.Runspace.Close()
                $statoUI.Runspace.Dispose()
                $statoUI.Runspace = $null
            }
        }

        # Stato condiviso sincronizzato con il Runspace
        $sync = [hashtable]::Synchronized(@{
            Finestra            = $finestra
            Catalogo            = $Catalogo
            Ambiente            = $Ambiente
            PercorsoCore        = $percorsoCore
            PercorsoChecks      = $percorsoChecks
            ControlId           = $ControlId
            AnnullaRichiesto    = $false
            ErroreFatale        = $null
            CallbackProgressoUI = $callbackProgresso
            CallbackFineUI      = $callbackFine
        })
        $statoUI.SyncRunspace = $sync

        # Prepara InitialSessionState con le funzioni del motore gia' caricate in memoria
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $funzioniDaPassare = @(Get-ChildItem Function:\Invoke-Controlli, Function:\Test-* -ErrorAction SilentlyContinue)
        foreach ($fn in $funzioniDaPassare) {
            $entryFn = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn.Name, $fn.Definition)
            [void]$iss.Commands.Add($entryFn)
        }

        # Crea e avvia il Runspace separato
        $runspace = [runspacefactory]::CreateRunspace($iss)
        $runspace.ApartmentState = 'STA'
        $runspace.ThreadOptions  = 'ReuseThread'
        $runspace.Open()
        $runspace.SessionStateProxy.SetVariable('Sync', $sync)

        $ps = [powershell]::Create()
        $ps.Runspace = $runspace

        [void]$ps.AddScript({
            Set-StrictMode -Version 2
            $ErrorActionPreference = 'Stop'

            try {
                if (-not [string]::IsNullOrWhiteSpace($Sync.PercorsoCore) -and (Test-Path -LiteralPath $Sync.PercorsoCore)) {
                    . (Join-Path $Sync.PercorsoCore 'Catalog.ps1')
                    . (Join-Path $Sync.PercorsoCore 'Runner.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'Registry.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'Firewall.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'Accounts.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'Defender.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'FileSecurity.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'Network.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'SystemSecurity.ps1')
                }

                $onProgressBlock = {
                    param($idx, $tot, $res)
                    [void]$Sync.Finestra.Dispatcher.Invoke(
                        [System.Windows.Threading.DispatcherPriority]::Background,
                        $Sync.CallbackProgressoUI,
                        $idx,
                        $tot,
                        $res
                    )
                }

                $shouldCancelBlock = {
                    return [bool]$Sync.AnnullaRichiesto
                }

                $parametri = @{
                    Catalogo       = $Sync.Catalogo
                    Ambiente       = $Sync.Ambiente
                    CartellaChecks = $Sync.PercorsoChecks
                    OnProgress     = $onProgressBlock
                    ShouldCancel   = $shouldCancelBlock
                }
                if ($null -ne $Sync.ControlId -and $Sync.ControlId.Count -gt 0) {
                    $parametri['ControlId'] = $Sync.ControlId
                }

                [void](Invoke-Controlli @parametri)
            }
            catch {
                $Sync.ErroreFatale = $_.Exception.Message
            }
            finally {
                [void]$Sync.Finestra.Dispatcher.BeginInvoke(
                    [System.Windows.Threading.DispatcherPriority]::Normal,
                    $Sync.CallbackFineUI
                )
            }
        })

        $statoUI.Runspace   = $runspace
        $statoUI.PsInstance = $ps
        [void]$ps.BeginInvoke()
    })

    # --- Pulsante Annulla ---
    $ctrl.BtnAnnulla.Add_Click({
        if ($statoUI.ScansioneInCorso -and $null -ne $statoUI.SyncRunspace) {
            $statoUI.SyncRunspace.AnnullaRichiesto = $true
            $ctrl.BtnAnnulla.IsEnabled = $false
            $ctrl.TxtProgresso.Text = switch ($statoUI.LinguaCorrente) {
                'EN' { "Canceling..." }
                'DE' { "Wird abgebrochen..." }
                default { "Annullamento in corso..." }
            }
        }
    })

    # --- Export JSON ---
    $ctrl.BtnEsportaJson.Add_Click({
        if ($statoUI.RisultatiGrezzi.Count -eq 0) { return }
        $lang = $statoUI.LinguaCorrente

        $dialogo = New-Object Microsoft.Win32.SaveFileDialog
        $dialogo.Title      = switch ($lang) { 'EN' { "Export JSON Report" } 'DE' { "JSON-Bericht exportieren" } default { "Esporta report JSON" } }
        $dialogo.Filter     = "JSON (*.json)|*.json"
        $dialogo.FileName   = (Get-NomeFileExport -Estensione 'json')
        $dialogo.DefaultExt = ".json"

        $esito = $dialogo.ShowDialog($finestra)
        if ($esito -eq $true) {
            $report = New-Report -Risultati $statoUI.RisultatiGrezzi -Ambiente $Ambiente -Catalogo $Catalogo -VersioneTool $VersioneTool
            Export-ReportJson -Report $report -PercorsoFile $dialogo.FileName

            if ($ctrl.ChkSalvaLogTecnico.IsChecked -eq $true) {
                $percorsoLog = "$($dialogo.FileName).errori.log"
                Export-TechnicalLog -Report $report -PercorsoFile $percorsoLog
            }

            $ctrl.TxtRiepilogoFooter.Text = switch ($lang) {
                'EN' { "Exported JSON: $(Split-Path -Leaf $dialogo.FileName)" }
                'DE' { "JSON exportiert: $(Split-Path -Leaf $dialogo.FileName)" }
                default { "Esportato JSON: $(Split-Path -Leaf $dialogo.FileName)" }
            }
        }
    })

    # --- Export HTML ---
    $ctrl.BtnEsportaHtml.Add_Click({
        if ($statoUI.RisultatiGrezzi.Count -eq 0) { return }
        $lang = $statoUI.LinguaCorrente

        $dialogo = New-Object Microsoft.Win32.SaveFileDialog
        $dialogo.Title      = switch ($lang) { 'EN' { "Export HTML Report" } 'DE' { "HTML-Bericht exportieren" } default { "Esporta report HTML" } }
        $dialogo.Filter     = "HTML (*.html)|*.html"
        $dialogo.FileName   = (Get-NomeFileExport -Estensione 'html')
        $dialogo.DefaultExt = ".html"

        $esito = $dialogo.ShowDialog($finestra)
        if ($esito -eq $true) {
            $report = New-Report -Risultati $statoUI.RisultatiGrezzi -Ambiente $Ambiente -Catalogo $Catalogo -VersioneTool $VersioneTool
            Export-ReportHtml -Report $report -Catalogo $Catalogo -PercorsoFile $dialogo.FileName

            if ($ctrl.ChkSalvaLogTecnico.IsChecked -eq $true) {
                $percorsoLog = "$($dialogo.FileName).errori.log"
                Export-TechnicalLog -Report $report -PercorsoFile $percorsoLog
            }

            $ctrl.TxtRiepilogoFooter.Text = switch ($lang) {
                'EN' { "Exported HTML: $(Split-Path -Leaf $dialogo.FileName)" }
                'DE' { "HTML exportiert: $(Split-Path -Leaf $dialogo.FileName)" }
                default { "Esportato HTML: $(Split-Path -Leaf $dialogo.FileName)" }
            }
        }
    })

    # --- Chiusura pulita della finestra ---
    $finestra.Add_Closing({
        if ($statoUI.ScansioneInCorso -and $null -ne $statoUI.SyncRunspace) {
            $statoUI.SyncRunspace.AnnullaRichiesto = $true
        }
        if ($null -ne $statoUI.PsInstance) {
            $statoUI.PsInstance.Dispose()
            $statoUI.PsInstance = $null
        }
        if ($null -ne $statoUI.Runspace) {
            $statoUI.Runspace.Close()
            $statoUI.Runspace.Dispose()
            $statoUI.Runspace = $null
        }
    })

    # Inizializza lingua e pannello dettaglio vuoto
    & $applicaLinguaUI

    # Mostra la finestra modale
    [void]$finestra.ShowDialog()
}
