<#
.SYNOPSIS
    Compila lo scanner in un singolo script autonomo (dist/scanner-win11.ps1) in stile winutil.

.DESCRIPTION
    Unisce il catalogo JSON (catalog/home_profile.json), il layout XAML
    (src/ui/MainWindow.xaml), il motore (src/core/*.ps1), tutti i controlli
    (src/core/Checks/*.ps1) e l'interfaccia grafica (src/ui/*.ps1) in un
    unico file PowerShell 5.1 autonomo eseguibile da qualsiasi cartella
    o direttamente da GitHub tramite 'irm <url> | iex'.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutFile = ''
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

$dirTools    = $PSScriptRoot
$dirProgetto = Split-Path -Parent $dirTools
if ([string]::IsNullOrWhiteSpace($OutFile)) {
    $dirDist = Join-Path $dirProgetto 'dist'
    if (-not (Test-Path -LiteralPath $dirDist)) {
        [void][System.IO.Directory]::CreateDirectory($dirDist)
    }
    $OutFile = Join-Path $dirDist 'scanner-win11.ps1'
}

$percorsoCatalogoJson = Join-Path $dirProgetto 'catalog\home_profile.json'
$percorsoXaml         = Join-Path $dirProgetto 'src\ui\MainWindow.xaml'

$fileModuli = @(
    'src\core\Environment.ps1',
    'src\core\Catalog.ps1',
    'src\core\Runner.ps1',
    'src\core\Report.ps1',
    'src\core\OllamaClient.ps1',
    'src\core\Checks\Registry.ps1',
    'src\core\Checks\Firewall.ps1',
    'src\core\Checks\Accounts.ps1',
    'src\core\Checks\Defender.ps1',
    'src\core\Checks\FileSecurity.ps1',
    'src\core\Checks\Network.ps1',
    'src\core\Checks\SystemSecurity.ps1',
    'src\ui\ViewModel.ps1',
    'src\ui\Start-ScannerUI.ps1'
)

$jsonRaw = Get-Content -LiteralPath $percorsoCatalogoJson -Raw -Encoding UTF8
$xamlRaw = Get-Content -LiteralPath $percorsoXaml -Raw -Encoding UTF8

$sb = New-Object System.Text.StringBuilder

[void]$sb.AppendLine('<#')
[void]$sb.AppendLine('.SYNOPSIS')
[void]$sb.AppendLine('    Scanner di sicurezza per Windows 11 — Script singolo autonomo (stile winutil).')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('.DESCRIPTION')
[void]$sb.AppendLine('    File generato automaticamente da tools/Build.ps1.')
[void]$sb.AppendLine('    Contiene catalogo, motore di scansione, 18 controlli e interfaccia WPF.')
[void]$sb.AppendLine('    Puo essere eseguito da qualsiasi cartella o direttamente da GitHub:')
[void]$sb.AppendLine('      irm https://raw.githubusercontent.com/elvys9/Scanner-sicurezza-powershell/main/dist/scanner-win11.ps1 | iex')
[void]$sb.AppendLine('#>')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('Set-StrictMode -Version 2')
[void]$sb.AppendLine('$ErrorActionPreference = ''Stop''')
[void]$sb.AppendLine('$script:VERSIONE_TOOL = ''0.2.0''')
[void]$sb.AppendLine('$script:LinguaPredefinita = ''IT''')
[void]$sb.AppendLine('$script:PercorsoScriptAutonomo = [string](Get-Variable -Name PSCommandPath -ValueOnly -ErrorAction SilentlyContinue)')
[void]$sb.AppendLine('$script:UrlScriptRemoto = ''https://raw.githubusercontent.com/elvys9/Scanner-sicurezza-powershell/main/dist/scanner-win11.ps1''')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('# --- CATALOGO JSON INCORPORATO ---')
[void]$sb.AppendLine('$script:CatalogoJsonIncorporato = @''')
[void]$sb.AppendLine($jsonRaw.TrimEnd())
[void]$sb.AppendLine('''@')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('# --- LAYOUT XAML INCORPORATO ---')
[void]$sb.AppendLine('$script:XamlIncorporato = @''')
[void]$sb.AppendLine($xamlRaw.TrimEnd())
[void]$sb.AppendLine('''@')
[void]$sb.AppendLine('')

foreach ($relPath in $fileModuli) {
    $fullPath = Join-Path $dirProgetto $relPath
    $codice = Get-Content -LiteralPath $fullPath -Raw -Encoding UTF8
    # Rimuovi Set-StrictMode ridondanti per pulizia pur mantenendo il codice intatto
    [void]$sb.AppendLine("# =============================================================================")
    [void]$sb.AppendLine("# MODULO: $relPath")
    [void]$sb.AppendLine("# =============================================================================")
    [void]$sb.AppendLine($codice.Trim())
    [void]$sb.AppendLine('')
}

$bloccoAvvio = @'
# =============================================================================
# PUNTO D'INGRESSO AUTONOMO (GUI / HEADLESS / IRM | IEX)
# =============================================================================
function Invoke-Win11Scanner {
    [CmdletBinding()]
    param(
        [switch]$Gui,
        [switch]$Cli,
        [switch]$Headless,
        [string]$OutFile,
        [string[]]$ControlId,
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lang = $script:LinguaPredefinita
    )

    if ($Headless -and $Gui) {
        Write-Error "I parametri -Gui e -Headless sono mutuamente esclusivi."
        return
    }

    if ($Headless -and (-not $OutFile)) {
        Write-Error "Il parametro -OutFile e' obbligatorio in modalita' -Headless."
        return
    }

    $modalitaGui = ($Gui -or (-not $Headless))
    $catalogo    = $script:CatalogoJsonIncorporato | ConvertFrom-Json
    $ambiente    = Get-AmbienteSistema

    if ($modalitaGui) {
        # Se siamo collegati via SSH o in modalita' terminale (-Cli), avvia l'interfaccia interattiva da console (TUI)
        if ($Cli -or (Test-SessioneTerminaleSsh)) {
            $paramConsole = @{
                Catalogo       = $catalogo
                Ambiente       = $ambiente
                VersioneTool   = $script:VERSIONE_TOOL
                LinguaIniziale = $Lang
            }
            if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
                $paramConsole['ControlId'] = $ControlId
            }
            Show-ScannerConsoleUI @paramConsole
            return
        }

        if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne [System.Threading.ApartmentState]::STA) {
            if (-not [string]::IsNullOrWhiteSpace($script:PercorsoScriptAutonomo) -and (Test-Path -LiteralPath $script:PercorsoScriptAutonomo)) {
                $argSta = "-NoProfile -ExecutionPolicy Bypass -STA -File `"$($script:PercorsoScriptAutonomo)`" -Gui"
                if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
                    $argSta += " -ControlId $($ControlId -join ',')"
                }
                $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argSta -Wait -PassThru
                return
            }
            else {
                $argSta = "-NoProfile -ExecutionPolicy Bypass -STA -Command `"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; irm '$($script:UrlScriptRemoto)' | iex`""
                $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argSta -Wait -PassThru
                return
            }
        }

        $paramGui = @{
            Catalogo       = $catalogo
            Ambiente       = $ambiente
            ContenutoXaml  = $script:XamlIncorporato
            VersioneTool   = $script:VERSIONE_TOOL
            LinguaIniziale = $Lang
        }
        if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
            $paramGui['ControlId'] = $ControlId
        }

        Start-ScannerUI @paramGui
    }
    else {
        Write-Host "Scanner di sicurezza Windows 11 v$($script:VERSIONE_TOOL) (Autonomo)"
        Write-Host "=========================================================="
        Write-Host "  Edizione:  $($ambiente.Edition) ($($ambiente.EditionId))"
        Write-Host "  Build:     $($ambiente.Build)"
        Write-Host "  Admin:     $($ambiente.IsAdmin)"

        $paramRunner = @{
            Catalogo = $catalogo
            Ambiente = $ambiente
        }
        if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
            $paramRunner['ControlId'] = $ControlId
        }

        $risultati = Invoke-Controlli @paramRunner
        $report    = New-Report -Risultati $risultati -Ambiente $ambiente -Catalogo $catalogo -VersioneTool $script:VERSIONE_TOOL
        Export-ReportJson -Report $report -PercorsoFile $OutFile

        Write-Host "`nReport scritto in: $OutFile"
        Write-Host "  Superato:        $($report.summary.superato)"
        Write-Host "  Fallito:         $($report.summary.fallito)"
        Write-Host "  Non applicabile: $($report.summary.non_applicabile)"
        Write-Host "  Sconosciuto:     $($report.summary.sconosciuto)"
        Write-Host "  Errore:          $($report.summary.errore)"
    }
}

# Gestione argomenti sia per esecuzione via 'irm ... | iex' sia via 'powershell -File scanner-win11.ps1 ...'
$argomentiRigaComando = @($args)
$parametriInvocazione = @{}
for ($i = 0; $i -lt $argomentiRigaComando.Count; $i++) {
    $token = [string]$argomentiRigaComando[$i]
    switch -Regex ($token) {
        '^-Gui$'       { $parametriInvocazione['Gui'] = $true }
        '^-Cli$'       { $parametriInvocazione['Cli'] = $true }
        '^-Headless$'  { $parametriInvocazione['Headless'] = $true }
        '^-OutFile$'   {
            if ($i + 1 -lt $argomentiRigaComando.Count) {
                $i++
                $parametriInvocazione['OutFile'] = [string]$argomentiRigaComando[$i]
            }
        }
        '^-ControlId$' {
            if ($i + 1 -lt $argomentiRigaComando.Count) {
                $i++
                $valId = $argomentiRigaComando[$i]
                if ($valId -is [array]) {
                    $parametriInvocazione['ControlId'] = [string[]]$valId
                }
                else {
                    $parametriInvocazione['ControlId'] = @([string]$valId -split ',')
                }
            }
        }
    }
}

Invoke-Win11Scanner @parametriInvocazione
'@

[void]$sb.AppendLine($bloccoAvvio)

# Salva in UTF-8 SENZA BOM per compatibilita' con 'irm <url> | iex' (evita il carattere \uFEFF iniziale in Invoke-Expression)
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$testoIt   = $sb.ToString()
[System.IO.File]::WriteAllText($OutFile, $testoIt, $utf8NoBom)
Write-Host "Script singolo (IT) compilato con successo in: $OutFile"

# Genera anche la versione con avvio predefinito in Inglese (dist/scanner-win11-en.ps1)
$outFileEn = Join-Path (Split-Path -Parent $OutFile) 'scanner-win11-en.ps1'
$testoEn   = $testoIt.Replace('$script:LinguaPredefinita = ''IT''', '$script:LinguaPredefinita = ''EN''')
$testoEn   = $testoEn.Replace('dist/scanner-win11.ps1', 'dist/scanner-win11-en.ps1')
[System.IO.File]::WriteAllText($outFileEn, $testoEn, $utf8NoBom)
Write-Host "Script singolo (EN) compilato con successo in: $outFileEn"

# Genera anche la versione con avvio predefinito in Tedesco (dist/scanner-win11-de.ps1)
$outFileDe = Join-Path (Split-Path -Parent $OutFile) 'scanner-win11-de.ps1'
$testoDe   = $testoIt.Replace('$script:LinguaPredefinita = ''IT''', '$script:LinguaPredefinita = ''DE''')
$testoDe   = $testoDe.Replace('dist/scanner-win11.ps1', 'dist/scanner-win11-de.ps1')
[System.IO.File]::WriteAllText($outFileDe, $testoDe, $utf8NoBom)
Write-Host "Script singolo (DE) compilato con successo in: $outFileDe"
