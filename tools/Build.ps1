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
    'src\core\Checks\Registry.ps1',
    'src\core\Checks\Firewall.ps1',
    'src\core\Checks\Accounts.ps1',
    'src\core\Checks\Defender.ps1',
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
[void]$sb.AppendLine('      irm https://raw.githubusercontent.com/<UTENTE>/<REPO>/main/dist/scanner-win11.ps1 | iex')
[void]$sb.AppendLine('#>')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('[CmdletBinding()]')
[void]$sb.AppendLine('param(')
[void]$sb.AppendLine('    [switch]$Gui,')
[void]$sb.AppendLine('    [switch]$Headless,')
[void]$sb.AppendLine('    [string]$OutFile,')
[void]$sb.AppendLine('    [string[]]$ControlId')
[void]$sb.AppendLine(')')
[void]$sb.AppendLine('')
[void]$sb.AppendLine('Set-StrictMode -Version 2')
[void]$sb.AppendLine('$ErrorActionPreference = ''Stop''')
[void]$sb.AppendLine('$script:VERSIONE_TOOL = ''0.2.0''')
[void]$sb.AppendLine('$script:PercorsoScriptAutonomo = $MyInvocation.MyCommand.Path')
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
if ($Headless -and $Gui) {
    Write-Error "I parametri -Gui e -Headless sono mutuamente esclusivi."
    exit 1
}

if ($Headless -and (-not $OutFile)) {
    Write-Error "Il parametro -OutFile e' obbligatorio in modalita' -Headless."
    exit 1
}

$modalitaGui = ($Gui -or (-not $Headless))
$catalogo    = $script:CatalogoJsonIncorporato | ConvertFrom-Json
$ambiente    = Get-AmbienteSistema

if ($modalitaGui) {
    if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne [System.Threading.ApartmentState]::STA) {
        if (-not [string]::IsNullOrWhiteSpace($script:PercorsoScriptAutonomo) -and (Test-Path -LiteralPath $script:PercorsoScriptAutonomo)) {
            $argSta = "-NoProfile -ExecutionPolicy Bypass -STA -File `"$($script:PercorsoScriptAutonomo)`" -Gui"
            if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
                $argSta += " -ControlId $($ControlId -join ',')"
            }
            $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argSta -Wait -PassThru
            exit $proc.ExitCode
        }
    }

    $paramGui = @{
        Catalogo       = $catalogo
        Ambiente       = $ambiente
        ContenutoXaml  = $script:XamlIncorporato
        VersioneTool   = $script:VERSIONE_TOOL
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
'@

[void]$sb.AppendLine($bloccoAvvio)

# Salva in UTF-8 con BOM per compatibilita' garantita con Windows PowerShell 5.1
[System.IO.File]::WriteAllText($OutFile, $sb.ToString(), [System.Text.Encoding]::UTF8)
Write-Host "Script singolo compilato con successo in: $OutFile"
