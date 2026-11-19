<#
.SYNOPSIS
    Windows 11 Security Scanner - Entry point.

.DESCRIPTION
    Executes the security controls defined in the catalog in WPF graphical mode
    (-Gui, default) or headless mode (-Headless), producing a JSON report.
    Never modifies system state (strictly read-only).

.PARAMETER Gui
    Launches the WPF graphical user interface (default when -Headless is not specified).

.PARAMETER Headless
    Headless mode: runs the scan without GUI and writes the results to a JSON file.

.PARAMETER OutFile
    Output JSON file path. Required when using -Headless.

.PARAMETER ControlId
    One or more control IDs to execute. If omitted, runs all controls in the catalog.

.EXAMPLE
    powershell -STA -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1 -Headless -OutFile out.json

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1 -Headless -OutFile out.json -ControlId HOME-FW-001,HOME-UAC-001
#>

[CmdletBinding()]
param(
    [switch]$Gui,

    [switch]$Headless,

    [string]$OutFile,

    [string[]]$ControlId
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# --- Parameter validation ---
if ($Headless -and $Gui) {
    Write-Error "The -Gui and -Headless parameters are mutually exclusive."
    exit 1
}

if ($Headless -and (-not $OutFile)) {
    Write-Error "The -OutFile parameter is required in -Headless mode."
    exit 1
}

# Default mode: GUI when -Headless is not specified
$modalitaGui = ($Gui -or (-not $Headless))

# --- STA check for GUI mode (only when not running over SSH / Session 0) ---
$isSshSession = (
    (-not [string]::IsNullOrWhiteSpace($env:SSH_CONNECTION)) -or
    (-not [string]::IsNullOrWhiteSpace($env:SSH_CLIENT)) -or
    (-not [string]::IsNullOrWhiteSpace($env:SSH_TTY)) -or
    (-not [Environment]::UserInteractive)
)
if ($modalitaGui -and (-not $isSshSession)) {
    if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne [System.Threading.ApartmentState]::STA) {
        $percorsoQuestoScript = $MyInvocation.MyCommand.Path
        $argomentiSta = @(
            '-NoProfile',
            '-ExecutionPolicy', 'Bypass',
            '-STA',
            '-File', "`"$percorsoQuestoScript`"",
            '-Gui'
        )
        if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
            $argomentiSta += '-ControlId'
            $argomentiSta += ($ControlId -join ',')
        }
        $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList ($argomentiSta -join ' ') -Wait -PassThru
        exit $proc.ExitCode
    }
}

# --- Constants ---
$VERSIONE_TOOL = '0.1.0'

# --- Paths ---
$percorsoScript = $PSScriptRoot
if (-not $percorsoScript) {
    $percorsoScript = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$percorsoCore   = Join-Path $percorsoScript 'core'
$percorsoChecks = Join-Path $percorsoCore 'Checks'
$percorsoUi     = Join-Path $percorsoScript 'ui'

# The JSON catalog is located in the catalog/ directory at the project root
$percorsoProgetto = Split-Path -Parent $percorsoScript
$percorsoCatalogo = Join-Path $percorsoProgetto 'catalog'
$percorsoJson     = Join-Path $percorsoCatalogo 'home_profile.json'

# --- Load core modules ---
. (Join-Path $percorsoCore 'Environment.ps1')
. (Join-Path $percorsoCore 'Catalog.ps1')
. (Join-Path $percorsoCore 'Runner.ps1')
. (Join-Path $percorsoCore 'Report.ps1')
. (Join-Path $percorsoCore 'OllamaClient.ps1')

# Load security check modules
. (Join-Path $percorsoChecks 'Registry.ps1')
. (Join-Path $percorsoChecks 'Firewall.ps1')
. (Join-Path $percorsoChecks 'Accounts.ps1')
. (Join-Path $percorsoChecks 'Defender.ps1')
. (Join-Path $percorsoChecks 'FileSecurity.ps1')
. (Join-Path $percorsoChecks 'Network.ps1')
. (Join-Path $percorsoChecks 'SystemSecurity.ps1')

# --- GUI Mode ---
if ($modalitaGui) {
    . (Join-Path $percorsoUi 'ViewModel.ps1')
    . (Join-Path $percorsoUi 'Start-ScannerUI.ps1')

    $ambiente = Get-AmbienteSistema
    $catalogo = Import-Catalogo -PercorsoCatalogo $percorsoJson

    $parametriGui = @{
        Catalogo         = $catalogo
        Ambiente         = $ambiente
        PercorsoProgetto = $percorsoProgetto
        VersioneTool     = $VERSIONE_TOOL
    }
    if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
        $parametriGui['ControlId'] = $ControlId
    }

    Start-ScannerUI @parametriGui
    exit 0
}

# --- Headless Mode ---
Write-Host "Windows 11 Security Scanner v$VERSIONE_TOOL"
Write-Host "============================================="

# 1. Detect execution environment
Write-Host "`nDetecting environment..."
$ambiente = Get-AmbienteSistema
Write-Host "  Edition:   $($ambiente.Edition) ($($ambiente.EditionId))"
Write-Host "  Build:     $($ambiente.Build)"
Write-Host "  Language:  $($ambiente.Language)"
Write-Host "  Admin:     $($ambiente.IsAdmin)"
Write-Host "  PS:        $($ambiente.PsVersion)"

# 2. Load catalog
Write-Host "`nLoading catalog..."
$catalogo = Import-Catalogo -PercorsoCatalogo $percorsoJson
$nControlli = @($catalogo.controls).Count
Write-Host "  $nControlli controls in catalog."

# 3. Execute controls
Write-Host "`nRunning security controls..."
$parametriRunner = @{
    Catalogo       = $catalogo
    Ambiente       = $ambiente
    CartellaChecks = $percorsoChecks
}
if ($ControlId) {
    $parametriRunner['ControlId'] = $ControlId
}
$risultati = Invoke-Controlli @parametriRunner

# 4. Build report
$report = New-Report -Risultati $risultati -Ambiente $ambiente -Catalogo $catalogo -VersioneTool $VERSIONE_TOOL

# 5. Output
Export-ReportJson -Report $report -PercorsoFile $OutFile
Write-Host "`nReport written to: $OutFile"

# Final summary
Write-Host "`n--- Summary ---"
Write-Host "  Passed:         $($report.summary.superato)"
Write-Host "  Failed:         $($report.summary.fallito)"
Write-Host "  Not Applicable: $($report.summary.non_applicabile)"
Write-Host "  Unknown:        $($report.summary.sconosciuto)"
Write-Host "  Error:          $($report.summary.errore)"
Write-Host ""
