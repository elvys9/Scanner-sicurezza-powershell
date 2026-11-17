<#
.SYNOPSIS
    Scanner di sicurezza per Windows 11 — punto d'ingresso.

.DESCRIPTION
    Esegue i controlli di sicurezza definiti nel catalogo in modalita' grafica
    WPF (-Gui, predefinita) oppure in modalita' senza interfaccia (-Headless)
    producendo un report in formato JSON. Non modifica mai lo stato del sistema.

.PARAMETER Gui
    Avvia l'interfaccia grafica WPF (modalita' predefinita se non si specifica -Headless).

.PARAMETER Headless
    Modalita' senza interfaccia: esegue la scansione e scrive il risultato su file JSON.

.PARAMETER OutFile
    Percorso del file JSON di output. Obbligatorio con -Headless.

.PARAMETER ControlId
    Uno o piu' ID di controllo da eseguire. Se omesso, esegue tutti i
    controlli del catalogo.

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

# --- Validazione parametri ---
if ($Headless -and $Gui) {
    Write-Error "I parametri -Gui e -Headless sono mutuamente esclusivi."
    exit 1
}

if ($Headless -and (-not $OutFile)) {
    Write-Error "Il parametro -OutFile e' obbligatorio in modalita' -Headless."
    exit 1
}

# Modalita' predefinita: GUI quando non e' specificato -Headless
$modalitaGui = ($Gui -or (-not $Headless))

# --- Verifica STA per modalita' GUI ---
if ($modalitaGui) {
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

# --- Costanti ---
$VERSIONE_TOOL = '0.1.0'

# --- Percorsi ---
$percorsoScript = $PSScriptRoot
if (-not $percorsoScript) {
    $percorsoScript = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$percorsoCore   = Join-Path $percorsoScript 'core'
$percorsoChecks = Join-Path $percorsoCore 'Checks'
$percorsoUi     = Join-Path $percorsoScript 'ui'

# Il catalogo JSON si trova nella cartella catalog/ alla radice del progetto
$percorsoProgetto = Split-Path -Parent $percorsoScript
$percorsoCatalogo = Join-Path $percorsoProgetto 'catalog'
$percorsoJson     = Join-Path $percorsoCatalogo 'home_profile.json'

# --- Caricamento moduli core ---
. (Join-Path $percorsoCore 'Environment.ps1')
. (Join-Path $percorsoCore 'Catalog.ps1')
. (Join-Path $percorsoCore 'Runner.ps1')
. (Join-Path $percorsoCore 'Report.ps1')

# Carica i file di controllo
. (Join-Path $percorsoChecks 'Registry.ps1')
. (Join-Path $percorsoChecks 'Firewall.ps1')
. (Join-Path $percorsoChecks 'Accounts.ps1')

# --- Modalita' GUI ---
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

# --- Modalita' Headless ---
Write-Host "Scanner di sicurezza Windows 11 v$VERSIONE_TOOL"
Write-Host "============================================="

# 1. Rileva l'ambiente
Write-Host "`nRilevamento ambiente..."
$ambiente = Get-AmbienteSistema
Write-Host "  Edizione:  $($ambiente.Edition) ($($ambiente.EditionId))"
Write-Host "  Build:     $($ambiente.Build)"
Write-Host "  Lingua:    $($ambiente.Language)"
Write-Host "  Admin:     $($ambiente.IsAdmin)"
Write-Host "  PS:        $($ambiente.PsVersion)"

# 2. Carica il catalogo
Write-Host "`nCaricamento catalogo..."
$catalogo = Import-Catalogo -PercorsoCatalogo $percorsoJson
$nControlli = @($catalogo.controls).Count
Write-Host "  $nControlli controlli nel catalogo."

# 3. Esegui i controlli
Write-Host "`nEsecuzione controlli..."
$parametriRunner = @{
    Catalogo       = $catalogo
    Ambiente       = $ambiente
    CartellaChecks = $percorsoChecks
}
if ($ControlId) {
    $parametriRunner['ControlId'] = $ControlId
}
$risultati = Invoke-Controlli @parametriRunner

# 4. Costruisci il report
$report = New-Report -Risultati $risultati -Ambiente $ambiente -Catalogo $catalogo -VersioneTool $VERSIONE_TOOL

# 5. Output
Export-ReportJson -Report $report -PercorsoFile $OutFile
Write-Host "`nReport scritto in: $OutFile"

# Riepilogo finale
Write-Host "`n--- Riepilogo ---"
Write-Host "  Superato:        $($report.summary.superato)"
Write-Host "  Fallito:         $($report.summary.fallito)"
Write-Host "  Non applicabile: $($report.summary.non_applicabile)"
Write-Host "  Sconosciuto:     $($report.summary.sconosciuto)"
Write-Host "  Errore:          $($report.summary.errore)"
Write-Host ""
