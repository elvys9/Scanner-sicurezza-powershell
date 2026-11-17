<#
.SYNOPSIS
    Scanner di sicurezza per Windows 11 — punto d'ingresso.

.DESCRIPTION
    Esegue i controlli di sicurezza definiti nel catalogo e produce un report
    in formato JSON. Non modifica mai lo stato del sistema.

.PARAMETER Headless
    Modalita' senza interfaccia: scrive il risultato su file JSON.

.PARAMETER OutFile
    Percorso del file JSON di output. Obbligatorio con -Headless.

.PARAMETER ControlId
    Uno o piu' ID di controllo da eseguire. Se omesso, esegue tutti i
    controlli implementati.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1 -Headless -OutFile out.json

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1 -Headless -OutFile out.json -ControlId HOME-FW-001,HOME-UAC-001
#>

[CmdletBinding()]
param(
    [switch]$Headless,

    [string]$OutFile,

    [string[]]$ControlId
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# --- Validazione parametri ---
if ($Headless -and (-not $OutFile)) {
    Write-Error "Il parametro -OutFile e' obbligatorio in modalita' -Headless."
    exit 1
}

# --- Costanti ---
$VERSIONE_TOOL = '0.1.0'

# --- Percorsi ---
$percorsoScript = $PSScriptRoot
if (-not $percorsoScript) {
    $percorsoScript = Split-Path -Parent $MyInvocation.MyCommand.Path
}
$percorsoCore = Join-Path $percorsoScript 'core'
$percorsoChecks = Join-Path $percorsoCore 'Checks'

# Il catalogo JSON si trova nella cartella catalog/ alla radice del progetto
$percorsoProgetto = Split-Path -Parent $percorsoScript
$percorsoCatalogo = Join-Path $percorsoProgetto 'catalog'
$percorsoJson = Join-Path $percorsoCatalogo 'home_profile.json'

# --- Caricamento moduli ---
. (Join-Path $percorsoCore 'Environment.ps1')
. (Join-Path $percorsoCore 'Catalog.ps1')
. (Join-Path $percorsoCore 'Runner.ps1')
. (Join-Path $percorsoCore 'Report.ps1')

# Carica i file di controllo (pre-caricamento per evitare problemi di scope)
. (Join-Path $percorsoChecks 'Registry.ps1')
. (Join-Path $percorsoChecks 'Firewall.ps1')
. (Join-Path $percorsoChecks 'Accounts.ps1')

# --- Esecuzione ---
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
$risultati = @(Invoke-Controlli @parametriRunner)

# 4. Costruisci il report
$report = New-Report -Risultati $risultati -Ambiente $ambiente -Catalogo $catalogo -VersioneTool $VERSIONE_TOOL

# 5. Output
if ($Headless) {
    Export-ReportJson -Report $report -PercorsoFile $OutFile
    Write-Host "`nReport scritto in: $OutFile"
}
else {
    # Senza -Headless, mostra un riepilogo a console
    $json = $report | ConvertTo-Json -Depth 10
    Write-Host $json
}

# Riepilogo finale
Write-Host "`n--- Riepilogo ---"
Write-Host "  Superato:        $($report.summary.superato)"
Write-Host "  Fallito:         $($report.summary.fallito)"
Write-Host "  Non applicabile: $($report.summary.non_applicabile)"
Write-Host "  Sconosciuto:     $($report.summary.sconosciuto)"
Write-Host "  Errore:          $($report.summary.errore)"
Write-Host ""
