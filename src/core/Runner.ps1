<#
.SYNOPSIS
    Runner: executes security controls from the catalog.

.DESCRIPTION
    Iterates through catalog controls, determines the check type (registry or function),
    executes each check, and collects the results. An error in a single control
    NEVER stops the remaining controls.
    Never modifies system state.
#>

Set-StrictMode -Version 2

function Invoke-Controlli {
    <#
    .SYNOPSIS
        Executes the specified controls and returns an array of results.
    .PARAMETER Catalogo
        The catalog object loaded by Import-Catalogo.
    .PARAMETER Ambiente
        The environment object returned by Get-AmbienteSistema.
    .PARAMETER ControlId
        Optional array of control IDs to run. If empty, all controls are executed.
    .PARAMETER CartellaChecks
        Path to the directory containing check script files.
    .PARAMETER OnProgress
        Optional scriptblock invoked after each control: receives ($CurrentIndex, $Total, $Result).
    .PARAMETER ShouldCancel
        Optional scriptblock invoked before each control: if it returns $true, scanning stops.
    .OUTPUTS
        Array of PSCustomObject control results.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Catalogo,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Ambiente,

        [Parameter(Mandatory = $false)]
        [string[]]$ControlId = @(),

        [Parameter(Mandatory = $false)]
        [string]$CartellaChecks = '',

        [Parameter(Mandatory = $false)]
        [scriptblock]$OnProgress = $null,

        [Parameter(Mandatory = $false)]
        [scriptblock]$ShouldCancel = $null
    )

    $risultati = @()

    # Normalize ControlId (handles comma-separated strings)
    $idFiltro = @()
    if ($null -ne $ControlId) {
        foreach ($id in $ControlId) {
            if ($id -match ',') {
                $idFiltro += ($id -split ',' | ForEach-Object { $_.Trim() })
            }
            elseif ($id.Trim() -ne '') {
                $idFiltro += $id.Trim()
            }
        }
    }

    # Build the list of controls to execute to know the exact total count
    $controlliDaEseguire = @()
    foreach ($c in $Catalogo.controls) {
        if ($idFiltro.Count -gt 0 -and ($idFiltro -notcontains $c.id)) {
            continue
        }
        $controlliDaEseguire += $c
    }

    $totale = $controlliDaEseguire.Count
    $indiceCorrente = 0

    foreach ($controllo in $controlliDaEseguire) {
        # Check for cancellation request before starting the control
        if ($null -ne $ShouldCancel) {
            $annulla = & $ShouldCancel
            if ($annulla) {
                break
            }
        }

        $indiceCorrente++
        $elementoRisultato = $null

        # Verify whether the control defines a check block
        $haCheck = ($null -ne $controllo.PSObject.Properties['check'] -and $null -ne $controllo.check)
        $haRegistry = $false
        $haCommandRef = $false

        if ($haCheck) {
            # Check for check.registry
            if ($null -ne $controllo.check.PSObject.Properties['registry'] -and
                $null -ne $controllo.check.registry -and
                $null -ne $controllo.check.registry.PSObject.Properties['path'] -and
                $null -ne $controllo.check.registry.path) {
                $haRegistry = $true
            }
            # Check for check.command_ref
            if ($null -ne $controllo.check.PSObject.Properties['command_ref'] -and
                $null -ne $controllo.check.command_ref -and
                $null -ne $controllo.check.command_ref -ne '') {
                $haCommandRef = $true
            }
        }

        # If neither registry nor command_ref is defined, the control is not implemented yet
        if (-not $haRegistry -and -not $haCommandRef) {
            $elementoRisultato = [PSCustomObject]@{
                control_id  = $controllo.id
                status      = 'sconosciuto'
                observed    = 'Control not yet implemented'
                expected    = $null
                evidence    = $null
                error       = $null
                duration_ms = 0
            }
            $risultati += $elementoRisultato
            if ($null -ne $OnProgress) {
                & $OnProgress $indiceCorrente $totale $elementoRisultato
            }
            continue
        }

        # Check edition applicability
        $edizioni = @()
        foreach ($ed in $controllo.editions) {
            $edizioni += $ed
        }
        if ($edizioni.Count -gt 0 -and $edizioni -notcontains $Ambiente.Edition) {
            $elementoRisultato = [PSCustomObject]@{
                control_id  = $controllo.id
                status      = 'non_applicabile'
                observed    = "Edition $($Ambiente.Edition) not in: $($edizioni -join ', ')"
                expected    = $null
                evidence    = @{ MachineEdition = $Ambiente.Edition; ControlEditions = $edizioni }
                error       = $null
                duration_ms = 0
            }
            $risultati += $elementoRisultato
            if ($null -ne $OnProgress) {
                & $OnProgress $indiceCorrente $totale $elementoRisultato
            }
            continue
        }

        # Execute the control with isolated error handling
        $cronometro = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $risultatoControllo = $null

            if ($haRegistry) {
                # Declarative registry check: use the generic evaluator
                $risultatoControllo = Test-RegistryValue -RegistryCheck $controllo.check.registry -Ambiente $Ambiente
            }
            elseif ($haCommandRef) {
                # Function-based check: resolve file and function reference
                $parti = $controllo.check.command_ref -split '#'
                if ($parti.Count -ne 2) {
                    throw "Invalid command_ref format: $($controllo.check.command_ref). Expected: 'File.ps1#Function-Name'"
                }

                $nomeFile = $parti[0]
                $nomeFunzione = $parti[1]

                # Dot-source the file if the function is not already loaded in memory
                if (-not (Get-Command -Name $nomeFunzione -ErrorAction SilentlyContinue)) {
                    $percorsoFile = if ($CartellaChecks) { Join-Path $CartellaChecks $nomeFile } else { $nomeFile }
                    if (-not (Test-Path -LiteralPath $percorsoFile)) {
                        throw "Check file not found: $percorsoFile"
                    }
                    . $percorsoFile
                }

                # Invoke the check function
                $risultatoControllo = & $nomeFunzione -Controllo $controllo -Ambiente $Ambiente
            }

            $cronometro.Stop()

            $elementoRisultato = [PSCustomObject]@{
                control_id  = $controllo.id
                status      = $risultatoControllo.Status
                observed    = $risultatoControllo.Observed
                expected    = $risultatoControllo.Expected
                evidence    = $risultatoControllo.Evidence
                error       = $risultatoControllo.Error
                duration_ms = [int]$cronometro.ElapsedMilliseconds
            }
        }
        catch {
            $cronometro.Stop()
            # A check failure produces status "errore" and does not halt remaining controls
            $elementoRisultato = [PSCustomObject]@{
                control_id  = $controllo.id
                status      = 'errore'
                observed    = $null
                expected    = $null
                evidence    = $null
                error       = $_.Exception.Message
                duration_ms = [int]$cronometro.ElapsedMilliseconds
            }
        }

        $risultati += $elementoRisultato
        if ($null -ne $OnProgress) {
            & $OnProgress $indiceCorrente $totale $elementoRisultato
        }
    }

    return ,$risultati
}
