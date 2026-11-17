<#
.SYNOPSIS
    Runner: esegue i controlli di sicurezza dal catalogo.

.DESCRIPTION
    Itera sui controlli del catalogo, determina il tipo (registro o funzione),
    li esegue e raccoglie i risultati. Un errore in un controllo NON ferma
    gli altri.
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Invoke-Controlli {
    <#
    .SYNOPSIS
        Esegue i controlli specificati e restituisce un array di risultati.
    .PARAMETER Catalogo
        L'oggetto catalogo caricato da Import-Catalogo.
    .PARAMETER Ambiente
        L'oggetto ambiente da Get-AmbienteSistema.
    .PARAMETER ControlId
        Array opzionale di ID di controllo da eseguire. Se vuoto, esegue tutti.
    .PARAMETER CartellaChecks
        Percorso della cartella contenente gli script di controllo.
    .PARAMETER OnProgress
        Scriptblock opzionale invocato dopo ogni controllo: riceve ($IndiceCorrente, $Totale, $Risultato).
    .PARAMETER ShouldCancel
        Scriptblock opzionale invocato prima di ogni controllo: se restituisce $true interrompe la scansione.
    .OUTPUTS
        Array di PSCustomObject con i risultati dei controlli.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Catalogo,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Ambiente,

        [Parameter(Mandatory = $false)]
        [string[]]$ControlId = @(),

        [Parameter(Mandatory = $true)]
        [string]$CartellaChecks,

        [Parameter(Mandatory = $false)]
        [scriptblock]$OnProgress = $null,

        [Parameter(Mandatory = $false)]
        [scriptblock]$ShouldCancel = $null
    )

    $risultati = @()

    # Normalizza ControlId (gestisce stringhe separate da virgola)
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

    # Determina la lista di controlli da eseguire per avere il totale esatto
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
        # Verifica eventuale richiesta di annullamento prima di iniziare il controllo
        if ($null -ne $ShouldCancel) {
            $annulla = & $ShouldCancel
            if ($annulla) {
                break
            }
        }

        $indiceCorrente++
        $elementoRisultato = $null

        # Verifica se il controllo ha i campi check necessari
        $haCheck = ($null -ne $controllo.PSObject.Properties['check'] -and $null -ne $controllo.check)
        $haRegistry = $false
        $haCommandRef = $false

        if ($haCheck) {
            # Verifica se ha check.registry
            if ($null -ne $controllo.check.PSObject.Properties['registry'] -and
                $null -ne $controllo.check.registry -and
                $null -ne $controllo.check.registry.PSObject.Properties['path'] -and
                $null -ne $controllo.check.registry.path) {
                $haRegistry = $true
            }
            # Verifica se ha check.command_ref
            if ($null -ne $controllo.check.PSObject.Properties['command_ref'] -and
                $null -ne $controllo.check.command_ref -and
                $null -ne $controllo.check.command_ref -ne '') {
                $haCommandRef = $true
            }
        }

        # Se non ha ne' registry ne' command_ref, il controllo non e' implementato
        if (-not $haRegistry -and -not $haCommandRef) {
            $elementoRisultato = [PSCustomObject]@{
                control_id  = $controllo.id
                status      = 'sconosciuto'
                observed    = 'Controllo non ancora implementato'
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

        # Verifica applicabilita' per edizione
        $edizioni = @()
        foreach ($ed in $controllo.editions) {
            $edizioni += $ed
        }
        if ($edizioni.Count -gt 0 -and $edizioni -notcontains $Ambiente.Edition) {
            $elementoRisultato = [PSCustomObject]@{
                control_id  = $controllo.id
                status      = 'non_applicabile'
                observed    = "Edizione $($Ambiente.Edition) non in: $($edizioni -join ', ')"
                expected    = $null
                evidence    = @{ EditioneMacchina = $Ambiente.Edition; EdizioniControllo = $edizioni }
                error       = $null
                duration_ms = 0
            }
            $risultati += $elementoRisultato
            if ($null -ne $OnProgress) {
                & $OnProgress $indiceCorrente $totale $elementoRisultato
            }
            continue
        }

        # Esegui il controllo con gestione errori
        $cronometro = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $risultatoControllo = $null

            if ($haRegistry) {
                # Controllo basato su registro: usa il valutatore generico
                $risultatoControllo = Test-RegistryValue -RegistryCheck $controllo.check.registry -Ambiente $Ambiente
            }
            elseif ($haCommandRef) {
                # Controllo basato su funzione: risolvi il riferimento
                $parti = $controllo.check.command_ref -split '#'
                if ($parti.Count -ne 2) {
                    throw "Formato command_ref non valido: $($controllo.check.command_ref). Atteso: 'File.ps1#Nome-Funzione'"
                }

                $nomeFile = $parti[0]
                $nomeFunzione = $parti[1]
                $percorsoFile = Join-Path $CartellaChecks $nomeFile

                # Verifica che il file esista
                if (-not (Test-Path -LiteralPath $percorsoFile)) {
                    throw "File di controllo non trovato: $percorsoFile"
                }

                # Carica il file (dot-source) se la funzione non e' gia' disponibile
                if (-not (Get-Command -Name $nomeFunzione -ErrorAction SilentlyContinue)) {
                    . $percorsoFile
                }

                # Esegui la funzione
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
            # Un errore nel controllo produce status "errore", non ferma gli altri
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
