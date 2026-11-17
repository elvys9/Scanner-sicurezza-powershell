<#
.SYNOPSIS
    Carica e valida il catalogo dei controlli di sicurezza.

.DESCRIPTION
    Legge il file JSON del catalogo e verifica la coerenza minima:
    - Il file esiste e contiene JSON valido
    - La versione dello schema e' supportata
    - Gli ID dei controlli non sono duplicati
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Import-Catalogo {
    <#
    .SYNOPSIS
        Carica il catalogo JSON e restituisce l'oggetto PowerShell.
    .PARAMETER PercorsoCatalogo
        Percorso completo del file home_profile.json.
    .OUTPUTS
        PSCustomObject rappresentante il catalogo.
    .NOTES
        Lancia un'eccezione se il file non esiste, il JSON non e' valido,
        o la coerenza minima non e' rispettata.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PercorsoCatalogo
    )

    # Verifica esistenza file
    if (-not (Test-Path -LiteralPath $PercorsoCatalogo)) {
        throw "Il file del catalogo non esiste: $PercorsoCatalogo"
    }

    # Leggi il contenuto
    $contenuto = Get-Content -LiteralPath $PercorsoCatalogo -Raw -Encoding UTF8 -ErrorAction Stop

    # Converti da JSON
    try {
        $catalogo = $contenuto | ConvertFrom-Json
    }
    catch {
        throw "Il file del catalogo non contiene JSON valido: $_"
    }

    # Verifica schema_version
    $versioniSupportate = @('0.1', '0.2')
    if (-not ($catalogo.PSObject.Properties['schema_version']) -or -not ($catalogo.schema_version)) {
        throw "Il catalogo non contiene il campo 'schema_version'."
    }
    if ($versioniSupportate -notcontains $catalogo.schema_version) {
        throw "Versione dello schema non supportata: $($catalogo.schema_version). Supportate: $($versioniSupportate -join ', ')"
    }

    # Verifica presenza controlli
    if (-not ($catalogo.PSObject.Properties['controls']) -or -not ($catalogo.controls)) {
        throw "Il catalogo non contiene il campo 'controls'."
    }

    # Verifica ID duplicati
    $ids = @()
    foreach ($controllo in $catalogo.controls) {
        if (-not ($controllo.PSObject.Properties['id']) -or -not $controllo.id) {
            throw "Un controllo nel catalogo non ha il campo 'id'."
        }
        if ($ids -contains $controllo.id) {
            throw "ID duplicato nel catalogo: $($controllo.id)"
        }
        $ids += $controllo.id
    }

    return $catalogo
}
