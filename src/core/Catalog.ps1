<#
.SYNOPSIS
    Loads and validates the security controls catalog.

.DESCRIPTION
    Reads the JSON catalog file and verifies minimum structural integrity:
    - The file exists and contains valid JSON
    - The schema_version is supported
    - Control IDs are unique (no duplicates)
    Never modifies system state.
#>

Set-StrictMode -Version 2

function Import-Catalogo {
    <#
    .SYNOPSIS
        Loads the JSON catalog and returns the parsed PowerShell object.
    .PARAMETER PercorsoCatalogo
        Full path to the home_profile.json file.
    .OUTPUTS
        PSCustomObject representing the catalog.
    .NOTES
        Throws an exception if the file does not exist, contains invalid JSON,
        or fails structural validation.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PercorsoCatalogo
    )

    # Verify file existence
    if (-not (Test-Path -LiteralPath $PercorsoCatalogo)) {
        throw "Catalog file not found: $PercorsoCatalogo"
    }

    # Read file contents
    $contenuto = Get-Content -LiteralPath $PercorsoCatalogo -Raw -Encoding UTF8 -ErrorAction Stop

    # Parse JSON
    try {
        $catalogo = $contenuto | ConvertFrom-Json
    }
    catch {
        throw "Catalog file does not contain valid JSON: $_"
    }

    # Verify schema_version
    $versioniSupportate = @('0.1', '0.2')
    if (-not ($catalogo.PSObject.Properties['schema_version']) -or -not ($catalogo.schema_version)) {
        throw "Catalog is missing the 'schema_version' field."
    }
    if ($versioniSupportate -notcontains $catalogo.schema_version) {
        throw "Unsupported schema version: $($catalogo.schema_version). Supported: $($versioniSupportate -join ', ')"
    }

    # Verify controls array presence
    if (-not ($catalogo.PSObject.Properties['controls']) -or -not ($catalogo.controls)) {
        throw "Catalog is missing the 'controls' field."
    }

    # Check for duplicate control IDs
    $ids = @()
    foreach ($controllo in $catalogo.controls) {
        if (-not ($controllo.PSObject.Properties['id']) -or -not $controllo.id) {
            throw "A control in the catalog is missing the 'id' field."
        }
        if ($ids -contains $controllo.id) {
            throw "Duplicate control ID in catalog: $($controllo.id)"
        }
        $ids += $controllo.id
    }

    return $catalogo
}
