<#
.SYNOPSIS
    Costruisce l'oggetto risultato e lo scrive in JSON.

.DESCRIPTION
    Genera l'oggetto report conforme al contratto (schema_version 0.1),
    calcola il riepilogo dai risultati e scrive il file JSON in UTF-8
    senza BOM.
    Non modifica mai lo stato del sistema (tranne il file di output).
#>

Set-StrictMode -Version 2

function New-Report {
    <#
    .SYNOPSIS
        Costruisce l'oggetto report a partire dai risultati dei controlli.
    .PARAMETER Risultati
        Array di risultati dei controlli (da Invoke-Controlli).
    .PARAMETER Ambiente
        Oggetto ambiente (da Get-AmbienteSistema).
    .PARAMETER Catalogo
        Oggetto catalogo (da Import-Catalogo).
    .PARAMETER VersioneTool
        Versione dello scanner.
    .OUTPUTS
        PSCustomObject conforme al contratto del risultato.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [array]$Risultati,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Ambiente,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Catalogo,

        [Parameter(Mandatory = $false)]
        [string]$VersioneTool = '0.1.0'
    )

    $risultatiArray = if ($null -eq $Risultati) { @() } else { @($Risultati) }

    # Calcola il riepilogo
    $riepilogo = @{
        superato         = 0
        fallito          = 0
        non_applicabile  = 0
        sconosciuto      = 0
        errore           = 0
    }

    foreach ($r in $risultatiArray) {
        if ($riepilogo.ContainsKey($r.status)) {
            $riepilogo[$r.status] = $riepilogo[$r.status] + 1
        }
    }

    # Costruisci l'oggetto report
    $report = [PSCustomObject]@{
        schema_version  = '0.1'
        run_id          = [guid]::NewGuid().ToString()
        timestamp       = (Get-Date).ToUniversalTime().ToString('o')
        tool_version    = $VersioneTool
        catalog_version = $Catalogo.schema_version
        environment     = [PSCustomObject]@{
            edition    = $Ambiente.Edition
            build      = $Ambiente.Build
            language   = $Ambiente.Language
            is_admin   = $Ambiente.IsAdmin
            ps_version = $Ambiente.PsVersion
        }
        results         = $risultatiArray
        summary         = [PSCustomObject]@{
            superato        = $riepilogo['superato']
            fallito         = $riepilogo['fallito']
            non_applicabile = $riepilogo['non_applicabile']
            sconosciuto     = $riepilogo['sconosciuto']
            errore          = $riepilogo['errore']
        }
    }

    return $report
}

function Export-ReportJson {
    <#
    .SYNOPSIS
        Scrive il report in formato JSON su file, in UTF-8 senza BOM.
    .PARAMETER Report
        L'oggetto report da scrivere.
    .PARAMETER PercorsoFile
        Percorso del file di output.
    .NOTES
        Usa [System.IO.File]::WriteAllText con UTF8Encoding($false) per
        garantire UTF-8 senza BOM.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Report,

        [Parameter(Mandatory = $true)]
        [string]$PercorsoFile
    )

    # Converti in JSON con profondita' sufficiente
    $json = $Report | ConvertTo-Json -Depth 10

    # Scrivi in UTF-8 senza BOM
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($PercorsoFile, $json, $utf8NoBom)
}
