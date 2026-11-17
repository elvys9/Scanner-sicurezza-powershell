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

function ConvertTo-ReportHtml {
    <#
    .SYNOPSIS
        Converte un oggetto Report (e opzionalmente il Catalogo) in una stringa HTML autonoma.
    .PARAMETER Report
        L'oggetto report generato da New-Report.
    .PARAMETER Catalogo
        Oggetto catalogo opzionale per arricchire la tabella con titoli, gravita' e categorie.
    .OUTPUTS
        Stringa HTML completa con CSS incorporato e nessuna risorsa esterna.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Report,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Catalogo = $null
    )

    # Mappa rapida dei controlli del catalogo per ID
    $mappaCatalogo = @{}
    if ($null -ne $Catalogo -and $null -ne $Catalogo.PSObject.Properties['controls'] -and $null -ne $Catalogo.controls) {
        foreach ($c in $Catalogo.controls) {
            if ($null -ne $c.PSObject.Properties['id'] -and $c.id) {
                $mappaCatalogo[$c.id] = $c
            }
        }
    }

    $escapeHtml = {
        param([AllowNull()][string]$Testo)
        if ([string]::IsNullOrEmpty($Testo)) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($Testo)
    }

    $righeHtml = New-Object System.Text.StringBuilder
    $risultatiLista = if ($null -ne $Report.results) { @($Report.results) } else { @() }

    foreach ($r in $risultatiLista) {
        $id = [string]$r.control_id
        $stato = [string]$r.status
        $titolo = $id
        $categoria = '-'
        $gravita = '-'
        $spiegazione = ''

        if ($mappaCatalogo.ContainsKey($id)) {
            $meta = $mappaCatalogo[$id]
            if ($null -ne $meta.PSObject.Properties['title'] -and $meta.title) { $titolo = [string]$meta.title }
            if ($null -ne $meta.PSObject.Properties['category'] -and $meta.category) { $categoria = [string]$meta.category }
            if ($null -ne $meta.PSObject.Properties['severity'] -and $meta.severity) { $gravita = [string]$meta.severity }
            if ($null -ne $meta.PSObject.Properties['rationale'] -and $meta.rationale) { $spiegazione = [string]$meta.rationale }
        }

        $simboloStato = '[?]'
        $etichettaStato = 'Sconosciuto'
        $classeStato = 'stato-sconosciuto'
        switch ($stato) {
            'superato'        { $simboloStato = '[OK]'; $etichettaStato = 'Superato';        $classeStato = 'stato-superato' }
            'fallito'         { $simboloStato = '[X]';  $etichettaStato = 'Fallito';         $classeStato = 'stato-fallito' }
            'sconosciuto'     { $simboloStato = '[?]';  $etichettaStato = 'Sconosciuto';     $classeStato = 'stato-sconosciuto' }
            'errore'          { $simboloStato = '[!]';  $etichettaStato = 'Errore';          $classeStato = 'stato-errore' }
            'non_applicabile' { $simboloStato = '[-]';  $etichettaStato = 'Non applicabile'; $classeStato = 'stato-na' }
        }

        $osservatoStr = if ($null -ne $r.observed) { [string]$r.observed } else { '-' }
        $attesoStr    = if ($null -ne $r.expected) { [string]$r.expected } else { '-' }

        [void]$righeHtml.AppendLine("<tr>")
        [void]$righeHtml.AppendLine("  <td><span class='badge $classeStato'>$(& $escapeHtml "$simboloStato $etichettaStato")</span></td>")
        [void]$righeHtml.AppendLine("  <td>$(& $escapeHtml $gravita)</td>")
        [void]$righeHtml.AppendLine("  <td>$(& $escapeHtml $categoria)</td>")
        [void]$righeHtml.AppendLine("  <td><code>$(& $escapeHtml $id)</code></td>")
        [void]$righeHtml.AppendLine("  <td><strong>$(& $escapeHtml $titolo)</strong><br><small>$(& $escapeHtml $spiegazione)</small></td>")
        [void]$righeHtml.AppendLine("  <td>$(& $escapeHtml $attesoStr)</td>")
        [void]$righeHtml.AppendLine("  <td>$(& $escapeHtml $osservatoStr)</td>")
        [void]$righeHtml.AppendLine("</tr>")
    }

    $adminStr = if ($Report.environment.is_admin) { 'Si' } else { 'No' }

    $html = @"
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Report Scanner Sicurezza Windows 11</title>
<style>
  body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f4f6f9; color: #1e293b; margin: 0; padding: 24px; line-height: 1.5; }
  .container { max-width: 1200px; margin: 0 auto; background: #ffffff; border-radius: 8px; padding: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
  h1 { margin-top: 0; font-size: 22px; color: #0f172a; }
  .meta { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 16px; margin-bottom: 20px; font-size: 14px; }
  .cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }
  .card { flex: 1; min-width: 140px; padding: 12px 16px; border-radius: 6px; font-weight: 600; border: 1px solid #cbd5e1; }
  .card-pass { background: #dcfce7; color: #166534; border-color: #86efac; }
  .card-fail { background: #fee2e2; color: #991b1b; border-color: #fca5a5; }
  .card-unk  { background: #f1f5f9; color: #334155; border-color: #cbd5e1; }
  .card-na   { background: #f8fafc; color: #475569; border-color: #e2e8f0; }
  .card-err  { background: #ffedd5; color: #9a3412; border-color: #fdba74; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; margin-bottom: 20px; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  th { background: #f1f5f9; font-weight: 600; color: #334155; }
  .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; white-space: nowrap; }
  .stato-superato    { background: #dcfce7; color: #166534; }
  .stato-fallito     { background: #fee2e2; color: #991b1b; }
  .stato-sconosciuto { background: #e2e8f0; color: #334155; }
  .stato-errore      { background: #ffedd5; color: #9a3412; }
  .stato-na          { background: #f1f5f9; color: #64748b; }
  .disclaimer { background: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px 16px; font-size: 13px; color: #92400e; margin-top: 16px; }
  small { color: #475569; }
</style>
</head>
<body>
<div class="container">
  <h1>Scanner di Sicurezza per Windows 11 — Report</h1>
  <div class="meta">
    <strong>ID Esecuzione:</strong> $(& $escapeHtml $Report.run_id) |
    <strong>Data (UTC):</strong> $(& $escapeHtml $Report.timestamp) |
    <strong>Versione Tool:</strong> $(& $escapeHtml $Report.tool_version) |
    <strong>Catalogo:</strong> v$(& $escapeHtml $Report.catalog_version)<br>
    <strong>Ambiente:</strong> Windows 11 $(& $escapeHtml $Report.environment.edition) (Build $(& $escapeHtml $Report.environment.build)) |
    <strong>Lingua:</strong> $(& $escapeHtml $Report.environment.language) |
    <strong>Amministratore:</strong> $adminStr |
    <strong>PowerShell:</strong> $(& $escapeHtml $Report.environment.ps_version)
  </div>
  <div class="cards">
    <div class="card card-pass">[OK] Superati: $($Report.summary.superato)</div>
    <div class="card card-fail">[X] Falliti: $($Report.summary.fallito)</div>
    <div class="card card-unk">[?] Sconosciuti: $($Report.summary.sconosciuto)</div>
    <div class="card card-na">[-] Non applicabili: $($Report.summary.non_applicabile)</div>
    <div class="card card-err">[!] Errori: $($Report.summary.errore)</div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Stato</th>
        <th>Gravita'</th>
        <th>Categoria</th>
        <th>ID</th>
        <th>Controllo</th>
        <th>Valore Atteso</th>
        <th>Valore Osservato</th>
      </tr>
    </thead>
    <tbody>
$($righeHtml.ToString())
    </tbody>
  </table>
  <div class="disclaimer">
    <strong>Avviso importante:</strong> Questo report e' il risultato di una verifica statica in sola lettura delle impostazioni di sicurezza.
    Un controllo superato o un audit conforme non dimostra l'assenza di compromissioni o malware sul sistema.
  </div>
</div>
</body>
</html>
"@
    return $html
}

function Export-ReportHtml {
    <#
    .SYNOPSIS
        Scrive il report in formato HTML autonomo su file, in UTF-8 senza BOM.
    .PARAMETER Report
        L'oggetto report da esportare.
    .PARAMETER Catalogo
        Oggetto catalogo opzionale per arricchire i dati visualizzati.
    .PARAMETER PercorsoFile
        Percorso del file HTML di output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Report,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Catalogo = $null,

        [Parameter(Mandatory = $true)]
        [string]$PercorsoFile
    )

    $html = ConvertTo-ReportHtml -Report $Report -Catalogo $Catalogo
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($PercorsoFile, $html, $utf8NoBom)
}

function Export-TechnicalLog {
    <#
    .SYNOPSIS
        Scrive un file di log con i dettagli tecnici degli errori riscontrati.
    .PARAMETER Report
        L'oggetto report contenente i risultati.
    .PARAMETER PercorsoFile
        Percorso del file di log da scrivere.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Report,

        [Parameter(Mandatory = $true)]
        [string]$PercorsoFile
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("=== LOG TECNICO SCANNER SICUREZZA WINDOWS ===")
    [void]$sb.AppendLine("Run ID:    $($Report.run_id)")
    [void]$sb.AppendLine("Timestamp: $($Report.timestamp)")
    [void]$sb.AppendLine("Edizione:  $($Report.environment.edition) (Build $($Report.environment.build))")
    [void]$sb.AppendLine("Admin:     $($Report.environment.is_admin)")
    [void]$sb.AppendLine("---------------------------------------------")

    $conErrori = 0
    if ($null -ne $Report.results) {
        foreach ($r in $Report.results) {
            if ($null -ne $r.error -and $r.error -ne '') {
                $conErrori++
                [void]$sb.AppendLine("[$($r.control_id)] Stato: $($r.status)")
                [void]$sb.AppendLine("  Dettaglio tecnico: $($r.error)")
                [void]$sb.AppendLine("")
            }
        }
    }

    if ($conErrori -eq 0) {
        [void]$sb.AppendLine("Nessun errore tecnico registrato durante la scansione.")
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($PercorsoFile, $sb.ToString(), $utf8NoBom)
}
