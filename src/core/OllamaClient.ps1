<#
.SYNOPSIS
    Client per l'integrazione con un LLM locale tramite Ollama (http://127.0.0.1:11434)
    con auto-rilevamento, auto-installazione silenziosa sulla VM e download automatico del modello.

.DESCRIPTION
    Fornisce:
    - Funzioni pure per la costruzione dei prompt (controllo singolo e resoconto complessivo)
    - Rilevamento automatico di Ollama su localhost (127.0.0.1) o sull'Host della VM (gateway)
    - Avvio automatico di 'ollama serve' se installato ma fermo
    - Installazione automatica silenziosa di Ollama (winget / OllamaSetup.exe /VERYSILENT)
      se assente sulla VM, senza richiedere download manuali all'utente
    - Download automatico del modello leggero (es. qwen2.5:0.5b) tramite API /api/pull
    - Motore esperto locale come risposta immediata di fallback
#>

Set-StrictMode -Version 2

$script:EndpointOllamaPredefinito = 'http://127.0.0.1:11434'
$script:ModelloOllamaPredefinito  = 'qwen2.5:0.5b'

function Format-PromptControlloOllama {
    <#
    .SYNOPSIS
        Costruisce il prompt (in italiano o inglese) per chiedere all'LLM di spiegare un singolo controllo.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Dettaglio,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    $infoOs = if ($null -ne $Ambiente) {
        "Windows 11 $($Ambiente.Edition) (Build $($Ambiente.Build), Admin: $($Ambiente.IsAdmin))"
    }
    else {
        "Windows 11"
    }

    $cmdRif = if ($Dettaglio.HaComando -and (-not [string]::IsNullOrWhiteSpace($Dettaglio.ComandoRimedio))) {
        $Dettaglio.ComandoRimedio
    }
    else {
        switch ($Lingua) {
            'EN' { "No terminal command (manual Windows/BIOS setting)" }
            'DE' { "Kein Terminal-Befehl (manuelle Windows-/BIOS-Einstellung)" }
            default { "Nessun comando da terminale (configurazione manuale da interfaccia di Windows/BIOS)" }
        }
    }

    $statoRawDett = if ($null -ne $Dettaglio.PSObject.Properties['Status'] -and $Dettaglio.Status) {
        [string]$Dettaglio.Status
    } else {
        [string]$Dettaglio.StatusLabel
    }

    if ($Lingua -eq 'EN') {
        $verdettoEn = if ($statoRawDett -match 'fallito|failed|fehlgeschlagen') {
            "IMPORTANT FACT: This security control FAILED on this PC (it is currently NOT configured securely)."
        } elseif ($statoRawDett -match 'superato|passed|bestanden') {
            "IMPORTANT FACT: This security control PASSED on this PC (it is already configured securely)."
        } else {
            "IMPORTANT FACT: This security control status is UNKNOWN (requires administrator privileges to verify)."
        }
        $promptEn = @"
[LANGUAGE: ENGLISH ONLY]
$verdettoEn
Control: $($Dettaglio.Title) ($($Dettaglio.ControlId))
Observed on this PC: $($Dettaglio.ValoreOsservato)
Expected secure setting: $($Dettaglio.ValoreAtteso)
Why it matters: $($Dettaglio.SpiegazioneSemplice)
How to fix it: $($Dettaglio.TestoRimedio)
Command: $cmdRif

Write 3 short bullet points in ENGLISH:
1. WHAT WAS FOUND: state clearly that '$($Dettaglio.Title)' is currently '$($Dettaglio.ValoreOsservato)'.
2. SECURITY RISK: explain why '$($Dettaglio.SpiegazioneSemplice)' matters for a home PC.
3. HOW TO FIX SAFELY: explain how to apply '$($Dettaglio.TestoRimedio)'.
"@
        return $promptEn.Trim()
    }
    elseif ($Lingua -eq 'DE') {
        $verdettoDe = if ($statoRawDett -match 'fallito|failed|fehlgeschlagen') {
            "WICHTIGE TATSACHE: Diese Sicherheitspruefung ist auf diesem PC FEHLGESCHLAGEN (momentan NICHT sicher konfiguriert)."
        } elseif ($statoRawDett -match 'superato|passed|bestanden') {
            "WICHTIGE TATSACHE: Diese Sicherheitspruefung wurde auf diesem PC BESTANDEN (bereits sicher konfiguriert)."
        } else {
            "WICHTIGE TATSACHE: Der Status dieser Sicherheitspruefung ist UNBEKANNT (Administratorrechte erforderlich)."
        }
        $promptDe = @"
[SPRACHE: NUR DEUTSCH - NICHT AUF ENGLISCH SCHREIBEN]
$verdettoDe
Sicherheitspruefung: $($Dettaglio.Title) ($($Dettaglio.ControlId))
Gefundener Wert auf dem PC: $($Dettaglio.ValoreOsservato)
Erwartete sichere Einstellung: $($Dettaglio.ValoreAtteso)
Warum es wichtig ist: $($Dettaglio.SpiegazioneSemplice)
Wie man es behebt: $($Dettaglio.TestoRimedio)
Befehl: $cmdRif

Schreibe 3 kurze Punkte auf DEUTSCH:
1. WAS GEFUNDEN WURDE: Erklaere klar, dass '$($Dettaglio.Title)' aktuell den Wert '$($Dettaglio.ValoreOsservato)' hat.
2. SICHERHEITSRISIKO: Erklaere auf Deutsch, warum '$($Dettaglio.SpiegazioneSemplice)' fuer den PC wichtig ist.
3. SICHERE BEHEBUNG: Erklaere auf Deutsch, wie man '$($Dettaglio.TestoRimedio)' anwendet.
"@
        return $promptDe.Trim()
    }

    $verdettoIt = if ($statoRawDett -match 'fallito|failed|fehlgeschlagen') {
        "FATTO ACCERTATO: Questo controllo di sicurezza e' FALLITO sul PC (NON e' configurato in modo sicuro)."
    } elseif ($statoRawDett -match 'superato|passed|bestanden') {
        "FATTO ACCERTATO: Questo controllo di sicurezza e' SUPERATO sul PC (e' gia' attivo e sicuro)."
    } else {
        "FATTO ACCERTATO: Lo stato del controllo e' SCONOSCIUTO (servono privilegi di amministratore)."
    }

    $prompt = @"
[LINGUA OBBLIGATORIA: SOLO ITALIANO - NON SCRIVERE IN INGLESE]
$verdettoIt
Controllo: $($Dettaglio.Title) ($($Dettaglio.ControlId))
Valore trovato sul PC: $($Dettaglio.ValoreOsservato)
Valore sicuro atteso: $($Dettaglio.ValoreAtteso)
Perche' conta: $($Dettaglio.SpiegazioneSemplice)
Come correggere: $($Dettaglio.TestoRimedio)
Comando: $cmdRif

Scrivi in LINGUA ITALIANA 3 brevi punti:
1. COSA SIGNIFICA: spiega che sul PC il controllo '$($Dettaglio.Title)' risulta '$($Dettaglio.ValoreOsservato)'.
2. RISCHIO PER IL PC: spiega in italiano perche' '$($Dettaglio.SpiegazioneSemplice)' e' importante.
3. COME MIGLIORARE IN SICUREZZA: spiega in italiano come applicare '$($Dettaglio.TestoRimedio)'.
"@

    return $prompt.Trim()
}

function Format-PromptResocontoOllama {
    <#
    .SYNOPSIS
        Costruisce il prompt (in italiano o inglese) per generare un resoconto complessivo della scansione.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$ElementiVista,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Conteggi,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    $infoOs = if ($null -ne $Ambiente) {
        "Windows 11 $($Ambiente.Edition) (Build $($Ambiente.Build), Admin: $($Ambiente.IsAdmin))"
    }
    else {
        "Windows 11"
    }

    $sbFalliti = New-Object System.Text.StringBuilder
    $nFalliti = 0

    foreach ($el in $ElementiVista) {
        if ($el.Status -eq 'fallito') {
            $nFalliti++
            $det = Format-DettaglioControllo -Elemento $el -Modalita 'Semplice' -Lingua $Lingua
            [void]$sbFalliti.AppendLine("- [$($el.SeverityLabel.ToUpperInvariant())] $($el.ControlId) - $($el.Title)")
            [void]$sbFalliti.AppendLine("  Observed: $($det.ValoreOsservato) (Expected: $($det.ValoreAtteso))")
            [void]$sbFalliti.AppendLine("  Remediation: $($det.TestoRimedio)")
        }
    }

    if ($nFalliti -eq 0) {
        [void]$sbFalliti.AppendLine("No failed controls! All applicable checks passed.")
    }

    if ($Lingua -eq 'EN') {
        $promptEn = @"
[LANGUAGE: ENGLISH ONLY]
You are a cybersecurity advisor for Windows 11 users.
Analyze the following read-only deterministic security scan report and write a clear report in English with practical step-by-step recommendations to improve PC security.

SYSTEM: $infoOs
SCAN SUMMARY:
- Total controls evaluated: $($Conteggi.totale)
- Passed: $($Conteggi.superato)
- Failed (needs attention): $($Conteggi.fallito)
- Unknown: $($Conteggi.sconosciuto)
- Not Applicable: $($Conteggi.non_applicabile)

FAILED CONTROLS (ORDERED BY SEVERITY):
$($sbFalliti.ToString().Trim())

Write a structured report in 4 sections:
1. OVERALL SECURITY POSTURE: clear summary of the current security level.
2. IMMEDIATE PRIORITIES: which issues to fix first (starting with Critical and High severity) and why.
3. STEP-BY-STEP REMEDIATION GUIDE: simple instructions to apply the recommended improvements on Windows 11.
4. SAFETY BEST PRACTICES: final reminder (e.g. create a System Restore Point before modifying system settings).
"@
        return $promptEn.Trim()
    }
    elseif ($Lingua -eq 'DE') {
        $promptDe = @"
[SPRACHE: NUR DEUTSCH - NICHT AUF ENGLISCH SCHREIBEN]
Du bist ein IT-Sicherheitsberater fuer Windows 11-Benutzer.
Analysiere den folgenden deterministischen Sicherheitsbericht und schreibe einen klaren Bericht auf DEUTSCH mit praktischen Empfehlungen zur Verbesserung der PC-Sicherheit.

SYSTEM: $infoOs
ZUSAMMENFASSUNG DES SCANS:
- Gepruefte Kontrollen insgesamt: $($Conteggi.totale)
- Bestanden: $($Conteggi.superato)
- Fehlgeschlagen (Handlungsbedarf): $($Conteggi.fallito)
- Unbekannt: $($Conteggi.sconosciuto)
- Nicht zutreffend: $($Conteggi.non_applicabile)

FEHLGESCHLAGENE PRUEFUNGEN (NACH SCHWEREGRAD SORTIERT):
$($sbFalliti.ToString().Trim())

Schreibe einen strukturierten Bericht auf DEUTSCH in 4 Abschnitten:
1. ALLGEMEINER SICHERHEITSZUSTAND: klare Zusammenfassung des aktuellen Sicherheitsniveaus.
2. SOFORTIGE PRIORITAETEN: welche Probleme zuerst behoben werden sollten (beginnend mit Kritisch und Hoch) und warum.
3. SCHRITT-FUER-SCHRITT-ANLEITUNG: einfache Anweisungen zur Umsetzung der empfohlenen Verbesserungen unter Windows 11.
4. SICHERHEITSHINWEISE: abschliessender Tipp (z. B. Systemwiederherstellungspunkt vor Systemaenderungen erstellen).
"@
        return $promptDe.Trim()
    }

    $prompt = @"
Sei un consulente di sicurezza informatica per utenti domestici su Windows 11.
Analizza il seguente report generato dallo scanner deterministico in sola lettura e scrivi un resoconto chiaro in lingua italiana con consigli pratici per migliorare la sicurezza del PC.

SISTEMA: $infoOs
RIEPILOGO SCANSIONE:
- Totale controlli eseguiti: $($Conteggi.totale)
- Superati: $($Conteggi.superato)
- Falliti (da migliorare): $($Conteggi.fallito)
- Sconosciuti: $($Conteggi.sconosciuto)
- Non applicabili: $($Conteggi.non_applicabile)

DETTAGLIO CONTROLLI FALLITI (ORDINATI PER GRAVITA'):
$($sbFalliti.ToString().Trim())

Scrivi un resoconto strutturato in 4 sezioni:
1. STATO GENERALE DEL PC: sintesi chiara del livello di sicurezza attuale.
2. PRIORITA' IMMEDIATE: quali problemi risolvere per primi (partendo da quelli Critici e Alti) e perche'.
3. GUIDA PRATICA PASSO-PASSO: istruzioni semplici per applicare i miglioramenti consigliati su Windows 11.
4. BUONE PRATICHE DI SICUREZZA: consiglio finale (es. creare un punto di ripristino prima di modificare impostazioni di sistema).
"@

    return $prompt.Trim()
}

function Format-AnalisiLocaleControllo {
    <#
    .SYNOPSIS
        Genera una spiegazione strutturata e contestuale del singolo controllo (IT o EN).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Dettaglio,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    $sb = New-Object System.Text.StringBuilder

    if ($Lingua -eq 'EN') {
        [void]$sb.AppendLine("=== DETAILED CONTROL ANALYSIS: $($Dettaglio.ControlId) ===")
        [void]$sb.AppendLine("Control: $($Dettaglio.Title)")
        [void]$sb.AppendLine("Category: $($Dettaglio.Category)  |  Severity: $($Dettaglio.SeverityLabel)  |  Status: $($Dettaglio.StatusLabel)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("1. WHAT THIS RESULT MEANS ON YOUR PC")
        switch ($Dettaglio.Status) {
            'superato' {
                [void]$sb.AppendLine("   Good news: the observed value ('$($Dettaglio.ValoreOsservato)') meets the expected security baseline ('$($Dettaglio.ValoreAtteso)'). No action is needed.")
            }
            'fallito' {
                [void]$sb.AppendLine("   Attention required: the scanner detected '$($Dettaglio.ValoreOsservato)', while the recommended secure setting is '$($Dettaglio.ValoreAtteso)'.")
            }
            default {
                [void]$sb.AppendLine("   Current observed state: '$($Dettaglio.ValoreOsservato)'.")
            }
        }
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("2. WHY IT MATTERS & RISK NOTES")
        [void]$sb.AppendLine("   $($Dettaglio.SpiegazioneSemplice)")
        [void]$sb.AppendLine("   Impact notes: $($Dettaglio.NoteRischi)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("3. HOW TO REMEDIATE SAFELY")
        if ($Dettaglio.Status -eq 'superato') {
            [void]$sb.AppendLine("   - No changes required: this control is already properly configured.")
        }
        else {
            [void]$sb.AppendLine("   - Guidance: $($Dettaglio.TestoRimedio)")
            if ($Dettaglio.HaComando -and (-not [string]::IsNullOrWhiteSpace($Dettaglio.ComandoRimedio))) {
                [void]$sb.AppendLine("   - Reference PowerShell Command (Run as Administrator):")
                [void]$sb.AppendLine("     $($Dettaglio.ComandoRimedio)")
            }
        }
        return $sb.ToString().Trim()
    }
    elseif ($Lingua -eq 'DE') {
        [void]$sb.AppendLine("=== DETAILLIERTE PRUEFUNGSANALYSE: $($Dettaglio.ControlId) ===")
        [void]$sb.AppendLine("Sicherheitspruefung: $($Dettaglio.Title)")
        [void]$sb.AppendLine("Kategorie: $($Dettaglio.Category)  |  Schweregrad: $($Dettaglio.SeverityLabel)  |  Status: $($Dettaglio.StatusLabel)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("1. WAS DIESES ERGEBNIS AUF IHREM PC BEDEUTET")
        switch ($Dettaglio.Status) {
            'superato' {
                [void]$sb.AppendLine("   Gute Nachrichten: Der gefundene Wert ('$($Dettaglio.ValoreOsservato)') entspricht der erwarteten Sicherheitsvorgabe ('$($Dettaglio.ValoreAtteso)'). Es ist kein Eingriff erforderlich.")
            }
            'fallito' {
                [void]$sb.AppendLine("   Handlungsbedarf: Der Scanner hat '$($Dettaglio.ValoreOsservato)' erkannt, waehrend die empfohlene sichere Einstellung '$($Dettaglio.ValoreAtteso)' lautet.")
            }
            default {
                [void]$sb.AppendLine("   Aktuell erkannter Zustand: '$($Dettaglio.ValoreOsservato)'.")
            }
        }
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("2. WARUM ES WICHTIG IST & RISIKOHINWEISE")
        [void]$sb.AppendLine("   $($Dettaglio.SpiegazioneSemplice)")
        [void]$sb.AppendLine("   Auswirkung der Aenderung: $($Dettaglio.NoteRischi)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("3. SICHERE BEHEBUNG (SCHRITT FUER SCHRITT)")
        if ($Dettaglio.Status -eq 'superato') {
            [void]$sb.AppendLine("   - Keine Aenderung erforderlich: Diese Einstellung ist bereits sicher konfiguriert.")
        }
        else {
            [void]$sb.AppendLine("   - Empfohlene Massnahme: $($Dettaglio.TestoRimedio)")
            if ($Dettaglio.HaComando -and (-not [string]::IsNullOrWhiteSpace($Dettaglio.ComandoRimedio))) {
                [void]$sb.AppendLine("   - PowerShell-Referenzbefehl (als Administrator ausfuehren):")
                [void]$sb.AppendLine("     $($Dettaglio.ComandoRimedio)")
            }
        }
        return $sb.ToString().Trim()
    }
    [void]$sb.AppendLine("=== ANALISI DETTAGLIATA DEL CONTROLLO: $($Dettaglio.ControlId) ===")
    [void]$sb.AppendLine("Controllo: $($Dettaglio.Title)")
    [void]$sb.AppendLine("Categoria: $($Dettaglio.Category)  |  Gravita': $($Dettaglio.SeverityLabel)  |  Stato: $($Dettaglio.StatusLabel)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("1. COSA SIGNIFICA QUESTO RISULTATO SUL TUO PC")

    switch ($Dettaglio.Status) {
        'superato' {
            [void]$sb.AppendLine("   Ottima notizia: sul tuo sistema il valore rilevato ('$($Dettaglio.ValoreOsservato)') rispetta pienamente il requisito di sicurezza atteso ('$($Dettaglio.ValoreAtteso)'). Non e' necessario alcun intervento correttivo.")
        }
        'fallito' {
            [void]$sb.AppendLine("   Attenzione: lo scanner ha rilevato '$($Dettaglio.ValoreOsservato)', mentre l'impostazione sicura raccomandata e' '$($Dettaglio.ValoreAtteso)'.")
        }
        'sconosciuto' {
            [void]$sb.AppendLine("   Lo stato attuale e' Sconosciuto ('$($Dettaglio.ValoreOsservato)'). Per verificare questo controllo avvia lo scanner come Amministratore.")
        }
        'non_applicabile' {
            [void]$sb.AppendLine("   Questo controllo non si applica all'edizione corrente di Windows ($($Dettaglio.ValoreOsservato)).")
        }
        default {
            [void]$sb.AppendLine("   Stato rilevato: $($Dettaglio.ValoreOsservato).")
        }
    }

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("2. PERCHE' E' IMPORTANTE (VALUTAZIONE DEL RISCHIO)")
    [void]$sb.AppendLine("   $($Dettaglio.SpiegazioneSemplice)")
    [void]$sb.AppendLine("   Impatto della modifica: $($Dettaglio.NoteRischi)")

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("3. COME INTERVENIRE IN SICUREZZA PASSO DOPO PASSO")
    if ($Dettaglio.Status -eq 'superato') {
        [void]$sb.AppendLine("   - Nessuna azione richiesta: l'impostazione e' gia' configurata in modo sicuro.")
    }
    else {
        [void]$sb.AppendLine("   - Azione consigliata: $($Dettaglio.TestoRimedio)")
        if ($Dettaglio.HaComando -and (-not [string]::IsNullOrWhiteSpace($Dettaglio.ComandoRimedio))) {
            [void]$sb.AppendLine("   - Comando PowerShell (da eseguire come Amministratore):")
            [void]$sb.AppendLine("     $($Dettaglio.ComandoRimedio)")
        }
    }

    return $sb.ToString().Trim()
}

function Format-ResocontoLocaleScansione {
    <#
    .SYNOPSIS
        Genera un resoconto completo e prioritizzato dell'intera scansione del PC (IT o EN).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$ElementiVista,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Conteggi,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    $perc = if ($Conteggi.totale -gt 0) {
        [int][math]::Round((($Conteggi.superato * 100.0) / $Conteggi.totale), 0)
    } else { 0 }

    if ($Lingua -eq 'EN') {
        $sbEn = New-Object System.Text.StringBuilder
        [void]$sbEn.AppendLine("======================================================================")
        [void]$sbEn.AppendLine("           WINDOWS 11 SECURITY REPORT & IMPROVEMENT PLAN              ")
        [void]$sbEn.AppendLine("======================================================================")
        if ($null -ne $Ambiente) {
            [void]$sbEn.AppendLine("Analyzed System: Windows 11 $($Ambiente.Edition) (Build $($Ambiente.Build)) | Admin: $($Ambiente.IsAdmin)")
        }
        [void]$sbEn.AppendLine("Compliance Score: $perc% ($($Conteggi.superato) Passed out of $($Conteggi.totale) controls)")
        [void]$sbEn.AppendLine("")
        [void]$sbEn.AppendLine("1. EXECUTIVE SUMMARY")
        [void]$sbEn.AppendLine("   - Passed Controls:         $($Conteggi.superato)")
        [void]$sbEn.AppendLine("   - Failed (Needs Action):   $($Conteggi.fallito)")
        [void]$sbEn.AppendLine("   - Unknown Controls:        $($Conteggi.sconosciuto)")
        [void]$sbEn.AppendLine("   - Not Applicable Controls: $($Conteggi.non_applicabile)")
        [void]$sbEn.AppendLine("")

        $fallitiEn = @($ElementiVista | Where-Object { $_.Status -eq 'fallito' })
        if ($fallitiEn.Count -eq 0) {
            [void]$sbEn.AppendLine("2. NO CRITICAL ISSUES FOUND")
            [void]$sbEn.AppendLine("   All evaluated controls meet the recommended security configuration.")
        }
        else {
            [void]$sbEn.AppendLine("2. PRIORITY REMEDIATION PLAN ($($fallitiEn.Count) recommended actions)")
            [void]$sbEn.AppendLine("")
            $idxEn = 0
            foreach ($f in $fallitiEn) {
                $idxEn++
                $det = Format-DettaglioControllo -Elemento $f -Modalita 'Semplice' -Lingua 'EN'
                [void]$sbEn.AppendLine("   Priority #$idxEn — [$($f.SeverityLabel.ToUpperInvariant())] $($f.Title) ($($f.ControlId))")
                [void]$sbEn.AppendLine("   * Observed on PC: $($det.ValoreOsservato) (Expected: $($det.ValoreAtteso))")
                [void]$sbEn.AppendLine("   * Why it matters: $($det.SpiegazioneSemplice)")
                [void]$sbEn.AppendLine("   * How to fix:     $($det.TestoRimedio)")
                if ($det.HaComando -and (-not [string]::IsNullOrWhiteSpace($det.ComandoRimedio))) {
                    [void]$sbEn.AppendLine("   * PowerShell Cmd: $($det.ComandoRimedio)")
                }
                [void]$sbEn.AppendLine("")
            }
        }
        [void]$sbEn.AppendLine("3. SAFETY BEST PRACTICES")
        [void]$sbEn.AppendLine("   - Always create a Windows System Restore Point before modifying registry or security policies.")
        [void]$sbEn.AppendLine("   - Apply changes one at a time starting from CRITICAL and HIGH severity controls.")
        return $sbEn.ToString().Trim()
    }
    elseif ($Lingua -eq 'DE') {
        $sbDe = New-Object System.Text.StringBuilder
        [void]$sbDe.AppendLine("======================================================================")
        [void]$sbDe.AppendLine("         WINDOWS 11 SICHERHEITSBERICHT & MASSNAHMENPLAN               ")
        [void]$sbDe.AppendLine("======================================================================")
        if ($null -ne $Ambiente) {
            [void]$sbDe.AppendLine("Analysiertes System: Windows 11 $($Ambiente.Edition) (Build $($Ambiente.Build)) | Admin: $($Ambiente.IsAdmin)")
        }
        [void]$sbDe.AppendLine("Konformitaetsrate: $perc% ($($Conteggi.superato) Bestanden von $($Conteggi.totale) Pruefungen)")
        [void]$sbDe.AppendLine("")
        [void]$sbDe.AppendLine("1. ZUSAMMENFASSUNG")
        [void]$sbDe.AppendLine("   - Bestandene Pruefungen:          $($Conteggi.superato)")
        [void]$sbDe.AppendLine("   - Fehlgeschlagen (Handlungsbed.): $($Conteggi.fallito)")
        [void]$sbDe.AppendLine("   - Unbekannte Pruefungen:          $($Conteggi.sconosciuto)")
        [void]$sbDe.AppendLine("   - Nicht zutreffende Pruefungen:   $($Conteggi.non_applicabile)")
        [void]$sbDe.AppendLine("")

        $fallitiDe = @($ElementiVista | Where-Object { $_.Status -eq 'fallito' })
        if ($fallitiDe.Count -eq 0) {
            [void]$sbDe.AppendLine("2. KEINE KRITISCHEN PROBLEME GEFUNDEN")
            [void]$sbDe.AppendLine("   Alle geprueften Kontrollen entsprechen der empfohlenen Sicherheitskonfiguration.")
        }
        else {
            [void]$sbDe.AppendLine("2. PRIORISIERTER MASSNAHMENPLAN ($($fallitiDe.Count) empfohlene Massnahmen)")
            [void]$sbDe.AppendLine("")
            $idxDe = 0
            foreach ($f in $fallitiDe) {
                $idxDe++
                $det = Format-DettaglioControllo -Elemento $f -Modalita 'Semplice' -Lingua 'DE'
                [void]$sbDe.AppendLine("   Prioritaet #$idxDe — [$($f.SeverityLabel.ToUpperInvariant())] $($f.Title) ($($f.ControlId))")
                [void]$sbDe.AppendLine("   * Gefunden auf PC: $($det.ValoreOsservato) (Erwartet: $($det.ValoreAtteso))")
                [void]$sbDe.AppendLine("   * Warum wichtig:   $($det.SpiegazioneSemplice)")
                [void]$sbDe.AppendLine("   * Behebung:        $($det.TestoRimedio)")
                if ($det.HaComando -and (-not [string]::IsNullOrWhiteSpace($det.ComandoRimedio))) {
                    [void]$sbDe.AppendLine("   * PowerShell-Cmd:  $($det.ComandoRimedio)")
                }
                [void]$sbDe.AppendLine("")
            }
        }
        [void]$sbDe.AppendLine("3. EMPFOHLENE SICHERHEITSHINWEISE")
        [void]$sbDe.AppendLine("   - Erstellen Sie vor Aenderungen an Registrierung oder Sicherheitsrichtlinien immer einen Systemwiederherstellungspunkt.")
        [void]$sbDe.AppendLine("   - Setzen Sie Aenderungen einzeln um, beginnend mit KRITISCHEN und HOHEN Schweregraden.")
        return $sbDe.ToString().Trim()
    }

    $giudizio = if ($Conteggi.fallito -eq 0) {
        "ECCELLENTE (Tutti i controlli verificati sono superati)"
    }
    elseif ($perc -ge 80) {
        "BUONO ($perc% di conformita' — presenti $($Conteggi.fallito) miglioramenti consigliati)"
    }
    elseif ($perc -ge 60) {
        "MODERATO ($perc% di conformita' — si raccomanda di applicare le correzioni prioritarie)"
    }
    else {
        "ATTENZIONE RICHIESTA ($perc% di conformita' — diversi controlli critici o alti risultano disattivati)"
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("======================================================================")
    [void]$sb.AppendLine("          RESOCONTO DI SICUREZZA E PIANO DI MIGLIORAMENTO PC          ")
    [void]$sb.AppendLine("======================================================================")
    if ($null -ne $Ambiente) {
        [void]$sb.AppendLine("Sistema analizzato: Windows 11 $($Ambiente.Edition) (Build $($Ambiente.Build)) | Admin: $($Ambiente.IsAdmin)")
    }
    [void]$sb.AppendLine("Punteggio conformita': $perc% ($($Conteggi.superato) Superati su $($Conteggi.totale) controlli)")
    [void]$sb.AppendLine("Valutazione complessiva: $giudizio")
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine("1. SINTESI DELLO STATO DEL PC")
    [void]$sb.AppendLine("   - Controlli Superati:        $($Conteggi.superato)")
    [void]$sb.AppendLine("   - Controlli da Migliorare:   $($Conteggi.fallito)")
    [void]$sb.AppendLine("   - Controlli Sconosciuti:     $($Conteggi.sconosciuto)")
    [void]$sb.AppendLine("   - Controlli Non Applicabili: $($Conteggi.non_applicabile)")
    [void]$sb.AppendLine("")

    $falliti = @($ElementiVista | Where-Object { $_.Status -eq 'fallito' })

    if ($falliti.Count -eq 0) {
        [void]$sb.AppendLine("2. NESSUNA CRITICITA' RILEVATA")
        [void]$sb.AppendLine("   Tutti i controlli eseguibili sul sistema risultano configurati correttamente.")
    }
    else {
        [void]$sb.AppendLine("2. PRIORITA' DI INTERVENTO E COME APPLICARE LA SICUREZZA ($($falliti.Count) azioni)")
        [void]$sb.AppendLine("")
        $num = 0
        foreach ($f in $falliti) {
            $num++
            $det = Format-DettaglioControllo -Elemento $f -Modalita 'Semplice'
            [void]$sb.AppendLine("   Priorita' #$num — [$($f.SeverityLabel.ToUpperInvariant())] $($f.Title) ($($f.ControlId))")
            [void]$sb.AppendLine("   * Stato attuale sul PC: $($det.ValoreOsservato)")
            [void]$sb.AppendLine("   * Perche' intervenire:  $($det.SpiegazioneSemplice)")
            [void]$sb.AppendLine("   * Come correggere:      $($det.TestoRimedio)")
            if ($det.HaComando -and (-not [string]::IsNullOrWhiteSpace($det.ComandoRimedio))) {
                [void]$sb.AppendLine("   * Comando rapido (Admin): $($det.ComandoRimedio)")
            }
            [void]$sb.AppendLine("   * Precauzioni:          $($det.NoteRischi)")
            [void]$sb.AppendLine("")
        }
    }

    [void]$sb.AppendLine("3. CONSIGLI PRATICI PRIMA DI APPLICARE LE MODIFICHE")
    [void]$sb.AppendLine("   - Crea sempre un Punto di Ripristino di Windows prima di modificare il registro o i criteri.")
    [void]$sb.AppendLine("   - Applica un miglioramento alla volta (partendo da quelli a gravita' CRITICO e ALTO) e verifica il normale funzionamento delle tue applicazioni.")
    [void]$sb.AppendLine("   - Puoi copiare il comando di ciascun controllo selezionandolo nella Pagina 1 (Scansione e Controlli).")

    return $sb.ToString().Trim()
}

function Find-EseguibileOllamaLocale {
    <#
    .SYNOPSIS
        Cerca il percorso di ollama.exe sul sistema locale.
    #>
    [CmdletBinding()]
    param()

    $cmd = Get-Command -Name 'ollama' -ErrorAction SilentlyContinue
    if ($null -ne $cmd -and (-not [string]::IsNullOrWhiteSpace($cmd.Source))) {
        return $cmd.Source
    }

    $percorsiCandidati = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'),
        'C:\Program Files\Ollama\ollama.exe'
    )
    foreach ($p in $percorsiCandidati) {
        if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path -LiteralPath $p)) {
            return $p
        }
    }

    return $null
}

function Test-ConnessioneOllama {
    <#
    .SYNOPSIS
        Verifica se il server Ollama e' attivo sull'endpoint specificato (o sull'Host della VM)
        e restituisce la lista dei modelli installati.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Endpoint = $script:EndpointOllamaPredefinito,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 2
    )

    $urlPulito = if ([string]::IsNullOrWhiteSpace($Endpoint)) { $script:EndpointOllamaPredefinito } else { $Endpoint.Trim().TrimEnd('/') }

    # Lista di endpoint candidati: quello scelto + fallback automatici per VM (Host NAT 10.0.2.2 e Default Gateway)
    $candidati = @($urlPulito)
    if ($urlPulito -match '127\.0\.0\.1|localhost') {
        $candidati += 'http://10.0.2.2:11434'
        try {
            $rot = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 2)
            foreach ($r in $rot) {
                if ($null -ne $r.PSObject.Properties['NextHop'] -and (-not [string]::IsNullOrWhiteSpace($r.NextHop)) -and $r.NextHop -ne '0.0.0.0') {
                    $gwUrl = "http://$($r.NextHop):11434"
                    if ($candidati -notcontains $gwUrl) {
                        $candidati += $gwUrl
                    }
                }
            }
        }
        catch { }
    }

    foreach ($cand in $candidati) {
        $uriTags = "$cand/api/tags"
        try {
            $risposta = Invoke-RestMethod -Uri $uriTags -Method Get -TimeoutSec $TimeoutSec -ErrorAction Stop
            $nomiModelli = @()

            if ($null -ne $risposta -and $null -ne $risposta.PSObject.Properties['models'] -and $null -ne $risposta.models) {
                foreach ($m in $risposta.models) {
                    if ($null -ne $m.PSObject.Properties['name'] -and (-not [string]::IsNullOrWhiteSpace([string]$m.name))) {
                        $nomiModelli += [string]$m.name
                    }
                }
            }

            $preferiti = @('qwen2.5:0.5b', 'qwen2.5:1.5b', 'llama3.2:1b', 'gemma2:2b', 'tinyllama:latest', 'phi3:mini')
            $consigliato = $script:ModelloOllamaPredefinito
            if ($nomiModelli.Count -gt 0) {
                $trovatoPreferito = $false
                foreach ($pref in $preferiti) {
                    if ($nomiModelli -contains $pref) {
                        $consigliato = $pref
                        $trovatoPreferito = $true
                        break
                    }
                }
                if (-not $trovatoPreferito) {
                    $consigliato = $nomiModelli[0]
                }
            }

            return [PSCustomObject]@{
                Disponibile        = $true
                Endpoint           = $cand
                Modelli            = $nomiModelli
                ModelloConsigliato = $consigliato
                Errore             = $null
            }
        }
        catch {
            # Prova il candidato successivo
        }
    }

    return [PSCustomObject]@{
        Disponibile        = $false
        Endpoint           = $urlPulito
        Modelli            = @()
        ModelloConsigliato = $script:ModelloOllamaPredefinito
        Errore             = "Server Ollama non attivo su $urlPulito."
    }
}

function Initialize-AmbienteOllama {
    <#
    .SYNOPSIS
        Garantisce che Ollama sia attivo: se e' installato lo avvia; se non e' installato
        sulla macchina/VM e AutoInstalla e' attivo, lo scarica e lo installa in modalita'
        silenziosa senza intervento manuale dell'utente.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Endpoint = $script:EndpointOllamaPredefinito,

        [Parameter(Mandatory = $false)]
        [bool]$AutoInstalla = $true,

        [Parameter(Mandatory = $false)]
        [scriptblock]$OnStatus = $null
    )

    # 1. Controlla se e' gia' attivo (in locale o sull'Host della VM)
    $stato = Test-ConnessioneOllama -Endpoint $Endpoint -TimeoutSec 2
    if ($stato.Disponibile) {
        return $stato
    }

    # 2. Cerca se ollama.exe e' gia' presente sul disco ma non avviato
    $exeOllama = Find-EseguibileOllamaLocale
    if (-not [string]::IsNullOrWhiteSpace($exeOllama)) {
        if ($null -ne $OnStatus) { & $OnStatus "Avvio automatico del servizio Ollama locale in corso..." }
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName        = $exeOllama
            $psi.Arguments       = 'serve'
            $psi.CreateNoWindow  = $true
            $psi.UseShellExecute = $false
            [void][System.Diagnostics.Process]::Start($psi)

            for ($i = 0; $i -lt 5; $i++) {
                [System.Threading.Thread]::Sleep(1000)
                $stato = Test-ConnessioneOllama -Endpoint 'http://127.0.0.1:11434' -TimeoutSec 2
                if ($stato.Disponibile) { return $stato }
            }
        }
        catch { }
    }

    # 3. Se non e' installato sulla macchina/VM e AutoInstalla e' True, installalo automaticamente!
    if ($AutoInstalla) {
        # 3a. Tentativo rapido tramite winget (se presente sulla macchina)
        $cmdWinget = Get-Command -Name 'winget' -ErrorAction SilentlyContinue
        if ($null -ne $cmdWinget) {
            if ($null -ne $OnStatus) { & $OnStatus "Ollama non trovato sulla VM: installazione automatica tramite Winget in corso (attendi 1-2 minuti)..." }
            try {
                $psiWg = New-Object System.Diagnostics.ProcessStartInfo
                $psiWg.FileName        = $cmdWinget.Source
                $psiWg.Arguments       = 'install -e --id Ollama.Ollama --silent --accept-package-agreements --accept-source-agreements'
                $psiWg.CreateNoWindow  = $true
                $psiWg.UseShellExecute = $false
                $procWg = [System.Diagnostics.Process]::Start($psiWg)
                [void]$procWg.WaitForExit(180000)
            }
            catch { }
        }

        # 3b. Se ancora non presente, scarica direttamente OllamaSetup.exe ufficiale ed eseguilo con /VERYSILENT
        $exeOllama = Find-EseguibileOllamaLocale
        if ([string]::IsNullOrWhiteSpace($exeOllama)) {
            if ($null -ne $OnStatus) { & $OnStatus "Scaricamento automatico di OllamaSetup.exe in corso (nessuna azione manuale richiesta)..." }
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $percorsoInstaller = Join-Path ([System.IO.Path]::GetTempPath()) 'OllamaSetup_Auto.exe'
                $wc = New-Object System.Net.WebClient
                $wc.DownloadFile('https://ollama.com/download/OllamaSetup.exe', $percorsoInstaller)

                if (Test-Path -LiteralPath $percorsoInstaller) {
                    if ($null -ne $OnStatus) { & $OnStatus "Installazione silenziosa di Ollama sulla VM in corso..." }
                    $psiInst = New-Object System.Diagnostics.ProcessStartInfo
                    $psiInst.FileName        = $percorsoInstaller
                    $psiInst.Arguments       = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
                    $psiInst.CreateNoWindow  = $true
                    $psiInst.UseShellExecute = $false
                    $procInst = [System.Diagnostics.Process]::Start($psiInst)
                    [void]$procInst.WaitForExit(180000)
                }
            }
            catch { }
        }

        # 3c. Avvia il servizio appena installato
        $exeOllama = Find-EseguibileOllamaLocale
        if (-not [string]::IsNullOrWhiteSpace($exeOllama)) {
            if ($null -ne $OnStatus) { & $OnStatus "Avvio del server Ollama appena installato..." }
            try {
                $psiSrv = New-Object System.Diagnostics.ProcessStartInfo
                $psiSrv.FileName        = $exeOllama
                $psiSrv.Arguments       = 'serve'
                $psiSrv.CreateNoWindow  = $true
                $psiSrv.UseShellExecute = $false
                [void][System.Diagnostics.Process]::Start($psiSrv)

                for ($j = 0; $j -lt 8; $j++) {
                    [System.Threading.Thread]::Sleep(1000)
                    $stato = Test-ConnessioneOllama -Endpoint 'http://127.0.0.1:11434' -TimeoutSec 2
                    if ($stato.Disponibile) { return $stato }
                }
            }
            catch { }
        }
    }

    return $stato
}

function Invoke-RichiestaOllama {
    <#
    .SYNOPSIS
        Invia un prompt al server locale Ollama (/api/generate).
        Se Ollama non e' installato sulla VM, puo' auto-installarlo silenziosamente,
        scaricare automaticamente il modello scelto (/api/pull) ed eseguire l'analisi.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [Parameter(Mandatory = $false)]
        [string]$Modello = $script:ModelloOllamaPredefinito,

        [Parameter(Mandatory = $false)]
        [string]$Endpoint = $script:EndpointOllamaPredefinito,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 120,

        [Parameter(Mandatory = $false)]
        [string]$TestoFallbackLocale = '',

        [Parameter(Mandatory = $false)]
        [bool]$AutoProvision = $false,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT',

        [Parameter(Mandatory = $false)]
        [scriptblock]$OnStatus = $null
    )

    $urlPulito = if ([string]::IsNullOrWhiteSpace($Endpoint)) { $script:EndpointOllamaPredefinito } else { $Endpoint.Trim().TrimEnd('/') }
    if ([string]::IsNullOrWhiteSpace($Modello)) {
        $Modello = $script:ModelloOllamaPredefinito
    }

    $cronometro = [System.Diagnostics.Stopwatch]::StartNew()

    # Se AutoProvision e' attivo (es. dalla GUI sulla VM), assicurati che Ollama sia attivo o auto-installato
    if ($AutoProvision) {
        $statoInit = Initialize-AmbienteOllama -Endpoint $urlPulito -AutoInstalla $true -OnStatus $OnStatus
        if ($statoInit.Disponibile) {
            $urlPulito = $statoInit.Endpoint
        }
    }

    $uriGen = "$urlPulito/api/generate"

    try {
        $isPromptEn = ($Lingua -eq 'EN') -or ($Prompt -match '\[LANGUAGE: ENGLISH ONLY\]|Write a structured report in 4 sections')
        $isPromptDe = ($Lingua -eq 'DE') -or ($Prompt -match '\[SPRACHE: NUR DEUTSCH|Schreibe einen strukturierten Bericht auf DEUTSCH')
        $sysMsg = if ($isPromptEn) {
            "You are a Windows 11 cybersecurity assistant. Reply strictly in ENGLISH. Never contradict the scanner facts provided in the prompt."
        }
        elseif ($isPromptDe) {
            "Du bist ein IT-Sicherheitsassistent fuer Windows 11. Antworte AUSSCHLIESSLICH auf DEUTSCH (niemals auf Englisch). Halte dich strikt an die im Prompt genannten Fakten."
        }
        else {
            "Sei un assistente di sicurezza informatica per Windows 11. Rispondi ESCLUSIVAMENTE in lingua ITALIANA (non scrivere mai in inglese). Attieniti rigorosamente ai fatti indicati nel prompt."
        }

        $corpoObj = @{
            model   = $Modello
            system  = $sysMsg
            prompt  = $Prompt
            stream  = $false
            options = @{
                temperature = 0.1
                num_predict = 650
            }
        }
        $corpoJson = $corpoObj | ConvertTo-Json -Depth 5
        $bytesBody = [System.Text.Encoding]::UTF8.GetBytes($corpoJson)

        if ($null -ne $OnStatus) { & $OnStatus "Generazione dell'analisi con il modello '$Modello' in corso..." }
        $risposta = Invoke-RestMethod -Uri $uriGen -Method Post -Body $bytesBody -ContentType 'application/json; charset=utf-8' -TimeoutSec $TimeoutSec -ErrorAction Stop
        $cronometro.Stop()

        $testoRisposta = if ($null -ne $risposta -and $null -ne $risposta.PSObject.Properties['response']) {
            ([string]$risposta.response).Trim()
        }
        else {
            ''
        }

        if ([string]::IsNullOrWhiteSpace($testoRisposta)) {
            return [PSCustomObject]@{
                Successo = $false
                Sorgente = 'Ollama'
                Risposta = $null
                Modello  = $Modello
                DurataMs = [int]$cronometro.ElapsedMilliseconds
                Errore   = "Ollama ha restituito una risposta vuota per il modello '$Modello'."
            }
        }

        # Se abbiamo i dati strutturati deterministici (TestoFallbackLocale), li affianchiamo
        # alla risposta di Ollama, verificando anche la coerenza della lingua per i modelli molto piccoli (0.5b)
        $rispostaFinale = $testoRisposta
        if (-not [string]::IsNullOrWhiteSpace($TestoFallbackLocale)) {
            $rispostaInIngleseIndesiderato = ((-not $isPromptEn) -and ($testoRisposta -match '(?i)\b(WHAT IT MEANS|WHY IT MATTERS|HOW TO FIX|The user should|The system disk is)\b'))
            if ($rispostaInIngleseIndesiderato) {
                $rispostaFinale = $TestoFallbackLocale
            }
            else {
                $titoloIa = if ($isPromptEn) {
                    "=== AI COMMENTARY ($Modello) ==="
                } elseif ($isPromptDe) {
                    "=== KI-KOMMENTAR ($Modello) ==="
                } else {
                    "=== COMMENTO GENERATO DALL'IA ($Modello) ==="
                }
                $rispostaFinale = "$TestoFallbackLocale`n`n$titoloIa`n$testoRisposta"
            }
        }

        return [PSCustomObject]@{
            Successo = $true
            Sorgente = "Ollama ($Modello su $urlPulito)"
            Risposta = $rispostaFinale
            Modello  = $Modello
            DurataMs = [int]$cronometro.ElapsedMilliseconds
            Errore   = $null
        }
    }
    catch {
        $cronometro.Stop()
        $msg = $_.Exception.Message

        # Se Ollama e' attivo ma il modello non e' ancora scaricato (404), scaricalo automaticamente via /api/pull!
        if ($msg -match '404|not found') {
            try {
                if ($null -ne $OnStatus) { & $OnStatus "Scaricamento automatico del modello '$Modello' tramite Ollama (/api/pull)..." }
                $uriPull  = "$urlPulito/api/pull"
                $pullJson = (@{ name = $Modello; stream = $false } | ConvertTo-Json)
                [void](Invoke-RestMethod -Uri $uriPull -Method Post -Body ([System.Text.Encoding]::UTF8.GetBytes($pullJson)) -ContentType 'application/json' -TimeoutSec 600 -ErrorAction Stop)

                if ($null -ne $OnStatus) { & $OnStatus "Modello '$Modello' scaricato! Generazione del resoconto in corso..." }
                $rispostaRetry = Invoke-RestMethod -Uri $uriGen -Method Post -Body $bytesBody -ContentType 'application/json; charset=utf-8' -TimeoutSec $TimeoutSec -ErrorAction Stop
                $testoRetry = ([string]$rispostaRetry.response).Trim()
                if (-not [string]::IsNullOrWhiteSpace($testoRetry)) {
                    return [PSCustomObject]@{
                        Successo = $true
                        Sorgente = "Ollama ($Modello - scaricato automaticamente)"
                        Risposta = $testoRetry
                        Modello  = $Modello
                        DurataMs = [int]$cronometro.ElapsedMilliseconds
                        Errore   = $null
                    }
                }
            }
            catch { }
        }

        if (-not [string]::IsNullOrWhiteSpace($TestoFallbackLocale)) {
            return [PSCustomObject]@{
                Successo = $true
                Sorgente = 'Motore Esperto Integrato'
                Risposta = $TestoFallbackLocale
                Modello  = 'Motore Esperto Locale'
                DurataMs = [int]$cronometro.ElapsedMilliseconds
                Errore   = $null
            }
        }

        $erroreAmichevole = if ($msg -match '404') {
            "Il modello '$Modello' non e' ancora scaricato in Ollama. Esegui: ollama pull $Modello"
        }
        else {
            "Impossibile connettersi a Ollama su $urlPulito ($msg). Esegui: ollama pull $Modello"
        }

        return [PSCustomObject]@{
            Successo = $false
            Sorgente = 'Errore'
            Risposta = $null
            Modello  = $Modello
            DurataMs = [int]$cronometro.ElapsedMilliseconds
            Errore   = $erroreAmichevole
        }
    }
}
