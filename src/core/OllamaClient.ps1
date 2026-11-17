<#
.SYNOPSIS
    Client per l'integrazione con un LLM locale tramite Ollama (http://127.0.0.1:11434)
    con generatore di resoconto intelligente integrato.

.DESCRIPTION
    Fornisce funzioni pure per la costruzione dei prompt (controllo singolo e
    resoconto complessivo della scansione), funzioni di chiamata all'API REST
    locale di Ollama (/api/tags, /api/pull e /api/generate) e un motore di
    analisi guidata locale caso-specifica quando il servizio Ollama non e'
    installato sulla macchina.
    Rispetta il principio architetturale D3: il rilevamento e' deterministico;
    l'assistente spiega i risultati e fornisce consigli di miglioramento senza mai
    decidere o modificare lo stato dei controlli ne' eseguire comandi sul sistema.
#>

Set-StrictMode -Version 2

$script:EndpointOllamaPredefinito = 'http://127.0.0.1:11434'
$script:ModelloOllamaPredefinito  = 'qwen2.5:0.5b'

function Format-PromptControlloOllama {
    <#
    .SYNOPSIS
        Costruisce il prompt in italiano per chiedere all'LLM di spiegare un singolo controllo.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Dettaglio,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Ambiente = $null
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
        "Nessun comando da terminale (configurazione manuale da interfaccia di Windows/BIOS)"
    }

    $prompt = @"
Sei un assistente esperto di sicurezza informatica per utenti domestici Windows 11.
Rispondi SOLO in lingua italiana, in modo chiaro, conciso e pratico.
Non inventare dati e non cambiare lo stato del controllo (che e' gia' stato verificato in modo deterministico dallo scanner).

CONTESTO SISTEMA: $infoOs
CONTROLLO ANALIZZATO:
- ID: $($Dettaglio.ControlId)
- Titolo: $($Dettaglio.Title)
- Categoria: $($Dettaglio.Category)
- Gravita': $($Dettaglio.SeverityLabel)
- Stato rilevato: $($Dettaglio.StatusLabel)
- Valore atteso: $($Dettaglio.ValoreAtteso)
- Valore trovato sul PC: $($Dettaglio.ValoreOsservato)
- Spiegazione base: $($Dettaglio.SpiegazioneSemplice)
- Rimedio consigliato: $($Dettaglio.TestoRimedio)
- Comando di riferimento: $cmdRif
- Note sui rischi: $($Dettaglio.NoteRischi)

Fornisci una risposta strutturata in 3 brevi punti:
1. COSA SIGNIFICA: spiega in parole semplici cosa e' stato trovato sul PC.
2. PERCHE' E' IMPORTANTE: spiega il rischio concreto per l'utente domestico.
3. COME MIGLIORARE IN SICUREZZA: spiega passo dopo passo cosa fare (se lo stato e' Fallito o Sconosciuto) o conferma che l'impostazione e' gia' ottimale (se Superato), ricordando eventuali precauzioni.
"@

    return $prompt.Trim()
}

function Format-PromptResocontoOllama {
    <#
    .SYNOPSIS
        Costruisce il prompt in italiano per generare un resoconto complessivo della scansione
        e un piano di miglioramento prioritario.
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
        [PSCustomObject]$Ambiente = $null
    )

    $infoOs = if ($null -ne $Ambiente) {
        "Windows 11 $($Ambiente.Edition) (Build $($Ambiente.Build), Eseguito come Admin: $($Ambiente.IsAdmin))"
    }
    else {
        "Windows 11"
    }

    $sbFalliti = New-Object System.Text.StringBuilder
    $nFalliti = 0

    foreach ($el in $ElementiVista) {
        if ($el.Status -eq 'fallito') {
            $nFalliti++
            $det = Format-DettaglioControllo -Elemento $el -Modalita 'Semplice'
            [void]$sbFalliti.AppendLine("- [$($el.SeverityLabel.ToUpperInvariant())] $($el.ControlId) - $($el.Title)")
            [void]$sbFalliti.AppendLine("  Trovato: $($det.ValoreOsservato) (Atteso: $($det.ValoreAtteso))")
            [void]$sbFalliti.AppendLine("  Come correggere: $($det.TestoRimedio)")
        }
    }

    if ($nFalliti -eq 0) {
        [void]$sbFalliti.AppendLine("Nessun controllo fallito! Tutti i controlli applicabili sono superati o richiedono verifica con privilegi amministrativi.")
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
        Genera una spiegazione strutturata e contestuale del singolo controllo
        anche quando il server Ollama locale non e' ancora attivo sulla macchina.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Dettaglio,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Ambiente = $null
    )

    $sb = New-Object System.Text.StringBuilder
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
        Genera un resoconto completo e prioritizzato dell'intera scansione del PC
        con consigli passo-passo per tutti i controlli falliti.
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
        [PSCustomObject]$Ambiente = $null
    )

    $perc = if ($Conteggi.totale -gt 0) {
        [int][math]::Round((($Conteggi.superato * 100.0) / $Conteggi.totale), 0)
    } else { 0 }

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
    [void]$sb.AppendLine("   - Puoi copiare il comando di ciascun controllo selezionandolo nella scheda 'Dettagli e Rimedio'.")

    return $sb.ToString().Trim()
}

function Test-ConnessioneOllama {
    <#
    .SYNOPSIS
        Verifica se il server locale Ollama e' attivo e restituisce la lista dei modelli installati.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Endpoint = $script:EndpointOllamaPredefinito,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 3
    )

    $urlPulito = if ([string]::IsNullOrWhiteSpace($Endpoint)) { $script:EndpointOllamaPredefinito } else { $Endpoint.Trim().TrimEnd('/') }
    $uriTags   = "$urlPulito/api/tags"

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
            Endpoint           = $urlPulito
            Modelli            = $nomiModelli
            ModelloConsigliato = $consigliato
            Errore             = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            Disponibile        = $false
            Endpoint           = $urlPulito
            Modelli            = @()
            ModelloConsigliato = $script:ModelloOllamaPredefinito
            Errore             = "Server Ollama non attivo su $urlPulito. Per usare un modello LLM neurale locale installa Ollama ('winget install Ollama.Ollama') ed esegui 'ollama run qwen2.5:0.5b'."
        }
    }
}

function Invoke-RichiestaOllama {
    <#
    .SYNOPSIS
        Invia un prompt al server locale Ollama (/api/generate). Se il modello non e'
        ancora scaricato ma Ollama e' attivo, tenta di usare un modello installato o
        scarica automaticamente il modello scelto tramite /api/pull.
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
        [string]$TestoFallbackLocale = ''
    )

    $urlPulito = if ([string]::IsNullOrWhiteSpace($Endpoint)) { $script:EndpointOllamaPredefinito } else { $Endpoint.Trim().TrimEnd('/') }
    $uriGen    = "$urlPulito/api/generate"

    if ([string]::IsNullOrWhiteSpace($Modello)) {
        $Modello = $script:ModelloOllamaPredefinito
    }

    $cronometro = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $corpoObj = @{
            model   = $Modello
            prompt  = $Prompt
            stream  = $false
            options = @{
                temperature = 0.2
                num_predict = 750
            }
        }
        $corpoJson = $corpoObj | ConvertTo-Json -Depth 5
        $bytesBody = [System.Text.Encoding]::UTF8.GetBytes($corpoJson)

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

        return [PSCustomObject]@{
            Successo = $true
            Sorgente = "Ollama ($Modello)"
            Risposta = $testoRisposta
            Modello  = $Modello
            DurataMs = [int]$cronometro.ElapsedMilliseconds
            Errore   = $null
        }
    }
    catch {
        $cronometro.Stop()
        $msg = $_.Exception.Message

        # Se Ollama e' attivo ma il modello specificato non e' presente (404), prova a scaricarlo via /api/pull
        if ($msg -match '404') {
            try {
                $uriPull  = "$urlPulito/api/pull"
                $pullJson = (@{ name = $Modello; stream = $false } | ConvertTo-Json)
                [void](Invoke-RestMethod -Uri $uriPull -Method Post -Body ([System.Text.Encoding]::UTF8.GetBytes($pullJson)) -ContentType 'application/json' -TimeoutSec 300 -ErrorAction Stop)

                # Riprova la generazione dopo il pull
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

        # Se abbiamo un'analisi guidata locale (quando Ollama non e' installato sulla VM/PC),
        # restituiamola insieme alle istruzioni per attivare Ollama
        if (-not [string]::IsNullOrWhiteSpace($TestoFallbackLocale)) {
            $avvisoHeader = "[Assistente Esperto Integrato — Il server Ollama non e' attivo su $urlPulito]`n" +
                            "(Nota: per usare il modello neurale Ollama, installa Ollama con 'winget install Ollama.Ollama' oppure premi 'Installa / Avvia Ollama' qui sopra).`n`n"
            return [PSCustomObject]@{
                Successo = $true
                Sorgente = 'Assistente Esperto Integrato (Ollama offline)'
                Risposta = ($avvisoHeader + $TestoFallbackLocale)
                Modello  = 'Motore Esperto Locale'
                DurataMs = [int]$cronometro.ElapsedMilliseconds
                Errore   = $null
            }
        }

        $erroreAmichevole = if ($msg -match '404') {
            "Il modello '$Modello' non e' ancora scaricato in Ollama. Apri il terminale ed esegui:`nollama pull $Modello"
        }
        else {
            "Impossibile connettersi a Ollama su $urlPulito ($msg).`nPer installare e avviare il modello leggero esegui in PowerShell:`n1. winget install Ollama.Ollama`n2. ollama pull $Modello"
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
