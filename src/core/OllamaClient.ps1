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
        Genera una spiegazione strutturata e contestuale del singolo controllo.
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
        Genera un resoconto completo e prioritizzato dell'intera scansione del PC.
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

        return [PSCustomObject]@{
            Successo = $true
            Sorgente = "Ollama ($Modello su $urlPulito)"
            Risposta = $testoRisposta
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
