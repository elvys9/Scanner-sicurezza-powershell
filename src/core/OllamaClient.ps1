<#
.SYNOPSIS
    Client per l'integrazione con un LLM locale tramite Ollama (http://localhost:11434).

.DESCRIPTION
    Fornisce funzioni pure per la costruzione dei prompt (controllo singolo e
    resoconto complessivo della scansione) e funzioni di chiamata all'API REST
    locale di Ollama (/api/tags e /api/generate).
    Rispetta il principio architetturale D3: il rilevamento e' deterministico;
    l'LLM spiega i risultati e fornisce consigli di miglioramento senza mai
    decidere o modificare lo stato dei controlli ne' eseguire comandi sul sistema.
#>

Set-StrictMode -Version 2

$script:EndpointOllamaPredefinito = 'http://localhost:11434'
$script:ModelloOllamaPredefinito  = 'qwen2.5:0.5b'

function Format-PromptControlloOllama {
    <#
    .SYNOPSIS
        Costruisce il prompt in italiano per chiedere all'LLM di spiegare un singolo controllo.
    .PARAMETER Dettaglio
        Oggetto prodotto da Format-DettaglioControllo (ViewModel.ps1).
    .PARAMETER Ambiente
        Oggetto ambiente opzionale (da Get-AmbienteSistema).
    .OUTPUTS
        Stringa con il prompt strutturato per Ollama.
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
    .PARAMETER ElementiVista
        Array di elementi vista (da ConvertTo-RisultatiVista).
    .PARAMETER Conteggi
        Oggetto conteggi (da Measure-ConteggiRisultati).
    .PARAMETER Ambiente
        Oggetto ambiente (da Get-AmbienteSistema).
    .OUTPUTS
        Stringa con il prompt completo per il resoconto IA.
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

function Test-ConnessioneOllama {
    <#
    .SYNOPSIS
        Verifica se il server locale Ollama e' attivo e restituisce la lista dei modelli installati.
    .PARAMETER Endpoint
        URL base del server Ollama (predefinito: http://localhost:11434).
    .PARAMETER TimeoutSec
        Timeout in secondi (predefinito: 4).
    .OUTPUTS
        PSCustomObject con Disponibile, Modelli, ModelloConsigliato, Errore.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Endpoint = $script:EndpointOllamaPredefinito,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 4
    )

    $urlPulito = $Endpoint.TrimEnd('/')
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

        # Preferenza per modelli leggeri ideali per test rapidi
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
            Errore             = "Ollama non raggiungibile su $urlPulito. Assicurati che Ollama sia installato ('winget install Ollama.Ollama') e avvia un modello leggero con: ollama run qwen2.5:0.5b"
        }
    }
}

function Invoke-RichiestaOllama {
    <#
    .SYNOPSIS
        Invia un prompt al server locale Ollama (/api/generate) e restituisce la risposta testuale.
    .PARAMETER Prompt
        Testo del prompt da inviare.
    .PARAMETER Modello
        Nome del modello Ollama (es. 'qwen2.5:0.5b', 'llama3.2:1b').
    .PARAMETER Endpoint
        URL base di Ollama (predefinito: http://localhost:11434).
    .PARAMETER TimeoutSec
        Timeout massimo per la generazione in secondi (predefinito: 120).
    .OUTPUTS
        PSCustomObject con Successo, Risposta, Modello, DurataMs, Errore.
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
        [int]$TimeoutSec = 120
    )

    $urlPulito = $Endpoint.TrimEnd('/')
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
                num_predict = 700
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
                Risposta = $null
                Modello  = $Modello
                DurataMs = [int]$cronometro.ElapsedMilliseconds
                Errore   = "Ollama ha restituito una risposta vuota per il modello '$Modello'."
            }
        }

        return [PSCustomObject]@{
            Successo = $true
            Risposta = $testoRisposta
            Modello  = $Modello
            DurataMs = [int]$cronometro.ElapsedMilliseconds
            Errore   = $null
        }
    }
    catch {
        $cronometro.Stop()
        $msg = $_.Exception.Message

        $erroreAmichevole = if ($msg -match '404') {
            "Il modello '$Modello' non e' ancora scaricato in Ollama. Apri il terminale ed esegui:`nollama pull $Modello"
        }
        elseif ($msg -match 'Unable to connect|Impossibile stabilire la connessione|timed out|rifiutata') {
            "Impossibile connettersi a Ollama su $urlPulito.`n1. Verifica che Ollama sia in esecuzione.`n2. Se non hai ancora scaricato il modello leggero di test, esegui in PowerShell:`n   ollama pull $Modello"
        }
        else {
            "Errore durante la comunicazione con Ollama ($Modello): $msg"
        }

        return [PSCustomObject]@{
            Successo = $false
            Risposta = $null
            Modello  = $Modello
            DurataMs = [int]$cronometro.ElapsedMilliseconds
            Errore   = $erroreAmichevole
        }
    }
}
