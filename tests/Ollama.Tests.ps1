<#
.SYNOPSIS
    Test Pester 5 per il client LLM locale Ollama (OllamaClient.ps1).
#>

Set-StrictMode -Version 2

Describe 'OllamaClient — Prompt e Chiamate API Locali' {

    BeforeAll {
        $percorsoCore = Join-Path $PSScriptRoot '..\src\core'
        $percorsoUi   = Join-Path $PSScriptRoot '..\src\ui'
        . (Join-Path $percorsoUi 'ViewModel.ps1')
        . (Join-Path $percorsoCore 'OllamaClient.ps1')

        $ambienteTest = [PSCustomObject]@{
            Edition = 'Pro'
            Build   = '26200.1'
            IsAdmin = $true
        }
    }

    Context 'Format-PromptControlloOllama' {

        It 'Genera un prompt in italiano con ID, stato, valore trovato e rimedio' {
            $dettaglioFinto = [PSCustomObject]@{
                ControlId           = 'HOME-FW-001'
                Title               = 'Firewall di Windows attivo'
                Category            = 'Firewall'
                SeverityLabel       = 'Critico'
                StatusLabel         = '[X] Fallito'
                ValoreAtteso        = 'Tutti i profili attivi'
                ValoreOsservato     = 'Profili disattivi: Public'
                SpiegazioneSemplice = 'Il firewall protegge la rete.'
                TestoRimedio        = 'Attiva il firewall.'
                HaComando           = $true
                ComandoRimedio      = 'Set-NetFirewallProfile -Enabled True'
                NoteRischi          = 'Basso'
            }

            $prompt = Format-PromptControlloOllama -Dettaglio $dettaglioFinto -Ambiente $ambienteTest
            $prompt | Should -Match 'HOME-FW-001'
            $prompt | Should -Match 'Profili disattivi: Public'
            $prompt | Should -Match 'COSA SIGNIFICA'
            $prompt | Should -Match 'COME MIGLIORARE IN SICUREZZA'
        }
    }

    Context 'Format-PromptResocontoOllama' {

        It 'Genera il prompt complessivo includendo i conteggi e i controlli falliti' {
            $elementi = @(
                [PSCustomObject]@{
                    ControlId     = 'HOME-AV-005'
                    Title         = 'Blocco PUA attivo'
                    Category      = 'Antivirus'
                    Severity      = 'medio'
                    SeverityLabel = 'Medio'
                    Status        = 'fallito'
                    StatusLabel   = '[X] Fallito'
                    Observed      = 'PUAProtection = 2'
                    Expected      = 'PUAProtection = 1'
                }
            )
            $conteggi = [PSCustomObject]@{
                totale          = 34
                superato        = 33
                fallito         = 1
                sconosciuto     = 0
                non_applicabile = 0
                errore          = 0
            }

            $prompt = Format-PromptResocontoOllama -ElementiVista $elementi -Conteggi $conteggi -Ambiente $ambienteTest
            $prompt | Should -Match 'Totale controlli eseguiti: 34'
            $prompt | Should -Match 'HOME-AV-005'
            $prompt | Should -Match 'GUIDA PRATICA PASSO-PASSO'
        }
    }

    Context 'Test-ConnessioneOllama e Invoke-RichiestaOllama (con Mock)' {

        It 'Test-ConnessioneOllama rileva i modelli installati e sceglie il modello leggero consigliato' {
            Mock Invoke-RestMethod {
                return [PSCustomObject]@{
                    models = @(
                        [PSCustomObject]@{ name = 'llama3:8b' }
                        [PSCustomObject]@{ name = 'qwen2.5:0.5b' }
                    )
                }
            }

            $stato = Test-ConnessioneOllama -Endpoint 'http://localhost:11434'
            $stato.Disponibile        | Should -Be $true
            $stato.Modelli.Count      | Should -Be 2
            $stato.ModelloConsigliato | Should -Be 'qwen2.5:0.5b'
        }

        It 'Invoke-RichiestaOllama restituisce la spiegazione generata dal modello' {
            Mock Invoke-RestMethod {
                return [PSCustomObject]@{
                    response = '1. COSA SIGNIFICA: Il firewall pubblico risulta disattivato...'
                }
            }

            $esito = Invoke-RichiestaOllama -Prompt 'Spiega HOME-FW-001' -Modello 'qwen2.5:0.5b'
            $esito.Successo | Should -Be $true
            $esito.Risposta | Should -Match 'COSA SIGNIFICA'
            $esito.Modello  | Should -Be 'qwen2.5:0.5b'
        }

        It 'Invoke-RichiestaOllama gestisce in modo amichevole il caso in cui Ollama non sia avviato' {
            Mock Invoke-RestMethod {
                throw [System.Net.WebException]::new("Unable to connect to the remote server")
            }

            $esito = Invoke-RichiestaOllama -Prompt 'Test' -Modello 'qwen2.5:0.5b'
            $esito.Successo | Should -Be $false
            $esito.Errore   | Should -Match 'ollama pull qwen2\.5:0\.5b'
        }
    }
}
