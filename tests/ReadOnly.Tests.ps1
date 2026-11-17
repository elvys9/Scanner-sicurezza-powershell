<#
.SYNOPSIS
    Test Pester 5 — Verifica di SOLA LETTURA.

.DESCRIPTION
    Analizza con l'AST tutti i file .ps1 nella cartella src/ e verifica
    che nessun comando usi un verbo vietato. Questo garantisce che lo
    scanner non modifichi mai lo stato del sistema.
#>

Set-StrictMode -Version 2

Describe 'Verifica SOLA LETTURA dei file sorgente' {

    BeforeAll {
        # Verbi vietati (il collettore non deve mai usare questi verbi)
        $verbiVietati = @(
            'Set',
            'New',
            'Remove',
            'Enable',
            'Disable',
            'Add',
            'Clear',
            'Start',
            'Stop',
            'Restart',
            'Install',
            'Uninstall'
        )

        # Comandi esplicitamente vietati (nome completo)
        $comandiVietati = @(
            'Invoke-Expression'
        )

        # Eccezioni ammesse (con motivazione):
        # - New-Object: crea oggetti .NET in memoria, non modifica il sistema
        # - New-Report: funzione interna per costruire l'oggetto report in memoria (sola lettura)
        # - Add-Member: aggiunge proprieta' a oggetti in memoria
        # - Add-Type: carica tipi .NET in memoria (non modifica il sistema)
        # - Set-StrictMode: configurazione dell'interprete (obbligatorio per qualita' del codice)
        $eccezioniAmmesse = @(
            'New-Object',
            'New-Report',
            'Add-Member',
            'Add-Type',
            'Set-StrictMode'
        )

        # Percorso della cartella sorgente
        $percorsoSrc = Join-Path $PSScriptRoot '..\src'
    }

    It 'La cartella src esiste' {
        Test-Path -LiteralPath $percorsoSrc | Should -Be $true
    }

    It 'Non contiene comandi con verbi vietati' {
        $fileSorgente = Get-ChildItem -Path $percorsoSrc -Filter '*.ps1' -Recurse

        $violazioni = @()

        foreach ($file in $fileSorgente) {
            # Analisi AST del file
            $erroriParse = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                $file.FullName,
                [ref]$null,
                [ref]$erroriParse
            )

            # Trova tutti i comandi nel file
            $comandi = $ast.FindAll(
                { param($nodo) $nodo -is [System.Management.Automation.Language.CommandAst] },
                $true
            )

            foreach ($comando in $comandi) {
                $nomeComando = $comando.GetCommandName()
                if (-not $nomeComando) { continue }

                # Verifica comandi esplicitamente vietati
                if ($comandiVietati -contains $nomeComando) {
                    $violazioni += "$($file.Name):$($comando.Extent.StartLineNumber) - $nomeComando (vietato)"
                    continue
                }

                # Verifica se e' un'eccezione ammessa
                if ($eccezioniAmmesse -contains $nomeComando) {
                    continue
                }

                # Estrai il verbo dal comando (formato Verbo-Nome)
                $parti = $nomeComando -split '-', 2
                if ($parti.Count -ge 2) {
                    $verbo = $parti[0]
                    if ($verbiVietati -contains $verbo) {
                        $violazioni += "$($file.Name):$($comando.Extent.StartLineNumber) - $nomeComando (verbo '$verbo' vietato)"
                    }
                }
            }
        }

        if ($violazioni.Count -gt 0) {
            $messaggio = "Trovate $($violazioni.Count) violazione/i di sola lettura:`n"
            $messaggio += ($violazioni -join "`n")
            $violazioni.Count | Should -Be 0 -Because $messaggio
        }
    }

    It 'Non contiene scritture nel registro (REG_SET pattern)' {
        $fileSorgente = Get-ChildItem -Path $percorsoSrc -Filter '*.ps1' -Recurse

        $violazioni = @()

        foreach ($file in $fileSorgente) {
            $contenuto = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
            $righe = $contenuto -split "`n"
            $numRiga = 0

            foreach ($riga in $righe) {
                $numRiga++
                # Cerca pattern di scrittura nel registro
                if ($riga -match 'Set-ItemProperty|New-ItemProperty|Remove-ItemProperty|Set-Item\s.*HK') {
                    # Ignora commenti
                    $rigaTrimmed = $riga.TrimStart()
                    if (-not $rigaTrimmed.StartsWith('#')) {
                        $violazioni += "$($file.Name):$numRiga - $($riga.Trim())"
                    }
                }
            }
        }

        if ($violazioni.Count -gt 0) {
            $messaggio = "Trovate scritture nel registro:`n$($violazioni -join "`n")"
            $violazioni.Count | Should -Be 0 -Because $messaggio
        }
    }
}
