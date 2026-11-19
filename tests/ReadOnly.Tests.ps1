<#
.SYNOPSIS
    Test Pester 5 — Verifica di SOLA LETTURA per src/core e src/ui.

.DESCRIPTION
    Analizza con l'AST tutti i file .ps1 in src/core, src/ui e src/Invoke-Scanner.ps1
    verificando che nessun comando usi un verbo di modifica non autorizzato.
    - Per src/core: elenco rigoroso di sola lettura.
    - Per src/ui (e Invoke-Scanner.ps1): elenco esplicito e commentato di
      comandi consentiti (costruzione oggetti UI, export scelto dall'utente,
      riavvio come amministratore o in STA). Qualsiasi altro verbo di
      scrittura fa fallire il test.
#>

Set-StrictMode -Version 2

Describe 'Verifica SOLA LETTURA dei file sorgente' {

    BeforeAll {
        # Verbi vietati (il codice non deve mai usare questi verbi per modificare il sistema)
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

        # Eccezioni ammesse per src/core (con motivazione):
        # - New-Object: crea oggetti .NET in memoria (es. UTF8Encoding, StringBuilder), non modifica il sistema
        # - New-Report: funzione interna per costruire l'oggetto report in memoria (sola lettura)
        # - Add-Member: aggiunge proprieta' a oggetti in memoria
        # - Add-Type: carica tipi .NET in memoria
        # - Set-StrictMode: configurazione dell'interprete (obbligatorio per qualita' del codice)
        $eccezioniCore = @(
            'New-Object',
            'New-Report',
            'Add-Member',
            'Add-Type',
            'Set-StrictMode'
        )

        # Elenco ESPLICITO e commentato di comandi consentiti per src/ui e Invoke-Scanner.ps1:
        # - New-Object: istanzia controlli WPF, SaveFileDialog (scelta file export), XmlNodeReader, BrushConverter in memoria
        # - New-Report: costruisce l'oggetto report in memoria per l'export JSON/HTML scelto dall'utente
        # - Add-Member: aggiunge proprieta' a oggetti in memoria
        # - Add-Type: carica gli assembly WPF (PresentationFramework, PresentationCore, WindowsBase)
        # - Set-StrictMode: imposta Set-StrictMode -Version 2 in ogni file e runspace
        # - Start-ScannerUI: funzione interna che apre la finestra WPF in sola lettura
        # - Start-Process: consentito SOLO per riavviare lo scanner stesso come amministratore (-Verb RunAs)
        #                  su richiesta esplicita dell'utente o per rilanciarsi con flag -STA
        # Nota: la copia negli appunti usa [System.Windows.Clipboard]::SetText e la scrittura
        #       dell'export usa Export-ReportJson / Export-ReportHtml / Export-TechnicalLog.
        $eccezioniUi = @(
            'New-Object',
            'New-Report',
            'Add-Member',
            'Add-Type',
            'Set-StrictMode',
            'Start-ScannerUI',
            'Start-Process'
        )

        $percorsoSrc         = Join-Path $PSScriptRoot '..\src'
        $percorsoCore        = Join-Path $percorsoSrc 'core'
        $percorsoUi          = Join-Path $percorsoSrc 'ui'
        $percorsoRemediation = Join-Path $percorsoSrc 'remediation'
    }

    Context 'Motore di scansione (src/core)' {

        It 'La cartella src/core esiste' {
            Test-Path -LiteralPath $percorsoCore | Should -Be $true
        }

        It 'src/core non contiene comandi con verbi vietati' {
            $fileCore = Get-ChildItem -Path $percorsoCore -Filter '*.ps1' -Recurse
            $violazioni = @()

            foreach ($file in $fileCore) {
                $erroriParse = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                    $file.FullName,
                    [ref]$null,
                    [ref]$erroriParse
                )

                $comandi = $ast.FindAll(
                    { param($nodo) $nodo -is [System.Management.Automation.Language.CommandAst] },
                    $true
                )

                foreach ($comando in $comandi) {
                    $nomeComando = $comando.GetCommandName()
                    if (-not $nomeComando) { continue }

                    if ($comandiVietati -contains $nomeComando) {
                        $violazioni += "$($file.Name):$($comando.Extent.StartLineNumber) - $nomeComando (vietato)"
                        continue
                    }

                    if ($eccezioniCore -contains $nomeComando) {
                        continue
                    }

                    $parti = $nomeComando -split '-', 2
                    if ($parti.Count -ge 2) {
                        $verbo = $parti[0]
                        if ($verbiVietati -contains $verbo) {
                            $violazioni += "$($file.Name):$($comando.Extent.StartLineNumber) - $nomeComando (verbo '$verbo' vietato in src/core)"
                        }
                    }
                }
            }

            $messaggio = if ($violazioni.Count -gt 0) {
                "Trovate $($violazioni.Count) violazione/i in src/core:`n$($violazioni -join "`n")"
            } else { 'Nessuna violazione' }
            $violazioni.Count | Should -Be 0 -Because $messaggio
        }
    }

    Context 'Interfaccia grafica e punto d ingresso (src/ui e Invoke-Scanner.ps1)' {

        It 'La cartella src/ui esiste' {
            Test-Path -LiteralPath $percorsoUi | Should -Be $true
        }

        It 'src/ui e Invoke-Scanner.ps1 usano solo comandi presenti nell elenco esplicito consentito' {
            $fileUi = @(Get-ChildItem -Path $percorsoUi -Filter '*.ps1' -Recurse)
            $fileEntry = Get-Item -LiteralPath (Join-Path $percorsoSrc 'Invoke-Scanner.ps1')
            $tuttiFileUi = @($fileUi) + @($fileEntry)

            $violazioni = @()

            foreach ($file in $tuttiFileUi) {
                $erroriParse = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                    $file.FullName,
                    [ref]$null,
                    [ref]$erroriParse
                )

                $comandi = $ast.FindAll(
                    { param($nodo) $nodo -is [System.Management.Automation.Language.CommandAst] },
                    $true
                )

                foreach ($comando in $comandi) {
                    $nomeComando = $comando.GetCommandName()
                    if (-not $nomeComando) { continue }

                    if ($comandiVietati -contains $nomeComando) {
                        $violazioni += "$($file.Name):$($comando.Extent.StartLineNumber) - $nomeComando (vietato)"
                        continue
                    }

                    if ($eccezioniUi -contains $nomeComando) {
                        continue
                    }

                    $parti = $nomeComando -split '-', 2
                    if ($parti.Count -ge 2) {
                        $verbo = $parti[0]
                        if ($verbiVietati -contains $verbo) {
                            $violazioni += "$($file.Name):$($comando.Extent.StartLineNumber) - $nomeComando (verbo '$verbo' non autorizzato in src/ui)"
                        }
                    }
                }
            }

            $messaggio = if ($violazioni.Count -gt 0) {
                "Trovate $($violazioni.Count) violazione/i in src/ui:`n$($violazioni -join "`n")"
            } else { 'Nessuna violazione' }
            $violazioni.Count | Should -Be 0 -Because $messaggio
        }

        It 'Nessun file eseguibile in src/core, src/ui e Invoke-Scanner.ps1 contiene scritture nel registro' {
            $fileCoreReg  = @(Get-ChildItem -Path $percorsoCore -Filter '*.ps1' -Recurse)
            $fileUiReg    = @(Get-ChildItem -Path $percorsoUi -Filter '*.ps1' -Recurse)
            $fileEntryReg = Get-Item -LiteralPath (Join-Path $percorsoSrc 'Invoke-Scanner.ps1')
            $fileSorgente = @($fileCoreReg) + @($fileUiReg) + @($fileEntryReg)
            $violazioni = @()

            foreach ($file in $fileSorgente) {
                # Analisi AST per verificare che nessun CommandAst sia Set-ItemProperty, New-ItemProperty, Remove-ItemProperty, Set-Item
                $erroriParse = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                    $file.FullName,
                    [ref]$null,
                    [ref]$erroriParse
                )
                $comandi = $ast.FindAll(
                    { param($nodo) $nodo -is [System.Management.Automation.Language.CommandAst] },
                    $true
                )
                foreach ($cmd in $comandi) {
                    $nome = $cmd.GetCommandName()
                    if ($nome -in @('Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Item', 'New-Item', 'Remove-Item')) {
                        $violazioni += "$($file.Name):$($cmd.Extent.StartLineNumber) - $nome"
                    }
                }
            }

            $messaggio = if ($violazioni.Count -gt 0) {
                "Trovati comandi di scrittura su Item/Registro:`n$($violazioni -join "`n")"
            } else { 'Nessuna scrittura trovata' }
            $violazioni.Count | Should -Be 0 -Because $messaggio
        }
    }

    Context 'Modulo opzionale di remediation (src/remediation)' {

        It 'La cartella src/remediation esiste e tutti gli script sono sintatticamente validi' {
            Test-Path -LiteralPath $percorsoRemediation | Should -Be $true

            $fileRemediation = @(Get-ChildItem -Path $percorsoRemediation -Filter '*.ps1' -Recurse)
            $fileRemediation.Count | Should -BeGreaterThan 0

            $erroriSintassi = @()
            foreach ($file in $fileRemediation) {
                $erroriParse = $null
                [System.Management.Automation.Language.Parser]::ParseFile(
                    $file.FullName,
                    [ref]$null,
                    [ref]$erroriParse
                ) | Out-Null

                foreach ($err in @($erroriParse)) {
                    $erroriSintassi += "$($file.Name):$($err.Extent.StartLineNumber) - $($err.Message)"
                }
            }

            $erroriSintassi.Count | Should -Be 0 -Because ($erroriSintassi -join "`n")
        }

        It 'src/remediation non usa comandi dinamici o distruttivi vietati (Invoke-Expression, iex, Invoke-Command, Remove-Item)' {
            $fileRemediation = @(Get-ChildItem -Path $percorsoRemediation -Filter '*.ps1' -Recurse)
            $comandiVietatiRem = @('Invoke-Expression', 'iex', 'Invoke-Command', 'Remove-Item')
            $violazioni = @()

            foreach ($file in $fileRemediation) {
                $erroriParse = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile(
                    $file.FullName,
                    [ref]$null,
                    [ref]$erroriParse
                )
                $comandi = $ast.FindAll(
                    { param($nodo) $nodo -is [System.Management.Automation.Language.CommandAst] },
                    $true
                )
                foreach ($cmd in $comandi) {
                    $nome = $cmd.GetCommandName()
                    if ($nome -and ($comandiVietatiRem -contains $nome)) {
                        $violazioni += "$($file.Name):$($cmd.Extent.StartLineNumber) - $nome"
                    }
                }
            }

            $violazioni.Count | Should -Be 0 -Because ($violazioni -join "`n")
        }

        It 'src/core e strettamente isolato e non referenzia o importa src/remediation' {
            $fileCore = @(Get-ChildItem -Path $percorsoCore -Filter '*.ps1' -Recurse)
            $riferimenti = @()

            foreach ($file in $fileCore) {
                $contenuto = [System.IO.File]::ReadAllText($file.FullName, [System.Text.Encoding]::UTF8)
                if ($contenuto -match '(?i)src[\\/]remediation|[\\/]remediation[\\/]|FixRunner|RemediationCatalog|BackupManager|Invoke-SecurityRemediation|Restore-RemediationBackup') {
                    $riferimenti += $file.Name
                }
            }

            $riferimenti.Count | Should -Be 0 -Because "Trovati riferimenti a remediation in src/core: $($riferimenti -join ', ')"
        }
    }
}
