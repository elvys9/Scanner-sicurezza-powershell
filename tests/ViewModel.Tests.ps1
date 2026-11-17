<#
.SYNOPSIS
    Test Pester 5 per le funzioni pure del ViewModel (src/ui/ViewModel.ps1),
    gli hook di avanzamento/annullamento del Runner e l'export HTML.
#>

Set-StrictMode -Version 2

Describe 'ViewModel — Funzioni pure (senza WPF)' {

    BeforeAll {
        $percorsoViewModel = Join-Path $PSScriptRoot '..\src\ui\ViewModel.ps1'
        . $percorsoViewModel

        $catalogoTest = [PSCustomObject]@{
            schema_version = '0.2'
            controls = @(
                [PSCustomObject]@{
                    id          = 'HOME-ACC-003'
                    title       = 'Nessun account senza password'
                    category    = 'Account'
                    severity    = 'alto'
                    editions    = @('Home', 'Pro')
                    description = 'Descrizione tecnica account password.'
                    rationale   = 'Spiegazione semplice account password.'
                    references  = @('CIS 1.1')
                }
                [PSCustomObject]@{
                    id          = 'HOME-FW-001'
                    title       = 'Firewall di Windows attivo'
                    category    = 'Firewall'
                    severity    = 'critico'
                    editions    = @('Home', 'Pro')
                    description = 'Descrizione tecnica firewall.'
                    rationale   = 'Spiegazione semplice firewall.'
                    references  = @('CIS 9.1.1')
                }
                [PSCustomObject]@{
                    id          = 'HOME-UAC-001'
                    title       = 'UAC abilitato'
                    category    = 'UAC'
                    severity    = 'critico'
                    editions    = @('Home', 'Pro')
                    description = 'Descrizione tecnica UAC.'
                    rationale   = 'Spiegazione semplice UAC.'
                    references  = @('CIS 2.3.17')
                }
                [PSCustomObject]@{
                    id          = 'HOME-PRV-001'
                    title       = 'Telemetria al minimo'
                    category    = 'Privacy'
                    severity    = 'medio'
                    editions    = @('Home', 'Pro')
                    description = 'Descrizione tecnica telemetria.'
                    rationale   = 'Spiegazione semplice telemetria.'
                    references  = @()
                }
                [PSCustomObject]@{
                    id          = 'HOME-RDP-001'
                    title       = 'Desktop remoto disabilitato'
                    category    = 'Desktop Remoto'
                    severity    = 'alto'
                    editions    = @('Pro')
                    description = 'Descrizione tecnica RDP.'
                    rationale   = 'Spiegazione semplice RDP.'
                    references  = @()
                }
            )
        }

        $risultatiTest = @(
            [PSCustomObject]@{ control_id = 'HOME-UAC-001'; status = 'superato';        observed = 1;      expected = 1;      evidence = @{ Value = 1 }; error = $null; duration_ms = 10 }
            [PSCustomObject]@{ control_id = 'HOME-PRV-001'; status = 'fallito';         observed = 3;      expected = 1;      evidence = $null;          error = $null; duration_ms = 12 }
            [PSCustomObject]@{ control_id = 'HOME-ACC-003'; status = 'sconosciuto';     observed = $null;  expected = $null;  evidence = $null;          error = $null; duration_ms = 0  }
            [PSCustomObject]@{ control_id = 'HOME-FW-001';  status = 'fallito';         observed = 'Off';  expected = 'On';   evidence = $null;          error = $null; duration_ms = 25 }
            [PSCustomObject]@{ control_id = 'HOME-RDP-001'; status = 'non_applicabile'; observed = 'Home'; expected = $null;  evidence = $null;          error = $null; duration_ms = 0  }
        )
    }

    Context 'Ordinamento predefinito (Sort-RisultatiVista / ConvertTo-RisultatiVista)' {

        It 'Ordina: falliti per gravita (critico prima di medio), poi sconosciuti, poi superati, infine non_applicabile' {
            $vista = @(ConvertTo-RisultatiVista -Risultati $risultatiTest -Catalogo $catalogoTest)

            $vista.Count | Should -Be 5
            # 1. Fallito + Critico (HOME-FW-001)
            $vista[0].ControlId | Should -Be 'HOME-FW-001'
            $vista[0].Status    | Should -Be 'fallito'
            # 2. Fallito + Medio (HOME-PRV-001)
            $vista[1].ControlId | Should -Be 'HOME-PRV-001'
            $vista[1].Status    | Should -Be 'fallito'
            # 3. Sconosciuto (HOME-ACC-003)
            $vista[2].ControlId | Should -Be 'HOME-ACC-003'
            $vista[2].Status    | Should -Be 'sconosciuto'
            # 4. Superato (HOME-UAC-001)
            $vista[3].ControlId | Should -Be 'HOME-UAC-001'
            $vista[3].Status    | Should -Be 'superato'
            # 5. Non applicabile (HOME-RDP-001)
            $vista[4].ControlId | Should -Be 'HOME-RDP-001'
            $vista[4].Status    | Should -Be 'non_applicabile'
        }

        It 'Include sempre simbolo testuale ed etichetta nello StatusLabel (mai solo colore)' {
            $vista = @(ConvertTo-RisultatiVista -Risultati $risultatiTest -Catalogo $catalogoTest)
            $vista[0].StatusLabel | Should -Be '[X] Fallito'
            $vista[2].StatusLabel | Should -Be '[?] Sconosciuto'
            $vista[3].StatusLabel | Should -Be '[OK] Superato'
            $vista[4].StatusLabel | Should -Be '[-] Non applicabile'
        }
    }

    Context 'Filtri combinabili e ricerca testuale (Select-RisultatiVista)' {

        BeforeAll {
            $elementiVista = @(ConvertTo-RisultatiVista -Risultati $risultatiTest -Catalogo $catalogoTest)
        }

        It 'Restituisce tutti gli elementi con i filtri predefiniti' {
            $res = @(Select-RisultatiVista -Elementi $elementiVista)
            $res.Count | Should -Be 5
        }

        It 'Filtra per stato (fallito)' {
            $res = @(Select-RisultatiVista -Elementi $elementiVista -Stato 'fallito')
            $res.Count | Should -Be 2
            $res[0].ControlId | Should -Be 'HOME-FW-001'
            $res[1].ControlId | Should -Be 'HOME-PRV-001'
        }

        It 'Filtra per gravita (critico)' {
            $res = @(Select-RisultatiVista -Elementi $elementiVista -Gravita 'critico')
            $res.Count | Should -Be 2
            $ids = @($res | ForEach-Object { $_.ControlId })
            $ids | Should -Contain 'HOME-FW-001'
            $ids | Should -Contain 'HOME-UAC-001'
        }

        It 'Filtra per categoria (UAC)' {
            $res = @(Select-RisultatiVista -Elementi $elementiVista -Categoria 'UAC')
            $res.Count | Should -Be 1
            $res[0].ControlId | Should -Be 'HOME-UAC-001'
        }

        It 'Cerca per testo su titolo e ID (case-insensitive)' {
            $resPerTitolo = @(Select-RisultatiVista -Elementi $elementiVista -TestoRicerca 'telemetria')
            $resPerTitolo.Count | Should -Be 1
            $resPerTitolo[0].ControlId | Should -Be 'HOME-PRV-001'

            $resPerId = @(Select-RisultatiVista -Elementi $elementiVista -TestoRicerca 'fw-001')
            $resPerId.Count | Should -Be 1
            $resPerId[0].ControlId | Should -Be 'HOME-FW-001'
        }

        It 'Combina stato + gravita + ricerca' {
            $res = @(Select-RisultatiVista -Elementi $elementiVista -Stato 'fallito' -Gravita 'critico' -TestoRicerca 'firewall')
            $res.Count | Should -Be 1
            $res[0].ControlId | Should -Be 'HOME-FW-001'
        }
    }

    Context 'Conteggi di riepilogo (Measure-ConteggiRisultati)' {

        It 'Calcola i conteggi esatti per ogni stato' {
            $conteggi = Measure-ConteggiRisultati -Elementi $risultatiTest
            $conteggi.superato        | Should -Be 1
            $conteggi.fallito         | Should -Be 2
            $conteggi.sconosciuto     | Should -Be 1
            $conteggi.non_applicabile | Should -Be 1
            $conteggi.errore          | Should -Be 0
            $conteggi.totale          | Should -Be 5
        }

        It 'Restituisce zeri su collezione vuota' {
            $conteggi = Measure-ConteggiRisultati -Elementi @()
            $conteggi.totale   | Should -Be 0
            $conteggi.superato | Should -Be 0
            $conteggi.fallito  | Should -Be 0
        }
    }

    Context 'Testo del dettaglio e gestione campi mancanti / command null (Format-DettaglioControllo)' {

        It 'Restituisce stato non selezionato quando Elemento e null' {
            $det = Format-DettaglioControllo -Elemento $null
            $det.Selezionato | Should -Be $false
            $det.HaComando   | Should -Be $false
        }

        It 'Cambia il testo attivo tra modalita Semplice e Tecnico' {
            $vista = @(ConvertTo-RisultatiVista -Risultati $risultatiTest -Catalogo $catalogoTest)
            $fw = $vista[0] # HOME-FW-001

            $semplice = Format-DettaglioControllo -Elemento $fw -Modalita 'Semplice'
            $tecnico  = Format-DettaglioControllo -Elemento $fw -Modalita 'Tecnico'

            $semplice.TestoSpiegazione | Should -Be 'Spiegazione semplice firewall.'
            $tecnico.TestoSpiegazione  | Should -Match 'Descrizione tecnica firewall\.'
            $tecnico.TestoSpiegazione  | Should -Match 'CIS 9\.1\.1'
        }

        It 'Se command e null mostra solo il testo di rimedio e imposta HaComando a false' {
            $controlloSenzaCmd = [PSCustomObject]@{
                id          = 'HOME-CUSTOM-001'
                title       = 'Controllo solo manuale'
                category    = 'Privacy'
                severity    = 'basso'
                description = 'Desc tecnica'
                rationale   = 'Desc semplice'
                remediation = [PSCustomObject]@{
                    text    = 'Apri Impostazioni -> Privacy e disattiva l opzione.'
                    command = $null
                    risk    = 'Nessun rischio.'
                }
            }
            $risultato = [PSCustomObject]@{
                control_id  = 'HOME-CUSTOM-001'
                status      = 'fallito'
                observed    = 'Attivo'
                expected    = 'Disattivo'
                evidence    = $null
                error       = $null
                duration_ms = 5
            }
            $merged = Merge-RisultatoConControllo -Risultato $risultato -ControlloCatalogo $controlloSenzaCmd
            $det = Format-DettaglioControllo -Elemento $merged

            $det.TestoRimedio   | Should -Be 'Apri Impostazioni -> Privacy e disattiva l opzione.'
            $det.ComandoRimedio | Should -BeNullOrEmpty
            $det.HaComando      | Should -Be $false
        }

        It 'Gestisce senza errori un controllo con campi mancanti (StrictMode v2)' {
            $oggettoIncompleto = [PSCustomObject]@{
                control_id = 'HOME-INCOMPLETO-999'
                status     = 'sconosciuto'
            }

            { Format-DettaglioControllo -Elemento $oggettoIncompleto -Modalita 'Semplice' } | Should -Not -Throw
            { Format-DettaglioControllo -Elemento $oggettoIncompleto -Modalita 'Tecnico' }  | Should -Not -Throw

            $det = Format-DettaglioControllo -Elemento $oggettoIncompleto
            $det.ControlId       | Should -Be 'HOME-INCOMPLETO-999'
            $det.ValoreAtteso    | Should -Be 'Non specificato'
            $det.ValoreOsservato | Should -Be 'Non disponibile'
            $det.HaComando       | Should -Be $false
        }

        It 'Non espone lo stack trace nel messaggio utente quando lo stato e errore' {
            $risultatoErrore = [PSCustomObject]@{
                control_id  = 'HOME-ERR-001'
                status      = 'errore'
                observed    = $null
                expected    = 'Valore 1'
                evidence    = $null
                error       = 'System.NullReferenceException: Object reference not set at línea 42 stacktrace...'
                duration_ms = 12
            }
            $det = Format-DettaglioControllo -Elemento $risultatoErrore

            $det.MessaggioErrore    | Should -Not -BeNullOrEmpty
            $det.MessaggioErrore    | Should -Not -Match 'NullReferenceException'
            $det.DettaglioErroreLog | Should -Match 'NullReferenceException'
        }
    }

    Context 'Nome file export predefinito (Get-NomeFileExport)' {

        It 'Genera un nome file con data e ora per json e html' {
            $dataFissa = [datetime]::new(2026, 11, 17, 14, 30, 45)
            $nomeJson = Get-NomeFileExport -Estensione 'json' -DataRiferimento $dataFissa
            $nomeHtml = Get-NomeFileExport -Estensione 'html' -DataRiferimento $dataFissa

            $nomeJson | Should -Be 'scanner_sicurezza_20261117_143045.json'
            $nomeHtml | Should -Be 'scanner_sicurezza_20261117_143045.html'
        }
    }
}

Describe 'Runner (-OnProgress / -ShouldCancel) e Report HTML' {

    BeforeAll {
        $percorsoCore = Join-Path $PSScriptRoot '..\src\core'
        . (Join-Path $percorsoCore 'Runner.ps1')
        . (Join-Path $percorsoCore 'Report.ps1')
        . (Join-Path $percorsoCore 'Checks\Registry.ps1')

        $ambienteTest = [PSCustomObject]@{
            Edition   = 'Pro'
            EditionId = 'Professional'
            Build     = '26200.1'
            Language  = 'it-IT'
            IsAdmin   = $true
            PsVersion = '5.1'
        }
    }

    It 'Invoca -OnProgress per ogni controllo e rispetta -ShouldCancel' {
        $catalogoPiccolo = [PSCustomObject]@{
            schema_version = '0.2'
            controls = @(
                [PSCustomObject]@{ id = 'HOME-A-001'; title = 'A'; editions = @('Pro'); check = [PSCustomObject]@{} }
                [PSCustomObject]@{ id = 'HOME-B-001'; title = 'B'; editions = @('Pro'); check = [PSCustomObject]@{} }
                [PSCustomObject]@{ id = 'HOME-C-001'; title = 'C'; editions = @('Pro'); check = [PSCustomObject]@{} }
            )
        }

        $passi = New-Object System.Collections.ArrayList
        $annullaDopoSecondo = $false

        $onProg = {
            param($idx, $tot, $res)
            [void]$passi.Add("${idx}/${tot}:$($res.control_id)")
            if ($idx -eq 2) {
                $script:stopFlag = $true
            }
        }

        $script:stopFlag = $false
        $shouldCancel = { return $script:stopFlag }

        $risultati = Invoke-Controlli -Catalogo $catalogoPiccolo -Ambiente $ambienteTest -CartellaChecks (Join-Path $percorsoCore 'Checks') -OnProgress $onProg -ShouldCancel $shouldCancel

        $risultati.Count | Should -Be 2
        $passi.Count     | Should -Be 2
        $passi[0]        | Should -Be '1/3:HOME-A-001'
        $passi[1]        | Should -Be '2/3:HOME-B-001'
    }

    It 'Genera un file HTML autonomo con CSS incorporato e senza risorse esterne' {
        $catalogoHtml = [PSCustomObject]@{
            schema_version = '0.2'
            controls = @(
                [PSCustomObject]@{
                    id        = 'HOME-UAC-001'
                    title     = 'UAC abilitato'
                    category  = 'UAC'
                    severity  = 'critico'
                    rationale = 'Importante per la sicurezza.'
                }
            )
        }
        $risultatiHtml = @(
            [PSCustomObject]@{ control_id = 'HOME-UAC-001'; status = 'superato'; observed = 1; expected = 1; evidence = $null; error = $null; duration_ms = 5 }
        )

        $report = New-Report -Risultati $risultatiHtml -Ambiente $ambienteTest -Catalogo $catalogoHtml
        $percorsoHtml = Join-Path $TestDrive 'report_autonomo.html'
        Export-ReportHtml -Report $report -Catalogo $catalogoHtml -PercorsoFile $percorsoHtml

        Test-Path -LiteralPath $percorsoHtml | Should -Be $true
        $contenutoHtml = Get-Content -LiteralPath $percorsoHtml -Raw -Encoding UTF8

        $contenutoHtml | Should -Match '<!DOCTYPE html>'
        $contenutoHtml | Should -Match '<style>'
        $contenutoHtml | Should -Match 'HOME-UAC-001'
        $contenutoHtml | Should -Match 'non dimostra l''assenza di compromissioni'
        $contenutoHtml | Should -Not -Match 'https?://'
    }
}

Describe 'MainWindow.xaml — Coerenza strutturale XAML' {

    It 'Il file MainWindow.xaml e XML valido e contiene tutti i controlli attesi da FindName' {
        $percorsoXaml = Join-Path $PSScriptRoot '..\src\ui\MainWindow.xaml'
        Test-Path -LiteralPath $percorsoXaml | Should -Be $true

        [xml]$xml = Get-Content -LiteralPath $percorsoXaml -Raw -Encoding UTF8
        $xml | Should -Not -BeNullOrEmpty

        $nomiRichiesti = @(
            'TxtAmbienteInfo',
            'BtnTema',
            'BannerNonAdmin',
            'BtnRiavviaAdmin',
            'BannerErrore',
            'BtnAvvia',
            'BtnAnnulla',
            'ProgressScansione',
            'TxtProgresso',
            'TxtCountSuperati',
            'TxtCountFalliti',
            'TxtCountSconosciuti',
            'TxtCountNonApplicabili',
            'TxtCountErrori',
            'CmbFiltroStato',
            'CmbFiltroGravita',
            'CmbFiltroCategoria',
            'TxtRicerca',
            'GridRisultati',
            'PanelGuidaVuota',
            'TxtDettaglioTitolo',
            'BtnModoSemplice',
            'BtnModoTecnico',
            'TxtDettaglioSpiegazione',
            'TxtDettaglioAtteso',
            'TxtDettaglioOsservato',
            'TxtDettaglioRimedio',
            'PanelComandoRimedio',
            'TxtComandoRimedio',
            'BtnCopiaComando',
            'TxtDettaglioRischi',
            'BtnSpiegaLLM',
            'BtnEsportaJson',
            'BtnEsportaHtml',
            'TxtRiepilogoFooter',
            'TxtDisclaimerPermanente'
        )

        $contenutoRaw = Get-Content -LiteralPath $percorsoXaml -Raw -Encoding UTF8
        foreach ($nome in $nomiRichiesti) {
            $contenutoRaw | Should -Match "x:Name=`"$nome`""
        }
    }
}
