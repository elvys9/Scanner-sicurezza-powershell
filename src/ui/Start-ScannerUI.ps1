<#
.SYNOPSIS
    Avvia l'interfaccia grafica WPF per lo scanner di sicurezza Windows 11.

.DESCRIPTION
    Carica il layout XAML da src/ui/MainWindow.xaml tramite XamlReader,
    collega i controlli con FindName, gestisce il tema chiaro/scuro,
    i filtri, il pannello di dettaglio, l'export JSON/HTML e l'esecuzione
    asincrona della scansione in un Runspace separato con aggiornamento
    tramite Dispatcher.
    Il codice e' in SOLA LETTURA e riusa esattamente il motore di src/core.
#>

Set-StrictMode -Version 2

function Update-TemaFinestra {
    <#
    .SYNOPSIS
        Applica il dizionario di colori del tema Chiaro o Scuro alle risorse della finestra.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Finestra,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Chiaro', 'Scuro')]
        [string]$Tema
    )

    $convertitore = New-Object System.Windows.Media.BrushConverter

    if ($Tema -eq 'Scuro') {
        $mappaColori = @{
            'BgPrimary'        = '#0F172A'
            'BgSurface'        = '#1E293B'
            'BgHeader'         = '#020617'
            'TextHeader'       = '#F8FAFC'
            'BgSubtle'         = '#0F172A'
            'TextPrimary'      = '#F1F5F9'
            'TextSecondary'    = '#94A3B8'
            'BorderSubtle'     = '#334155'
            'AccentBrush'      = '#3B82F6'
            'AccentText'       = '#FFFFFF'
            'PassBg'           = '#064E3B'
            'PassFg'           = '#A7F3D0'
            'PassBorder'       = '#059669'
            'FailBg'           = '#7F1D1D'
            'FailFg'           = '#FECACA'
            'FailBorder'       = '#DC2626'
            'UnknownBg'        = '#334155'
            'UnknownFg'        = '#E2E8F0'
            'UnknownBorder'    = '#64748B'
            'NaBg'             = '#1E293B'
            'NaFg'             = '#94A3B8'
            'NaBorder'         = '#475569'
            'ErrorBg'          = '#7C2D12'
            'ErrorFg'          = '#FED7AA'
            'ErrorBorder'      = '#EA580C'
            'WarnBannerBg'     = '#78350F'
            'WarnBannerFg'     = '#FEF3C7'
            'WarnBannerBorder' = '#D97706'
        }
    }
    else {
        $mappaColori = @{
            'BgPrimary'        = '#F4F6F9'
            'BgSurface'        = '#FFFFFF'
            'BgHeader'         = '#0F172A'
            'TextHeader'       = '#F8FAFC'
            'BgSubtle'         = '#F8FAFC'
            'TextPrimary'      = '#1E293B'
            'TextSecondary'    = '#475569'
            'BorderSubtle'     = '#CBD5E1'
            'AccentBrush'      = '#2563EB'
            'AccentText'       = '#FFFFFF'
            'PassBg'           = '#DCFCE7'
            'PassFg'           = '#166534'
            'PassBorder'       = '#86EFAC'
            'FailBg'           = '#FEE2E2'
            'FailFg'           = '#991B1B'
            'FailBorder'       = '#FCA5A5'
            'UnknownBg'        = '#E2E8F0'
            'UnknownFg'        = '#334155'
            'UnknownBorder'    = '#94A3B8'
            'NaBg'             = '#F1F5F9'
            'NaFg'             = '#475569'
            'NaBorder'         = '#CBD5E1'
            'ErrorBg'          = '#FFEDD5'
            'ErrorFg'          = '#9A3412'
            'ErrorBorder'      = '#FDBA74'
            'WarnBannerBg'     = '#FEF3C7'
            'WarnBannerFg'     = '#92400E'
            'WarnBannerBorder' = '#F59E0B'
        }
    }

    foreach ($chiave in $mappaColori.Keys) {
        $pennello = $convertitore.ConvertFromString($mappaColori[$chiave])
        $Finestra.Resources[$chiave] = $pennello
    }
}

function Start-ScannerUI {
    <#
    .SYNOPSIS
        Costruisce e mostra la finestra WPF dello scanner di sicurezza.
    .PARAMETER Catalogo
        Oggetto catalogo caricato da Import-Catalogo.
    .PARAMETER Ambiente
        Oggetto ambiente rilevato da Get-AmbienteSistema.
    .PARAMETER PercorsoProgetto
        Percorso radice del repository (opzionale in modalita' standalone singolo file).
    .PARAMETER ContenutoXaml
        Stringa XAML opzionale (usata nella versione compilata in singolo file in stile winutil).
    .PARAMETER ControlId
        Filtro opzionale di ID di controllo passato da riga di comando.
    .PARAMETER VersioneTool
        Versione dello scanner (es. '0.1.0').
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Catalogo,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Ambiente,

        [Parameter(Mandatory = $false)]
        [string]$PercorsoProgetto = '',

        [Parameter(Mandatory = $false)]
        [string]$ContenutoXaml = '',

        [Parameter(Mandatory = $false)]
        [string[]]$ControlId = @(),

        [Parameter(Mandatory = $false)]
        [string]$VersioneTool = '0.1.0'
    )

    # Verifica che il thread corrente sia STA (obbligatorio per WPF)
    if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne [System.Threading.ApartmentState]::STA) {
        throw "La modalita' grafica WPF richiede un thread STA (avviare PowerShell con -STA)."
    }

    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase

    $percorsoUi     = if ($PercorsoProgetto) { Join-Path $PercorsoProgetto 'src\ui' } else { '' }
    $percorsoCore   = if ($PercorsoProgetto) { Join-Path $PercorsoProgetto 'src\core' } else { '' }
    $percorsoChecks = if ($percorsoCore) { Join-Path $percorsoCore 'Checks' } else { '' }

    if ([string]::IsNullOrWhiteSpace($ContenutoXaml)) {
        $percorsoXaml = Join-Path $percorsoUi 'MainWindow.xaml'
        if (-not (Test-Path -LiteralPath $percorsoXaml)) {
            throw "File XAML dell'interfaccia non trovato: $percorsoXaml"
        }
        $ContenutoXaml = Get-Content -LiteralPath $percorsoXaml -Raw -Encoding UTF8
    }

    # Carica il contenuto XAML con XamlReader
    [xml]$xmlXaml = $ContenutoXaml
    $lettoreXml = New-Object System.Xml.XmlNodeReader($xmlXaml)
    $finestra = [System.Windows.Markup.XamlReader]::Load($lettoreXml)

    # Riferimenti ai controlli tramite FindName
    $ctrl = @{
        TxtAmbienteInfo        = $finestra.FindName('TxtAmbienteInfo')
        BtnTema                = $finestra.FindName('BtnTema')
        BannerNonAdmin         = $finestra.FindName('BannerNonAdmin')
        BtnRiavviaAdmin        = $finestra.FindName('BtnRiavviaAdmin')
        BannerErrore           = $finestra.FindName('BannerErrore')
        TxtBannerErrore        = $finestra.FindName('TxtBannerErrore')
        BtnAvvia               = $finestra.FindName('BtnAvvia')
        BtnAnnulla             = $finestra.FindName('BtnAnnulla')
        ProgressScansione      = $finestra.FindName('ProgressScansione')
        TxtProgresso           = $finestra.FindName('TxtProgresso')
        TxtCountSuperati       = $finestra.FindName('TxtCountSuperati')
        TxtCountFalliti        = $finestra.FindName('TxtCountFalliti')
        TxtCountSconosciuti    = $finestra.FindName('TxtCountSconosciuti')
        TxtCountNonApplicabili = $finestra.FindName('TxtCountNonApplicabili')
        TxtCountErrori         = $finestra.FindName('TxtCountErrori')
        CmbFiltroStato         = $finestra.FindName('CmbFiltroStato')
        CmbFiltroGravita       = $finestra.FindName('CmbFiltroGravita')
        CmbFiltroCategoria     = $finestra.FindName('CmbFiltroCategoria')
        TxtRicerca             = $finestra.FindName('TxtRicerca')
        BtnResetFiltri         = $finestra.FindName('BtnResetFiltri')
        GridRisultati          = $finestra.FindName('GridRisultati')
        PanelGuidaVuota        = $finestra.FindName('PanelGuidaVuota')
        TxtMessaggioGuida      = $finestra.FindName('TxtMessaggioGuida')
        TxtDettaglioTitolo     = $finestra.FindName('TxtDettaglioTitolo')
        TxtDettaglioSottotitolo= $finestra.FindName('TxtDettaglioSottotitolo')
        BtnModoSemplice        = $finestra.FindName('BtnModoSemplice')
        BtnModoTecnico         = $finestra.FindName('BtnModoTecnico')
        TxtTitoloSpiegazione   = $finestra.FindName('TxtTitoloSpiegazione')
        TxtDettaglioSpiegazione= $finestra.FindName('TxtDettaglioSpiegazione')
        BannerDettaglioErrore  = $finestra.FindName('BannerDettaglioErrore')
        TxtDettaglioErrore     = $finestra.FindName('TxtDettaglioErrore')
        TxtDettaglioAtteso     = $finestra.FindName('TxtDettaglioAtteso')
        TxtDettaglioOsservato  = $finestra.FindName('TxtDettaglioOsservato')
        TxtDettaglioRimedio    = $finestra.FindName('TxtDettaglioRimedio')
        PanelComandoRimedio    = $finestra.FindName('PanelComandoRimedio')
        TxtComandoRimedio      = $finestra.FindName('TxtComandoRimedio')
        BtnCopiaComando        = $finestra.FindName('BtnCopiaComando')
        TxtFeedbackCopia       = $finestra.FindName('TxtFeedbackCopia')
        TxtDettaglioRischi     = $finestra.FindName('TxtDettaglioRischi')
        BtnSpiegaLLM           = $finestra.FindName('BtnSpiegaLLM')
        BtnEsportaJson         = $finestra.FindName('BtnEsportaJson')
        BtnEsportaHtml         = $finestra.FindName('BtnEsportaHtml')
        ChkSalvaLogTecnico     = $finestra.FindName('ChkSalvaLogTecnico')
        TxtRiepilogoFooter     = $finestra.FindName('TxtRiepilogoFooter')
    }

    # Stato interno dell'interfaccia
    $totaleControlli = @($Catalogo.controls).Count
    $statoUI = @{
        TemaCorrente        = 'Chiaro'
        ModalitaDettaglio   = 'Semplice'
        RisultatiGrezzi     = @()
        ElementiVista       = @()
        ElementoSelezionato = $null
        ScansioneInCorso    = $false
        SyncRunspace        = $null
        PsInstance          = $null
        Runspace            = $null
    }

    # Popola informazioni ambiente nell'intestazione
    $testoAdmin = if ($Ambiente.IsAdmin) { 'Si' } else { 'No' }
    $ctrl.TxtAmbienteInfo.Text = "Windows 11 $($Ambiente.Edition) $($Ambiente.Build) | Admin: $testoAdmin"
    $ctrl.ProgressScansione.Maximum = if ($totaleControlli -gt 0) { $totaleControlli } else { 1 }
    $ctrl.TxtProgresso.Text = "Pronto (0/$totaleControlli)"

    # Banner giallo se non avviato come amministratore
    if (-not $Ambiente.IsAdmin) {
        $ctrl.BannerNonAdmin.Visibility = [System.Windows.Visibility]::Visible
    }

    # Popola le categorie nel filtro Categoria
    $categorieUniche = @()
    foreach ($c in $Catalogo.controls) {
        if ($null -ne $c.PSObject.Properties['category'] -and $c.category) {
            if ($categorieUniche -notcontains $c.category) {
                $categorieUniche += $c.category
            }
        }
    }
    foreach ($cat in ($categorieUniche | Sort-Object)) {
        $itemCat = New-Object System.Windows.Controls.ComboBoxItem
        $itemCat.Content = $cat
        [void]$ctrl.CmbFiltroCategoria.Items.Add($itemCat)
    }

    # --- Funzioni di aggiornamento UI ---
    $aggiornaPannelloDettaglio = {
        $dettaglio = Format-DettaglioControllo -Elemento $statoUI.ElementoSelezionato -Modalita $statoUI.ModalitaDettaglio
        $ctrl.TxtDettaglioTitolo.Text = $dettaglio.Title
        $ctrl.TxtDettaglioSottotitolo.Text = "ID: $($dettaglio.ControlId)  |  Stato: $($dettaglio.StatusLabel)  |  Gravita': $($dettaglio.SeverityLabel)  |  Categoria: $($dettaglio.Category)"

        if ($statoUI.ModalitaDettaglio -eq 'Tecnico') {
            $ctrl.TxtTitoloSpiegazione.Text = "Dettaglio tecnico e riferimenti"
            $ctrl.BtnModoTecnico.FontWeight = [System.Windows.FontWeights]::Bold
            $ctrl.BtnModoSemplice.FontWeight = [System.Windows.FontWeights]::Normal
        }
        else {
            $ctrl.TxtTitoloSpiegazione.Text = "Perche' conta (spiegazione semplice)"
            $ctrl.BtnModoSemplice.FontWeight = [System.Windows.FontWeights]::Bold
            $ctrl.BtnModoTecnico.FontWeight = [System.Windows.FontWeights]::Normal
        }

        $ctrl.TxtDettaglioSpiegazione.Text = $dettaglio.TestoSpiegazione
        $ctrl.TxtDettaglioAtteso.Text      = $dettaglio.ValoreAtteso
        $ctrl.TxtDettaglioOsservato.Text   = $dettaglio.ValoreOsservato
        $ctrl.TxtDettaglioRimedio.Text     = $dettaglio.TestoRimedio
        $ctrl.TxtDettaglioRischi.Text      = $dettaglio.NoteRischi
        $ctrl.TxtFeedbackCopia.Visibility  = [System.Windows.Visibility]::Collapsed

        if ($null -ne $dettaglio.MessaggioErrore) {
            $ctrl.TxtDettaglioErrore.Text = $dettaglio.MessaggioErrore
            $ctrl.BannerDettaglioErrore.Visibility = [System.Windows.Visibility]::Visible
        }
        else {
            $ctrl.BannerDettaglioErrore.Visibility = [System.Windows.Visibility]::Collapsed
        }

        if ($dettaglio.HaComando) {
            $ctrl.TxtComandoRimedio.Text = $dettaglio.ComandoRimedio
            $ctrl.PanelComandoRimedio.Visibility = [System.Windows.Visibility]::Visible
        }
        else {
            $ctrl.TxtComandoRimedio.Text = ''
            $ctrl.PanelComandoRimedio.Visibility = [System.Windows.Visibility]::Collapsed
        }
    }

    $aggiornaConteggiERiepilogo = {
        $conteggi = Measure-ConteggiRisultati -Elementi $statoUI.RisultatiGrezzi
        $ctrl.TxtCountSuperati.Text       = "[OK] $($conteggi.superato) Superati"
        $ctrl.TxtCountFalliti.Text        = "[X] $($conteggi.fallito) Falliti"
        $ctrl.TxtCountSconosciuti.Text    = "[?] $($conteggi.sconosciuto) Sconosciuti"
        $ctrl.TxtCountNonApplicabili.Text = "[-] $($conteggi.non_applicabile) Non applicabili"
        $ctrl.TxtCountErrori.Text         = "[!] $($conteggi.errore) Errori"

        $ctrl.TxtRiepilogoFooter.Text = "Riepilogo calcolato dal codice: $($conteggi.totale) controlli valutati ($($conteggi.superato) superati, $($conteggi.fallito) falliti, $($conteggi.sconosciuto) sconosciuti)"

        if ($conteggi.errore -gt 0) {
            $ctrl.TxtBannerErrore.Text = "Alcuni controlli ($($conteggi.errore)) hanno restituito un imprevisto durante la lettura. Seleziona il controllo per maggiori informazioni o esporta il log tecnico."
            $ctrl.BannerErrore.Visibility = [System.Windows.Visibility]::Visible
        }
        else {
            $ctrl.BannerErrore.Visibility = [System.Windows.Visibility]::Collapsed
        }
    }

    $applicaFiltriTabella = {
        $statoSel = if ($null -ne $ctrl.CmbFiltroStato.SelectedItem) { [string]$ctrl.CmbFiltroStato.SelectedItem.Content } else { 'Tutti' }
        $gravSel  = if ($null -ne $ctrl.CmbFiltroGravita.SelectedItem) { [string]$ctrl.CmbFiltroGravita.SelectedItem.Content } else { 'Tutte' }
        $catSel   = if ($null -ne $ctrl.CmbFiltroCategoria.SelectedItem) { [string]$ctrl.CmbFiltroCategoria.SelectedItem.Content } else { 'Tutte' }
        $ricerca  = $ctrl.TxtRicerca.Text

        $filtrati = @(Select-RisultatiVista -Elementi $statoUI.ElementiVista -Stato $statoSel -Gravita $gravSel -Categoria $catSel -TestoRicerca $ricerca)

        $idPrecedente = if ($null -ne $statoUI.ElementoSelezionato) { $statoUI.ElementoSelezionato.ControlId } else { $null }
        $ctrl.GridRisultati.ItemsSource = $filtrati

        if ($statoUI.ElementiVista.Count -eq 0) {
            $ctrl.PanelGuidaVuota.Visibility = [System.Windows.Visibility]::Visible
        }
        elseif ($filtrati.Count -eq 0) {
            $ctrl.TxtMessaggioGuida.Text = "Nessun controllo corrisponde ai filtri selezionati."
            $ctrl.PanelGuidaVuota.Visibility = [System.Windows.Visibility]::Visible
        }
        else {
            $ctrl.PanelGuidaVuota.Visibility = [System.Windows.Visibility]::Collapsed
            if ($null -ne $idPrecedente) {
                foreach ($item in $filtrati) {
                    if ($item.ControlId -eq $idPrecedente) {
                        $ctrl.GridRisultati.SelectedItem = $item
                        break
                    }
                }
            }
            if ($null -eq $ctrl.GridRisultati.SelectedItem -and $filtrati.Count -gt 0 -and (-not $statoUI.ScansioneInCorso)) {
                $ctrl.GridRisultati.SelectedIndex = 0
            }
        }
    }

    # --- Eventi Tema ---
    $ctrl.BtnTema.Add_Click({
        if ($statoUI.TemaCorrente -eq 'Chiaro') {
            $statoUI.TemaCorrente = 'Scuro'
            Update-TemaFinestra -Finestra $finestra -Tema 'Scuro'
            $ctrl.BtnTema.Content = 'Tema: Chiaro'
        }
        else {
            $statoUI.TemaCorrente = 'Chiaro'
            Update-TemaFinestra -Finestra $finestra -Tema 'Chiaro'
            $ctrl.BtnTema.Content = 'Tema: Scuro'
        }
    })

    # --- Evento Riavvia come Amministratore ---
    $ctrl.BtnRiavviaAdmin.Add_Click({
        try {
            $percorsoEntry = if ($PercorsoProgetto -and (Test-Path -LiteralPath (Join-Path $PercorsoProgetto 'src\Invoke-Scanner.ps1'))) {
                Join-Path $PercorsoProgetto 'src\Invoke-Scanner.ps1'
            }
            elseif (Get-Variable -Name 'PercorsoScriptAutonomo' -Scope Script -ErrorAction SilentlyContinue) {
                $script:PercorsoScriptAutonomo
            }
            else {
                ''
            }

            if (-not [string]::IsNullOrWhiteSpace($percorsoEntry) -and (Test-Path -LiteralPath $percorsoEntry)) {
                $argomenti = "-NoProfile -ExecutionPolicy Bypass -STA -File `"$percorsoEntry`" -Gui"
                if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
                    $argomenti += " -ControlId $($ControlId -join ',')"
                }
                Start-Process -FilePath 'powershell.exe' -ArgumentList $argomenti -Verb RunAs
                $finestra.Close()
            }
            elseif (Get-Variable -Name 'UrlScriptRemoto' -Scope Script -ErrorAction SilentlyContinue) {
                $argomentiRemoti = "-NoProfile -ExecutionPolicy Bypass -STA -Command `"irm '$($script:UrlScriptRemoto)' | iex`""
                Start-Process -FilePath 'powershell.exe' -ArgumentList $argomentiRemoti -Verb RunAs
                $finestra.Close()
            }
            else {
                [System.Windows.MessageBox]::Show(
                    "Avviato da memoria remota: apri una nuova finestra di PowerShell come Amministratore e riesegui il comando.",
                    "Scanner sicurezza Windows",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Information
                ) | Out-Null
            }
        }
        catch {
            [System.Windows.MessageBox]::Show(
                "Riavvio come amministratore annullato o non riuscito.",
                "Scanner sicurezza Windows",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            ) | Out-Null
        }
    })

    # --- Eventi Filtri ---
    $ctrl.CmbFiltroStato.Add_SelectionChanged({ & $applicaFiltriTabella })
    $ctrl.CmbFiltroGravita.Add_SelectionChanged({ & $applicaFiltriTabella })
    $ctrl.CmbFiltroCategoria.Add_SelectionChanged({ & $applicaFiltriTabella })
    $ctrl.TxtRicerca.Add_TextChanged({ & $applicaFiltriTabella })

    $ctrl.BtnResetFiltri.Add_Click({
        $ctrl.CmbFiltroStato.SelectedIndex = 0
        $ctrl.CmbFiltroGravita.SelectedIndex = 0
        $ctrl.CmbFiltroCategoria.SelectedIndex = 0
        $ctrl.TxtRicerca.Text = ''
        & $applicaFiltriTabella
    })

    # --- Selezione riga nella tabella ---
    $ctrl.GridRisultati.Add_SelectionChanged({
        $statoUI.ElementoSelezionato = $ctrl.GridRisultati.SelectedItem
        & $aggiornaPannelloDettaglio
    })

    # --- Selettore Semplice / Tecnico ---
    $ctrl.BtnModoSemplice.Add_Click({
        $statoUI.ModalitaDettaglio = 'Semplice'
        & $aggiornaPannelloDettaglio
    })

    $ctrl.BtnModoTecnico.Add_Click({
        $statoUI.ModalitaDettaglio = 'Tecnico'
        & $aggiornaPannelloDettaglio
    })

    # --- Copia comando negli appunti ---
    $ctrl.BtnCopiaComando.Add_Click({
        $cmd = $ctrl.TxtComandoRimedio.Text
        if (-not [string]::IsNullOrWhiteSpace($cmd)) {
            [System.Windows.Clipboard]::SetText($cmd)
            $ctrl.TxtFeedbackCopia.Visibility = [System.Windows.Visibility]::Visible
        }
    })

    # --- Avvia scansione in Runspace separato ---
    $ctrl.BtnAvvia.Add_Click({
        if ($statoUI.ScansioneInCorso) { return }

        $statoUI.ScansioneInCorso    = $true
        $statoUI.RisultatiGrezzi     = @()
        $statoUI.ElementiVista       = @()
        $statoUI.ElementoSelezionato = $null

        $ctrl.BtnAvvia.IsEnabled        = $false
        $ctrl.BtnAnnulla.IsEnabled      = $true
        $ctrl.BtnEsportaJson.IsEnabled  = $false
        $ctrl.BtnEsportaHtml.IsEnabled  = $false
        $ctrl.BannerErrore.Visibility   = [System.Windows.Visibility]::Collapsed
        $ctrl.ProgressScansione.Value   = 0
        $ctrl.TxtProgresso.Text         = "Avvio scansione..."
        $ctrl.TxtMessaggioGuida.Text    = "Scansione in corso... I risultati compariranno man mano."
        $ctrl.PanelGuidaVuota.Visibility = [System.Windows.Visibility]::Visible
        $ctrl.GridRisultati.ItemsSource = @()
        & $aggiornaConteggiERiepilogo
        & $aggiornaPannelloDettaglio

        # Callback invocato sul thread UI tramite Dispatcher per ogni controllo completato
        $callbackProgresso = [Action[int, int, object]]{
            param([int]$Indice, [int]$Totale, [object]$RisultatoSingolo)

            $statoUI.RisultatiGrezzi += $RisultatoSingolo
            $statoUI.ElementiVista = @(ConvertTo-RisultatiVista -Risultati $statoUI.RisultatiGrezzi -Catalogo $Catalogo)

            $ctrl.ProgressScansione.Maximum = if ($Totale -gt 0) { $Totale } else { 1 }
            $ctrl.ProgressScansione.Value   = $Indice
            $ctrl.TxtProgresso.Text         = "Avanzamento: $Indice/$Totale"

            & $aggiornaConteggiERiepilogo
            & $applicaFiltriTabella
        }

        # Callback invocato sul thread UI al termine (o annullamento) della scansione
        $callbackFine = [Action]{
            $statoUI.ScansioneInCorso   = $false
            $ctrl.BtnAvvia.IsEnabled    = $true
            $ctrl.BtnAnnulla.IsEnabled  = $false

            $nValutati = $statoUI.RisultatiGrezzi.Count
            if ($nValutati -gt 0) {
                $ctrl.BtnEsportaJson.IsEnabled = $true
                $ctrl.BtnEsportaHtml.IsEnabled = $true
            }

            if ($null -ne $statoUI.SyncRunspace -and $statoUI.SyncRunspace.ErroreFatale) {
                $ctrl.TxtBannerErrore.Text = "Si e' verificato un problema durante l'esecuzione della scansione. Riprova o esporta il log tecnico."
                $ctrl.BannerErrore.Visibility = [System.Windows.Visibility]::Visible
                $ctrl.TxtProgresso.Text = "Interrotto per errore ($nValutati/$totaleControlli)"
            }
            elseif ($null -ne $statoUI.SyncRunspace -and $statoUI.SyncRunspace.AnnullaRichiesto) {
                $ctrl.TxtProgresso.Text = "Annullata ($nValutati/$totaleControlli)"
                if ($nValutati -eq 0) {
                    $ctrl.TxtMessaggioGuida.Text = "Scansione annullata. Premi 'Avvia scansione' per riprovare."
                }
            }
            else {
                $ctrl.TxtProgresso.Text = "Completata ($nValutati/$nValutati)"
            }

            & $aggiornaConteggiERiepilogo
            & $applicaFiltriTabella

            # Pulizia risorse Runspace
            if ($null -ne $statoUI.PsInstance) {
                $statoUI.PsInstance.Dispose()
                $statoUI.PsInstance = $null
            }
            if ($null -ne $statoUI.Runspace) {
                $statoUI.Runspace.Close()
                $statoUI.Runspace.Dispose()
                $statoUI.Runspace = $null
            }
        }

        # Stato condiviso sincronizzato con il Runspace
        $sync = [hashtable]::Synchronized(@{
            Finestra            = $finestra
            Catalogo            = $Catalogo
            Ambiente            = $Ambiente
            PercorsoCore        = $percorsoCore
            PercorsoChecks      = $percorsoChecks
            ControlId           = $ControlId
            AnnullaRichiesto    = $false
            ErroreFatale        = $null
            CallbackProgressoUI = $callbackProgresso
            CallbackFineUI      = $callbackFine
        })
        $statoUI.SyncRunspace = $sync

        # Prepara InitialSessionState con le funzioni del motore gia' caricate in memoria
        # (consente l'esecuzione anche da singolo file autonomo senza cartella src/)
        $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $funzioniDaPassare = @(Get-ChildItem Function:\Invoke-Controlli, Function:\Test-* -ErrorAction SilentlyContinue)
        foreach ($fn in $funzioniDaPassare) {
            $entryFn = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fn.Name, $fn.Definition)
            [void]$iss.Commands.Add($entryFn)
        }

        # Crea e avvia il Runspace separato
        $runspace = [runspacefactory]::CreateRunspace($iss)
        $runspace.ApartmentState = 'STA'
        $runspace.ThreadOptions  = 'ReuseThread'
        $runspace.Open()
        $runspace.SessionStateProxy.SetVariable('Sync', $sync)

        $ps = [powershell]::Create()
        $ps.Runspace = $runspace

        [void]$ps.AddScript({
            Set-StrictMode -Version 2
            $ErrorActionPreference = 'Stop'

            try {
                if (-not [string]::IsNullOrWhiteSpace($Sync.PercorsoCore) -and (Test-Path -LiteralPath $Sync.PercorsoCore)) {
                    . (Join-Path $Sync.PercorsoCore 'Catalog.ps1')
                    . (Join-Path $Sync.PercorsoCore 'Runner.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'Registry.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'Firewall.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'Accounts.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'Defender.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'Network.ps1')
                    . (Join-Path $Sync.PercorsoChecks 'SystemSecurity.ps1')
                }

                $onProgressBlock = {
                    param($idx, $tot, $res)
                    [void]$Sync.Finestra.Dispatcher.Invoke(
                        [System.Windows.Threading.DispatcherPriority]::Background,
                        $Sync.CallbackProgressoUI,
                        $idx,
                        $tot,
                        $res
                    )
                }

                $shouldCancelBlock = {
                    return [bool]$Sync.AnnullaRichiesto
                }

                $parametri = @{
                    Catalogo       = $Sync.Catalogo
                    Ambiente       = $Sync.Ambiente
                    CartellaChecks = $Sync.PercorsoChecks
                    OnProgress     = $onProgressBlock
                    ShouldCancel   = $shouldCancelBlock
                }
                if ($null -ne $Sync.ControlId -and $Sync.ControlId.Count -gt 0) {
                    $parametri['ControlId'] = $Sync.ControlId
                }

                [void](Invoke-Controlli @parametri)
            }
            catch {
                $Sync.ErroreFatale = $_.Exception.Message
            }
            finally {
                [void]$Sync.Finestra.Dispatcher.BeginInvoke(
                    [System.Windows.Threading.DispatcherPriority]::Normal,
                    $Sync.CallbackFineUI
                )
            }
        })

        $statoUI.Runspace   = $runspace
        $statoUI.PsInstance = $ps
        [void]$ps.BeginInvoke()
    })

    # --- Pulsante Annulla ---
    $ctrl.BtnAnnulla.Add_Click({
        if ($statoUI.ScansioneInCorso -and $null -ne $statoUI.SyncRunspace) {
            $statoUI.SyncRunspace.AnnullaRichiesto = $true
            $ctrl.BtnAnnulla.IsEnabled = $false
            $ctrl.TxtProgresso.Text = "Annullamento in corso..."
        }
    })

    # --- Export JSON ---
    $ctrl.BtnEsportaJson.Add_Click({
        if ($statoUI.RisultatiGrezzi.Count -eq 0) { return }

        $dialogo = New-Object Microsoft.Win32.SaveFileDialog
        $dialogo.Title      = "Esporta report JSON"
        $dialogo.Filter     = "File JSON (*.json)|*.json"
        $dialogo.FileName   = (Get-NomeFileExport -Estensione 'json')
        $dialogo.DefaultExt = ".json"

        $esito = $dialogo.ShowDialog($finestra)
        if ($esito -eq $true) {
            $report = New-Report -Risultati $statoUI.RisultatiGrezzi -Ambiente $Ambiente -Catalogo $Catalogo -VersioneTool $VersioneTool
            Export-ReportJson -Report $report -PercorsoFile $dialogo.FileName

            if ($ctrl.ChkSalvaLogTecnico.IsChecked -eq $true) {
                $percorsoLog = "$($dialogo.FileName).errori.log"
                Export-TechnicalLog -Report $report -PercorsoFile $percorsoLog
            }

            $ctrl.TxtRiepilogoFooter.Text = "Esportato JSON: $(Split-Path -Leaf $dialogo.FileName)"
        }
    })

    # --- Export HTML ---
    $ctrl.BtnEsportaHtml.Add_Click({
        if ($statoUI.RisultatiGrezzi.Count -eq 0) { return }

        $dialogo = New-Object Microsoft.Win32.SaveFileDialog
        $dialogo.Title      = "Esporta report HTML"
        $dialogo.Filter     = "Pagina HTML (*.html)|*.html"
        $dialogo.FileName   = (Get-NomeFileExport -Estensione 'html')
        $dialogo.DefaultExt = ".html"

        $esito = $dialogo.ShowDialog($finestra)
        if ($esito -eq $true) {
            $report = New-Report -Risultati $statoUI.RisultatiGrezzi -Ambiente $Ambiente -Catalogo $Catalogo -VersioneTool $VersioneTool
            Export-ReportHtml -Report $report -Catalogo $Catalogo -PercorsoFile $dialogo.FileName

            if ($ctrl.ChkSalvaLogTecnico.IsChecked -eq $true) {
                $percorsoLog = "$($dialogo.FileName).errori.log"
                Export-TechnicalLog -Report $report -PercorsoFile $percorsoLog
            }

            $ctrl.TxtRiepilogoFooter.Text = "Esportato HTML: $(Split-Path -Leaf $dialogo.FileName)"
        }
    })

    # --- Chiusura pulita della finestra ---
    $finestra.Add_Closing({
        if ($statoUI.ScansioneInCorso -and $null -ne $statoUI.SyncRunspace) {
            $statoUI.SyncRunspace.AnnullaRichiesto = $true
        }
        if ($null -ne $statoUI.PsInstance) {
            $statoUI.PsInstance.Dispose()
            $statoUI.PsInstance = $null
        }
        if ($null -ne $statoUI.Runspace) {
            $statoUI.Runspace.Close()
            $statoUI.Runspace.Dispose()
            $statoUI.Runspace = $null
        }
    })

    # Inizializza pannello dettaglio vuoto
    & $aggiornaPannelloDettaglio

    # Mostra la finestra modale
    [void]$finestra.ShowDialog()
}
