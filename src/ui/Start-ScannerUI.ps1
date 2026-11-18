<#
.SYNOPSIS
    Avvia l'interfaccia grafica WPF per lo scanner di sicurezza Windows 11.

.DESCRIPTION
    Carica il layout XAML da src/ui/MainWindow.xaml tramite XamlReader,
    collega i controlli con FindName, gestisce il tema chiaro/scuro,
    la localizzazione completa bilingue (IT/EN), i filtri, il pannello
    di dettaglio, l'export JSON/HTML e l'esecuzione asincrona della
    scansione e dell'assistente IA Ollama in Runspace separati.
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
            'BgPrimary'        = '#0B0F19'
            'BgSurface'        = '#131C2E'
            'BgHeader'         = '#060913'
            'TextHeader'       = '#F8FAFC'
            'BgSubtle'         = '#0F172A'
            'TextPrimary'      = '#F1F5F9'
            'TextSecondary'    = '#94A3B8'
            'BorderSubtle'     = '#1E293B'
            'AccentBrush'      = '#3B82F6'
            'AccentText'       = '#FFFFFF'
            'PassBg'           = '#064E3B'
            'PassFg'           = '#6EE7B7'
            'PassBorder'       = '#10B981'
            'FailBg'           = '#7F1D1D'
            'FailFg'           = '#FCA5A5'
            'FailBorder'       = '#EF4444'
            'UnknownBg'        = '#1E293B'
            'UnknownFg'        = '#CBD5E1'
            'UnknownBorder'    = '#64748B'
            'NaBg'             = '#0F172A'
            'NaFg'             = '#94A3B8'
            'NaBorder'         = '#475569'
            'ErrorBg'          = '#7C2D12'
            'ErrorFg'          = '#FDBA74'
            'ErrorBorder'      = '#F97316'
            'WarnBannerBg'     = '#451A03'
            'WarnBannerFg'     = '#FDE68A'
            'WarnBannerBorder' = '#D97706'
        }
    }
    else {
        $mappaColori = @{
            'BgPrimary'        = '#F1F5F9'
            'BgSurface'        = '#FFFFFF'
            'BgHeader'         = '#0B1120'
            'TextHeader'       = '#F8FAFC'
            'BgSubtle'         = '#F8FAFC'
            'TextPrimary'      = '#0F172A'
            'TextSecondary'    = '#475569'
            'BorderSubtle'     = '#E2E8F0'
            'AccentBrush'      = '#2563EB'
            'AccentText'       = '#FFFFFF'
            'PassBg'           = '#ECFDF5'
            'PassFg'           = '#065F46'
            'PassBorder'       = '#10B981'
            'FailBg'           = '#FEF2F2'
            'FailFg'           = '#991B1B'
            'FailBorder'       = '#EF4444'
            'UnknownBg'        = '#F1F5F9'
            'UnknownFg'        = '#334155'
            'UnknownBorder'    = '#64748B'
            'NaBg'             = '#F8FAFC'
            'NaFg'             = '#64748B'
            'NaBorder'         = '#94A3B8'
            'ErrorBg'          = '#FFF7ED'
            'ErrorFg'          = '#9A3412'
            'ErrorBorder'      = '#F97316'
            'WarnBannerBg'     = '#FFFBEB'
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
        [string]$VersioneTool = '0.1.0',

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN')]
        [string]$LinguaIniziale = 'IT'
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
        TxtTitoloApp           = $finestra.FindName('TxtTitoloApp')
        TxtBadgeSolaLettura    = $finestra.FindName('TxtBadgeSolaLettura')
        TxtSottotitoloApp      = $finestra.FindName('TxtSottotitoloApp')
        TxtAmbienteInfo        = $finestra.FindName('TxtAmbienteInfo')
        BtnLingua              = $finestra.FindName('BtnLingua')
        BtnTema                = $finestra.FindName('BtnTema')
        BannerNonAdmin         = $finestra.FindName('BannerNonAdmin')
        TxtBannerNonAdmin      = $finestra.FindName('TxtBannerNonAdmin')
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
        LblFiltroStato         = $finestra.FindName('LblFiltroStato')
        LblFiltroGravita       = $finestra.FindName('LblFiltroGravita')
        LblFiltroCategoria     = $finestra.FindName('LblFiltroCategoria')
        LblFiltroCerca         = $finestra.FindName('LblFiltroCerca')
        CmbFiltroStato         = $finestra.FindName('CmbFiltroStato')
        CmbFiltroGravita       = $finestra.FindName('CmbFiltroGravita')
        CmbFiltroCategoria     = $finestra.FindName('CmbFiltroCategoria')
        TxtRicerca             = $finestra.FindName('TxtRicerca')
        BtnResetFiltri         = $finestra.FindName('BtnResetFiltri')
        GridRisultati          = $finestra.FindName('GridRisultati')
        ColStato               = $finestra.FindName('ColStato')
        ColGravita             = $finestra.FindName('ColGravita')
        ColCategoria           = $finestra.FindName('ColCategoria')
        ColId                  = $finestra.FindName('ColId')
        ColControllo           = $finestra.FindName('ColControllo')
        PanelGuidaVuota        = $finestra.FindName('PanelGuidaVuota')
        TxtMessaggioGuida      = $finestra.FindName('TxtMessaggioGuida')
        TxtSottotitoloGuida    = $finestra.FindName('TxtSottotitoloGuida')
        TxtDettaglioTitolo     = $finestra.FindName('TxtDettaglioTitolo')
        TxtDettaglioSottotitolo= $finestra.FindName('TxtDettaglioSottotitolo')
        BtnModoSemplice        = $finestra.FindName('BtnModoSemplice')
        BtnModoTecnico         = $finestra.FindName('BtnModoTecnico')
        TxtTitoloSpiegazione   = $finestra.FindName('TxtTitoloSpiegazione')
        TxtDettaglioSpiegazione= $finestra.FindName('TxtDettaglioSpiegazione')
        BannerDettaglioErrore  = $finestra.FindName('BannerDettaglioErrore')
        TxtDettaglioErrore     = $finestra.FindName('TxtDettaglioErrore')
        LblValoreAtteso        = $finestra.FindName('LblValoreAtteso')
        LblValoreOsservato     = $finestra.FindName('LblValoreOsservato')
        TxtDettaglioAtteso     = $finestra.FindName('TxtDettaglioAtteso')
        TxtDettaglioOsservato  = $finestra.FindName('TxtDettaglioOsservato')
        LblComeCorreggere      = $finestra.FindName('LblComeCorreggere')
        TxtDettaglioRimedio    = $finestra.FindName('TxtDettaglioRimedio')
        PanelComandoRimedio    = $finestra.FindName('PanelComandoRimedio')
        LblComandoRif          = $finestra.FindName('LblComandoRif')
        TxtComandoRimedio      = $finestra.FindName('TxtComandoRimedio')
        BtnCopiaComando        = $finestra.FindName('BtnCopiaComando')
        TxtFeedbackCopia       = $finestra.FindName('TxtFeedbackCopia')
        LblNoteRischi          = $finestra.FindName('LblNoteRischi')
        TxtDettaglioRischi     = $finestra.FindName('TxtDettaglioRischi')
        BtnNavScansione        = $finestra.FindName('BtnNavScansione')
        BtnNavIA               = $finestra.FindName('BtnNavIA')
        BtnTornaScansione      = $finestra.FindName('BtnTornaScansione')
        GridPaginaScansione    = $finestra.FindName('GridPaginaScansione')
        GridPaginaIA           = $finestra.FindName('GridPaginaIA')
        LblMotoreIaTitle       = $finestra.FindName('LblMotoreIaTitle')
        LblIndirizzoOllama     = $finestra.FindName('LblIndirizzoOllama')
        TxtEndpointOllama      = $finestra.FindName('TxtEndpointOllama')
        LblModelloOllama       = $finestra.FindName('LblModelloOllama')
        CmbModelloOllama       = $finestra.FindName('CmbModelloOllama')
        ChkAutoInstallaOllama  = $finestra.FindName('ChkAutoInstallaOllama')
        TxtChkAutoInstalla     = $finestra.FindName('TxtChkAutoInstalla')
        BtnVerificaOllama      = $finestra.FindName('BtnVerificaOllama')
        LblGeneraAnalisiTitle  = $finestra.FindName('LblGeneraAnalisiTitle')
        BtnSpiegaLLM           = $finestra.FindName('BtnSpiegaLLM')
        BtnResocontoLLM        = $finestra.FindName('BtnResocontoLLM')
        BtnSpiegaControlloTab  = $finestra.FindName('BtnSpiegaControlloTab')
        BtnResocontoTab        = $finestra.FindName('BtnResocontoTab')
        LblCriticitaRilevate   = $finestra.FindName('LblCriticitaRilevate')
        LblTitoloResocontoIA   = $finestra.FindName('LblTitoloResocontoIA')
        BtnCopiaRispostaLLM    = $finestra.FindName('BtnCopiaRispostaLLM')
        ListFallitiIA          = $finestra.FindName('ListFallitiIA')
        TxtStatoLLM            = $finestra.FindName('TxtStatoLLM')
        TxtRispostaLLM         = $finestra.FindName('TxtRispostaLLM')
        BtnEsportaJson         = $finestra.FindName('BtnEsportaJson')
        BtnEsportaHtml         = $finestra.FindName('BtnEsportaHtml')
        ChkSalvaLogTecnico     = $finestra.FindName('ChkSalvaLogTecnico')
        TxtRiepilogoFooter     = $finestra.FindName('TxtRiepilogoFooter')
        TxtDisclaimerPermanente= $finestra.FindName('TxtDisclaimerPermanente')
    }

    # Stato interno dell'interfaccia
    $totaleControlli = @($Catalogo.controls).Count
    $statoUI = @{
        LinguaCorrente      = $LinguaIniziale
        TemaCorrente        = 'Chiaro'
        ModalitaDettaglio   = 'Semplice'
        RisultatiGrezzi     = @()
        ElementiVista       = @()
        ElementoSelezionato = $null
        ScansioneInCorso    = $false
        UltimaModalitaIA    = 'Resoconto'
        SyncRunspace        = $null
        PsInstance          = $null
        Runspace            = $null
    }

    $ctrl.ProgressScansione.Maximum = if ($totaleControlli -gt 0) { $totaleControlli } else { 1 }

    # Banner giallo se non avviato come amministratore
    if (-not $Ambiente.IsAdmin) {
        $ctrl.BannerNonAdmin.Visibility = [System.Windows.Visibility]::Visible
    }

    # Funzione helper per ripopolare i filtri ComboBox nella lingua corrente
    $aggiornaFiltriComboLingua = {
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')

        $idxStato = if ($ctrl.CmbFiltroStato.SelectedIndex -ge 0) { $ctrl.CmbFiltroStato.SelectedIndex } else { 0 }
        $idxGrav  = if ($ctrl.CmbFiltroGravita.SelectedIndex -ge 0) { $ctrl.CmbFiltroGravita.SelectedIndex } else { 0 }
        $idxCat   = if ($ctrl.CmbFiltroCategoria.SelectedIndex -ge 0) { $ctrl.CmbFiltroCategoria.SelectedIndex } else { 0 }

        $vociStato = if ($isEn) {
            @('All', 'Failed', 'Passed', 'Unknown', 'N/A', 'Error')
        } else {
            @('Tutti', 'Fallito', 'Superato', 'Sconosciuto', 'Non_Applicabile', 'Errore')
        }

        $vociGrav = if ($isEn) {
            @('All', 'Critical', 'High', 'Medium', 'Low', 'Info')
        } else {
            @('Tutte', 'Critico', 'Alto', 'Medio', 'Basso', 'Informativo')
        }

        $ctrl.CmbFiltroStato.Items.Clear()
        foreach ($v in $vociStato) {
            $item = New-Object System.Windows.Controls.ComboBoxItem
            $item.Content = $v
            [void]$ctrl.CmbFiltroStato.Items.Add($item)
        }
        $ctrl.CmbFiltroStato.SelectedIndex = [Math]::Min($idxStato, $vociStato.Count - 1)

        $ctrl.CmbFiltroGravita.Items.Clear()
        foreach ($v in $vociGrav) {
            $item = New-Object System.Windows.Controls.ComboBoxItem
            $item.Content = $v
            [void]$ctrl.CmbFiltroGravita.Items.Add($item)
        }
        $ctrl.CmbFiltroGravita.SelectedIndex = [Math]::Min($idxGrav, $vociGrav.Count - 1)

        # Popola categorie nella lingua corrente
        $categorieUniche = @()
        foreach ($c in $Catalogo.controls) {
            $cid = [string]$c.id
            $catVal = [string]$c.category
            if ($isEn -and $script:TraduzioniControlliEN.ContainsKey($cid)) {
                $catVal = $script:TraduzioniControlliEN[$cid].cat
            }
            if ($catVal -and ($categorieUniche -notcontains $catVal)) {
                $categorieUniche += $catVal
            }
        }

        $ctrl.CmbFiltroCategoria.Items.Clear()
        $itemTutte = New-Object System.Windows.Controls.ComboBoxItem
        $itemTutte.Content = if ($isEn) { 'All' } else { 'Tutte' }
        [void]$ctrl.CmbFiltroCategoria.Items.Add($itemTutte)

        foreach ($cat in ($categorieUniche | Sort-Object)) {
            $itemCat = New-Object System.Windows.Controls.ComboBoxItem
            $itemCat.Content = $cat
            [void]$ctrl.CmbFiltroCategoria.Items.Add($itemCat)
        }
        $ctrl.CmbFiltroCategoria.SelectedIndex = [Math]::Min($idxCat, $ctrl.CmbFiltroCategoria.Items.Count - 1)
    }

    # --- Funzioni di aggiornamento UI ---
    $aggiornaPannelloDettaglio = {
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')
        $dettaglio = Format-DettaglioControllo -Elemento $statoUI.ElementoSelezionato -Modalita $statoUI.ModalitaDettaglio -Lingua $statoUI.LinguaCorrente
        $ctrl.TxtDettaglioTitolo.Text = $dettaglio.Title

        if ($isEn) {
            $ctrl.TxtDettaglioSottotitolo.Text = "ID: $($dettaglio.ControlId)  |  Status: $($dettaglio.StatusLabel)  |  Severity: $($dettaglio.SeverityLabel)  |  Category: $($dettaglio.Category)"
        }
        else {
            $ctrl.TxtDettaglioSottotitolo.Text = "ID: $($dettaglio.ControlId)  |  Stato: $($dettaglio.StatusLabel)  |  Gravita': $($dettaglio.SeverityLabel)  |  Categoria: $($dettaglio.Category)"
        }

        if ($statoUI.ModalitaDettaglio -eq 'Tecnico') {
            $ctrl.TxtTitoloSpiegazione.Text = if ($isEn) { "Technical details & references" } else { "Dettaglio tecnico e riferimenti" }
            $ctrl.BtnModoTecnico.FontWeight = [System.Windows.FontWeights]::Bold
            $ctrl.BtnModoSemplice.FontWeight = [System.Windows.FontWeights]::Normal
        }
        else {
            $ctrl.TxtTitoloSpiegazione.Text = if ($isEn) { "Why it matters (simple explanation)" } else { "Perche' conta (spiegazione semplice)" }
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
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')

        if ($isEn) {
            $ctrl.TxtCountSuperati.Text       = "[OK] $($conteggi.superato) Passed"
            $ctrl.TxtCountFalliti.Text        = "[X] $($conteggi.fallito) Failed"
            $ctrl.TxtCountSconosciuti.Text    = "[?] $($conteggi.sconosciuto) Unknown"
            $ctrl.TxtCountNonApplicabili.Text = "[-] $($conteggi.non_applicabile) N/A"
            $ctrl.TxtCountErrori.Text         = "[!] $($conteggi.errore) Errors"
            $ctrl.TxtRiepilogoFooter.Text     = "Summary: $($conteggi.totale) controls evaluated ($($conteggi.superato) passed, $($conteggi.fallito) failed, $($conteggi.sconosciuto) unknown)"
        }
        else {
            $ctrl.TxtCountSuperati.Text       = "[OK] $($conteggi.superato) Superati"
            $ctrl.TxtCountFalliti.Text        = "[X] $($conteggi.fallito) Falliti"
            $ctrl.TxtCountSconosciuti.Text    = "[?] $($conteggi.sconosciuto) Sconosciuti"
            $ctrl.TxtCountNonApplicabili.Text = "[-] $($conteggi.non_applicabile) Non applicabili"
            $ctrl.TxtCountErrori.Text         = "[!] $($conteggi.errore) Errori"
            $ctrl.TxtRiepilogoFooter.Text     = "Riepilogo calcolato dal codice: $($conteggi.totale) controlli valutati ($($conteggi.superato) superati, $($conteggi.fallito) falliti, $($conteggi.sconosciuto) sconosciuti)"
        }

        if ($conteggi.errore -gt 0) {
            $ctrl.TxtBannerErrore.Text = if ($isEn) {
                "Some controls ($($conteggi.errore)) returned an unexpected read error. Select the control for details or export the technical log."
            } else {
                "Alcuni controlli ($($conteggi.errore)) hanno restituito un imprevisto durante la lettura. Seleziona il controllo per maggiori informazioni o esporta il log tecnico."
            }
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
            $ctrl.TxtMessaggioGuida.Text = if ($statoUI.LinguaCorrente -eq 'EN') {
                "No controls match the selected filters."
            } else {
                "Nessun controllo corrisponde ai filtri selezionati."
            }
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

    $applicaLinguaUI = {
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')
        $testoAdmin = if ($Ambiente.IsAdmin) {
            if ($isEn) { 'Yes' } else { 'Si' }
        } else {
            'No'
        }
        $ctrl.TxtAmbienteInfo.Text = "Windows 11 $($Ambiente.Edition) $($Ambiente.Build) | Admin: $testoAdmin"

        if ($isEn) {
            $finestra.Title                        = "Windows 11 Security Scanner (Read-Only)"
            $ctrl.TxtTitoloApp.Text                = "Windows 11 Security Scanner"
            $ctrl.TxtBadgeSolaLettura.Text         = "READ-ONLY"
            $ctrl.TxtSottotitoloApp.Text           = "$totaleControlli Deterministic Controls + Local AI Security Advisor (Ollama)"
            $ctrl.BtnLingua.Content                = "Lang: IT"
            $ctrl.BtnTema.Content                  = if ($statoUI.TemaCorrente -eq 'Chiaro') { "Theme: Dark" } else { "Theme: Light" }
            $ctrl.TxtBannerNonAdmin.Text           = "[!] Non-administrative session: some controls will report 'Unknown'. Restart as Administrator for a complete audit."
            $ctrl.BtnRiavviaAdmin.Content          = "Restart as Administrator"
            $ctrl.BtnNavScansione.Content          = "1. Security Controls & Details"
            $ctrl.BtnNavIA.Content                 = "2. AI Security Advisor (Ollama)"
            $ctrl.BtnAvvia.Content                 = "Start Scan ($totaleControlli controls)"
            $ctrl.BtnAnnulla.Content               = "Cancel"
            $ctrl.BtnResocontoLLM.Content          = "Open AI Security Report"
            $ctrl.LblFiltroStato.Text              = "Status:"
            $ctrl.LblFiltroGravita.Text            = "Severity:"
            $ctrl.LblFiltroCategoria.Text          = "Category:"
            $ctrl.LblFiltroCerca.Text              = "Search:"
            $ctrl.BtnResetFiltri.Content           = "Reset Filters"
            $ctrl.ColStato.Header                  = "Status"
            $ctrl.ColGravita.Header                = "Severity"
            $ctrl.ColCategoria.Header              = "Category"
            $ctrl.ColId.Header                     = "ID"
            $ctrl.ColControllo.Header              = "Security Control"
            $ctrl.TxtSottotitoloGuida.Text         = "The scanner operates strictly in read-only mode and modifies no Windows settings."
            $ctrl.BtnModoSemplice.Content          = "Simple View"
            $ctrl.BtnModoTecnico.Content           = "Technical Details"
            $ctrl.BtnSpiegaLLM.Content             = "Explain with AI (Page 2)"
            $ctrl.LblValoreAtteso.Text             = "EXPECTED VALUE"
            $ctrl.LblValoreOsservato.Text          = "OBSERVED VALUE"
            $ctrl.LblComeCorreggere.Text           = "How to Remediate (Manual Instructions)"
            $ctrl.LblComandoRif.Text               = "REFERENCE COMMAND (NOT EXECUTED AUTOMATICALLY):"
            $ctrl.BtnCopiaComando.Content          = "Copy Command to Clipboard"
            $ctrl.TxtFeedbackCopia.Text            = "Copied!"
            $ctrl.LblNoteRischi.Text               = "Risk & Impact Notes"
            $ctrl.LblMotoreIaTitle.Text            = "LOCAL AI ENGINE (OLLAMA)"
            $ctrl.LblIndirizzoOllama.Text          = "Ollama Server Address:"
            $ctrl.LblModelloOllama.Text            = "Lightweight LLM Model:"
            $ctrl.TxtChkAutoInstalla.Text          = "If Ollama is missing on VM, silently auto-install and start it in background"
            $ctrl.BtnVerificaOllama.Content        = "Check / Auto-Setup Ollama"
            $ctrl.LblGeneraAnalisiTitle.Text       = "GENERATE ANALYSIS & ADVICE"
            $ctrl.BtnResocontoTab.Content          = "Generate Full PC Security Report"
            $ctrl.BtnSpiegaControlloTab.Content    = "Explain Selected Control"
            $ctrl.LblCriticitaRilevate.Text        = "DETECTED ISSUES (CLICK TO ANALYZE):"
            $ctrl.LblTitoloResocontoIA.Text        = "AI SECURITY REPORT & HARDENING PLAN"
            $ctrl.BtnCopiaRispostaLLM.Content      = "Copy AI Report"
            $ctrl.BtnTornaScansione.Content        = "Back to Controls Table"
            $ctrl.BtnEsportaJson.Content           = "Export JSON"
            $ctrl.BtnEsportaHtml.Content           = "Export HTML"
            $ctrl.ChkSalvaLogTecnico.Content       = "Include technical error log next to export"
            $ctrl.TxtDisclaimerPermanente.Text     = "Permanent Notice: This tool audits security configurations strictly in read-only mode. A compliant audit does not guarantee the absence of system compromise."
        }
        else {
            $finestra.Title                        = "Scanner Sicurezza Windows 11 (Sola Lettura)"
            $ctrl.TxtTitoloApp.Text                = "Scanner Sicurezza Windows 11"
            $ctrl.TxtBadgeSolaLettura.Text         = "SOLA LETTURA"
            $ctrl.TxtSottotitoloApp.Text           = "$totaleControlli Controlli Deterministici + Assistente IA Locale (Ollama)"
            $ctrl.BtnLingua.Content                = "Lang: EN"
            $ctrl.BtnTema.Content                  = if ($statoUI.TemaCorrente -eq 'Chiaro') { "Tema: Scuro" } else { "Tema: Chiaro" }
            $ctrl.TxtBannerNonAdmin.Text           = "[!] Sessione non amministrativa: alcuni controlli risulteranno 'Sconosciuto'. Riavvia come Amministratore per l'analisi completa."
            $ctrl.BtnRiavviaAdmin.Content          = "Riavvia come amministratore"
            $ctrl.BtnNavScansione.Content          = "1. Tabella Controlli & Dettagli"
            $ctrl.BtnNavIA.Content                 = "2. Pagina Resoconto IA (Ollama)"
            $ctrl.BtnAvvia.Content                 = "Avvia scansione ($totaleControlli controlli)"
            $ctrl.BtnAnnulla.Content               = "Annulla"
            $ctrl.BtnResocontoLLM.Content          = "Apri Resoconto IA & Consigli"
            $ctrl.LblFiltroStato.Text              = "Stato:"
            $ctrl.LblFiltroGravita.Text            = "Gravita':"
            $ctrl.LblFiltroCategoria.Text          = "Categoria:"
            $ctrl.LblFiltroCerca.Text              = "Cerca:"
            $ctrl.BtnResetFiltri.Content           = "Reimposta filtri"
            $ctrl.ColStato.Header                  = "Stato"
            $ctrl.ColGravita.Header                = "Gravita'"
            $ctrl.ColCategoria.Header              = "Categoria"
            $ctrl.ColId.Header                     = "ID"
            $ctrl.ColControllo.Header              = "Controllo"
            $ctrl.TxtSottotitoloGuida.Text         = "Lo strumento opera esclusivamente in sola lettura e non modifica alcuna impostazione di Windows."
            $ctrl.BtnModoSemplice.Content          = "Spiegazione Semplice"
            $ctrl.BtnModoTecnico.Content           = "Dettagli Tecnici"
            $ctrl.BtnSpiegaLLM.Content             = "Spiega con IA (Pagina 2)"
            $ctrl.LblValoreAtteso.Text             = "VALORE ATTESO"
            $ctrl.LblValoreOsservato.Text          = "VALORE OSSERVATO"
            $ctrl.LblComeCorreggere.Text           = "Come correggere (istruzioni manuali)"
            $ctrl.LblComandoRif.Text               = "COMANDO DI RIFERIMENTO (NON ESEGUITO AUTOMATICAMENTE):"
            $ctrl.BtnCopiaComando.Content          = "Copia comando negli appunti"
            $ctrl.TxtFeedbackCopia.Text            = "Copiato!"
            $ctrl.LblNoteRischi.Text               = "Note sui rischi"
            $ctrl.LblMotoreIaTitle.Text            = "MOTORE IA LOCALE (OLLAMA)"
            $ctrl.LblIndirizzoOllama.Text          = "Indirizzo Server Ollama:"
            $ctrl.LblModelloOllama.Text            = "Modello LLM leggero:"
            $ctrl.TxtChkAutoInstalla.Text          = "Se Ollama manca sulla VM, installalo e avvialo automaticamente in background"
            $ctrl.BtnVerificaOllama.Content        = "Verifica / Auto-Configura Ollama"
            $ctrl.LblGeneraAnalisiTitle.Text       = "GENERA ANALISI E CONSIGLI"
            $ctrl.BtnResocontoTab.Content          = "Genera Resoconto Completo PC"
            $ctrl.BtnSpiegaControlloTab.Content    = "Spiega il Controllo Selezionato"
            $ctrl.LblCriticitaRilevate.Text        = "CRITICITA' RILEVATE (CLICCA PER ANALIZZARE):"
            $ctrl.LblTitoloResocontoIA.Text        = "RESOCONTO DI SICUREZZA & PIANO DI MIGLIORAMENTO IA"
            $ctrl.BtnCopiaRispostaLLM.Content      = "Copia Resoconto"
            $ctrl.BtnTornaScansione.Content        = "Torna alla Tabella Controlli"
            $ctrl.BtnEsportaJson.Content           = "Esporta JSON"
            $ctrl.BtnEsportaHtml.Content           = "Esporta HTML"
            $ctrl.ChkSalvaLogTecnico.Content       = "Includi file di log tecnico accanto all'export"
            $ctrl.TxtDisclaimerPermanente.Text     = "Avviso permanente: questo strumento verifica solo alcune configurazioni di sicurezza in sola lettura. Un audit conforme non dimostra l'assenza di compromissioni sul sistema."
        }

        & $aggiornaFiltriComboLingua

        if ($statoUI.RisultatiGrezzi.Count -eq 0) {
            if ($isEn) {
                $ctrl.TxtMessaggioGuida.Text = "Click 'Start Scan' to audit all $totaleControlli Windows 11 security controls."
                $ctrl.TxtProgresso.Text      = "Ready (0/$totaleControlli)"
                $ctrl.TxtStatoLLM.Text       = "Status: Ready (auto-connects or auto-installs Ollama on demand)"
                $ctrl.TxtRispostaLLM.Text    = "1. Run the PC scan using the 'Start Scan (34 controls)' button at the top.`r`n2. Click 'Generate Full PC Security Report' on the left to get an executive summary, prioritized remediation plan, and hardening recommendations.`r`n3. On a VM without Ollama installed, leave the auto-install checkbox enabled: the tool will silently configure Ollama or provide an instant built-in expert analysis."
            }
            else {
                $ctrl.TxtMessaggioGuida.Text = "Premi 'Avvia scansione' per analizzare i $totaleControlli controlli di sicurezza del PC."
                $ctrl.TxtProgresso.Text      = "Pronto (0/$totaleControlli)"
                $ctrl.TxtStatoLLM.Text       = "Stato: Pronto (connessione o auto-installazione automatica al primo avvio)"
                $ctrl.TxtRispostaLLM.Text    = "1. Esegui prima la scansione del PC col pulsante 'Avvia scansione (34 controlli)' in alto.`r`n2. Premi 'Genera Resoconto Completo PC' qui a sinistra per ricevere l'analisi di tutte le vulnerabilita' trovate e i consigli pratici di messa in sicurezza.`r`n3. Se sei su una Macchina Virtuale senza Ollama, lascia attiva la spunta a sinistra: il tool pensera' a tutto in automatico (oppure fornira' l'analisi immediata tramite il motore esperto integrato)."
            }
        }
        else {
            $nValutati = $statoUI.RisultatiGrezzi.Count
            $idSelPrec = if ($null -ne $statoUI.ElementoSelezionato) { $statoUI.ElementoSelezionato.ControlId } else { $null }

            # Rigenera gli elementi della vista nella lingua selezionata
            $statoUI.ElementiVista = @(ConvertTo-RisultatiVista -Risultati $statoUI.RisultatiGrezzi -Catalogo $Catalogo -Lingua $statoUI.LinguaCorrente)
            if ($null -ne $idSelPrec) {
                foreach ($el in $statoUI.ElementiVista) {
                    if ($el.ControlId -eq $idSelPrec) {
                        $statoUI.ElementoSelezionato = $el
                        break
                    }
                }
            }

            if (-not $statoUI.ScansioneInCorso) {
                $ctrl.TxtProgresso.Text = if ($isEn) { "Completed ($nValutati/$nValutati)" } else { "Completata ($nValutati/$nValutati)" }
            }

            # Aggiorna la lista delle criticita' nella Pagina 2 (IA)
            $falliti = @($statoUI.ElementiVista | Where-Object { $_.Status -eq 'fallito' })
            $ctrl.ListFallitiIA.ItemsSource = $falliti
            if ($null -ne $statoUI.ElementoSelezionato -and $statoUI.ElementoSelezionato.Status -eq 'fallito') {
                $ctrl.ListFallitiIA.SelectedItem = $statoUI.ElementoSelezionato
            }

            # Aggiorna anche il testo del Resoconto IA nella lingua selezionata cosi' non resta mai nella lingua precedente
            if ($statoUI.UltimaModalitaIA -eq 'Controllo' -and $null -ne $statoUI.ElementoSelezionato) {
                $dettCorr = Format-DettaglioControllo -Elemento $statoUI.ElementoSelezionato -Modalita 'Semplice' -Lingua $statoUI.LinguaCorrente
                $ctrl.TxtRispostaLLM.Text = Format-AnalisiLocaleControllo -Dettaglio $dettCorr -Ambiente $Ambiente -Lingua $statoUI.LinguaCorrente
                $ctrl.TxtStatoLLM.Text    = if ($isEn) { "Completed: Instant Security Analysis ($($dettCorr.ControlId))" } else { "Completato: Analisi di Sicurezza ($($dettCorr.ControlId))" }
            }
            else {
                $conteggiCorr = Measure-ConteggiRisultati -Elementi $statoUI.RisultatiGrezzi
                $ctrl.TxtRispostaLLM.Text = Format-ResocontoLocaleScansione -ElementiVista $statoUI.ElementiVista -Conteggi $conteggiCorr -Ambiente $Ambiente -Lingua $statoUI.LinguaCorrente
                $ctrl.TxtStatoLLM.Text    = if ($isEn) { "Completed: Full PC Security Report (EN)" } else { "Completato: Resoconto Completo Sicurezza PC (IT)" }
            }

            & $applicaFiltriTabella
        }

        & $aggiornaConteggiERiepilogo
        & $aggiornaPannelloDettaglio
    }

    $ctrl.BtnLingua.Add_Click({
        if ($statoUI.LinguaCorrente -eq 'IT') {
            $statoUI.LinguaCorrente = 'EN'
        }
        else {
            $statoUI.LinguaCorrente = 'IT'
        }
        & $applicaLinguaUI
    })

    # --- Eventi Tema ---
    $ctrl.BtnTema.Add_Click({
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')
        if ($statoUI.TemaCorrente -eq 'Chiaro') {
            $statoUI.TemaCorrente = 'Scuro'
            Update-TemaFinestra -Finestra $finestra -Tema 'Scuro'
            $ctrl.BtnTema.Content = if ($isEn) { 'Theme: Light' } else { 'Tema: Chiaro' }
        }
        else {
            $statoUI.TemaCorrente = 'Chiaro'
            Update-TemaFinestra -Finestra $finestra -Tema 'Chiaro'
            $ctrl.BtnTema.Content = if ($isEn) { 'Theme: Dark' } else { 'Tema: Scuro' }
        }
    })

    # --- Evento Riavvia come Amministratore ---
    $ctrl.BtnRiavviaAdmin.Add_Click({
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')
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
                $argomentiRemoti = "-NoProfile -ExecutionPolicy Bypass -STA -Command `"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; irm '$($script:UrlScriptRemoto)' | iex`""
                Start-Process -FilePath 'powershell.exe' -ArgumentList $argomentiRemoti -Verb RunAs
                $finestra.Close()
            }
            else {
                $msg = if ($isEn) {
                    "Launched from remote memory: open a new PowerShell window as Administrator and re-run the command."
                } else {
                    "Avviato da memoria remota: apri una nuova finestra di PowerShell come Amministratore e riesegui il comando."
                }
                [System.Windows.MessageBox]::Show($msg, $finestra.Title, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
            }
        }
        catch {
            $msgErr = if ($isEn) {
                "Restart as Administrator was canceled or failed."
            } else {
                "Riavvio come amministratore annullato o non riuscito."
            }
            [System.Windows.MessageBox]::Show($msgErr, $finestra.Title, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
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

    # --- Navigazione tra Pagina 1 (Scansione) e Pagina 2 (Resoconto IA a tutto schermo) ---
    $mostraPagina = {
        param([string]$NomePagina)
        if ($NomePagina -eq 'IA') {
            $ctrl.GridPaginaScansione.Visibility = [System.Windows.Visibility]::Collapsed
            $ctrl.GridPaginaIA.Visibility        = [System.Windows.Visibility]::Visible
            # Aggiorna la lista delle criticita' nella barra laterale della Pagina IA
            $falliti = @($statoUI.ElementiVista | Where-Object { $_.Status -eq 'fallito' })
            $ctrl.ListFallitiIA.ItemsSource = $falliti
            if ($null -ne $statoUI.ElementoSelezionato) {
                $ctrl.ListFallitiIA.SelectedItem = $statoUI.ElementoSelezionato
            }
            elseif ($falliti.Count -gt 0) {
                $ctrl.ListFallitiIA.SelectedIndex = 0
            }
        }
        else {
            $ctrl.GridPaginaIA.Visibility        = [System.Windows.Visibility]::Collapsed
            $ctrl.GridPaginaScansione.Visibility = [System.Windows.Visibility]::Visible
        }
    }

    $ctrl.BtnNavScansione.Add_Click({ & $mostraPagina 'Scansione' })
    $ctrl.BtnTornaScansione.Add_Click({ & $mostraPagina 'Scansione' })
    $ctrl.BtnNavIA.Add_Click({ & $mostraPagina 'IA' })

    $ctrl.ListFallitiIA.Add_SelectionChanged({
        if ($null -ne $ctrl.ListFallitiIA.SelectedItem) {
            $statoUI.ElementoSelezionato = $ctrl.ListFallitiIA.SelectedItem
            & $aggiornaPannelloDettaglio
        }
    })

    # --- Funzione asincrona per eseguire una richiesta Ollama in un Runspace (con Auto-Provisioning sulla VM) ---
    $avviaRichiestaOllamaAsincrona = {
        param(
            [string]$PromptDaInviare,
            [string]$EtichettaOperazione,
            [string]$TestoFallback = ''
        )

        $isEn = ($statoUI.LinguaCorrente -eq 'EN')

        # Passa automaticamente alla Pagina 2 (Pagina dedicata Assistente IA)
        & $mostraPagina 'IA'

        $modelloScelto = $ctrl.CmbModelloOllama.Text
        if ([string]::IsNullOrWhiteSpace($modelloScelto)) {
            $modelloScelto = 'qwen2.5:0.5b'
        }

        $endpointScelto = $ctrl.TxtEndpointOllama.Text
        if ([string]::IsNullOrWhiteSpace($endpointScelto)) {
            $endpointScelto = 'http://127.0.0.1:11434'
        }

        $autoInstalla = ($ctrl.ChkAutoInstallaOllama.IsChecked -eq $true)

        $ctrl.BtnSpiegaLLM.IsEnabled          = $false
        $ctrl.BtnSpiegaControlloTab.IsEnabled = $false
        $ctrl.BtnResocontoLLM.IsEnabled       = $false
        $ctrl.BtnResocontoTab.IsEnabled       = $false
        $ctrl.BtnVerificaOllama.IsEnabled     = $false
        $ctrl.TxtStatoLLM.Text                = if ($isEn) { "$EtichettaOperazione in progress ($modelloScelto)..." } else { "$EtichettaOperazione in corso ($modelloScelto)..." }

        # Mostra subito l'analisi preliminare mentre Ollama genera (o si auto-installa sulla VM)
        if (-not [string]::IsNullOrWhiteSpace($TestoFallback)) {
            $bannerAttesa = if ($isEn) {
                "[Connecting/Preparing Ollama ($modelloScelto) in background... Here is the immediate structured report:]"
            } else {
                "[Connessione/Preparazione di Ollama ($modelloScelto) in corso in background... Ecco intanto il resoconto strutturato immediato:]"
            }
            $ctrl.TxtRispostaLLM.Text = "$bannerAttesa`n`n$TestoFallback"
        }
        else {
            $ctrl.TxtRispostaLLM.Text = if ($isEn) {
                "Processing with Ollama ($modelloScelto)... If you are on a VM without Ollama, the scanner is auto-configuring it in background."
            } else {
                "Elaborazione in corso con Ollama ($modelloScelto)... Se ti trovi su una VM senza Ollama, lo scanner lo sta configurando automaticamente in background."
            }
        }

        $callbackStatoLlm = [Action[string]]{
            param([string]$MsgStato)
            $ctrl.TxtStatoLLM.Text = $MsgStato
        }

        $callbackFineLlm = [Action[object]]{
            param($EsitoLlm)
            $isEnNow = ($statoUI.LinguaCorrente -eq 'EN')
            $ctrl.BtnSpiegaLLM.IsEnabled          = $true
            $ctrl.BtnSpiegaControlloTab.IsEnabled = $true
            $ctrl.BtnResocontoTab.IsEnabled       = $true
            $ctrl.BtnVerificaOllama.IsEnabled     = $true
            if ($statoUI.RisultatiGrezzi.Count -gt 0) {
                $ctrl.BtnResocontoLLM.IsEnabled = $true
            }

            if ($EsitoLlm.Successo) {
                $sec = [math]::Round(($EsitoLlm.DurataMs / 1000.0), 1)
                $sorgente = if ($null -ne $EsitoLlm.PSObject.Properties['Sorgente']) { $EsitoLlm.Sorgente } else { $EsitoLlm.Modello }
                $ctrl.TxtStatoLLM.Text    = if ($isEnNow) { "Completed by: $sorgente (${sec}s)" } else { "Completato da: $sorgente (${sec}s)" }
                $ctrl.TxtRispostaLLM.Text = $EsitoLlm.Risposta
            }
            else {
                $ctrl.TxtStatoLLM.Text    = if ($isEnNow) { "Status: $($EsitoLlm.Modello) unavailable" } else { "Stato: $($EsitoLlm.Modello) non disponibile" }
                $ctrl.TxtRispostaLLM.Text = $EsitoLlm.Errore
            }
        }

        $syncLlm = [hashtable]::Synchronized(@{
            Finestra       = $finestra
            Prompt         = $PromptDaInviare
            Modello        = $modelloScelto
            Endpoint       = $endpointScelto
            Fallback       = $TestoFallback
            AutoProvision  = $autoInstalla
            Lingua         = $statoUI.LinguaCorrente
            CallbackStato  = $callbackStatoLlm
            CallbackFine   = $callbackFineLlm
        })

        $issLlm = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $nomiFnOllama = @('Find-EseguibileOllamaLocale', 'Test-ConnessioneOllama', 'Initialize-AmbienteOllama', 'Invoke-RichiestaOllama')
        foreach ($nomeFn in $nomiFnOllama) {
            $fnObj = Get-Command -Name $nomeFn -ErrorAction SilentlyContinue
            if ($null -ne $fnObj) {
                $entryFn = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fnObj.Name, $fnObj.Definition)
                [void]$issLlm.Commands.Add($entryFn)
            }
        }

        $rsLlm = [runspacefactory]::CreateRunspace($issLlm)
        $rsLlm.ApartmentState = 'STA'
        $rsLlm.ThreadOptions  = 'ReuseThread'
        $rsLlm.Open()
        $rsLlm.SessionStateProxy.SetVariable('SyncLlm', $syncLlm)

        $psLlm = [powershell]::Create()
        $psLlm.Runspace = $rsLlm
        [void]$psLlm.AddScript({
            $onStatusBlock = {
                param([string]$statoMsg)
                [void]$SyncLlm.Finestra.Dispatcher.Invoke(
                    [System.Windows.Threading.DispatcherPriority]::Background,
                    $SyncLlm.CallbackStato,
                    $statoMsg
                )
            }
            $esito = Invoke-RichiestaOllama -Prompt $SyncLlm.Prompt -Modello $SyncLlm.Modello -Endpoint $SyncLlm.Endpoint -TestoFallbackLocale $SyncLlm.Fallback -AutoProvision $SyncLlm.AutoProvision -Lingua $SyncLlm.Lingua -OnStatus $onStatusBlock
            [void]$SyncLlm.Finestra.Dispatcher.Invoke(
                [System.Windows.Threading.DispatcherPriority]::Normal,
                $SyncLlm.CallbackFine,
                $esito
            )
        })
        [void]$psLlm.BeginInvoke()
    }

    # --- Pulsante Verifica / Auto-Configura Ollama in background ---
    $ctrl.BtnVerificaOllama.Add_Click({
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')
        $endpointScelto = if ([string]::IsNullOrWhiteSpace($ctrl.TxtEndpointOllama.Text)) { 'http://127.0.0.1:11434' } else { $ctrl.TxtEndpointOllama.Text.Trim() }
        $autoInst = ($ctrl.ChkAutoInstallaOllama.IsChecked -eq $true)
        $ctrl.BtnVerificaOllama.IsEnabled = $false
        $ctrl.TxtStatoLLM.Text = if ($isEn) { "Checking or auto-installing Ollama..." } else { "Verifica o installazione automatica di Ollama in corso..." }

        $cbStato = [Action[string]]{ param([string]$m) $ctrl.TxtStatoLLM.Text = $m }
        $cbFine  = [Action[object]]{
            param($statoOll)
            $isEnNow = ($statoUI.LinguaCorrente -eq 'EN')
            $ctrl.BtnVerificaOllama.IsEnabled = $true
            if ($statoOll.Disponibile) {
                $ctrl.TxtEndpointOllama.Text = $statoOll.Endpoint
                if ($statoOll.Modelli.Count -gt 0) {
                    $ctrl.CmbModelloOllama.Items.Clear()
                    foreach ($mod in $statoOll.Modelli) {
                        $itemM = New-Object System.Windows.Controls.ComboBoxItem
                        $itemM.Content = $mod
                        [void]$ctrl.CmbModelloOllama.Items.Add($itemM)
                    }
                    $ctrl.CmbModelloOllama.SelectedIndex = 0
                    $ctrl.TxtStatoLLM.Text = if ($isEnNow) {
                        "Ollama connected on $($statoOll.Endpoint)! Ready models: $($statoOll.Modelli -join ', ')"
                    } else {
                        "Ollama connesso su $($statoOll.Endpoint)! Modelli pronti: $($statoOll.Modelli -join ', ')"
                    }
                }
                else {
                    $ctrl.TxtStatoLLM.Text = if ($isEnNow) {
                        "Ollama active on $($statoOll.Endpoint)! Model '$($ctrl.CmbModelloOllama.Text)' will be downloaded automatically on first analysis."
                    } else {
                        "Ollama attivo su $($statoOll.Endpoint)! Il modello '$($ctrl.CmbModelloOllama.Text)' verra' scaricato automaticamente alla prima analisi."
                    }
                }
            }
            else {
                $ctrl.TxtStatoLLM.Text = if ($isEnNow) {
                    "Ollama unreachable: Built-in Expert Security Engine is active."
                } else {
                    "Ollama non raggiungibile: attivo il Motore Esperto Integrato."
                }
            }
        }

        $syncCfg = [hashtable]::Synchronized(@{
            Finestra     = $finestra
            Endpoint     = $endpointScelto
            AutoInstalla = $autoInst
            CbStato      = $cbStato
            CbFine       = $cbFine
        })

        $issCfg = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        foreach ($nomeFn in @('Find-EseguibileOllamaLocale', 'Test-ConnessioneOllama', 'Initialize-AmbienteOllama')) {
            $fnObj = Get-Command -Name $nomeFn -ErrorAction SilentlyContinue
            if ($null -ne $fnObj) {
                [void]$issCfg.Commands.Add((New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fnObj.Name, $fnObj.Definition)))
            }
        }

        $rsCfg = [runspacefactory]::CreateRunspace($issCfg)
        $rsCfg.ApartmentState = 'STA'
        $rsCfg.ThreadOptions  = 'ReuseThread'
        $rsCfg.Open()
        $rsCfg.SessionStateProxy.SetVariable('SyncCfg', $syncCfg)

        $psCfg = [powershell]::Create()
        $psCfg.Runspace = $rsCfg
        [void]$psCfg.AddScript({
            $sbStato = {
                param([string]$msg)
                [void]$SyncCfg.Finestra.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Background, $SyncCfg.CbStato, $msg)
            }
            $esitoCfg = Initialize-AmbienteOllama -Endpoint $SyncCfg.Endpoint -AutoInstalla $SyncCfg.AutoInstalla -OnStatus $sbStato
            [void]$SyncCfg.Finestra.Dispatcher.Invoke([System.Windows.Threading.DispatcherPriority]::Normal, $SyncCfg.CbFine, $esitoCfg)
        })
        [void]$psCfg.BeginInvoke()
    })

    # --- Azione: Spiega controllo selezionato ---
    $eseguiSpiegazioneControllo = {
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')
        & $mostraPagina 'IA'
        if ($null -eq $statoUI.ElementoSelezionato) {
            $ctrl.TxtStatoLLM.Text = if ($isEn) {
                "Please select a control from the 'Detected Issues' list on the left (or from the Controls Table) first."
            } else {
                "Seleziona prima un controllo dalla lista 'Criticita' rilevate' qui a sinistra (o dalla Tabella Controlli)."
            }
            return
        }
        $statoUI.UltimaModalitaIA = 'Controllo'
        $dettaglio   = Format-DettaglioControllo -Elemento $statoUI.ElementoSelezionato -Modalita 'Semplice' -Lingua $statoUI.LinguaCorrente
        $promptCtrl  = Format-PromptControlloOllama -Dettaglio $dettaglio -Ambiente $Ambiente -Lingua $statoUI.LinguaCorrente
        $fallbackLoc = Format-AnalisiLocaleControllo -Dettaglio $dettaglio -Ambiente $Ambiente -Lingua $statoUI.LinguaCorrente
        $lblOp       = if ($isEn) { "Analyzing $($dettaglio.ControlId)" } else { "Analisi di $($dettaglio.ControlId)" }
        & $avviaRichiestaOllamaAsincrona $promptCtrl $lblOp $fallbackLoc
    }

    # --- Azione: Genera Resoconto Completo della Scansione ---
    $eseguiResocontoScansione = {
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')
        & $mostraPagina 'IA'
        if ($statoUI.ElementiVista.Count -eq 0) {
            $ctrl.TxtStatoLLM.Text = if ($isEn) {
                "Click 'Start Scan' at the top first to collect PC security data."
            } else {
                "Premi prima 'Avvia scansione' in alto per raccogliere i dati del PC."
            }
            return
        }
        $statoUI.UltimaModalitaIA = 'Resoconto'
        $conteggi    = Measure-ConteggiRisultati -Elementi $statoUI.RisultatiGrezzi
        $promptRes   = Format-PromptResocontoOllama -ElementiVista $statoUI.ElementiVista -Conteggi $conteggi -Ambiente $Ambiente -Lingua $statoUI.LinguaCorrente
        $fallbackRes = Format-ResocontoLocaleScansione -ElementiVista $statoUI.ElementiVista -Conteggi $conteggi -Ambiente $Ambiente -Lingua $statoUI.LinguaCorrente
        $lblOp       = if ($isEn) { "Generating Full PC Security Report" } else { "Generazione Resoconto Sicurezza PC" }
        & $avviaRichiestaOllamaAsincrona $promptRes $lblOp $fallbackRes
    }

    $ctrl.BtnSpiegaLLM.Add_Click($eseguiSpiegazioneControllo)
    $ctrl.BtnSpiegaControlloTab.Add_Click($eseguiSpiegazioneControllo)
    $ctrl.BtnResocontoLLM.Add_Click($eseguiResocontoScansione)
    $ctrl.BtnResocontoTab.Add_Click($eseguiResocontoScansione)

    $ctrl.BtnCopiaRispostaLLM.Add_Click({
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')
        if (-not [string]::IsNullOrWhiteSpace($ctrl.TxtRispostaLLM.Text)) {
            [System.Windows.Clipboard]::SetText($ctrl.TxtRispostaLLM.Text)
            $ctrl.TxtStatoLLM.Text = if ($isEn) { "AI Report copied to Windows clipboard!" } else { "Resoconto copiato negli appunti di Windows!" }
        }
    })

    # --- Avvia scansione in Runspace separato ---
    $ctrl.BtnAvvia.Add_Click({
        if ($statoUI.ScansioneInCorso) { return }
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')

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
        $ctrl.TxtProgresso.Text         = if ($isEn) { "Starting scan..." } else { "Avvio scansione..." }
        $ctrl.TxtMessaggioGuida.Text    = if ($isEn) { "Scan in progress... Results will appear as controls are evaluated." } else { "Scansione in corso... I risultati compariranno man mano." }
        $ctrl.PanelGuidaVuota.Visibility = [System.Windows.Visibility]::Visible
        $ctrl.GridRisultati.ItemsSource = @()
        & $aggiornaConteggiERiepilogo
        & $aggiornaPannelloDettaglio

        # Callback invocato sul thread UI tramite Dispatcher per ogni controllo completato
        $callbackProgresso = [Action[int, int, object]]{
            param([int]$Indice, [int]$Totale, [object]$RisultatoSingolo)

            $isEnProg = ($statoUI.LinguaCorrente -eq 'EN')
            $statoUI.RisultatiGrezzi += $RisultatoSingolo
            $statoUI.ElementiVista = @(ConvertTo-RisultatiVista -Risultati $statoUI.RisultatiGrezzi -Catalogo $Catalogo -Lingua $statoUI.LinguaCorrente)

            $ctrl.ProgressScansione.Maximum = if ($Totale -gt 0) { $Totale } else { 1 }
            $ctrl.ProgressScansione.Value   = $Indice
            $ctrl.TxtProgresso.Text         = if ($isEnProg) { "Progress: $Indice/$Totale" } else { "Avanzamento: $Indice/$Totale" }

            & $aggiornaConteggiERiepilogo
            & $applicaFiltriTabella
        }

        # Callback invocato sul thread UI al termine (o annullamento) della scansione
        $callbackFine = [Action]{
            $isEnEnd = ($statoUI.LinguaCorrente -eq 'EN')
            $statoUI.ScansioneInCorso   = $false
            $ctrl.BtnAvvia.IsEnabled    = $true
            $ctrl.BtnAnnulla.IsEnabled  = $false

            $nValutati = $statoUI.RisultatiGrezzi.Count
            if ($nValutati -gt 0) {
                $ctrl.BtnEsportaJson.IsEnabled  = $true
                $ctrl.BtnEsportaHtml.IsEnabled  = $true
                $ctrl.BtnResocontoLLM.IsEnabled = $true
            }

            if ($null -ne $statoUI.SyncRunspace -and $statoUI.SyncRunspace.ErroreFatale) {
                $ctrl.TxtBannerErrore.Text = if ($isEnEnd) {
                    "An error occurred during the scan execution. Please retry or export the technical log."
                } else {
                    "Si e' verificato un problema durante l'esecuzione della scansione. Riprova o esporta il log tecnico."
                }
                $ctrl.BannerErrore.Visibility = [System.Windows.Visibility]::Visible
                $ctrl.TxtProgresso.Text = if ($isEnEnd) { "Stopped on error ($nValutati/$totaleControlli)" } else { "Interrotto per errore ($nValutati/$totaleControlli)" }
            }
            elseif ($null -ne $statoUI.SyncRunspace -and $statoUI.SyncRunspace.AnnullaRichiesto) {
                $ctrl.TxtProgresso.Text = if ($isEnEnd) { "Canceled ($nValutati/$totaleControlli)" } else { "Annullata ($nValutati/$totaleControlli)" }
                if ($nValutati -eq 0) {
                    $ctrl.TxtMessaggioGuida.Text = if ($isEnEnd) { "Scan canceled. Click 'Start Scan' to try again." } else { "Scansione annullata. Premi 'Avvia scansione' per riprovare." }
                }
            }
            else {
                $ctrl.TxtProgresso.Text = if ($isEnEnd) { "Completed ($nValutati/$nValutati)" } else { "Completata ($nValutati/$nValutati)" }
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
                    . (Join-Path $Sync.PercorsoChecks 'FileSecurity.ps1')
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
            $ctrl.TxtProgresso.Text = if ($statoUI.LinguaCorrente -eq 'EN') { "Canceling..." } else { "Annullamento in corso..." }
        }
    })

    # --- Export JSON ---
    $ctrl.BtnEsportaJson.Add_Click({
        if ($statoUI.RisultatiGrezzi.Count -eq 0) { return }
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')

        $dialogo = New-Object Microsoft.Win32.SaveFileDialog
        $dialogo.Title      = if ($isEn) { "Export JSON Report" } else { "Esporta report JSON" }
        $dialogo.Filter     = "JSON (*.json)|*.json"
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

            $ctrl.TxtRiepilogoFooter.Text = if ($isEn) {
                "Exported JSON: $(Split-Path -Leaf $dialogo.FileName)"
            } else {
                "Esportato JSON: $(Split-Path -Leaf $dialogo.FileName)"
            }
        }
    })

    # --- Export HTML ---
    $ctrl.BtnEsportaHtml.Add_Click({
        if ($statoUI.RisultatiGrezzi.Count -eq 0) { return }
        $isEn = ($statoUI.LinguaCorrente -eq 'EN')

        $dialogo = New-Object Microsoft.Win32.SaveFileDialog
        $dialogo.Title      = if ($isEn) { "Export HTML Report" } else { "Esporta report HTML" }
        $dialogo.Filter     = "HTML (*.html)|*.html"
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

            $ctrl.TxtRiepilogoFooter.Text = if ($isEn) {
                "Exported HTML: $(Split-Path -Leaf $dialogo.FileName)"
            } else {
                "Esportato HTML: $(Split-Path -Leaf $dialogo.FileName)"
            }
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

    # Inizializza lingua e pannello dettaglio vuoto
    & $applicaLinguaUI

    # Mostra la finestra modale
    [void]$finestra.ShowDialog()
}
