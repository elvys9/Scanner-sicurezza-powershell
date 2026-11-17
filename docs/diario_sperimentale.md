# Diario sperimentale

## 2026-11-17 — Fetta verticale iniziale

### Obiettivo
Costruire la struttura del progetto e una fetta verticale funzionante con tre
controlli: HOME-FW-001 (firewall), HOME-UAC-001 (UAC), HOME-ACC-001 (Guest).

### Attivita' svolte
- Creata la struttura di directory del progetto
- Scritto il catalogo `home_profile.yaml` con 18 controlli e lo schema
  `schema.json` v0.2 (decisione D5)
- Implementato il motore: Catalog.ps1, Environment.ps1, Runner.ps1, Report.ps1
- Implementati i tre controlli della fetta:
  - `Firewall.ps1` — stato dei tre profili via Get-NetFirewallProfile
  - `Registry.ps1` — valutatore generico per controlli su registro
  - `Accounts.ps1` — account Guest via SID -501
- Scritto il punto d'ingresso `Invoke-Scanner.ps1` con parametri -Headless,
  -OutFile, -ControlId
- Scritto `yaml_to_json.py` per la conversione YAML -> JSON
- Scritti i test Pester 5

### Decisioni
- Vedi docs/decisioni.md, decisione D5 (estensione schema 0.2)

### Note
- PowerShell 5.1: attenzione alla codifica dei file (UTF-8 con BOM per .ps1)
- Il file JSON di output e' UTF-8 senza BOM
- L'account Guest si identifica con il SID che termina in -501, non con il nome
- Set-StrictMode -Version 2: accesso a proprieta' facoltative su PSCustomObject protetto tramite `.PSObject.Properties['nome']`
- Esecuzione non-admin: se mancano privilegi per CIM o account locali, lo stato e' correttamente classificato come `sconosciuto` (non `errore` o `fallito`)
- Test Pester 5+: il dot-sourcing dei moduli nei test deve avvenire dentro i blocchi `BeforeAll` per evitare problemi di scope tra fase di Discovery e Run

## 2026-11-17 — Interfaccia grafica WPF in stile winutil

### Obiettivo
Realizzare l'interfaccia grafica WPF in PowerShell 5.1 (`src/ui/`) in sola lettura, riusando lo stesso motore della modalita' `-Headless`, con scansione in Runspace separato, filtri combinabili, tema chiaro/scuro, export JSON/HTML e test Pester 5 sul ViewModel.

### Attivita' svolte
- Esteso `src/core/Runner.ps1` con i parametri opzionali `-OnProgress` e `-ShouldCancel` mantenendo la piena retrocompatibilita'
- Esteso `src/core/Report.ps1` con `ConvertTo-ReportHtml`, `Export-ReportHtml` (HTML autonomo con CSS incorporato) ed `Export-TechnicalLog`
- Creato `src/ui/ViewModel.ps1` con funzioni pure (senza dipendenze WPF) per unione catalogo/risultati, ordinamento predefinito, filtri combinabili, conteggi e formattazione del pannello di dettaglio
- Creato `src/ui/MainWindow.xaml` con layout ridimensionabile (min 900x600), supporto DPI 100%/125%/150%, navigazione da tastiera e risorse dinamiche per tema chiaro/scuro
- Creato `src/ui/Start-ScannerUI.ps1` con caricamento `XamlReader`, gestione eventi tramite `FindName`, esecuzione della scansione in un `[runspace]` separato con aggiornamento via `Dispatcher`, pulsante `Annulla`, copia negli appunti e riavvio come amministratore
- Aggiornato `src/Invoke-Scanner.ps1` aggiungendo il parametro `-Gui` (predefinito quando non si specifica `-Headless`) e il controllo automatico dell'ApartmentState `STA`
- Scritti i test unitari in `tests/ViewModel.Tests.ps1` e aggiornato `tests/ReadOnly.Tests.ps1` con la lista esplicita e commentata dei comandi consentiti per `src/ui`
- Redatta la documentazione e checklist di collaudo manuale in `docs/ui.md` e la decisione `D6` in `docs/decisioni.md`
