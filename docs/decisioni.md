# Decisioni architetturali

## D1 — Linguaggio e distribuzione (2026-11-17)

PowerShell 5.1 (Windows PowerShell), senza dipendenze esterne.
Distribuzione simile a winutil: un solo script lanciabile senza installare nulla.

## D2 — Sola lettura (2026-11-17)

Il collettore non modifica mai lo stato del sistema. Verbi PowerShell vietati:
Set-, New-, Remove-, Enable-, Disable-, Add-, Clear-, Start-, Stop-, Restart-,
Install-, Invoke-Expression. Scritture nel registro vietate.
L'unica scrittura ammessa e' il file di output scelto dall'utente.

## D3 — Rilevamento deterministico (2026-11-17)

I controlli di sicurezza sono deterministici: leggono lo stato del sistema e
confrontano con valori attesi. L'LLM (fase futura) servira' solo per spiegare
i risultati, non per decidere lo stato.

## D4 — Catalogo in YAML, runtime in JSON (2026-11-17)

Il catalogo dei controlli e' mantenuto in YAML (leggibile, con commenti) ma
PowerShell 5.1 non ha un parser YAML nativo. La conversione YAML -> JSON
avviene in fase di sviluppo tramite `tools/yaml_to_json.py`. Il runtime legge
solo il file JSON.

## D5 — Estensione schema a versione 0.2 (2026-11-17)

Lo schema del catalogo viene esteso alla versione 0.2 per supportare i campi
necessari all'esecuzione automatica dei controlli:

- `check.registry`: oggetto con campi `path`, `name`, `operator`
  (`eq`, `ne`, `ge`, `le`, `exists`, `notexists`), `value`. Permette al
  valutatore generico (`Registry.ps1`) di eseguire il controllo senza codice
  dedicato.
- `check.command_ref`: stringa nel formato `"NomeFile.ps1#Nome-Funzione"`,
  riferimento a una funzione in `src/core/Checks/`. Per controlli che
  richiedono logica complessa non esprimibile con un confronto su registro.

Motivazione: separare la descrizione del controllo (catalogo) dalla logica di
esecuzione (codice), rendendo l'aggiunta di nuovi controlli un'operazione
prevalentemente dichiarativa. Un nuovo controllo su registro richiede solo
l'aggiunta nel catalogo; uno con logica complessa richiede una funzione in
`Checks/` e il riferimento `command_ref`.

## D6 — Scelta di WPF (PresentationFramework) in PowerShell 5.1 per l'interfaccia grafica (2026-11-17)

Per l'interfaccia grafica (in stile winutil) viene scelto **WPF (`PresentationFramework`)** eseguito direttamente da Windows PowerShell 5.1 in modalita' `-STA`, con layout dichiarato in un file XAML separato (`src/ui/MainWindow.xaml`) caricato tramite `XamlReader` e logica di presentazione pura isolata in `src/ui/ViewModel.ps1`.

Motivazione:
- **Zero dipendenze esterne**: `PresentationFramework`, `PresentationCore` e `WindowsBase` sono preinstallati su tutte le edizioni di Windows 11 (Home e Pro), rispettando il vincolo di eseguibilita' immediata senza installare runtime aggiuntivi.
- **Scalabilita' DPI e accessibilita'**: a differenza di Windows Forms, WPF utilizza unita' indipendenti dai dispositivi (DIP) e layout fluidi (`Grid`, `UniformGrid`, `WrapPanel`, `ScrollViewer`) che scalano nitidamente a 100%, 125% e 150% di DPI, oltre a supportare dizionari di risorse dinamici (`DynamicResource`) per il cambio istantaneo tra Tema Chiaro e Tema Scuro.
- **Reattivita' e testabilita'**: l'esecuzione della scansione in un `[runspace]` separato con aggiornamento tramite `Dispatcher` evita il blocco della finestra, mentre l'isolamento delle funzioni pure nel `ViewModel.ps1` consente il test automatizzato con Pester 5 senza dover istanziare la finestra grafica.

## D7 — Script singolo autonomo (`dist/scanner-win11.ps1`) e distribuzione stile winutil (2026-11-17)

Per consentire l'esecuzione da qualsiasi cartella o direttamente da GitHub tramite `irm <url> | iex` (senza dover clonare l'intero repository), viene introdotto lo script di build `tools/Build.ps1` che compila catalogo JSON, XAML, motore, i 18 controlli e la GUI in un unico file autonomo `dist/scanner-win11.ps1`.
Il Runspace di scansione riceve le funzioni caricate in memoria tramite `InitialSessionState`, eliminando la dipendenza da file esterni sul disco a runtime.
