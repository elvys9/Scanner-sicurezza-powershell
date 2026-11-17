# Scanner di Sicurezza per Windows 11

Scanner di sicurezza in sola lettura per Windows 11 (Home/Pro), pensato per utenti domestici.
Scritto in PowerShell 5.1, distribuibile come singolo script senza installare nulla.

## Stato attuale

**Profilo completo v0.2** — tutti i **18 controlli** del profilo Windows 11 (Home/Pro) implementati e testati (91 test Pester):

| ID            | Categoria          | Descrizione                                        | Tipo      |
|---------------|--------------------|----------------------------------------------------|-----------|
| HOME-FW-001   | Firewall           | Firewall attivo su tutti i profili                 | Funzione  |
| HOME-UAC-001  | UAC                | UAC abilitato (`EnableLUA = 1`)                    | Registro  |
| HOME-UAC-002  | UAC                | UAC richiede conferma (`ConsentPromptBehaviorAdmin != 0`) | Registro |
| HOME-UAC-003  | UAC                | UAC rileva installazioni (`EnableInstallerDetection = 1`) | Registro |
| HOME-ACC-001  | Account            | Account Guest disabilitato (SID `-501`)            | Funzione  |
| HOME-ACC-002  | Account            | Account Administrator locale disabilitato (SID `-500`) | Funzione |
| HOME-ACC-003  | Account            | Nessun account locale attivo senza password        | Funzione  |
| HOME-UPD-001  | Aggiornamenti      | Aggiornamenti automatici Windows Update abilitati  | Funzione  |
| HOME-AV-001   | Antivirus          | Protezione in tempo reale Windows Defender attiva  | Funzione  |
| HOME-AV-002   | Antivirus          | Definizioni antivirus aggiornate (<= 7 giorni)     | Funzione  |
| HOME-RDP-001  | Desktop Remoto     | Desktop remoto disabilitato (`fDenyTSConnections = 1`) | Registro |
| HOME-NET-001  | Rete               | Protocollo SMBv1 disabilitato                      | Funzione  |
| HOME-NET-002  | Rete               | NetBIOS su TCP/IP disabilitato                     | Funzione  |
| HOME-ENC-001  | Crittografia       | BitLocker attivo sul disco di sistema              | Funzione  |
| HOME-PRV-001  | Privacy            | Telemetria impostata al livello minimo (`<= 1`)    | Funzione  |
| HOME-SEC-001  | Sicurezza Avanzata | Avvio protetto UEFI (Secure Boot) attivo           | Funzione  |
| HOME-SEC-002  | Sicurezza Avanzata | Protezione LSA (`RunAsPPL`) abilitata              | Funzione  |
| HOME-SEC-003  | Sicurezza Avanzata | PowerShell Script Block Logging abilitato          | Funzione  |

## Uso rapido (anche fuori dalla cartella o da GitHub, in stile winutil)

```powershell
# 1. Esecuzione diretta da GitHub (da qualsiasi cartella, in stile winutil):
irm https://raw.githubusercontent.com/<TUO-UTENTE>/<TUO-REPO>/main/dist/scanner-win11.ps1 | iex

# 2. Esecuzione dello script singolo autonomo locale da qualsiasi cartella:
powershell -STA -ExecutionPolicy Bypass -File "C:\percorso\dist\scanner-win11.ps1"

# 3. Avvio dai sorgenti del progetto (GUI):
powershell -STA -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1

# 4. Modalita' Headless (scrive il report JSON su file):
powershell -ExecutionPolicy Bypass -File dist\scanner-win11.ps1 -Headless -OutFile out.json
```

### Parametri

| Parametro    | Descrizione                                                       |
|--------------|-------------------------------------------------------------------|
| `-Gui`       | Avvia l'interfaccia grafica WPF (predefinito senza `-Headless`)   |
| `-Headless`  | Modalita' senza interfaccia, scrive JSON su file                  |
| `-OutFile`   | Percorso del file JSON di output (obbligatorio con `-Headless`)   |
| `-ControlId` | Uno o piu' ID di controllo da eseguire                            |

## Architettura

```
src/
  Invoke-Scanner.ps1       punto d'ingresso (-Gui / -Headless)
  core/
    Catalog.ps1            carica il catalogo JSON
    Environment.ps1        rileva edizione, build, lingua, admin, versione PS
    Runner.ps1             esegue i controlli (isolamento errori, hook progresso/annulla)
    Report.ps1             costruisce il risultato e scrive JSON / HTML / Log
    Checks/
      Registry.ps1         valutatore generico per controlli su registro
      Firewall.ps1         controllo firewall
      Accounts.ps1         controllo account Guest
  ui/
    MainWindow.xaml        layout e stili WPF (tema chiaro e scuro)
    Start-ScannerUI.ps1    costruisce la finestra, gestisce eventi e Runspace asincrono
    ViewModel.ps1          funzioni pure: filtri, ordinamento, conteggi, dettaglio
catalog/
  home_profile.yaml        catalogo sorgente (YAML)
  home_profile.json        catalogo runtime (JSON, generato)
  schema.json              schema di validazione
tools/
  yaml_to_json.py          conversione YAML -> JSON + validazione
tests/
  *.Tests.ps1              test Pester 5 (core, sola lettura AST, ViewModel, integrazione)
docs/
  decisioni.md             decisioni architetturali (D1-D6)
  diario_sperimentale.md   diario delle attivita'
  ui.md                    design della GUI e checklist di collaudo manuale
```

## Sviluppo

### Rigenerare il catalogo JSON

```bash
python tools/yaml_to_json.py
```

### Eseguire i test

```powershell
Invoke-Pester tests -Output Detailed
```

## Vincoli di progetto

- **Sola lettura**: il collettore non modifica mai lo stato del sistema
- **Nessuna dipendenza**: solo cmdlet inclusi in Windows 11
- **Nessuna rete**: nessuna chiamata di rete
- **PowerShell 5.1**: compatibile con Windows PowerShell, niente sintassi PS 7
- **Deterministico**: il rilevamento non usa LLM; l'LLM (fase futura) spieghera' soltanto

## Licenza

Progetto di tirocinio — uso interno.
