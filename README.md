# Windows 11 Security Scanner (PowerShell 5.1 & WPF)

> **Read-only, zero-dependency security configuration scanner for Windows 11 (Home & Pro), inspired by [winutil](https://github.com/ChrisTitusTech/winutil).**  
> Built natively for Windows PowerShell 5.1 with a responsive WPF graphical interface (Light/Dark theme) and a headless JSON/HTML reporting engine.

---

## Quick Launch (Run from anywhere via PowerShell)

Open **PowerShell** (recommended: *Run as Administrator*) and run:

```powershell
irm https://raw.githubusercontent.com/elvys9/Scanner-sicurezza-powershell/main/dist/scanner-win11.ps1 | iex
```

---

## Overview (English)

**Windows 11 Security Scanner** is a deterministic, **100% read-only** security auditing tool designed for home and prosumer Windows 11 systems:
- **Zero Installation & Zero External Dependencies**: runs natively on built-in Windows PowerShell 5.1 and `.NET Framework` (`PresentationFramework` WPF). No external modules or internet connections required at runtime.
- **Strictly Read-Only**: the scanner **never modifies** system settings, registry keys, or services (enforced via AST static analysis tests). Remediation PowerShell commands are provided strictly for reference and one-click clipboard copy.
- **Winutil-Style Single-Script Execution**: launch the GUI from any directory or directly from GitHub via `irm ... | iex`.
- **Responsive WPF GUI**:
  - Asynchronous background `Runspace` execution (UI never freezes, clean **Cancel** support).
  - Instant **Light / Dark Theme** switching and DPI scaling (100%, 125%, 150%).
  - Combinable filters (Status, Severity, Category, Text search) and priority sorting (Failed checks by severity first).
  - Dual explanation mode (**Simple** for home users / **Technical** with CIS Benchmark references & JSON evidence).
- **Export Capabilities**: exports machine-readable **JSON** (UTF-8 without BOM, schema v0.1) and standalone self-contained **HTML** reports with embedded CSS.

---

## Panoramica e Stato Attuale (Italiano)

Scanner di sicurezza deterministico in **sola lettura** per Windows 11 (Home/Pro), pensato per utenti domestici e distribuibile come singolo script PowerShell 5.1 senza installare nulla.

### Tutti i 18 controlli di sicurezza implementati (Profilo v0.2)

| ID            | Categoria          | Descrizione                                                    | Tipo      |
|---------------|--------------------|----------------------------------------------------------------|-----------|
| `HOME-FW-001` | Firewall           | Firewall di Windows attivo su tutti i profili (Domain, Private, Public) | Funzione |
| `HOME-UAC-001`| UAC                | UAC abilitato (`EnableLUA = 1`)                                | Registro  |
| `HOME-UAC-002`| UAC                | UAC richiede conferma per elevazione (`ConsentPromptBehaviorAdmin != 0`) | Registro |
| `HOME-UAC-003`| UAC                | UAC rileva installazioni applicazioni (`EnableInstallerDetection = 1`) | Registro |
| `HOME-ACC-001`| Account            | Account Guest disabilitato (`SID -501`)                        | Funzione  |
| `HOME-ACC-002`| Account            | Account Administrator predefinito disabilitato (`SID -500`)    | Funzione  |
| `HOME-ACC-003`| Account            | Nessun account locale attivo senza password (`PasswordRequired`) | Funzione |
| `HOME-UPD-001`| Aggiornamenti      | Aggiornamenti automatici Windows Update abilitati (`wuauserv`) | Funzione  |
| `HOME-AV-001` | Antivirus          | Protezione in tempo reale Windows Defender attiva              | Funzione  |
| `HOME-AV-002` | Antivirus          | Definizioni antivirus aggiornate (`<= 7 giorni`)               | Funzione  |
| `HOME-RDP-001`| Desktop Remoto     | Desktop remoto disabilitato (`fDenyTSConnections = 1`)         | Registro  |
| `HOME-NET-001`| Rete               | Protocollo SMBv1 disabilitato                                  | Funzione  |
| `HOME-NET-002`| Rete               | NetBIOS su TCP/IP disabilitato (`NetbiosOptions = 2`)          | Funzione  |
| `HOME-ENC-001`| Crittografia       | Crittografia BitLocker attiva sul disco di sistema             | Funzione  |
| `HOME-PRV-001`| Privacy            | Telemetria impostata al livello minimo (`AllowTelemetry <= 1`) | Funzione  |
| `HOME-SEC-001`| Sicurezza Avanzata | Avvio protetto UEFI (Secure Boot) attivo                       | Funzione  |
| `HOME-SEC-002`| Sicurezza Avanzata | Protezione LSA (`RunAsPPL`) abilitata                          | Funzione  |
| `HOME-SEC-003`| Sicurezza Avanzata | PowerShell Script Block Logging abilitato                      | Funzione  |

---

## Modalita' di Esecuzione / Usage

```powershell
# 1. Esecuzione diretta da GitHub (da qualsiasi cartella, in stile winutil):
irm https://raw.githubusercontent.com/elvys9/Scanner-sicurezza-powershell/main/dist/scanner-win11.ps1 | iex

# 2. Esecuzione dello script singolo autonomo locale da qualsiasi cartella:
powershell -STA -ExecutionPolicy Bypass -File "dist\scanner-win11.ps1"

# 3. Avvio dai sorgenti del progetto (GUI):
powershell -STA -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1

# 4. Modalita' Headless (scrive il report JSON su file):
powershell -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1 -Headless -OutFile out.json
```

### Parametri

| Parametro    | Descrizione                                                       |
|--------------|-------------------------------------------------------------------|
| `-Gui`       | Avvia l'interfaccia grafica WPF (predefinito senza `-Headless`)   |
| `-Headless`  | Modalita' senza interfaccia, scrive JSON su file                  |
| `-OutFile`   | Percorso del file JSON di output (obbligatorio con `-Headless`)   |
| `-ControlId` | Uno o piu' ID di controllo da eseguire                            |

---

## Architettura del Repository

```
dist/
  scanner-win11.ps1        script singolo autonomo compilato (stile winutil)
src/
  Invoke-Scanner.ps1       punto d'ingresso (-Gui / -Headless)
  core/
    Catalog.ps1            carica e valida il catalogo JSON
    Environment.ps1        rileva edizione, build, lingua, admin, versione PS
    Runner.ps1             esegue i controlli (isolamento errori, hook progresso/annulla)
    Report.ps1             costruisce il risultato e scrive JSON / HTML / Log
    Checks/
      Registry.ps1         valutatore generico per controlli su registro
      Firewall.ps1         controllo firewall (profili Domain, Private, Public)
      Accounts.ps1         controlli account Guest (-501), Admin (-500), PasswordRequired
      Defender.ps1         controlli protezione in tempo reale e firme Windows Defender
      Network.ps1          controlli SMBv1 e NetBIOS su TCP/IP
      SystemSecurity.ps1   controlli Windows Update, BitLocker, Telemetria, Secure Boot, LSA, PS Logging
  ui/
    MainWindow.xaml        layout e stili WPF (tema chiaro e scuro)
    Start-ScannerUI.ps1    costruisce la finestra, gestisce eventi e Runspace asincrono
    ViewModel.ps1          funzioni pure: filtri, ordinamento, conteggi, dettaglio
catalog/
  home_profile.yaml        catalogo sorgente (YAML)
  home_profile.json        catalogo runtime (JSON, generato)
  schema.json              schema di validazione (v0.2)
tools/
  Build.ps1                compila i moduli in dist/scanner-win11.ps1
  yaml_to_json.py          conversione YAML -> JSON + validazione schema
tests/
  *.Tests.ps1              91 test Pester 5 (core, sola lettura AST, ViewModel, 18 controlli, integrazione)
docs/
  decisioni.md             decisioni architetturali (D1-D7)
  diario_sperimentale.md   diario delle attivita'
  ui.md                    design della GUI e checklist di collaudo manuale
```

---

## Sviluppo e Test

```powershell
# Rigenerare il catalogo JSON dal sorgente YAML
python tools/yaml_to_json.py

# Ricompilare lo script singolo autonomo dist/scanner-win11.ps1
powershell -ExecutionPolicy Bypass -File tools\Build.ps1

# Eseguire tutti i 91 test Pester 5
Invoke-Pester tests -Output Detailed
```
