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
