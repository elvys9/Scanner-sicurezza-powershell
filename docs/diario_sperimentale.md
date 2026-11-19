# Experimental Development Log

## 2026-11-17 - Initial Vertical Slice

### Goal
Build the project structure and a working vertical slice with three initial controls:
`HOME-FW-001` (Firewall), `HOME-UAC-001` (UAC), and `HOME-ACC-001` (Guest account).

### Completed Work
- Created repository directory layout (`catalog/`, `src/`, `tests/`, `tools/`, `docs/`, `dist/`).
- Authored `catalog/home_profile.yaml` (initial 18 controls) and `catalog/schema.json` v0.2 (decision D5).
- Implemented core engine: `Catalog.ps1`, `Environment.ps1`, `Runner.ps1`, `Report.ps1`.
- Implemented initial check modules (`Firewall.ps1`, `Registry.ps1`, `Accounts.ps1`).
- Created entry point `src/Invoke-Scanner.ps1` supporting `-Headless`, `-OutFile`, and `-ControlId`.
- Added `tools/yaml_to_json.py` for YAML -> JSON conversion and validation.
- Added Pester 5 unit and read-only AST tests.

### Technical Notes
- PowerShell 5.1 encoding: source `.ps1`/`.xaml` files use UTF-8 with BOM; JSON reports and `dist/*.ps1` bundles use UTF-8 without BOM.
- Built-in Guest (`-501`) and Administrator (`-500`) accounts are matched by SID suffix rather than localized display names.
- `Set-StrictMode -Version 2`: optional properties on `PSCustomObject` are guarded via `.PSObject.Properties['name']`.
- Non-admin execution: insufficient privileges for CIM or local accounts cleanly return `sconosciuto` (Unknown), never `errore` or `fallito`.
- Pester 5+: dot-sourcing modules inside `BeforeAll` ensures proper scope isolation between Discovery and Run phases.

## 2026-11-17 - Winutil-Style WPF GUI

### Goal
Build a read-only WPF graphical interface in PowerShell 5.1 (`src/ui/`) reusing the headless engine, with background Runspace scanning, combinable filters, Light/Dark themes, JSON/HTML export, and Pester 5 ViewModel tests.

### Completed Work
- Extended `src/core/Runner.ps1` with optional `-OnProgress` and `-ShouldCancel` hooks.
- Extended `src/core/Report.ps1` with `ConvertTo-ReportHtml`, `Export-ReportHtml`, and `Export-TechnicalLog`.
- Created pure presentation layer `src/ui/ViewModel.ps1`, XAML layout `src/ui/MainWindow.xaml`, and controller `src/ui/Start-ScannerUI.ps1`.
- Added `-Gui` (default) and automatic `-STA` apartment check to `src/Invoke-Scanner.ps1`.
- Added `tests/ViewModel.Tests.ps1` and updated `tests/ReadOnly.Tests.ps1` allowlists for `src/ui/`.

## 2026-11-17 to 2026-11-19 - Baseline Expansion (58 Controls), AI Advisor & TUI

### Completed Work
- Expanded catalog to **58 read-only controls** aligned with Microsoft Security Baselines (Windows 11 24H2/25H2/26H2), CIS Windows 11 Benchmark, HardeningKitty, and MITRE ATT&CK (including HVCI runtime check, ASR rules, TPM 2.0, Smart App Control, Vulnerable Driver Blocklist, WSH, ExecutionPolicy, Administrator Protection, WMI Event Subscriptions, and Browser Forced Extensions).
- Added local Ollama AI Advisor (`src/core/OllamaClient.ps1`) with deterministic local expert fallback.
- Added interactive console TUI fallback for SSH / non-interactive terminal sessions (`-Cli`).
- Built standalone single-file distributions via `tools/Build.ps1`: `dist/scanner-win11.ps1` (IT), `dist/scanner-win11-en.ps1` (EN), and `dist/scanner-win11-de.ps1` (DE).
- Standardized catalog, code comments, documentation, and test suite in technical English with full Pester 5 coverage.
