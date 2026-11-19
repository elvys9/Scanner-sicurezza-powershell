# Architectural Decisions

## D1 - Language and Distribution (2026-11-17)

Windows PowerShell 5.1 with zero external dependencies.
Distributed in a winutil-like single-script model runnable without installation.

## D2 - Strictly Read-Only (2026-11-17)

The collector never modifies system state. Forbidden PowerShell verbs in `src/`:
`Set-`, `New-`, `Remove-`, `Enable-`, `Disable-`, `Add-`, `Clear-`, `Start-`, `Stop-`, `Restart-`,
`Install-`, `Invoke-Expression`. Registry writes are prohibited.
The only permitted writes are user-requested export files (JSON, HTML, technical log).

## D3 - Deterministic Detection (2026-11-17)

Security controls are deterministic: they read live system state and compare it
against expected baseline values. The local LLM (Ollama) is used solely to explain
results and prioritize remediation—never to determine control pass/fail status.

## D4 - YAML Source Catalog, JSON Runtime (2026-11-17)

The security controls catalog is authored in YAML (`catalog/home_profile.yaml`) for readability
and comments, while Windows PowerShell 5.1 lacks a native YAML parser. Conversion from YAML to
JSON happens at development time via `tools/yaml_to_json.py`. The runtime loads only JSON.

## D5 - Schema Extension to Version 0.2 (2026-11-17)

The catalog schema is extended to version `0.2` to support declarative and function-based checks:

- `check.registry`: object with fields `path`, `name`, `operator`
  (`eq`, `ne`, `ge`, `le`, `exists`, `notexists`), and `value`. Allows the generic
  evaluator (`Registry.ps1`) to evaluate registry checks without dedicated code.
- `check.command_ref`: string formatted as `"FileName.ps1#Function-Name"`,
  referencing a function in `src/core/Checks/` for complex checks that cannot be
  expressed as a single registry comparison.

Rationale: decouples control metadata (catalog) from execution logic (code), making
most new registry controls purely declarative.

## D6 - WPF (PresentationFramework) on PowerShell 5.1 for the GUI (2026-11-17)

The graphical interface uses **WPF (`PresentationFramework`)** running directly on Windows
PowerShell 5.1 in `-STA` mode, with layout declared in `src/ui/MainWindow.xaml` loaded via
`XamlReader` and pure presentation logic isolated in `src/ui/ViewModel.ps1`.

Rationale:
- **Zero external dependencies**: `PresentationFramework`, `PresentationCore`, and `WindowsBase` ship pre-installed on all Windows 11 editions (Home and Pro).
- **DPI scaling and accessibility**: WPF uses device-independent pixels (DIPs), responsive layouts (`Grid`, `UniformGrid`, `ScrollViewer`), and `DynamicResource` dictionaries for instant Light/Dark theme switching.
- **Responsiveness and testability**: scanning runs in a dedicated `[runspace]` with `Dispatcher` updates to keep the UI responsive, while pure functions in `ViewModel.ps1` are unit-tested in Pester 5 without instantiating WPF windows.

## D7 - Standalone Single-File Bundles (`dist/scanner-win11*.ps1`) (2026-11-17)

To enable execution from any directory or directly from GitHub via `irm <url> | iex` without
cloning the repository, `tools/Build.ps1` compiles the JSON catalog, XAML layout, core engine,
all security checks, and the WPF/TUI UI into standalone scripts (`dist/scanner-win11.ps1`,
`dist/scanner-win11-en.ps1`, `dist/scanner-win11-de.ps1`).
The scan runspace receives in-memory functions via `InitialSessionState`, removing any runtime
dependency on external files on disk.
