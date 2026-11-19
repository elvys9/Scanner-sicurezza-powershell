# Graphical User Interface (WPF) - Design & Manual Verification

## 1. Objective & Design Philosophy

The Windows 11 Security Scanner GUI follows a **winutil-style** architecture:
- **Zero installation**: uses only native WPF (`PresentationFramework`) built into Windows 11 and Windows PowerShell 5.1.
- **Strict separation between View and Engine**: the UI contains no security evaluation logic. It invokes `Invoke-Controlli` and `New-Report` from `src/core` and delegates sorting, filtering, summary counters, and detail formatting to pure functions in `src/ui/ViewModel.ps1`.
- **Guaranteed read-only mode**: no button modifies Windows configuration or automatically applies remediation. Users can inspect results, copy reference commands to the clipboard, export reports (JSON/HTML/log), or relaunch elevated as Administrator.

---

## 2. Screen Layout Overview

### 2.1 Initial Startup (Non-Administrator, Before Scan)

```
+----------------------------------------------------------------------------------+
| [Lock] Windows 11 Security Scanner (READ-ONLY) [Win 11 Pro | Admin: No] [Lang][Theme]|
+----------------------------------------------------------------------------------+
| [!] Non-administrator session: some controls will report 'Unknown'.              |
|                                                         [Relaunch as Admin]      |
+----------------------------------------------------------------------------------+
| [1. Security Controls] [2. AI Advisor] [Start Scan] [Cancel] [----] Ready (0/58) |
+----------------------------------------------------------------------------------+
| [ [OK] 0 Passed ] [ [X] 0 Failed ] [ [?] 0 Unknown ] [ [-] 0 N/A ] [ [!] 0 Err ] |
+----------------------------------------------------------------------------------+
| Status: [All v]  Severity: [All v]  Category: [All v]  Search: [________] [Reset]|
+-----------------------------------------------+----------------------------------+
|                                               | CONTROL DETAILS                  |
|                                               | No control selected              |
|            [Magnifier Icon]                   | ID: - | Status: - | Severity: -  |
|   Click 'Start Scan' to audit Windows 11      | [Simple View] [Technical Details]|
|        security configurations.               | Why it matters:                  |
|   The scanner operates strictly in read-only  | Select a row in the table        |
|   mode and modifies no Windows settings.      | Expected: - | Observed: -        |
|                                               | How to Remediate: -              |
|                                               | [Explain with AI (Page 2)]       |
+-----------------------------------------------+----------------------------------+
| [Export JSON] [Export HTML] [ ] Include technical log    Summary: 0 evaluated    |
| Permanent Notice: a compliant audit does not guarantee absence of compromise.    |
+----------------------------------------------------------------------------------+
```

---

## 3. Key Design Choices

1. **Visual accessibility (never color alone)**: every status combines a textual symbol (`[OK]`, `[X]`, `[?]`, `[-]`, `[!]`), a localized text label (`Passed`, `Failed`, `Unknown`, `N/A`, `Error`), and high-contrast color tokens.
2. **Priority-first sorting**: failed controls appear first ordered by descending severity (`Critical` -> `High` -> `Medium` -> `Low` -> `Info`), followed by `Error`/`Unknown`, `Passed`, and `N/A`.
3. **Dual explanation mode (`Simple` / `Technical`)**:
   - **Simple View** displays the user-friendly `rationale`.
   - **Technical Details** displays `description`, control ID, applicable editions, check duration (ms), collected JSON evidence, and compliance references (CIS Benchmark, Microsoft Security Baseline, MITRE ATT&CK).
4. **Responsiveness via Runspace & Dispatcher**: scanning executes in a background `[runspace]`. After each control, `Runner.ps1` invokes `-OnProgress`, marshaling UI updates through `$Window.Dispatcher.Invoke(...)` without blocking resizing or cancellation.
5. **DPI scaling & scrolling (100%, 125%, 150%)**: responsive `Grid` proportions (`*`/`Auto`), `UniformGrid`, horizontal/vertical scrollbars on `GridRisultati`, and vertical `ScrollViewer` in the details panel.

---

## 4. Manual Verification Checklist (Windows 11 VM)

Run the following verification checks on a Windows 11 (Home or Pro) virtual machine:

- [ ] **1. Fast launch (< 3 seconds)**:
  - Run `powershell -STA -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1`.
  - Verify the window opens quickly with the empty-state prompt visible.
- [ ] **2. Non-Admin Behavior**:
  - Launch from a standard (non-elevated) PowerShell terminal.
  - Verify `Admin: No` appears in the header and the yellow warning banner with **"Relaunch as Administrator"** is displayed.
  - Verify privilege-restricted controls report `[?] Unknown` rather than `[X] Failed`.
- [ ] **3. Live Scan & Responsiveness**:
  - Click **"Start Scan"** and confirm real-time progress bar updates, live KPI counter increments, and smooth window resizing.
- [ ] **4. Cancellation**:
  - Start a scan and immediately click **"Cancel"**; confirm clean stop without errors or UI freeze.
- [ ] **5. Combined Filters & Search**:
  - Combine Status, Severity, Category, and Search text filters, then click **"Reset Filters"**.
- [ ] **6. Details Panel & Copy Command**:
  - Switch between **Simple View** and **Technical Details**, verify copy-to-clipboard works, and verify controls without a command hide the command box.
- [ ] **7. JSON / HTML Export & Technical Log**:
  - Export both JSON and HTML reports, open the HTML report offline in a browser, and verify `.log` generation when the technical log checkbox is enabled.
- [ ] **8. Theme & Language Switching**:
  - Toggle **Light / Dark** theme and switch between **IT / EN / DE** languages; verify labels and contrast update cleanly.
- [ ] **9. Horizontal & Vertical Scrolling**:
  - Resize the window to non-fullscreen dimensions and verify the horizontal scrollbar on the results table allows reading full control titles and IDs without clipping.
