# Windows 11 Security Scanner (PowerShell 5.1 & WPF + Local Ollama AI)

> **A zero-dependency, 100% read-only security configuration, antivirus, and suspicious file scanner for Windows 11 (Home & Pro), inspired by [winutil](https://github.com/ChrisTitusTech/winutil).**  
> Built natively for Windows PowerShell 5.1 with a modernized two-page Fluent WPF graphical interface (Dark/Light themes, explicit `IT` / `EN` / `DE` language selector), **64 deterministic CIS & MITRE ATT&CK aligned checks**, and an integrated **Local AI Security Advisor powered by Ollama**.

---

## 🚀 Quick Start — Run Directly in PowerShell (No Installation Needed)

Open **Windows PowerShell** (recommended: **Run as Administrator**) from any folder and paste one of the commands below:

### Option 1: Launch in English (`EN` default)
```powershell
irm https://raw.githubusercontent.com/elvys9/Powershell-Vulnerability-Scanner/main/dist/scanner-win11-en.ps1 | iex
```

### Option 2: Launch in Italian (`IT` default)
```powershell
irm https://raw.githubusercontent.com/elvys9/Powershell-Vulnerability-Scanner/main/dist/scanner-win11.ps1 | iex
```

### Option 3: Launch in German (`DE` default)
```powershell
irm https://raw.githubusercontent.com/elvys9/Powershell-Vulnerability-Scanner/main/dist/scanner-win11-de.ps1 | iex
```

*(Note: Inside the GUI you can switch at any time between **Italian (`[*] IT Italiano`)**, **English (`[*] EN English`)**, and **German (`[*] DE Deutsch`)**, as well as between **Dark** and **Light** themes with a single click in the top header).*

---

## ✨ Key Features

- **100% Read-Only & Deterministic**: The scanner **never modifies** system settings, registry keys, or services (enforced via automated PowerShell AST static analysis tests). All 64 checks are evaluated deterministically; the AI only explains results and recommends prioritized fixes.
- **Zero External Runtime Dependencies**: Runs out-of-the-box on Windows 11 using built-in Windows PowerShell 5.1 and `.NET Framework` (`PresentationFramework` WPF).
- **Two-Page Full-Screen WPF Interface**:
  1. **Page 1 — Security Controls & Technical Details**: Filterable table of 64 security controls (Status, Severity, Category, Search), live progress bar, KPI summary cards, and step-by-step remediation guidance with one-click copyable PowerShell commands.
  2. **Page 2 — Full-Screen Local AI Security Advisor (Ollama)**: Dedicated full-screen workspace that analyzes all failed controls and generates an executive security report and prioritized remediation plan.
- **Zero-Touch Ollama Auto-Setup (Works on VMs too)**:
  - Automatically detects a local Ollama instance (`127.0.0.1:11434`) or a VM Host gateway (`10.0.2.2:11434`).
  - If Ollama is not installed on the machine/VM, the scanner can **silently download, install, and start Ollama + the lightweight `qwen2.5:0.5b` model (~390 MB) in the background** without manual user intervention, while immediately providing a built-in expert fallback report.
- **JSON & Standalone HTML Export**: Exports machine-readable JSON reports (UTF-8 without BOM) and standalone HTML reports with embedded CSS.

---

## 🛡️ All 64 Implemented Security Controls

| ID             | Category          | Security Check Description                                                  | Type     |
|----------------|-------------------|-----------------------------------------------------------------------------|----------|
| `HOME-FW-001`  | Firewall          | Windows Defender Firewall enabled across all profiles (`DefaultInboundAction != Allow`) | Function |
| `HOME-UAC-001` | UAC               | User Account Control (UAC) enabled (`EnableLUA = 1`)                        | Registry |
| `HOME-UAC-002` | UAC               | UAC elevation prompt required on Secure Desktop (`ConsentPromptBehaviorAdmin in 1,2,5` & `PromptOnSecureDesktop = 1`) | Function |
| `HOME-UAC-003` | UAC               | UAC application installer detection enabled (`EnableInstallerDetection = 1`) | Registry |
| `HOME-UAC-004` | UAC               | Windows 11 Administrator Protection (`TypeOfAdminApprovalMode = 2`) enabled | Function |
| `HOME-ACC-001` | Accounts          | Built-in Guest account disabled (`SID -501`)                                | Function |
| `HOME-ACC-002` | Accounts          | Built-in local Administrator account disabled (`SID -500`)                  | Function |
| `HOME-ACC-003` | Accounts          | No active local user accounts without a password (`PasswordRequired = True` or `MicrosoftAccount`) | Function |
| `HOME-ACC-004` | Accounts          | Account lockout policy active against brute-force attacks (`1..10` attempts) | Function |
| `HOME-ACC-005` | Accounts          | Local Administrators group members minimized (`<= 2` active admins)         | Function |
| `HOME-UPD-001` | Updates           | Windows Update automatic updates enabled (`wuauserv` not disabled)          | Function |
| `HOME-UPD-002` | Updates           | Authentic Windows Update server (no unauthorized WSUS redirection)          | Function |
| `HOME-AV-001`  | Antivirus         | Windows Defender Real-Time Protection enabled                               | Function |
| `HOME-AV-002`  | Antivirus         | Windows Defender antivirus signatures up to date (`<= 7 days`)              | Function |
| `HOME-AV-003`  | Antivirus         | Zero active malware or virus threats detected by Windows Defender           | Function |
| `HOME-AV-004`  | Antivirus         | Downloaded files scanning (`IOAV`) and Behavior Monitoring enabled          | Function |
| `HOME-AV-005`  | Antivirus         | Potentially Unwanted Application (`PUAProtection = 1`) blocking enabled     | Function |
| `HOME-AV-006`  | Antivirus         | Defender Tamper Protection and Cloud `MAPS` protection enabled              | Function |
| `HOME-AV-007`  | Antivirus         | Periodic antivirus scan completed within the last 14 days                   | Function |
| `HOME-AV-008`  | Antivirus         | No dangerous folder (`C:\`, `Downloads`, `Temp`) or `.exe`/`.ps1` exclusions in Defender | Function |
| `HOME-AV-009`  | Antivirus         | Ransomware protection (Controlled Folder Access) enabled                    | Function |
| `HOME-AV-010`  | Antivirus         | Microsoft Defender Network Protection (Exploit Guard) active                | Function |
| `HOME-AV-011`  | Antivirus         | Microsoft Defender Attack Surface Reduction (`ASR`) rules active (`Block`/`Warn`) | Function |
| `HOME-FIL-001` | File Security     | No disguised double-extension executables (`.pdf.exe`, `.jpg.scr`) in `Downloads`, `Desktop`, or `Temp` | Function |
| `HOME-FIL-002` | File Security     | No suspicious or obfuscated commands (`-enc`, `Temp`, `mshta`) in Startup `Run`/`RunOnce` keys | Function |
| `HOME-FIL-003` | File Security     | Windows `hosts` file integrity (no hijacking of Microsoft Update or antivirus domains) | Function |
| `HOME-FIL-004` | File Security     | No suspicious or obfuscated Windows Scheduled Tasks                         | Function |
| `HOME-FIL-005` | File Security     | No system executable hijacking (`IFEO` Debugger backdoors on `sethc.exe`, `taskmgr.exe`, `MsMpEng.exe`) | Function |
| `HOME-FIL-006` | File Security     | No suspicious scripts or executables (`.vbs`, `.js`, `.bat`, `.ps1`) in Startup folders | Function |
| `HOME-FIL-007` | File Security     | No fileless persistence via WMI Event Subscriptions (`root\subscription`)   | Function |
| `HOME-FIL-008` | File Security     | No policy-forced browser extensions (`ExtensionInstallForcelist` on Chrome/Edge) | Function |
| `HOME-FIL-009` | File Security     | No vulnerable unquoted third-party service executable paths (`Win32_Service`) | Function |
| `HOME-SYS-001` | Windows Settings  | File extensions visible for known file types in File Explorer (`HideFileExt = 0`) | Function |
| `HOME-SYS-002` | Windows Settings  | AutoRun and AutoPlay disabled for removable USB drives                      | Function |
| `HOME-SYS-003` | Windows Settings  | Microsoft Defender SmartScreen enabled for apps and downloaded files        | Function |
| `HOME-SYS-004` | Windows Settings  | Core Isolation / Memory Integrity (`HVCI`) running at runtime (`Win32_DeviceGuard`) | Function |
| `HOME-SYS-005` | Windows Settings  | Anonymous enumeration of SAM accounts and shares restricted (`RestrictAnonymousSAM = 1`) | Function |
| `HOME-SYS-006` | Windows Settings  | WDigest cleartext credential caching in memory disabled (`UseLogonCredential = 0`) | Function |
| `HOME-SYS-007` | Windows Settings  | Windows Solicited Remote Assistance disabled (`fAllowToGetHelp = 0`)        | Function |
| `HOME-SYS-008` | Windows Settings  | Remote Registry service (`RemoteRegistry`) disabled and stopped             | Function |
| `HOME-SYS-009` | Windows Settings  | Windows Script Host (`WSH`) disabled against `.vbs`/`.js` malware (`Enabled = 0`) | Function |
| `HOME-SYS-010` | Windows Settings  | PrintNightmare printer driver installation protection (`PointAndPrint` / `Spooler`) | Function |
| `HOME-RDP-001` | Remote Desktop    | Remote Desktop Protocol (RDP) disabled (`fDenyTSConnections = 1`)           | Registry |
| `HOME-NET-001` | Network           | Legacy SMBv1 protocol disabled                                              | Function |
| `HOME-NET-002` | Network           | NetBIOS over TCP/IP disabled (`NetbiosOptions = 2`) across network adapters | Function |
| `HOME-NET-003` | Network           | Link-Local Multicast Name Resolution (`LLMNR`) disabled (`EnableMulticast = 0`) | Function |
| `HOME-NET-004` | Network           | No non-standard user SMB network folder shares exposed                      | Function |
| `HOME-NET-005` | Network           | Mandatory SMB digital packet signing enabled (`RequireSecuritySignature = 1`) | Function |
| `HOME-NET-006` | Network           | Windows Remote Management (`WinRM` / PowerShell Remoting) service stopped   | Function |
| `HOME-NET-007` | Network           | WPAD automatic web proxy discovery disabled (anti-MITM)                     | Function |
| `HOME-NET-008` | Network           | Legacy TLS 1.0/1.1 disabled and DNS over HTTPS (`DoH`) supported            | Function |
| `HOME-NET-009` | Network           | No insecure Wi-Fi profiles configured for AutoConnect                       | Function |
| `HOME-NET-010` | Network           | No high-risk TCP ports exposed on all network interfaces                    | Function |
| `HOME-ENC-001` | Encryption        | BitLocker or Device Encryption active on the system drive (`C:`) (Home & Pro) | Function |
| `HOME-PRV-001` | Privacy           | Windows diagnostic telemetry set to minimum required level (`AllowTelemetry <= 1`) | Function |
| `HOME-SEC-001` | Advanced Security | UEFI Secure Boot enabled                                                    | Function |
| `HOME-SEC-002` | Advanced Security | Local Security Authority (`LSA`) protection (`RunAsPPL`) enabled            | Function |
| `HOME-SEC-003` | Advanced Security | PowerShell Script Block Logging enabled (`EnableScriptBlockLogging = 1`)    | Function |
| `HOME-SEC-006` | Advanced Security | Microsoft Vulnerable Driver Blocklist (anti-BYOVD) enabled (`VulnerableDriverBlocklistEnable = 1`) | Registry |
| `HOME-SEC-007` | Advanced Security | Smart App Control (`SAC`) active (`Enforced` or `Evaluation`)               | Function |
| `HOME-SEC-008` | Advanced Security | Hardware TPM 2.0 security module present and ready (`Get-Tpm` / `Win32_Tpm`) | Function |
| `HOME-SEC-009` | Advanced Security | Secure PowerShell `ExecutionPolicy` (no persistent `Unrestricted` or `Bypass`) | Function |
| `HOME-SEC-010` | Advanced Security | Windows Event Log integrity and no recent Security log clearing (`Event ID 1102`) | Function |
| `HOME-SEC-011` | Advanced Security | Kernel DMA Protection active against external PCIe/Thunderbolt attacks | Function |

---

## 💻 Local & Headless CLI Usage

If you cloned the repository locally:

```powershell
# 1. Launch the WPF Graphical Interface from source:
powershell -STA -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1

# 2. Run in Headless CLI mode and export a JSON report:
powershell -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1 -Headless -OutFile out.json

# 3. Run only specific controls by ID:
powershell -ExecutionPolicy Bypass -File src\Invoke-Scanner.ps1 -Headless -OutFile out.json -ControlId HOME-FW-001,HOME-AV-003,HOME-FIL-001
```

---

## 📂 Repository Structure

```
dist/
  scanner-win11-en.ps1     Standalone single-file bundle (English default, winutil-style)
  scanner-win11.ps1        Standalone single-file bundle (Italian default, winutil-style)
src/
  Invoke-Scanner.ps1       Main CLI & GUI entry point (-Gui / -Headless)
  core/
    Catalog.ps1            Loads and validates the JSON security catalog
    Environment.ps1        Detects Windows edition, build/UBR, language, admin rights, PS version
    Runner.ps1             Executes security checks with error isolation & progress/cancel hooks
    Report.ps1             Builds JSON/HTML/Log reports (UTF-8 without BOM)
    OllamaClient.ps1       Local Ollama REST client, auto-provisioning & built-in expert fallback
    Checks/
      Registry.ps1         Generic declarative registry evaluator
      Firewall.ps1         Windows Defender Firewall profile checks
      Accounts.ps1         Guest (-501), Admin (-500), and PasswordRequired checks
      Defender.ps1         Real-time, signatures, active threats, IOAV, PUA, Tamper, Exclusions
      FileSecurity.ps1     Double-extension malware scan, Run/RunOnce persistence, hosts integrity
      Network.ps1          SMBv1, NetBIOS over TCP/IP, and LLMNR checks
      SystemSecurity.ps1   Windows Update, BitLocker, Telemetry, Secure Boot, LSA, HVCI, SmartScreen
  ui/
    MainWindow.xaml        Two-page WPF XAML layout (Light/Dark themes, IT/EN/DE support)
    Start-ScannerUI.ps1    WPF controller, asynchronous Runspace execution & Ollama integration
    ViewModel.ps1          Pure functions for sorting, filtering, counters, and detail formatting
catalog/
  home_profile.yaml        Source security catalog (YAML, 64 controls)
  home_profile.json        Generated runtime catalog (JSON)
  schema.json              JSON Schema v0.2 validation specification
tools/
  Build.ps1                Compiles all modules into dist/scanner-win11*.ps1 (IT/EN/DE)
  yaml_to_json.py          Converts YAML catalog to JSON and validates against schema.json
tests/
  *.Tests.ps1              178 Pester 5 automated tests (Unit, AST Read-Only, ViewModel, Ollama, E2E)
```

---

## 🧪 Development & Automated Testing (Pester 5)

```powershell
# 1. Regenerate catalog/home_profile.json from YAML and validate schema:
python tools/yaml_to_json.py

# 2. Rebuild the standalone single-file scripts in dist/:
powershell -ExecutionPolicy Bypass -File tools\Build.ps1

# 3. Run the entire Pester 5 test suite (178 tests):
Invoke-Pester tests -Output Detailed
```
