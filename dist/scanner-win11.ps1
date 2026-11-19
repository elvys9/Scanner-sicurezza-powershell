<#
.SYNOPSIS
    Scanner di sicurezza per Windows 11 — Script singolo autonomo (stile winutil).

.DESCRIPTION
    File generato automaticamente da tools/Build.ps1.
    Contiene catalogo, motore di scansione, 18 controlli e interfaccia WPF.
    Puo essere eseguito da qualsiasi cartella o direttamente da GitHub:
      irm https://raw.githubusercontent.com/elvys9/Scanner-sicurezza-powershell/main/dist/scanner-win11.ps1 | iex
#>

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'
$script:VERSIONE_TOOL = '0.2.0'
$script:LinguaPredefinita = 'IT'
$script:PercorsoScriptAutonomo = [string](Get-Variable -Name PSCommandPath -ValueOnly -ErrorAction SilentlyContinue)
$script:UrlScriptRemoto = 'https://raw.githubusercontent.com/elvys9/Scanner-sicurezza-powershell/main/dist/scanner-win11.ps1'

# --- CATALOGO JSON INCORPORATO ---
$script:CatalogoJsonIncorporato = @'
{
  "schema_version": "0.2",
  "profile": {
    "name": "home",
    "description": "Profilo di sicurezza completo per utenti domestici Windows 11 (Antivirus, File, Persistenza e Impostazioni di Sistema)",
    "target_os": "Windows 11"
  },
  "controls": [
    {
      "id": "HOME-FW-001",
      "title": "Firewall di Windows attivo su tutti i profili",
      "category": "Firewall",
      "severity": "critico",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che Windows Defender Firewall sia attivo sui profili Domain, Private e Public.",
      "rationale": "Il firewall e' la prima linea di difesa contro connessioni non autorizzate. Disattivarlo espone il sistema a rischi di rete.",
      "check": {
        "command_ref": "Firewall.ps1#Test-FirewallProfiles"
      },
      "references": [
        "CIS Benchmark Windows 11 - 9.1.1"
      ]
    },
    {
      "id": "HOME-UAC-001",
      "title": "UAC (User Account Control) abilitato",
      "category": "UAC",
      "severity": "critico",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che il controllo dell'account utente (UAC) sia abilitato tramite il valore EnableLUA nel registro.",
      "rationale": "UAC protegge il sistema chiedendo conferma prima di eseguire operazioni con privilegi elevati. Disattivarlo permette a qualsiasi programma di agire come amministratore.",
      "check": {
        "registry": {
          "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
          "name": "EnableLUA",
          "operator": "eq",
          "value": 1
        }
      },
      "references": [
        "CIS Benchmark Windows 11 - 2.3.17.6"
      ]
    },
    {
      "id": "HOME-UAC-002",
      "title": "UAC richiede conferma su Desktop sicuro per elevazione",
      "category": "UAC",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che UAC richieda il consenso per l'elevazione (ConsentPromptBehaviorAdmin in 1, 2, 5) sul Desktop sicuro (PromptOnSecureDesktop = 1).",
      "rationale": "Se UAC non richiede conferma sul Desktop sicuro, processi malevoli possono intercettare o simulare il clic di conferma per ottenere privilegi di amministratore.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-UacSecureElevation"
      },
      "references": [
        "CIS Benchmark Windows 11 - 2.3.17.1 / 2.3.17.7"
      ]
    },
    {
      "id": "HOME-UAC-003",
      "title": "UAC rileva installazioni applicazioni",
      "category": "UAC",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che UAC rilevi le installazioni di applicazioni e richieda l'elevazione (EnableInstallerDetection = 1).",
      "rationale": "Il rilevamento delle installazioni aiuta a prevenire installazioni non autorizzate di software.",
      "check": {
        "registry": {
          "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
          "name": "EnableInstallerDetection",
          "operator": "eq",
          "value": 1
        }
      },
      "references": [
        "CIS Benchmark Windows 11 - 2.3.17.3"
      ]
    },
    {
      "id": "HOME-ACC-001",
      "title": "Account Guest disabilitato",
      "category": "Account",
      "severity": "critico",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che l'account locale con SID che termina in -501 (Guest) sia disabilitato.",
      "rationale": "L'account Guest permette accesso anonimo al sistema. Se abilitato, chiunque puo' accedere senza credenziali.",
      "check": {
        "command_ref": "Accounts.ps1#Test-GuestAccount"
      },
      "references": [
        "CIS Benchmark Windows 11 - 1.1.1"
      ]
    },
    {
      "id": "HOME-ACC-002",
      "title": "Account Administrator locale disabilitato",
      "category": "Account",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che l'account locale Administrator predefinito (SID che termina in -500) sia disabilitato.",
      "rationale": "L'account Administrator predefinito e' un bersaglio comune per attacchi brute-force. Usare un account personale con privilegi di amministratore e' piu' sicuro.",
      "check": {
        "command_ref": "Accounts.ps1#Test-AdminAccount"
      },
      "references": [
        "CIS Benchmark Windows 11 - 1.1.2"
      ]
    },
    {
      "id": "HOME-ACC-003",
      "title": "Nessun account senza password",
      "category": "Account",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che tutti gli account locali attivi abbiano una password impostata (PasswordRequired = True).",
      "rationale": "Account senza password permettono a chiunque abbia accesso fisico o di rete al sistema di effettuare il login senza credenziali.",
      "check": {
        "command_ref": "Accounts.ps1#Test-AccountsPasswordRequired"
      },
      "references": [
        "CIS Benchmark Windows 11 - 1.1"
      ]
    },
    {
      "id": "HOME-UPD-001",
      "title": "Aggiornamenti automatici abilitati",
      "category": "Aggiornamenti",
      "severity": "critico",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che il servizio Windows Update (wuauserv) non sia disabilitato e che la policy NoAutoUpdate non sia attiva.",
      "rationale": "Gli aggiornamenti di sicurezza correggono vulnerabilita' note. Disabilitarli lascia il sistema esposto.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-WindowsUpdateEnabled"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.102.2"
      ]
    },
    {
      "id": "HOME-UPD-002",
      "title": "Server Windows Update ufficiale (nessun dirottamento WSUS)",
      "category": "Aggiornamenti",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che gli aggiornamenti di Windows non siano rediretti verso un server WSUS esterno non autorizzato (WUServer).",
      "rationale": "Un malware puo' impostare un falso server di aggiornamento per bloccare le patch di sicurezza di Microsoft.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-WindowsUpdateAuthenticServer"
      },
      "references": [
        "Microsoft Security Baseline Windows 11"
      ]
    },
    {
      "id": "HOME-AV-001",
      "title": "Protezione in tempo reale attiva",
      "category": "Antivirus",
      "severity": "critico",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che la protezione in tempo reale di Windows Defender sia attiva.",
      "rationale": "La protezione in tempo reale analizza i file durante l'accesso e blocca le minacce note prima che possano eseguirsi.",
      "check": {
        "command_ref": "Defender.ps1#Test-DefenderRealtime"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.47.4.1"
      ]
    },
    {
      "id": "HOME-AV-002",
      "title": "Definizioni antivirus aggiornate",
      "category": "Antivirus",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che le definizioni di Windows Defender siano state aggiornate negli ultimi 7 giorni.",
      "rationale": "Definizioni obsolete non rilevano le minacce piu' recenti.",
      "check": {
        "command_ref": "Defender.ps1#Test-DefenderSignatures"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.47"
      ]
    },
    {
      "id": "HOME-AV-003",
      "title": "Nessun virus o minaccia attiva rilevata da Defender",
      "category": "Antivirus",
      "severity": "critico",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Interroga il catalogo delle minacce di Windows Defender (Get-MpThreat / Get-MpThreatDetection) per verificare che non vi siano virus o malware attivi.",
      "rationale": "La presenza di minacce attive indica un'infezione in corso o un file malevolo non ancora messo in quarantena.",
      "check": {
        "command_ref": "Defender.ps1#Test-DefenderNoActiveThreats"
      },
      "references": [
        "Microsoft Defender Antivirus Threat Detection"
      ]
    },
    {
      "id": "HOME-AV-004",
      "title": "Scansione file scaricati (IOAV) e monitoraggio comportamentale attivi",
      "category": "Antivirus",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che BehaviorMonitorEnabled e IoavProtectionEnabled siano attivi in Windows Defender.",
      "rationale": "La protezione IOAV analizza automaticamente tutti i file scaricati dal browser o allegati email, mentre il monitoraggio comportamentale blocca ransomware e attacchi sospetti.",
      "check": {
        "command_ref": "Defender.ps1#Test-DefenderBehaviorAndIoav"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.47.4"
      ]
    },
    {
      "id": "HOME-AV-005",
      "title": "Blocco applicazioni potenzialmente indesiderate (PUA) attivo",
      "category": "Antivirus",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che PUAProtection sia impostato su 1 (Blocco) nelle preferenze di Windows Defender.",
      "rationale": "La protezione PUA blocca adware, cryptominer, barre degli strumenti invasive e software indesiderati inclusi nei programmi scaricati da Internet.",
      "check": {
        "command_ref": "Defender.ps1#Test-DefenderPuaProtection"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.47.11"
      ]
    },
    {
      "id": "HOME-AV-006",
      "title": "Protezione antimanomissione (Tamper Protection) e Cloud MAPS attive",
      "category": "Antivirus",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che IsTamperProtected sia True e che MAPSReporting (Cloud Protection) sia abilitato.",
      "rationale": "La protezione antimanomissione impedisce ai virus di disattivare Windows Defender tramite registro o comandi, mentre il Cloud MAPS blocca i nuovi malware zero-day.",
      "check": {
        "command_ref": "Defender.ps1#Test-DefenderTamperAndCloud"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.47.5"
      ]
    },
    {
      "id": "HOME-AV-007",
      "title": "Scansione antivirus periodica eseguita negli ultimi 14 giorni",
      "category": "Antivirus",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che una scansione rapida o completa dei file sia stata completata negli ultimi 14 giorni.",
      "rationale": "Le scansioni periodiche individuano minacce dormienti sui file salvati sul disco prima dell'ultimo aggiornamento delle firme.",
      "check": {
        "command_ref": "Defender.ps1#Test-DefenderRecentScan"
      },
      "references": [
        "Microsoft Defender Antivirus Scheduled Scan"
      ]
    },
    {
      "id": "HOME-AV-008",
      "title": "Nessuna esclusione pericolosa di cartelle o estensioni in Defender",
      "category": "Antivirus",
      "severity": "critico",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che non siano state escluse dalla scansione antivirus intere unita' (C:\\), cartelle utente (Downloads, Temp, Windows) o estensioni eseguibili (.exe, .ps1, .bat).",
      "rationale": "Molti trojan e stealer aggiungono l'intera cartella Utenti, Download o l'estensione .exe alle esclusioni di Defender per agire indisturbati.",
      "check": {
        "command_ref": "Defender.ps1#Test-DefenderSafeExclusions"
      },
      "references": [
        "MITRE ATT&CK T1562.001 - Disable or Modify Tools"
      ]
    },
    {
      "id": "HOME-FIL-001",
      "title": "Nessun file eseguibile camuffato con doppia estensione (Download, Desktop, Temp)",
      "category": "Controllo File",
      "severity": "critico",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Scansiona in sola lettura le cartelle Download, Desktop e Temp alla ricerca di file eseguibili camuffati con doppia estensione (es. fattura.pdf.exe, foto.jpg.scr, doc.txt.vbs).",
      "rationale": "La doppia estensione e' una delle tecniche piu' usate per indurre l'utente ad aprire un virus convinto che si tratti di un documento PDF o di un'immagine.",
      "check": {
        "command_ref": "FileSecurity.ps1#Test-SuspiciousDoubleExtensionFiles"
      },
      "references": [
        "MITRE ATT&CK T1036.007 - Double File Extension"
      ]
    },
    {
      "id": "HOME-FIL-002",
      "title": "Nessun programma sospetto o offuscato nelle chiavi di avvio automatico (Run)",
      "category": "Controllo File",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Analizza le voci di avvio automatico nel registro (HKCU/HKLM Run e RunOnce) verificando l'assenza di eseguibili in cartelle Temp o comandi PowerShell/script offuscati.",
      "rationale": "I malware si registrano nelle chiavi Run puntando a cartelle temporanee o usando comandi nascosti (-w hidden, -enc, mshta, wscript) per riavviarsi a ogni accensione del PC.",
      "check": {
        "command_ref": "FileSecurity.ps1#Test-StartupPersistenceEntries"
      },
      "references": [
        "MITRE ATT&CK T1547.001 - Registry Run Keys / Startup Folder"
      ]
    },
    {
      "id": "HOME-FIL-003",
      "title": "Integrita' del file hosts di Windows (nessun dirottamento siti di sicurezza)",
      "category": "Controllo File",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Analizza il file C:\\Windows\\System32\\drivers\\etc\\hosts verificando che non siano bloccati o dirottati domini di Windows Update, Microsoft o siti antivirus.",
      "rationale": "Alcuni malware modificano il file hosts per impedire al PC di scaricare aggiornamenti di sicurezza o contattare i siti dei produttori di antivirus.",
      "check": {
        "command_ref": "FileSecurity.ps1#Test-HostsFileIntegrity"
      },
      "references": [
        "MITRE ATT&CK T1565.001 - Stored Data Manipulation"
      ]
    },
    {
      "id": "HOME-SYS-001",
      "title": "Estensioni dei file conosciuti visibili in Esplora file",
      "category": "Impostazioni Windows",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che HideFileExt sia impostato a 0 in HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced.",
      "rationale": "Mostrare sempre le estensioni dei file in Esplora file permette all'utente di accorgersi subito se un file e' in realta' un programma eseguibile (.exe, .scr, .bat).",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-FileExtensionsVisible"
      },
      "references": [
        "CIS Benchmark Windows 11 - User Explorer Settings"
      ]
    },
    {
      "id": "HOME-SYS-002",
      "title": "AutoRun e AutoPlay disabilitati per le unita' rimovibili USB",
      "category": "Impostazioni Windows",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che l'esecuzione automatica all'inserimento di chiavette USB o dischi esterni sia disattivata (NoDriveTypeAutoRun >= 145 o DisableAutoplay = 1).",
      "rationale": "Disattivare AutoRun e AutoPlay impedisce l'avvio automatico di malware presenti su chiavette USB infette.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-AutorunDisabled"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.8.3"
      ]
    },
    {
      "id": "HOME-SYS-003",
      "title": "Filtro Microsoft Defender SmartScreen attivo per app e file",
      "category": "Impostazioni Windows",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che SmartScreen per Esplora file e per le applicazioni web (EnableWebContentEvaluation) sia attivo.",
      "rationale": "SmartScreen avvisa l'utente prima di eseguire programmi sconosciuti o potenzialmente malevoli scaricati da Internet.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-SmartScreenEnabled"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.85.1"
      ]
    },
    {
      "id": "HOME-SYS-004",
      "title": "Isolamento core / Integrita' della memoria (HVCI) attivo",
      "category": "Impostazioni Windows",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che Hypervisor-Enforced Code Integrity (HVCI) sia abilitato nel registro DeviceGuard.",
      "rationale": "L'integrita' della memoria usa la virtualizzazione hardware per impedire l'iniezione di codice malevolo nei processi ad alta sicurezza del kernel di Windows.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-MemoryIntegrityEnabled"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.5.2"
      ]
    },
    {
      "id": "HOME-SYS-005",
      "title": "Enumerazione anonima degli account locali (SAM) bloccata",
      "category": "Impostazioni Windows",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che il valore RestrictAnonymousSAM in HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa sia impostato a 1.",
      "rationale": "Impedisce a utenti non autenticati sulla rete locale di elencare i nomi degli account presenti sul computer.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-AnonymousSamRestricted"
      },
      "references": [
        "CIS Benchmark Windows 11 - 2.3.10.2"
      ]
    },
    {
      "id": "HOME-RDP-001",
      "title": "Desktop remoto disabilitato",
      "category": "Desktop Remoto",
      "severity": "alto",
      "editions": [
        "Pro"
      ],
      "description": "Verifica che il desktop remoto (RDP) sia disabilitato tramite fDenyTSConnections = 1.",
      "rationale": "RDP e' uno dei vettori di attacco piu' comuni. Se non necessario, va disabilitato.",
      "check": {
        "registry": {
          "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
          "name": "fDenyTSConnections",
          "operator": "eq",
          "value": 1
        }
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.65.3.3.2"
      ]
    },
    {
      "id": "HOME-NET-001",
      "title": "SMBv1 disabilitato",
      "category": "Rete",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che il protocollo SMBv1 sia disabilitato.",
      "rationale": "SMBv1 ha vulnerabilita' note (EternalBlue/WannaCry). Le versioni moderne di SMB sono piu' sicure.",
      "check": {
        "command_ref": "Network.ps1#Test-Smb1Disabled"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.3.3"
      ]
    },
    {
      "id": "HOME-NET-002",
      "title": "NetBIOS su TCP/IP disabilitato",
      "category": "Rete",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che NetBIOS su TCP/IP sia disabilitato (NetbiosOptions = 2) sulle interfacce di rete.",
      "rationale": "NetBIOS puo' esporre informazioni sul sistema e facilitare attacchi di spoofing sulla rete locale. Se non necessario, va disabilitato.",
      "check": {
        "command_ref": "Network.ps1#Test-NetbiosDisabled"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.5"
      ]
    },
    {
      "id": "HOME-NET-003",
      "title": "Protocollo multicast LLMNR disabilitato",
      "category": "Rete",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che il protocollo Link-Local Multicast Name Resolution (EnableMulticast = 0) sia disabilitato.",
      "rationale": "LLMNR e' vulnerabile ad attacchi di avvelenamento (es. Responder) su reti locali e Wi-Fi condivise che permettono il furto degli hash delle password.",
      "check": {
        "command_ref": "Network.ps1#Test-LlmnrDisabled"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.5.4.2"
      ]
    },
    {
      "id": "HOME-ENC-001",
      "title": "BitLocker o Crittografia dispositivo attivo sul disco di sistema",
      "category": "Crittografia",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che BitLocker o Crittografia dispositivo (Device Encryption) sia attivo sulla partizione di sistema (C:).",
      "rationale": "La crittografia del disco protegge i dati in caso di furto o smarrimento del dispositivo.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-BitLockerSystemDrive"
      },
      "references": [
        "CIS Benchmark Windows 11 - 6.2"
      ]
    },
    {
      "id": "HOME-PRV-001",
      "title": "Telemetria impostata al livello minimo",
      "category": "Privacy",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che il livello di telemetria di Windows (AllowTelemetry) sia impostato al minimo consentito (<= 1).",
      "rationale": "Ridurre la telemetria limita la quantita' di dati diagnostici raccolti e inviati a Microsoft.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-TelemetryMinimum"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.17.1"
      ]
    },
    {
      "id": "HOME-SEC-001",
      "title": "Avvio protetto (Secure Boot) attivo",
      "category": "Sicurezza Avanzata",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che Secure Boot sia abilitato nel firmware UEFI.",
      "rationale": "Secure Boot impedisce l'esecuzione di bootloader non firmati, proteggendo da rootkit e bootkit.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-SecureBoot"
      },
      "references": [
        "CIS Benchmark Windows 11 - 1.2.2"
      ]
    },
    {
      "id": "HOME-SEC-002",
      "title": "Protezione LSA abilitata",
      "category": "Sicurezza Avanzata",
      "severity": "alto",
      "editions": [
        "Pro"
      ],
      "description": "Verifica che la protezione LSA (RunAsPPL) sia abilitata.",
      "rationale": "La protezione LSA impedisce l'estrazione di credenziali dalla memoria da parte di processi non protetti (attacchi tipo Mimikatz).",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-LsaProtection"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.3.1"
      ]
    },
    {
      "id": "HOME-SEC-003",
      "title": "PowerShell script block logging abilitato",
      "category": "Sicurezza Avanzata",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che il logging degli script block di PowerShell (EnableScriptBlockLogging) sia abilitato.",
      "rationale": "Il logging degli script block permette di tracciare nei registri eventi l'esecuzione di comandi PowerShell sospetti o offuscati.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-PsScriptBlockLogging"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.100.1"
      ]
    },
    {
      "id": "HOME-AV-009",
      "title": "Protezione ransomware (Accesso alle cartelle controllato) attiva",
      "category": "Antivirus",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che l'Accesso alle cartelle controllato (EnableControlledFolderAccess = 1) di Windows Defender sia attivo.",
      "rationale": "L'accesso alle cartelle controllato impedisce a ransomware e applicazioni non autorizzate di cifrare o modificare i tuoi file personali (Documenti, Immagini, Desktop).",
      "check": {
        "command_ref": "Defender.ps1#Test-DefenderRansomwareCartelle"
      },
      "references": [
        "Microsoft Defender Exploit Guard - Controlled Folder Access"
      ]
    },
    {
      "id": "HOME-AV-010",
      "title": "Protezione di rete di Microsoft Defender (Exploit Guard) attiva",
      "category": "Antivirus",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che la Protezione di rete di Defender (EnableNetworkProtection = 1) sia attiva in modalita' blocco.",
      "rationale": "La protezione di rete blocca a livello di sistema le connessioni verso domini di phishing, server C2 malware ed exploit noti in qualsiasi applicazione o browser.",
      "check": {
        "command_ref": "Defender.ps1#Test-DefenderNetworkProtection"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.47.11.1"
      ]
    },
    {
      "id": "HOME-FIL-004",
      "title": "Nessuna attivita' pianificata (Scheduled Task) sospetta o offuscata",
      "category": "Controllo File",
      "severity": "critico",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Analizza le Attivita' pianificate non-Microsoft alla ricerca di esecuzioni da cartelle Temp/Public o comandi PowerShell/LOLBin offuscati.",
      "rationale": "I malware utilizzano frequentemente le Attivita' pianificate di Windows per rieseguirsi automaticamente in background ad ogni accesso o ad orari prestabiliti.",
      "check": {
        "command_ref": "FileSecurity.ps1#Test-TaskPianificatiSospetti"
      },
      "references": [
        "MITRE ATT&CK T1053.005 - Scheduled Task/Job"
      ]
    },
    {
      "id": "HOME-FIL-005",
      "title": "Nessun dirottamento di eseguibili di sistema (IFEO Debugger Hijacking)",
      "category": "Controllo File",
      "severity": "critico",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che nessun eseguibile di sistema o di accessibilita' (sethc.exe, utilman.exe, taskmgr.exe, MsMpEng.exe) abbia un valore Debugger in Image File Execution Options.",
      "rationale": "Gli attaccanti usano il dirottamento IFEO per creare backdoor nella schermata di login (Sticky Keys) o per impedire l'avvio di Task Manager e Windows Defender.",
      "check": {
        "command_ref": "FileSecurity.ps1#Test-HijackingIFEO"
      },
      "references": [
        "MITRE ATT&CK T1546.012 - Image File Execution Options Injection"
      ]
    },
    {
      "id": "HOME-FIL-006",
      "title": "Nessuno script o eseguibile sospetto nella cartella Esecuzione automatica",
      "category": "Controllo File",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Scansiona le cartelle Startup dell'utente e di sistema alla ricerca di script o eseguibili sospetti (.vbs, .js, .bat, .cmd, .ps1, .hta, .scr).",
      "rationale": "Qualsiasi file o script inserito nella cartella Esecuzione automatica (Startup) viene lanciato automaticamente ad ogni accesso dell'utente.",
      "check": {
        "command_ref": "FileSecurity.ps1#Test-CartellaStartupUtente"
      },
      "references": [
        "MITRE ATT&CK T1547.001 - Registry Run Keys / Startup Folder"
      ]
    },
    {
      "id": "HOME-ACC-004",
      "title": "Politica di blocco account contro attacchi brute-force attiva",
      "category": "Account",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che la soglia di blocco account (Account Lockout Threshold) sia impostata tra 1 e 10 tentativi di accesso falliti.",
      "rationale": "Senza una soglia di blocco account, un attaccante o un malware sulla rete locale puo' tentare migliaia di password al minuto senza essere bloccato.",
      "check": {
        "command_ref": "Accounts.ps1#Test-PoliticaBloccoAccount"
      },
      "references": [
        "CIS Benchmark Windows 11 - 1.2.2"
      ]
    },
    {
      "id": "HOME-ACC-005",
      "title": "Numero di account nel gruppo Amministratori locali ridotto al minimo (<= 2)",
      "category": "Account",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che il gruppo locale Amministratori (SID S-1-5-32-544) non contenga piu' di 2 account abilitati.",
      "rationale": "Limitare il numero di account con privilegi di amministratore riduce la superficie d'attacco e il rischio di compromissione totale del sistema.",
      "check": {
        "command_ref": "Accounts.ps1#Test-LimiteAmministratoriLocali"
      },
      "references": [
        "Principio del Privilegio Minimo (Least Privilege)"
      ]
    },
    {
      "id": "HOME-NET-004",
      "title": "Nessuna cartella condivisa di rete (SMB Share) non standard esposta",
      "category": "Rete",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che non vi siano condivisioni SMB utente esposte sulla rete locale oltre a quelle amministrative predefinite.",
      "rationale": "Le cartelle condivise sulla rete locale possono essere sfruttate da ransomware o utenti sulla stessa rete Wi-Fi per leggere o cifrare file.",
      "check": {
        "command_ref": "Network.ps1#Test-CondivisioniSmbPericolose"
      },
      "references": [
        "MITRE ATT&CK T1135 - Network Share Discovery"
      ]
    },
    {
      "id": "HOME-NET-005",
      "title": "Firma digitale SMB (SMB Signing) obbligatoria contro attacchi NTLM Relay",
      "category": "Rete",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che RequireSecuritySignature = 1 sia attivo sia per il Server che per il Client SMB.",
      "rationale": "La firma digitale obbligatoria dei pacchetti SMB impedisce agli attaccanti sulla rete locale di intercettare e inoltrare le tue credenziali (attacchi SMB/NTLM Relay).",
      "check": {
        "command_ref": "Network.ps1#Test-FirmaSmbObbligatoria"
      },
      "references": [
        "CIS Benchmark Windows 11 - 2.3.8.1 / 2.3.9.2"
      ]
    },
    {
      "id": "HOME-NET-006",
      "title": "Servizio Gestione remota Windows (WinRM / PowerShell Remoting) disabilitato",
      "category": "Rete",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che il servizio WinRM sia fermo (Stopped) per non esporre le porte di amministrazione remota 5985/5986.",
      "rationale": "Su un PC desktop o portatile, WinRM espone un endpoint di esecuzione remota di comandi PowerShell utilizzato per movimenti laterali.",
      "check": {
        "command_ref": "Network.ps1#Test-WinRmDisabilitatoOSicuro"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.102.2"
      ]
    },
    {
      "id": "HOME-NET-007",
      "title": "Risoluzione automatica proxy WPAD disabilitata (anti-MITM)",
      "category": "Rete",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che il protocollo WPAD (Web Proxy Auto-Discovery) sia disabilitato nel registro o tramite il servizio WinHttpAutoProxySvc.",
      "rationale": "Un attaccante sulla stessa rete locale/Wi-Fi puo' rispondere alle richieste WPAD per dirottare tutto il traffico web del PC attraverso un proxy malevolo.",
      "check": {
        "command_ref": "Network.ps1#Test-WpadDisabilitato"
      },
      "references": [
        "MITRE ATT&CK T1557.001 - LLMNR/NBT-NS/WPAD Poisoning"
      ]
    },
    {
      "id": "HOME-SYS-006",
      "title": "Protezione credenziali WDigest (nessuna password in chiaro in memoria)",
      "category": "Impostazioni Windows",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica anti-manomissione che UseLogonCredential in WDigest sia 0 (o assente) per impedire la memorizzazione di password in chiaro in LSASS.",
      "rationale": "Se WDigest UseLogonCredential viene impostato a 1 da un attaccante, Windows conserva le password utente in chiaro nella memoria RAM.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-WDigestDisabilitato"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.4.8"
      ]
    },
    {
      "id": "HOME-SYS-007",
      "title": "Assistenza remota di Windows (Remote Assistance) disabilitata",
      "category": "Impostazioni Windows",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che fAllowToGetHelp sia impostato a 0 nella chiave Remote Assistance.",
      "rationale": "Disabilitare l'Assistenza remota riduce il rischio di connessioni remote non autorizzate verso il PC.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-AssistenzaRemotaDisabilitata"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.65.2"
      ]
    },
    {
      "id": "HOME-SYS-008",
      "title": "Servizio Registro di sistema remoto (Remote Registry) disabilitato",
      "category": "Impostazioni Windows",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che il servizio RemoteRegistry sia disabilitato (Start = 4) e non in esecuzione.",
      "rationale": "Il servizio Remote Registry permette la lettura e modifica del registro di sistema da remoto attraverso la rete.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-RegistroRemotoDisabilitato"
      },
      "references": [
        "CIS Benchmark Windows 11 - 5.27"
      ]
    },
    {
      "id": "HOME-SEC-006",
      "title": "Microsoft Vulnerable Driver Blocklist (anti-BYOVD) abilitata",
      "category": "Sicurezza Avanzata",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che la blocklist dei driver vulnerabili di Microsoft (VulnerableDriverBlocklistEnable = 1) sia attiva in CI\\Config.",
      "rationale": "Impedisce il caricamento di driver firmati ma con vulnerabilita' note sfruttati negli attacchi Bring Your Own Vulnerable Driver (BYOVD) per disabilitare EDR/Defender nel kernel.",
      "check": {
        "registry": {
          "path": "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config",
          "name": "VulnerableDriverBlocklistEnable",
          "operator": "eq",
          "value": 1
        }
      },
      "references": [
        "Microsoft Security Baseline Windows 11 - Driver Block Rules",
        "MITRE ATT&CK T1068 - Exploitation for Privilege Escalation (BYOVD)"
      ]
    },
    {
      "id": "HOME-SEC-007",
      "title": "Smart App Control (SAC) attivo",
      "category": "Sicurezza Avanzata",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica lo stato di Smart App Control (VerifiedAndReputablePolicyState = 1 Enforced o 2 Evaluation) in Control\\CI\\Policy.",
      "rationale": "Smart App Control blocca a livello di sistema l'esecuzione di applicazioni non attendibili, non firmate o potenzialmente malevole su Windows 11.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-SmartAppControl"
      },
      "references": [
        "Microsoft Windows 11 Security - Smart App Control",
        "Harden-Windows-Security Baseline"
      ]
    },
    {
      "id": "HOME-AV-011",
      "title": "Regole Attack Surface Reduction (ASR) di Microsoft Defender attive",
      "category": "Antivirus",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica tramite Get-MpPreference che siano configurate regole ASR in modalita' Block (1) o Warn (6), incluso il blocco furto credenziali LSASS e script offuscati.",
      "rationale": "Le regole ASR bloccano i vettori di attacco piu' comuni usati da ransomware e malware fileless (estrazione credenziali da LSASS, macro Office, script offuscati).",
      "check": {
        "command_ref": "Defender.ps1#Test-DefenderAsrRules"
      },
      "references": [
        "CIS Benchmark Windows 11 - 18.9.47.5",
        "Microsoft Defender Exploit Guard - Attack Surface Reduction"
      ]
    },
    {
      "id": "HOME-SEC-008",
      "title": "Chip di sicurezza hardware TPM 2.0 presente e pronto",
      "category": "Sicurezza Avanzata",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica tramite Get-Tpm (o Win32_Tpm) che il modulo TPM 2.0 sia presente e pronto all'uso (TpmPresent = True, TpmReady = True).",
      "rationale": "Il chip TPM 2.0 fornisce la radice di fiducia hardware indispensabile per BitLocker, Windows Hello, Secure Boot e Credential Guard.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-Tpm20Ready"
      },
      "references": [
        "Microsoft Windows 11 Hardware Security Baseline - TPM 2.0"
      ]
    },
    {
      "id": "HOME-NET-008",
      "title": "Protocolli obsoleti TLS 1.0/1.1 disabilitati e DNS over HTTPS (DoH) supportato",
      "category": "Rete",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che TLS 1.0 e TLS 1.1 non siano forzatamente abilitati in SCHANNEL e che il client DNS supporti DNS over HTTPS (DoH).",
      "rationale": "Disabilitare TLS 1.0/1.1 previene attacchi di downgrade crittografico (BEAST/POODLE), mentre DNS over HTTPS cifra le query DNS contro intercettazioni e spoofing.",
      "check": {
        "command_ref": "Network.ps1#Test-LegacyTlsAndDoh"
      },
      "references": [
        "IETF RFC 8996 - Deprecating TLS 1.0 and TLS 1.1",
        "IETF RFC 8484 - DNS Queries over HTTPS (DoH)"
      ]
    },
    {
      "id": "HOME-SYS-009",
      "title": "Windows Script Host (WSH) disabilitato contro script .vbs/.js malevoli",
      "category": "Impostazioni Windows",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che Windows Script Host (wscript.exe/cscript.exe) sia disabilitato impostando Enabled = 0 in Windows Script Host\\Settings.",
      "rationale": "Disabilitare WSH impedisce l'esecuzione automatica di script VBScript (.vbs/.vbe) e JScript (.js/.jse) comunemente usati come dropper da campagne phishing e malware.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-WshDisabled"
      },
      "references": [
        "HardeningKitty - Windows Script Host Hardening",
        "MITRE ATT&CK T1059.005 / T1059.007"
      ]
    },
    {
      "id": "HOME-SEC-009",
      "title": "PowerShell ExecutionPolicy sicura (nessuno scope Unrestricted o Bypass)",
      "category": "Sicurezza Avanzata",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica tramite Get-ExecutionPolicy -List che nessuno scope persistente (MachinePolicy, UserPolicy, LocalMachine, CurrentUser) sia impostato su Unrestricted o Bypass.",
      "rationale": "Una ExecutionPolicy troppo permissiva consente l'avvio diretto di script PowerShell non firmati o scaricati da Internet senza alcun controllo.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-PowerShellExecutionPolicySecure"
      },
      "references": [
        "Microsoft PowerShell Security Best Practices",
        "HardeningKitty - PowerShell Execution Policy"
      ]
    },
    {
      "id": "HOME-UAC-004",
      "title": "Protezione Amministratore (Administrator Protection) attiva",
      "category": "UAC",
      "severity": "medio",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che la nuova modalita' Administrator Protection just-in-time di Windows 11 24H2/25H2/26H2 sia abilitata tramite TypeOfAdminApprovalMode = 2 in Policies\\System.",
      "rationale": "Administrator Protection crea un account amministratore nascosto separato con privilegi just-in-time, impedendo ai malware di ereditare silenziosamente il token amministrativo permanente dell'utente.",
      "check": {
        "command_ref": "SystemSecurity.ps1#Test-AdministratorProtection"
      },
      "references": [
        "Microsoft Security Baseline Windows 11 25H2/26H2 - Administrator Protection"
      ]
    },
    {
      "id": "HOME-FIL-007",
      "title": "Nessuna persistenza fileless tramite WMI Event Subscriptions",
      "category": "Controllo File",
      "severity": "critico",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Interroga in sola lettura il namespace root\\subscription per verificare l'assenza di CommandLineEventConsumer, ActiveScriptEventConsumer ed EventFilter sospetti.",
      "rationale": "Gli attaccanti utilizzano le sottoscrizioni WMI permanenti per ottenere persistenza fileless invisibile alle normali chiavi Run, eseguendo script o comandi ad ogni evento di sistema.",
      "check": {
        "command_ref": "FileSecurity.ps1#Test-WmiEventSubscriptions"
      },
      "references": [
        "MITRE ATT&CK T1546.003 - Windows Management Instrumentation Event Subscription"
      ]
    },
    {
      "id": "HOME-FIL-008",
      "title": "Nessuna estensione browser forzata da policy (Chrome / Edge)",
      "category": "Controllo File",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che le chiavi ExtensionInstallForcelist in HKLM/HKCU per Google Chrome e Microsoft Edge non contengano estensioni forzate da policy.",
      "rationale": "Malware, adware e infostealer forzano spesso l'installazione silenziosa di estensioni browser malevole tramite ExtensionInstallForcelist impedendo all'utente di rimuoverle dall'interfaccia.",
      "check": {
        "command_ref": "FileSecurity.ps1#Test-BrowserForcedExtensions"
      },
      "references": [
        "MITRE ATT&CK T1176 - Browser Extensions"
      ]
    }
  ]
}
'@

# --- LAYOUT XAML INCORPORATO ---
$script:XamlIncorporato = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Windows 11 Security Scanner (Read-Only)"
        Width="1280"
        Height="860"
        MinWidth="1040"
        MinHeight="700"
        WindowStartupLocation="CenterScreen"
        FontFamily="Segoe UI"
        FontSize="13"
        SnapsToDevicePixels="True"
        UseLayoutRounding="True"
        TextOptions.TextFormattingMode="Display"
        TextOptions.TextRenderingMode="ClearType"
        Background="{DynamicResource BgPrimary}"
        Foreground="{DynamicResource TextPrimary}">

    <Window.Resources>
        <!-- Palette predefinita (Tema Scuro Moderno Fluent - aggiornabile a caldo in Chiaro/Scuro) -->
        <SolidColorBrush x:Key="BgPrimary" Color="#0B0F19"/>
        <SolidColorBrush x:Key="BgSurface" Color="#111827"/>
        <SolidColorBrush x:Key="BgElevated" Color="#1E293B"/>
        <SolidColorBrush x:Key="BgHeader" Color="#060911"/>
        <SolidColorBrush x:Key="TextHeader" Color="#F8FAFC"/>
        <SolidColorBrush x:Key="BgSubtle" Color="#0F172A"/>
        <SolidColorBrush x:Key="BgInput" Color="#0F172A"/>
        <SolidColorBrush x:Key="BgAlternating" Color="#131C2E"/>
        <SolidColorBrush x:Key="SelectedRowBg" Color="#1E3A8A"/>
        <SolidColorBrush x:Key="SelectedRowFg" Color="#FFFFFF"/>
        <SolidColorBrush x:Key="HoverRowBg" Color="#1E293B"/>
        <SolidColorBrush x:Key="TextPrimary" Color="#F1F5F9"/>
        <SolidColorBrush x:Key="TextSecondary" Color="#94A3B8"/>
        <SolidColorBrush x:Key="BorderSubtle" Color="#1E293B"/>
        <SolidColorBrush x:Key="BorderStrong" Color="#334155"/>
        <SolidColorBrush x:Key="AccentBrush" Color="#3B82F6"/>
        <SolidColorBrush x:Key="AccentText" Color="#FFFFFF"/>

        <!-- Colori semantici per i 5 stati -->
        <SolidColorBrush x:Key="PassBg" Color="#064E3B"/>
        <SolidColorBrush x:Key="PassFg" Color="#6EE7B7"/>
        <SolidColorBrush x:Key="PassBorder" Color="#10B981"/>

        <SolidColorBrush x:Key="FailBg" Color="#7F1D1D"/>
        <SolidColorBrush x:Key="FailFg" Color="#FCA5A5"/>
        <SolidColorBrush x:Key="FailBorder" Color="#EF4444"/>

        <SolidColorBrush x:Key="UnknownBg" Color="#1E293B"/>
        <SolidColorBrush x:Key="UnknownFg" Color="#CBD5E1"/>
        <SolidColorBrush x:Key="UnknownBorder" Color="#64748B"/>

        <SolidColorBrush x:Key="NaBg" Color="#0F172A"/>
        <SolidColorBrush x:Key="NaFg" Color="#94A3B8"/>
        <SolidColorBrush x:Key="NaBorder" Color="#475569"/>

        <SolidColorBrush x:Key="ErrorBg" Color="#7C2D12"/>
        <SolidColorBrush x:Key="ErrorFg" Color="#FDBA74"/>
        <SolidColorBrush x:Key="ErrorBorder" Color="#F97316"/>

        <SolidColorBrush x:Key="WarnBannerBg" Color="#451A03"/>
        <SolidColorBrush x:Key="WarnBannerFg" Color="#FDE68A"/>
        <SolidColorBrush x:Key="WarnBannerBorder" Color="#D97706"/>

        <!-- Stile Moderno per tutti i Pulsanti con bordi arrotondati -->
        <Style x:Key="ModernButton" TargetType="Button">
            <Setter Property="Background" Value="{DynamicResource BgElevated}"/>
            <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
            <Setter Property="BorderBrush" Value="{DynamicResource BorderStrong}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="14,7"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="border"
                                Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center"
                                              VerticalAlignment="Center"
                                              RecognizesAccessKey="True"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="border" Property="Opacity" Value="0.88"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="border" Property="Opacity" Value="0.74"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="border" Property="Opacity" Value="0.38"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Stile TextBox compatibile con Dark e Light Theme -->
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="{DynamicResource BgInput}"/>
            <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
            <Setter Property="CaretBrush" Value="{DynamicResource TextPrimary}"/>
            <Setter Property="BorderBrush" Value="{DynamicResource BorderStrong}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="SelectionBrush" Value="{DynamicResource AccentBrush}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border x:Name="Bd"
                                Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="{TemplateBinding BorderThickness}"
                                CornerRadius="6"
                                Padding="{TemplateBinding Padding}">
                            <ScrollViewer x:Name="PART_ContentHost" Focusable="False" HorizontalScrollBarVisibility="Hidden" VerticalScrollBarVisibility="Hidden"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsKeyboardFocused" Value="True">
                                <Setter TargetName="Bd" Property="BorderBrush" Value="{DynamicResource AccentBrush}"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Stile ComboBoxItem compatibile con Dark e Light Theme -->
        <Style TargetType="ComboBoxItem">
            <Setter Property="Background" Value="{DynamicResource BgElevated}"/>
            <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
            <Setter Property="Padding" Value="10,6"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBoxItem">
                        <Border x:Name="Bd"
                                Background="{TemplateBinding Background}"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Left" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsHighlighted" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="{DynamicResource SelectedRowBg}"/>
                                <Setter Property="Foreground" Value="{DynamicResource SelectedRowFg}"/>
                            </Trigger>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="Bd" Property="Background" Value="{DynamicResource SelectedRowBg}"/>
                                <Setter Property="Foreground" Value="{DynamicResource SelectedRowFg}"/>
                                <Setter Property="FontWeight" Value="SemiBold"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Stile ComboBox completamente personalizzato per Dark e Light Theme -->
        <Style TargetType="ComboBox">
            <Setter Property="Background" Value="{DynamicResource BgInput}"/>
            <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
            <Setter Property="BorderBrush" Value="{DynamicResource BorderStrong}"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="Padding" Value="10,4"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBox">
                        <Grid>
                            <ToggleButton x:Name="ToggleButton"
                                          Focusable="False"
                                          IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"
                                          ClickMode="Press"
                                          Background="{TemplateBinding Background}"
                                          BorderBrush="{TemplateBinding BorderBrush}"
                                          BorderThickness="{TemplateBinding BorderThickness}">
                                <ToggleButton.Template>
                                    <ControlTemplate TargetType="ToggleButton">
                                        <Border x:Name="Border"
                                                Background="{TemplateBinding Background}"
                                                BorderBrush="{TemplateBinding BorderBrush}"
                                                BorderThickness="{TemplateBinding BorderThickness}"
                                                CornerRadius="6">
                                            <Grid>
                                                <Grid.ColumnDefinitions>
                                                    <ColumnDefinition Width="*"/>
                                                    <ColumnDefinition Width="26"/>
                                                </Grid.ColumnDefinitions>
                                                <Path Grid.Column="1"
                                                      HorizontalAlignment="Center"
                                                      VerticalAlignment="Center"
                                                      Data="M 0 0 L 4 4 L 8 0 Z"
                                                      Fill="{DynamicResource TextSecondary}"/>
                                            </Grid>
                                        </Border>
                                        <ControlTemplate.Triggers>
                                            <Trigger Property="IsMouseOver" Value="True">
                                                <Setter TargetName="Border" Property="BorderBrush" Value="{DynamicResource AccentBrush}"/>
                                            </Trigger>
                                        </ControlTemplate.Triggers>
                                    </ControlTemplate>
                                </ToggleButton.Template>
                            </ToggleButton>

                            <ContentPresenter x:Name="ContentSite"
                                              IsHitTestVisible="False"
                                              Content="{TemplateBinding SelectionBoxItem}"
                                              ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                                              ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}"
                                              Margin="10,3,26,3"
                                              VerticalAlignment="Center"
                                              HorizontalAlignment="Left"/>

                            <TextBox x:Name="PART_EditableTextBox"
                                     Visibility="Hidden"
                                     IsReadOnly="{TemplateBinding IsReadOnly}"
                                     Background="Transparent"
                                     Foreground="{DynamicResource TextPrimary}"
                                     CaretBrush="{DynamicResource TextPrimary}"
                                     BorderThickness="0"
                                     Margin="8,3,26,3"
                                     VerticalAlignment="Center"
                                     HorizontalAlignment="Stretch"
                                     Focusable="True"/>

                            <Popup x:Name="Popup"
                                   Placement="Bottom"
                                   IsOpen="{TemplateBinding IsDropDownOpen}"
                                   AllowsTransparency="True"
                                   Focusable="False"
                                   PopupAnimation="Slide">
                                <Grid x:Name="DropDown"
                                      SnapsToDevicePixels="True"
                                      MinWidth="{TemplateBinding ActualWidth}"
                                      MaxHeight="{TemplateBinding MaxDropDownHeight}">
                                    <Border x:Name="DropDownBorder"
                                            Background="{DynamicResource BgElevated}"
                                            BorderBrush="{DynamicResource BorderStrong}"
                                            BorderThickness="1"
                                            CornerRadius="6"
                                            Margin="0,2,0,0">
                                        <ScrollViewer Margin="2" SnapsToDevicePixels="True">
                                            <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Contained"/>
                                        </ScrollViewer>
                                    </Border>
                                </Grid>
                            </Popup>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsEditable" Value="True">
                                <Setter Property="IsTabStop" Value="False"/>
                                <Setter TargetName="PART_EditableTextBox" Property="Visibility" Value="Visible"/>
                                <Setter TargetName="ContentSite" Property="Visibility" Value="Hidden"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Stile DataGridColumnHeader per Dark e Light Theme -->
        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="{DynamicResource BgSubtle}"/>
            <Setter Property="Foreground" Value="{DynamicResource TextSecondary}"/>
            <Setter Property="BorderBrush" Value="{DynamicResource BorderSubtle}"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
            <Setter Property="Padding" Value="12,9"/>
            <Setter Property="FontWeight" Value="Bold"/>
            <Setter Property="FontSize" Value="11.5"/>
            <Setter Property="HorizontalContentAlignment" Value="Left"/>
        </Style>

        <!-- Stile DataGridRow e DataGridCell per selezione nitida in Dark e Light Theme -->
        <Style TargetType="DataGridRow">
            <Setter Property="Background" Value="{DynamicResource BgSurface}"/>
            <Setter Property="Foreground" Value="{DynamicResource TextPrimary}"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Style.Triggers>
                <Trigger Property="ItemsControl.AlternationIndex" Value="1">
                    <Setter Property="Background" Value="{DynamicResource BgAlternating}"/>
                </Trigger>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="{DynamicResource HoverRowBg}"/>
                </Trigger>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="{DynamicResource SelectedRowBg}"/>
                    <Setter Property="Foreground" Value="{DynamicResource SelectedRowFg}"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <Style TargetType="DataGridCell">
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="10,4"/>
            <Setter Property="FocusVisualStyle" Value="{x:Null}"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridCell">
                        <Border Background="{TemplateBinding Background}"
                                BorderThickness="0"
                                Padding="{TemplateBinding Padding}"
                                SnapsToDevicePixels="True">
                            <ContentPresenter VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="{DynamicResource SelectedRowBg}"/>
                    <Setter Property="Foreground" Value="{DynamicResource SelectedRowFg}"/>
                </Trigger>
            </Style.Triggers>
        </Style>
    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <!-- 0: Intestazione principale (Brand + Selettore Lingua 3 pulsanti + Tema + OS Info) -->
            <RowDefinition Height="Auto"/>
            <!-- 1: Banner avviso non-amministratore / errore -->
            <RowDefinition Height="Auto"/>
            <!-- 2: Barra Navigazione Schede (Tab 1 / Tab 2) + Azioni Scansione e Progresso -->
            <RowDefinition Height="Auto"/>
            <!-- 3: 5 Card KPI contatori stato -->
            <RowDefinition Height="Auto"/>
            <!-- 4: Corpo principale (Pagina 1: Tabella + Dettaglio / Pagina 2: Assistente IA Ollama) -->
            <RowDefinition Height="*"/>
            <!-- 5: Footer con Export e Disclaimer permanente -->
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- ================= RIGA 0: INTESTAZIONE ================= -->
        <Border Grid.Row="0"
                Background="{DynamicResource BgHeader}"
                BorderBrush="{DynamicResource BorderSubtle}"
                BorderThickness="0,0,0,1"
                Padding="20,12">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <!-- Colonna 0: Logo e Titolo -->
                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <Border Background="#1D4ED8" CornerRadius="8" Width="38" Height="38" Margin="0,0,12,0" VerticalAlignment="Center">
                        <Canvas Width="20" Height="20" HorizontalAlignment="Center" VerticalAlignment="Center">
                            <Path Data="M6,9 V6 A4,4 0 0,1 14,6 V9 M4,9 H16 A1,1 0 0,1 17,10 V17 A1,1 0 0,1 16,18 H4 A1,1 0 0,1 3,17 V10 A1,1 0 0,1 4,9 Z"
                                  Stroke="#FFFFFF" StrokeThickness="1.8" StrokeLineJoin="Round"/>
                        </Canvas>
                    </Border>
                    <StackPanel VerticalAlignment="Center">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock x:Name="TxtTitoloApp"
                                       Text="Scanner Sicurezza Windows 11"
                                       FontSize="18"
                                       FontWeight="Bold"
                                       Foreground="{DynamicResource TextHeader}"
                                       VerticalAlignment="Center"/>
                            <Border Background="#065F46" BorderBrush="#10B981" BorderThickness="1" CornerRadius="5" Padding="8,2" Margin="10,0,0,0" VerticalAlignment="Center">
                                <TextBlock x:Name="TxtBadgeSolaLettura"
                                           Text="SOLA LETTURA"
                                           FontSize="10"
                                           FontWeight="Bold"
                                           Foreground="#A7F3D0"/>
                            </Border>
                        </StackPanel>
                        <TextBlock x:Name="TxtSottotitoloApp"
                                   Text="58 Controlli Deterministici + Assistente IA Locale (Ollama)"
                                   FontSize="11.5"
                                   Foreground="#94A3B8"
                                   Margin="0,2,0,0"/>
                    </StackPanel>
                </StackPanel>

                <!-- Colonna 1: Info OS + Selettore Lingua esplicito [IT | EN | DE] + Pulsante Tema -->
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                    <!-- Badge Sistema Operativo -->
                    <Border Background="#111827"
                            BorderBrush="#334155"
                            BorderThickness="1"
                            CornerRadius="6"
                            Padding="11,6"
                            Margin="0,0,10,0"
                            VerticalAlignment="Center">
                        <TextBlock x:Name="TxtAmbienteInfo"
                                   Text="Windows 11 | Admin: No"
                                   FontSize="11.5"
                                   FontWeight="SemiBold"
                                   Foreground="#E2E8F0"/>
                    </Border>

                    <!-- Selettore Lingua Esplicito a 3 pulsanti (mostra chiaramente la lingua attiva) -->
                    <Border Background="#111827"
                            BorderBrush="#334155"
                            BorderThickness="1"
                            CornerRadius="7"
                            Padding="3"
                            Margin="0,0,10,0"
                            VerticalAlignment="Center">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock x:Name="LblLinguaAttiva"
                                       Text="Lingua:"
                                       FontSize="11"
                                       FontWeight="SemiBold"
                                       Foreground="#94A3B8"
                                       VerticalAlignment="Center"
                                       Margin="7,0,6,0"/>
                            <Button x:Name="BtnLinguaIT"
                                    Style="{StaticResource ModernButton}"
                                    Content="IT Italiano"
                                    Padding="9,4"
                                    Margin="0,0,3,0"
                                    FontSize="11.5"
                                    FontWeight="Bold"
                                    Background="#2563EB"
                                    Foreground="#FFFFFF"
                                    BorderThickness="0"/>
                            <Button x:Name="BtnLinguaEN"
                                    Style="{StaticResource ModernButton}"
                                    Content="EN English"
                                    Padding="9,4"
                                    Margin="0,0,3,0"
                                    FontSize="11.5"
                                    FontWeight="SemiBold"
                                    Background="Transparent"
                                    Foreground="#94A3B8"
                                    BorderThickness="0"/>
                            <Button x:Name="BtnLinguaDE"
                                    Style="{StaticResource ModernButton}"
                                    Content="DE Deutsch"
                                    Padding="9,4"
                                    FontSize="11.5"
                                    FontWeight="SemiBold"
                                    Background="Transparent"
                                    Foreground="#94A3B8"
                                    BorderThickness="0"/>
                            <!-- Alias nascosto per retrocompatibilita' -->
                            <Button x:Name="BtnLingua" Visibility="Collapsed"/>
                        </StackPanel>
                    </Border>

                    <!-- Pulsante Tema con indicazione chiara del tema attivo -->
                    <Button x:Name="BtnTema"
                            Style="{StaticResource ModernButton}"
                            Content="Tema: Scuro"
                            Padding="12,6"
                            FontSize="11.5"
                            FontWeight="SemiBold"
                            Background="#1E293B"
                            Foreground="#F8FAFC"
                            BorderBrush="#475569"/>
                </StackPanel>
            </Grid>
        </Border>

        <!-- ================= RIGA 1: BANNER AVVISI ================= -->
        <StackPanel Grid.Row="1">
            <!-- Banner Non-Amministratore -->
            <Border x:Name="BannerNonAdmin"
                    Visibility="Collapsed"
                    Background="{DynamicResource WarnBannerBg}"
                    BorderBrush="{DynamicResource WarnBannerBorder}"
                    BorderThickness="0,0,0,1"
                    Padding="20,8">
                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>
                    <TextBlock x:Name="TxtBannerNonAdmin"
                               Grid.Column="0"
                               VerticalAlignment="Center"
                               Foreground="{DynamicResource WarnBannerFg}"
                               FontWeight="SemiBold"
                               TextWrapping="Wrap"
                               Text="[!] Sessione non amministrativa: alcuni controlli risulteranno 'Sconosciuto'. Riavvia come Amministratore per l'analisi completa."/>
                    <Button x:Name="BtnRiavviaAdmin"
                            Style="{StaticResource ModernButton}"
                            Grid.Column="1"
                            Content="Riavvia come amministratore"
                            Padding="12,5"
                            Margin="12,0,0,0"
                            FontWeight="SemiBold"/>
                </Grid>
            </Border>

            <!-- Banner Errore Generale -->
            <Border x:Name="BannerErrore"
                    Visibility="Collapsed"
                    Background="{DynamicResource ErrorBg}"
                    BorderBrush="{DynamicResource ErrorBorder}"
                    BorderThickness="0,0,0,1"
                    Padding="20,8">
                <TextBlock x:Name="TxtBannerErrore"
                           Foreground="{DynamicResource ErrorFg}"
                           FontWeight="SemiBold"
                           TextWrapping="Wrap"
                           Text=""/>
            </Border>
        </StackPanel>

        <!-- ================= RIGA 2: BARRA SCHEDE E AZIONI SCANSIONE ================= -->
        <Border Grid.Row="2"
                Background="{DynamicResource BgSurface}"
                BorderBrush="{DynamicResource BorderSubtle}"
                BorderThickness="0,0,0,1"
                Padding="20,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <!-- Schede di navigazione Pagina 1 / Pagina 2 (mai troncate, evidenziano la scheda attiva) -->
                <Border Grid.Column="0"
                        Background="{DynamicResource BgSubtle}"
                        BorderBrush="{DynamicResource BorderStrong}"
                        BorderThickness="1"
                        CornerRadius="8"
                        Padding="3"
                        Margin="0,0,16,0"
                        VerticalAlignment="Center">
                    <StackPanel Orientation="Horizontal">
                        <Button x:Name="BtnNavScansione"
                                Style="{StaticResource ModernButton}"
                                Content="1. Tabella Controlli &amp; Dettagli"
                                Padding="14,6"
                                Margin="0,0,4,0"
                                FontWeight="Bold"
                                Background="#2563EB"
                                Foreground="#FFFFFF"
                                BorderThickness="0"/>
                        <Button x:Name="BtnNavIA"
                                Style="{StaticResource ModernButton}"
                                Content="2. Assistente IA (Ollama)"
                                Padding="14,6"
                                FontWeight="SemiBold"
                                Background="Transparent"
                                Foreground="{DynamicResource TextSecondary}"
                                BorderThickness="0"/>
                    </StackPanel>
                </Border>

                <!-- Pulsanti Azione Scansione -->
                <StackPanel Grid.Column="1" Orientation="Horizontal" VerticalAlignment="Center">
                    <Button x:Name="BtnAvvia"
                            Style="{StaticResource ModernButton}"
                            Content="Avvia scansione (34 controlli)"
                            FontWeight="Bold"
                            Padding="16,7"
                            Margin="0,0,8,0"
                            Background="#10B981"
                            Foreground="#FFFFFF"
                            BorderThickness="0"/>

                    <Button x:Name="BtnAnnulla"
                            Style="{StaticResource ModernButton}"
                            Content="Annulla"
                            Padding="12,7"
                            Margin="0,0,8,0"
                            IsEnabled="False"/>

                    <Button x:Name="BtnResocontoLLM"
                            Style="{StaticResource ModernButton}"
                            Content="Apri Resoconto IA &amp; Consigli"
                            FontWeight="Bold"
                            Padding="14,7"
                            Margin="0,0,14,0"
                            Background="#7C3AED"
                            Foreground="#FFFFFF"
                            BorderThickness="0"
                            IsEnabled="False"/>
                </StackPanel>

                <!-- Barra di Progresso arrotondata -->
                <Border Grid.Column="2"
                        CornerRadius="6"
                        Background="{DynamicResource BgSubtle}"
                        BorderBrush="{DynamicResource BorderStrong}"
                        BorderThickness="1"
                        Height="14"
                        VerticalAlignment="Center"
                        Margin="0,0,14,0"
                        ClipToBounds="True">
                    <ProgressBar x:Name="ProgressScansione"
                                 Minimum="0"
                                 Maximum="100"
                                 Value="0"
                                 Background="Transparent"
                                 Foreground="#10B981"
                                 BorderThickness="0"/>
                </Border>

                <TextBlock x:Name="TxtProgresso"
                           Grid.Column="3"
                           VerticalAlignment="Center"
                           Foreground="{DynamicResource TextPrimary}"
                           FontWeight="Bold"
                           FontSize="12.5"
                           Text="Pronto (0/34)"/>
            </Grid>
        </Border>

        <!-- ================= RIGA 3: 5 CARD KPI STATO ================= -->
        <UniformGrid Grid.Row="3" Columns="5" Margin="16,10,16,6">
            <!-- Superati -->
            <Border Background="{DynamicResource PassBg}"
                    BorderBrush="{DynamicResource PassBorder}"
                    BorderThickness="4,1,1,1"
                    CornerRadius="7"
                    Padding="12,8"
                    Margin="4,0">
                <TextBlock x:Name="TxtCountSuperati"
                           HorizontalAlignment="Center"
                           VerticalAlignment="Center"
                           FontWeight="Bold"
                           FontSize="13"
                           Foreground="{DynamicResource PassFg}"
                           Text="[OK] 0 Superati"/>
            </Border>

            <!-- Falliti -->
            <Border Background="{DynamicResource FailBg}"
                    BorderBrush="{DynamicResource FailBorder}"
                    BorderThickness="4,1,1,1"
                    CornerRadius="7"
                    Padding="12,8"
                    Margin="4,0">
                <TextBlock x:Name="TxtCountFalliti"
                           HorizontalAlignment="Center"
                           VerticalAlignment="Center"
                           FontWeight="Bold"
                           FontSize="13"
                           Foreground="{DynamicResource FailFg}"
                           Text="[X] 0 Falliti"/>
            </Border>

            <!-- Sconosciuti -->
            <Border Background="{DynamicResource UnknownBg}"
                    BorderBrush="{DynamicResource UnknownBorder}"
                    BorderThickness="4,1,1,1"
                    CornerRadius="7"
                    Padding="12,8"
                    Margin="4,0">
                <TextBlock x:Name="TxtCountSconosciuti"
                           HorizontalAlignment="Center"
                           VerticalAlignment="Center"
                           FontWeight="Bold"
                           FontSize="13"
                           Foreground="{DynamicResource UnknownFg}"
                           Text="[?] 0 Sconosciuti"/>
            </Border>

            <!-- Non applicabili -->
            <Border Background="{DynamicResource NaBg}"
                    BorderBrush="{DynamicResource NaBorder}"
                    BorderThickness="4,1,1,1"
                    CornerRadius="7"
                    Padding="12,8"
                    Margin="4,0">
                <TextBlock x:Name="TxtCountNonApplicabili"
                           HorizontalAlignment="Center"
                           VerticalAlignment="Center"
                           FontWeight="Bold"
                           FontSize="13"
                           Foreground="{DynamicResource NaFg}"
                           Text="[-] 0 Non applicabili"/>
            </Border>

            <!-- Errori -->
            <Border Background="{DynamicResource ErrorBg}"
                    BorderBrush="{DynamicResource ErrorBorder}"
                    BorderThickness="4,1,1,1"
                    CornerRadius="7"
                    Padding="12,8"
                    Margin="4,0">
                <TextBlock x:Name="TxtCountErrori"
                           HorizontalAlignment="Center"
                           VerticalAlignment="Center"
                           FontWeight="Bold"
                           FontSize="13"
                           Foreground="{DynamicResource ErrorFg}"
                           Text="[!] 0 Errori"/>
            </Border>
        </UniformGrid>

        <!-- ================= RIGA 4: CORPO PRINCIPALE A 2 PAGINE ================= -->
        <Grid Grid.Row="4" Margin="20,4,20,10">

            <!-- ==================== PAGINA 1: TABELLA CONTROLLI & DETTAGLI ==================== -->
            <Grid x:Name="GridPaginaScansione" Visibility="Visible">
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="*"/>
                </Grid.RowDefinitions>

                <!-- Barra Filtri -->
                <Border Grid.Row="0"
                        Background="{DynamicResource BgSurface}"
                        BorderBrush="{DynamicResource BorderSubtle}"
                        BorderThickness="1"
                        CornerRadius="8"
                        Padding="14,9"
                        Margin="0,0,0,10">
                    <Grid>
                        <Grid.ColumnDefinitions>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="155"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="145"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="185"/>
                            <ColumnDefinition Width="Auto"/>
                            <ColumnDefinition Width="*"/>
                            <ColumnDefinition Width="Auto"/>
                        </Grid.ColumnDefinitions>

                        <TextBlock x:Name="LblFiltroStato" Grid.Column="0" Text="Stato:" VerticalAlignment="Center" FontWeight="SemiBold" Margin="0,0,8,0" Foreground="{DynamicResource TextSecondary}"/>
                        <ComboBox x:Name="CmbFiltroStato" Grid.Column="1" VerticalContentAlignment="Center" Margin="0,0,14,0" SelectedIndex="0">
                            <ComboBoxItem Content="Tutti"/>
                        </ComboBox>

                        <TextBlock x:Name="LblFiltroGravita" Grid.Column="2" Text="Gravita':" VerticalAlignment="Center" FontWeight="SemiBold" Margin="0,0,8,0" Foreground="{DynamicResource TextSecondary}"/>
                        <ComboBox x:Name="CmbFiltroGravita" Grid.Column="3" VerticalContentAlignment="Center" Margin="0,0,14,0" SelectedIndex="0">
                            <ComboBoxItem Content="Tutte"/>
                        </ComboBox>

                        <TextBlock x:Name="LblFiltroCategoria" Grid.Column="4" Text="Categoria:" VerticalAlignment="Center" FontWeight="SemiBold" Margin="0,0,8,0" Foreground="{DynamicResource TextSecondary}"/>
                        <ComboBox x:Name="CmbFiltroCategoria" Grid.Column="5" VerticalContentAlignment="Center" Margin="0,0,14,0" SelectedIndex="0">
                            <ComboBoxItem Content="Tutte"/>
                        </ComboBox>

                        <TextBlock x:Name="LblFiltroCerca" Grid.Column="6" Text="Cerca:" VerticalAlignment="Center" FontWeight="SemiBold" Margin="0,0,8,0" Foreground="{DynamicResource TextSecondary}"/>
                        <TextBox x:Name="TxtRicerca"
                                 Grid.Column="7"
                                 VerticalContentAlignment="Center"
                                 Padding="10,5"
                                 Margin="0,0,12,0"/>

                        <Button x:Name="BtnResetFiltri"
                                Style="{StaticResource ModernButton}"
                                Grid.Column="8"
                                Content="Reimposta filtri"
                                Padding="12,5"/>
                    </Grid>
                </Border>

                <!-- Tabella + Pannello Dettaglio -->
                <Grid Grid.Row="1">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="3.1*" MinWidth="380"/>
                        <ColumnDefinition Width="12"/>
                        <ColumnDefinition Width="2.3*" MinWidth="320"/>
                    </Grid.ColumnDefinitions>

                    <!-- SINISTRA: Tabella Risultati -->
                    <Border Grid.Column="0"
                            Background="{DynamicResource BgSurface}"
                            BorderBrush="{DynamicResource BorderSubtle}"
                            BorderThickness="1"
                            CornerRadius="8"
                            ClipToBounds="True">
                        <Grid>
                            <DataGrid x:Name="GridRisultati"
                                      AutoGenerateColumns="False"
                                      IsReadOnly="True"
                                      SelectionMode="Single"
                                      SelectionUnit="FullRow"
                                      HeadersVisibility="Column"
                                      GridLinesVisibility="Horizontal"
                                      AlternationCount="2"
                                      HorizontalGridLinesBrush="{DynamicResource BorderSubtle}"
                                      Background="{DynamicResource BgSurface}"
                                      RowBackground="{DynamicResource BgSurface}"
                                      AlternatingRowBackground="{DynamicResource BgAlternating}"
                                      Foreground="{DynamicResource TextPrimary}"
                                      BorderThickness="0"
                                      RowHeight="36"
                                      HorizontalScrollBarVisibility="Auto"
                                      VerticalScrollBarVisibility="Auto"
                                      CanUserResizeColumns="True"
                                      CanUserAddRows="False"
                                      CanUserDeleteRows="False"
                                      CanUserReorderColumns="False">
                                <DataGrid.Columns>
                                    <DataGridTextColumn x:Name="ColStato" Header="Stato" Binding="{Binding StatusLabel}" Width="Auto" MinWidth="130"/>
                                    <DataGridTextColumn x:Name="ColGravita" Header="Gravita'" Binding="{Binding SeverityLabel}" Width="Auto" MinWidth="95"/>
                                    <DataGridTextColumn x:Name="ColCategoria" Header="Categoria" Binding="{Binding Category}" Width="Auto" MinWidth="150"/>
                                    <DataGridTextColumn x:Name="ColId" Header="ID" Binding="{Binding ControlId}" Width="Auto" MinWidth="130"/>
                                    <DataGridTextColumn x:Name="ColControllo" Header="Controllo" Binding="{Binding Title}" Width="Auto" MinWidth="560"/>
                                </DataGrid.Columns>
                            </DataGrid>

                            <!-- Overlay iniziale / lista vuota -->
                            <Border x:Name="PanelGuidaVuota"
                                    Background="{DynamicResource BgSurface}"
                                    CornerRadius="8"
                                    Padding="32"
                                    HorizontalAlignment="Stretch"
                                    VerticalAlignment="Stretch">
                                <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center" MaxWidth="440">
                                    <Border Background="{DynamicResource BgElevated}"
                                            BorderBrush="{DynamicResource BorderStrong}"
                                            BorderThickness="1"
                                            Width="64" Height="64"
                                            CornerRadius="32"
                                            HorizontalAlignment="Center"
                                            Margin="0,0,0,16">
                                        <Canvas Width="32" Height="32" HorizontalAlignment="Center" VerticalAlignment="Center">
                                            <Ellipse Canvas.Left="3" Canvas.Top="3" Width="18" Height="18" Stroke="#3B82F6" StrokeThickness="2.5"/>
                                            <Line X1="18" Y1="18" X2="28" Y2="28" Stroke="#3B82F6" StrokeThickness="2.8" StrokeStartLineCap="Round" StrokeEndLineCap="Round"/>
                                        </Canvas>
                                    </Border>
                                    <TextBlock x:Name="TxtMessaggioGuida"
                                               Text="Premi 'Avvia scansione' per analizzare i 34 controlli di sicurezza del PC."
                                               FontSize="15"
                                               FontWeight="Bold"
                                               Foreground="{DynamicResource TextPrimary}"
                                               TextAlignment="Center"
                                               TextWrapping="Wrap"
                                               Margin="0,0,0,8"/>
                                    <TextBlock x:Name="TxtSottotitoloGuida"
                                               Text="Lo strumento opera esclusivamente in sola lettura e non modifica alcuna impostazione di Windows."
                                               FontSize="12.5"
                                               Foreground="{DynamicResource TextSecondary}"
                                               TextAlignment="Center"
                                               TextWrapping="Wrap"/>
                                </StackPanel>
                            </Border>
                        </Grid>
                    </Border>

                    <GridSplitter Grid.Column="1"
                                  Width="12"
                                  HorizontalAlignment="Stretch"
                                  VerticalAlignment="Stretch"
                                  Background="Transparent"/>

                    <!-- DESTRA: Pannello di Dettaglio del Controllo -->
                    <Border Grid.Column="2"
                            Background="{DynamicResource BgSurface}"
                            BorderBrush="{DynamicResource BorderSubtle}"
                            BorderThickness="1"
                            CornerRadius="8"
                            Padding="16">
                        <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                            <StackPanel>
                                <!-- Card Titolo e Metadati Controllo -->
                                <Border Background="{DynamicResource BgSubtle}"
                                        BorderBrush="{DynamicResource BorderStrong}"
                                        BorderThickness="1"
                                        CornerRadius="7"
                                        Padding="13,11"
                                        Margin="0,0,0,12">
                                    <StackPanel>
                                        <TextBlock x:Name="TxtDettaglioTitolo"
                                                   Text="Nessun controllo selezionato"
                                                   FontSize="15.5"
                                                   FontWeight="Bold"
                                                   TextWrapping="Wrap"
                                                   Margin="0,0,0,5"/>
                                        <TextBlock x:Name="TxtDettaglioSottotitolo"
                                                   Text="Seleziona una riga dalla tabella a sinistra"
                                                   FontSize="12"
                                                   Foreground="{DynamicResource TextSecondary}"
                                                   TextWrapping="Wrap"/>
                                    </StackPanel>
                                </Border>

                                <!-- Barra Pulsanti Modalita' Semplice / Tecnica + Accesso rapido IA -->
                                <Grid Margin="0,0,0,12">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="Auto"/>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="Auto"/>
                                    </Grid.ColumnDefinitions>
                                    <Button x:Name="BtnModoSemplice"
                                            Style="{StaticResource ModernButton}"
                                            Grid.Column="0"
                                            Content="Spiegazione Semplice"
                                            Padding="11,5"
                                            Margin="0,0,6,0"
                                            FontWeight="Bold"/>
                                    <Button x:Name="BtnModoTecnico"
                                            Style="{StaticResource ModernButton}"
                                            Grid.Column="1"
                                            Content="Dettagli Tecnici"
                                            Padding="11,5"/>
                                    <Button x:Name="BtnSpiegaLLM"
                                            Style="{StaticResource ModernButton}"
                                            Grid.Column="3"
                                            Content="Spiega con IA (Pagina 2)"
                                            Padding="12,5"
                                            Background="#7C3AED"
                                            Foreground="#FFFFFF"
                                            BorderThickness="0"
                                            FontWeight="SemiBold"/>
                                </Grid>

                                <!-- Banner errore specifico del controllo -->
                                <Border x:Name="BannerDettaglioErrore"
                                        Visibility="Collapsed"
                                        Background="{DynamicResource ErrorBg}"
                                        BorderBrush="{DynamicResource ErrorBorder}"
                                        BorderThickness="1"
                                        CornerRadius="6"
                                        Padding="10,8"
                                        Margin="0,0,0,12">
                                    <TextBlock x:Name="TxtDettaglioErrore"
                                               Foreground="{DynamicResource ErrorFg}"
                                               TextWrapping="Wrap"
                                               Text=""/>
                                </Border>

                                <!-- Sezione Spiegazione -->
                                <TextBlock x:Name="TxtTitoloSpiegazione"
                                           Text="Perche' conta (spiegazione semplice)"
                                           FontWeight="Bold"
                                           FontSize="13"
                                           Margin="0,0,0,5"/>
                                <Border Background="{DynamicResource BgSubtle}"
                                        BorderBrush="{DynamicResource BorderSubtle}"
                                        BorderThickness="1"
                                        CornerRadius="6"
                                        Padding="12,9"
                                        Margin="0,0,0,12">
                                    <TextBlock x:Name="TxtDettaglioSpiegazione"
                                               Text="-"
                                               TextWrapping="Wrap"
                                               LineHeight="19"/>
                                </Border>

                                <!-- Valore Atteso vs Valore Osservato -->
                                <Grid Margin="0,0,0,12">
                                    <Grid.ColumnDefinitions>
                                        <ColumnDefinition Width="*"/>
                                        <ColumnDefinition Width="10"/>
                                        <ColumnDefinition Width="*"/>
                                    </Grid.ColumnDefinitions>

                                    <Border Grid.Column="0"
                                            Background="{DynamicResource BgSubtle}"
                                            BorderBrush="{DynamicResource BorderSubtle}"
                                            BorderThickness="1"
                                            CornerRadius="6"
                                            Padding="11,9">
                                        <StackPanel>
                                            <TextBlock x:Name="LblValoreAtteso"
                                                       Text="VALORE ATTESO"
                                                       FontWeight="Bold"
                                                       FontSize="10.5"
                                                       Foreground="{DynamicResource TextSecondary}"
                                                       Margin="0,0,0,4"/>
                                            <TextBlock x:Name="TxtDettaglioAtteso"
                                                       Text="-"
                                                       FontWeight="SemiBold"
                                                       TextWrapping="Wrap"/>
                                        </StackPanel>
                                    </Border>

                                    <Border Grid.Column="2"
                                            Background="{DynamicResource BgSubtle}"
                                            BorderBrush="{DynamicResource BorderSubtle}"
                                            BorderThickness="1"
                                            CornerRadius="6"
                                            Padding="11,9">
                                        <StackPanel>
                                            <TextBlock x:Name="LblValoreOsservato"
                                                       Text="VALORE OSSERVATO"
                                                       FontWeight="Bold"
                                                       FontSize="10.5"
                                                       Foreground="{DynamicResource TextSecondary}"
                                                       Margin="0,0,0,4"/>
                                            <TextBlock x:Name="TxtDettaglioOsservato"
                                                       Text="-"
                                                       FontWeight="SemiBold"
                                                       TextWrapping="Wrap"/>
                                        </StackPanel>
                                    </Border>
                                </Grid>

                                <!-- Come correggere (Rimedio) -->
                                <TextBlock x:Name="LblComeCorreggere"
                                           Text="Come correggere (istruzioni manuali)"
                                           FontWeight="Bold"
                                           FontSize="13"
                                           Margin="0,0,0,5"/>
                                <Border Background="{DynamicResource BgSubtle}"
                                        BorderBrush="{DynamicResource BorderSubtle}"
                                        BorderThickness="1"
                                        CornerRadius="6"
                                        Padding="12,9"
                                        Margin="0,0,0,10">
                                    <TextBlock x:Name="TxtDettaglioRimedio"
                                               Text="-"
                                               TextWrapping="Wrap"
                                               LineHeight="19"/>
                                </Border>

                                <!-- Blocco Comando PowerShell (visibile solo se HaComando = true) -->
                                <StackPanel x:Name="PanelComandoRimedio" Visibility="Collapsed" Margin="0,0,0,12">
                                    <TextBlock x:Name="LblComandoRif"
                                               Text="COMANDO DI RIFERIMENTO (NON ESEGUITO AUTOMATICAMENTE):"
                                               FontSize="10.5"
                                               FontWeight="Bold"
                                               Foreground="{DynamicResource TextSecondary}"
                                               Margin="0,0,0,4"/>
                                    <TextBox x:Name="TxtComandoRimedio"
                                             IsReadOnly="True"
                                             FontFamily="Consolas"
                                             FontSize="12"
                                             TextWrapping="Wrap"
                                             Padding="10,8"
                                             Margin="0,0,0,6"/>
                                    <StackPanel Orientation="Horizontal">
                                        <Button x:Name="BtnCopiaComando"
                                                Style="{StaticResource ModernButton}"
                                                Content="Copia comando negli appunti"
                                                Padding="12,5"/>
                                        <TextBlock x:Name="TxtFeedbackCopia"
                                                   Text="Copiato!"
                                                   VerticalAlignment="Center"
                                                   Margin="10,0,0,0"
                                                   FontWeight="Bold"
                                                   Foreground="{DynamicResource PassFg}"
                                                   Visibility="Collapsed"/>
                                    </StackPanel>
                                </StackPanel>

                                <!-- Note sui rischi -->
                                <TextBlock x:Name="LblNoteRischi"
                                           Text="Note sui rischi"
                                           FontWeight="Bold"
                                           FontSize="13"
                                           Margin="0,0,0,4"/>
                                <TextBlock x:Name="TxtDettaglioRischi"
                                           Text="-"
                                           Foreground="{DynamicResource TextSecondary}"
                                           TextWrapping="Wrap"/>
                            </StackPanel>
                        </ScrollViewer>
                    </Border>
                </Grid>
            </Grid>

            <!-- ==================== PAGINA 2: ASSISTENTE IA & RESOCONTO (A TUTTO SCHERMO) ==================== -->
            <Grid x:Name="GridPaginaIA" Visibility="Collapsed">
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="375"/>
                    <ColumnDefinition Width="16"/>
                    <ColumnDefinition Width="*"/>
                </Grid.ColumnDefinitions>

                <!-- COLONNA SINISTRA PAGINA IA: Configurazione Auto-Ollama & Azioni Rapide -->
                <Border Grid.Column="0"
                        Background="{DynamicResource BgSurface}"
                        BorderBrush="{DynamicResource BorderSubtle}"
                        BorderThickness="1"
                        CornerRadius="8"
                        Padding="16">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>

                        <!-- Box Configurazione Server Ollama (Auto-Setup VM) -->
                        <Border Grid.Row="0"
                                Background="{DynamicResource BgSubtle}"
                                BorderBrush="{DynamicResource BorderStrong}"
                                BorderThickness="1"
                                CornerRadius="8"
                                Padding="13"
                                Margin="0,0,0,14">
                            <StackPanel>
                                <TextBlock x:Name="LblMotoreIaTitle"
                                           Text="MOTORE IA LOCALE (OLLAMA)"
                                           FontWeight="Bold"
                                           FontSize="12"
                                           Foreground="{DynamicResource AccentBrush}"
                                           Margin="0,0,0,8"/>

                                <TextBlock x:Name="LblIndirizzoOllama"
                                           Text="Indirizzo Server Ollama:"
                                           FontSize="11.5"
                                           FontWeight="SemiBold"
                                           Foreground="{DynamicResource TextSecondary}"
                                           Margin="0,0,0,3"/>
                                <TextBox x:Name="TxtEndpointOllama"
                                         Text="http://127.0.0.1:11434"
                                         FontFamily="Consolas"
                                         FontSize="12"
                                         Padding="8,5"
                                         Margin="0,0,0,9"/>

                                <TextBlock x:Name="LblModelloOllama"
                                           Text="Modello LLM leggero:"
                                           FontSize="11.5"
                                           FontWeight="SemiBold"
                                           Foreground="{DynamicResource TextSecondary}"
                                           Margin="0,0,0,3"/>
                                <ComboBox x:Name="CmbModelloOllama"
                                          IsEditable="True"
                                          SelectedIndex="0"
                                          Padding="6,4"
                                          Margin="0,0,0,9">
                                    <ComboBoxItem Content="qwen2.5:0.5b"/>
                                    <ComboBoxItem Content="qwen2.5:1.5b"/>
                                    <ComboBoxItem Content="llama3.2:1b"/>
                                    <ComboBoxItem Content="gemma2:2b"/>
                                </ComboBox>

                                <CheckBox x:Name="ChkAutoInstallaOllama"
                                          IsChecked="True"
                                          Margin="0,0,0,10"
                                          Foreground="{DynamicResource TextPrimary}">
                                    <TextBlock x:Name="TxtChkAutoInstalla"
                                               Text="Se Ollama manca sulla VM, installalo e avvialo automaticamente in background"
                                               FontSize="11.5"
                                               TextWrapping="Wrap"/>
                                </CheckBox>

                                <Button x:Name="BtnVerificaOllama"
                                        Style="{StaticResource ModernButton}"
                                        Content="Verifica / Auto-Configura Ollama"
                                        Padding="10,7"
                                        FontWeight="SemiBold"
                                        HorizontalAlignment="Stretch"/>
                            </StackPanel>
                        </Border>

                        <!-- Pulsanti Generazione Analisi -->
                        <StackPanel Grid.Row="1" Margin="0,0,0,14">
                            <TextBlock x:Name="LblGeneraAnalisiTitle"
                                       Text="GENERA ANALISI E CONSIGLI"
                                       FontWeight="Bold"
                                       FontSize="11.5"
                                       Foreground="{DynamicResource TextSecondary}"
                                       Margin="0,0,0,7"/>

                            <Button x:Name="BtnResocontoTab"
                                    Style="{StaticResource ModernButton}"
                                    Content="Genera Resoconto Completo PC"
                                    Padding="12,10"
                                    Margin="0,0,0,8"
                                    Background="#7C3AED"
                                    Foreground="#FFFFFF"
                                    BorderThickness="0"
                                    FontWeight="Bold"
                                    FontSize="13"/>

                            <Button x:Name="BtnSpiegaControlloTab"
                                    Style="{StaticResource ModernButton}"
                                    Content="Spiega il Controllo Selezionato"
                                    Padding="12,9"
                                    Background="#2563EB"
                                    Foreground="#FFFFFF"
                                    BorderThickness="0"
                                    FontWeight="SemiBold"/>
                        </StackPanel>

                        <!-- Lista rapida dei controlli falliti (senza scrollbar orizzontale, con card avvolte) -->
                        <Grid Grid.Row="2">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            <TextBlock x:Name="LblCriticitaRilevate"
                                       Grid.Row="0"
                                       Text="CRITICITA' RILEVATE (CLICCA PER ANALIZZARE):"
                                       FontSize="11"
                                       FontWeight="Bold"
                                       Foreground="{DynamicResource TextSecondary}"
                                       Margin="0,0,0,6"/>
                            <ListBox x:Name="ListFallitiIA"
                                     Grid.Row="1"
                                     ScrollViewer.HorizontalScrollBarVisibility="Disabled"
                                     HorizontalContentAlignment="Stretch"
                                     Background="{DynamicResource BgSubtle}"
                                     Foreground="{DynamicResource TextPrimary}"
                                     BorderBrush="{DynamicResource BorderSubtle}"
                                     BorderThickness="1"
                                     Padding="4">
                                <ListBox.ItemTemplate>
                                    <DataTemplate>
                                        <Border Background="{DynamicResource BgSurface}"
                                                BorderBrush="{DynamicResource FailBorder}"
                                                BorderThickness="3,1,1,1"
                                                CornerRadius="5"
                                                Padding="9,7"
                                                Margin="0,2">
                                            <StackPanel>
                                                <TextBlock Text="{Binding Title}"
                                                           FontWeight="SemiBold"
                                                           FontSize="12"
                                                           Foreground="{DynamicResource TextPrimary}"
                                                           TextWrapping="Wrap"/>
                                                <TextBlock Text="{Binding ControlId}"
                                                           FontSize="10.5"
                                                           Foreground="{DynamicResource TextSecondary}"
                                                           Margin="0,2,0,0"/>
                                            </StackPanel>
                                        </Border>
                                    </DataTemplate>
                                </ListBox.ItemTemplate>
                            </ListBox>
                        </Grid>
                    </Grid>
                </Border>

                <!-- COLONNA DESTRA PAGINA IA: Resoconto a Tutto Schermo -->
                <Border Grid.Column="2"
                        Background="{DynamicResource BgSurface}"
                        BorderBrush="{DynamicResource BorderSubtle}"
                        BorderThickness="1"
                        CornerRadius="8"
                        Padding="22">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>

                        <!-- Intestazione Resoconto IA -->
                        <Grid Grid.Row="0" Margin="0,0,0,14">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="Auto"/>
                                <ColumnDefinition Width="Auto"/>
                            </Grid.ColumnDefinitions>
                            <StackPanel Grid.Column="0">
                                <TextBlock x:Name="LblTitoloResocontoIA"
                                           Text="RESOCONTO DI SICUREZZA &amp; PIANO DI MIGLIORAMENTO IA"
                                           FontSize="16"
                                           FontWeight="Bold"
                                           Foreground="{DynamicResource TextPrimary}"/>
                                <TextBlock x:Name="TxtStatoLLM"
                                           Text="Stato: Pronto (connessione o auto-installazione automatica al primo avvio)"
                                           FontSize="12"
                                           FontWeight="SemiBold"
                                           Foreground="{DynamicResource AccentBrush}"
                                           Margin="0,4,0,0"/>
                            </StackPanel>
                            <Button x:Name="BtnCopiaRispostaLLM"
                                    Style="{StaticResource ModernButton}"
                                    Grid.Column="1"
                                    Content="Copia Resoconto"
                                    Padding="14,7"
                                    Margin="0,0,8,0"
                                    VerticalAlignment="Center"/>
                            <Button x:Name="BtnTornaScansione"
                                    Style="{StaticResource ModernButton}"
                                    Grid.Column="2"
                                    Content="Torna alla Tabella Controlli"
                                    Padding="14,7"
                                    VerticalAlignment="Center"/>
                        </Grid>

                        <!-- Area di lettura ampia e spaziata del Resoconto -->
                        <TextBox x:Name="TxtRispostaLLM"
                                 Grid.Row="1"
                                 IsReadOnly="True"
                                 TextWrapping="Wrap"
                                 VerticalScrollBarVisibility="Auto"
                                 FontFamily="Segoe UI"
                                 FontSize="14"
                                 Padding="18"
                                 Text="1. Esegui prima la scansione del PC col pulsante 'Avvia scansione (34 controlli)' in alto.&#x0a;2. Premi 'Genera Resoconto Completo PC' qui a sinistra per ricevere l'analisi di tutte le vulnerabilita' trovate e i consigli pratici di messa in sicurezza.&#x0a;3. Se sei su una Macchina Virtuale senza Ollama, lascia attiva la spunta a sinistra: il tool pensera' a tutto in automatico."/>
                    </Grid>
                </Border>
            </Grid>
        </Grid>

        <!-- ================= RIGA 5: FOOTER EXPORT & DISCLAIMER ================= -->
        <Border Grid.Row="5"
                Background="{DynamicResource BgSurface}"
                BorderBrush="{DynamicResource BorderSubtle}"
                BorderThickness="0,1,0,0"
                Padding="20,10">
            <StackPanel>
                <Grid Margin="0,0,0,5">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="Auto"/>
                    </Grid.ColumnDefinitions>

                    <Button x:Name="BtnEsportaJson"
                            Style="{StaticResource ModernButton}"
                            Grid.Column="0"
                            Content="Esporta JSON"
                            Padding="14,6"
                            Margin="0,0,8,0"
                            FontWeight="SemiBold"
                            IsEnabled="False"/>

                    <Button x:Name="BtnEsportaHtml"
                            Style="{StaticResource ModernButton}"
                            Grid.Column="1"
                            Content="Esporta HTML"
                            Padding="14,6"
                            Margin="0,0,16,0"
                            FontWeight="SemiBold"
                            IsEnabled="False"/>

                    <CheckBox x:Name="ChkSalvaLogTecnico"
                              Grid.Column="2"
                              VerticalAlignment="Center"
                              Foreground="{DynamicResource TextPrimary}"
                              Content="Includi file di log tecnico accanto all'export"/>

                    <TextBlock x:Name="TxtRiepilogoFooter"
                               Grid.Column="4"
                               VerticalAlignment="Center"
                               FontSize="12"
                               FontWeight="SemiBold"
                               Foreground="{DynamicResource TextSecondary}"
                               Text="Riepilogo calcolato dal codice: 0 controlli valutati"/>
                </Grid>

                <TextBlock x:Name="TxtDisclaimerPermanente"
                           FontSize="11"
                           FontStyle="Italic"
                           Foreground="{DynamicResource TextSecondary}"
                           TextWrapping="Wrap"
                           Text="Avviso permanente: questo strumento verifica solo alcune configurazioni di sicurezza in sola lettura. Un audit conforme non dimostra l'assenza di compromissioni sul sistema."/>
            </StackPanel>
        </Border>
    </Grid>
</Window>
'@

# =============================================================================
# MODULO: src\core\Environment.ps1
# =============================================================================
<#
.SYNOPSIS
    Rileva le informazioni sull'ambiente di esecuzione.

.DESCRIPTION
    Raccoglie edizione di Windows, build e UBR, lingua di sistema,
    stato di amministratore e versione di PowerShell.
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Get-AmbienteSistema {
    <#
    .SYNOPSIS
        Restituisce un oggetto con le informazioni sull'ambiente.
    .OUTPUTS
        PSCustomObject con proprieta': Edition, Build, Language, IsAdmin, PsVersion
    #>
    [CmdletBinding()]
    param()

    # Edizione: EditionID dal registro (es. "Core" = Home, "Professional" = Pro)
    $editionId = $null
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $editionId = (Get-ItemProperty -Path $regPath -Name 'EditionID' -ErrorAction Stop).EditionID
    }
    catch {
        $editionId = 'Sconosciuta'
    }

    # Mappa EditionID ai nomi usati nel catalogo
    $editionMap = @{
        'Core'              = 'Home'
        'CoreSingleLanguage'= 'Home'
        'Professional'      = 'Pro'
        'Education'         = 'Pro'   # trattata come Pro per i controlli
        'Enterprise'        = 'Pro'   # trattata come Pro per i controlli
    }
    $editionName = $editionId
    if ($editionMap.ContainsKey($editionId)) {
        $editionName = $editionMap[$editionId]
    }

    # Build e UBR
    $build = $null
    $ubr = $null
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $ntVer = Get-ItemProperty -Path $regPath -ErrorAction Stop
        if ($ntVer.PSObject.Properties['CurrentBuildNumber']) {
            $build = $ntVer.CurrentBuildNumber
        }
        else {
            $build = 'Sconosciuto'
        }
        if ($ntVer.PSObject.Properties['UBR']) {
            $ubr = $ntVer.UBR
        }
    }
    catch {
        $build = 'Sconosciuto'
        $ubr = $null
    }

    $buildString = $build
    if ($null -ne $ubr) {
        $buildString = "$build.$ubr"
    }

    # Lingua di sistema (codice LCID -> nome cultura)
    $language = $null
    try {
        $culture = [System.Globalization.CultureInfo]::InstalledUICulture
        $language = $culture.Name  # es. "it-IT", "en-US"
    }
    catch {
        $language = 'Sconosciuta'
    }

    # Stato di amministratore
    $isAdmin = $false
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        $isAdmin = $false
    }

    # Versione PowerShell
    $psVersion = $PSVersionTable.PSVersion.ToString()

    # Costruisci l'oggetto risultato
    $ambiente = [PSCustomObject]@{
        Edition   = $editionName
        EditionId = $editionId
        Build     = $buildString
        Language  = $language
        IsAdmin   = $isAdmin
        PsVersion = $psVersion
    }

    return $ambiente
}

# =============================================================================
# MODULO: src\core\Catalog.ps1
# =============================================================================
<#
.SYNOPSIS
    Carica e valida il catalogo dei controlli di sicurezza.

.DESCRIPTION
    Legge il file JSON del catalogo e verifica la coerenza minima:
    - Il file esiste e contiene JSON valido
    - La versione dello schema e' supportata
    - Gli ID dei controlli non sono duplicati
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Import-Catalogo {
    <#
    .SYNOPSIS
        Carica il catalogo JSON e restituisce l'oggetto PowerShell.
    .PARAMETER PercorsoCatalogo
        Percorso completo del file home_profile.json.
    .OUTPUTS
        PSCustomObject rappresentante il catalogo.
    .NOTES
        Lancia un'eccezione se il file non esiste, il JSON non e' valido,
        o la coerenza minima non e' rispettata.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PercorsoCatalogo
    )

    # Verifica esistenza file
    if (-not (Test-Path -LiteralPath $PercorsoCatalogo)) {
        throw "Il file del catalogo non esiste: $PercorsoCatalogo"
    }

    # Leggi il contenuto
    $contenuto = Get-Content -LiteralPath $PercorsoCatalogo -Raw -Encoding UTF8 -ErrorAction Stop

    # Converti da JSON
    try {
        $catalogo = $contenuto | ConvertFrom-Json
    }
    catch {
        throw "Il file del catalogo non contiene JSON valido: $_"
    }

    # Verifica schema_version
    $versioniSupportate = @('0.1', '0.2')
    if (-not ($catalogo.PSObject.Properties['schema_version']) -or -not ($catalogo.schema_version)) {
        throw "Il catalogo non contiene il campo 'schema_version'."
    }
    if ($versioniSupportate -notcontains $catalogo.schema_version) {
        throw "Versione dello schema non supportata: $($catalogo.schema_version). Supportate: $($versioniSupportate -join ', ')"
    }

    # Verifica presenza controlli
    if (-not ($catalogo.PSObject.Properties['controls']) -or -not ($catalogo.controls)) {
        throw "Il catalogo non contiene il campo 'controls'."
    }

    # Verifica ID duplicati
    $ids = @()
    foreach ($controllo in $catalogo.controls) {
        if (-not ($controllo.PSObject.Properties['id']) -or -not $controllo.id) {
            throw "Un controllo nel catalogo non ha il campo 'id'."
        }
        if ($ids -contains $controllo.id) {
            throw "ID duplicato nel catalogo: $($controllo.id)"
        }
        $ids += $controllo.id
    }

    return $catalogo
}

# =============================================================================
# MODULO: src\core\Runner.ps1
# =============================================================================
<#
.SYNOPSIS
    Runner: esegue i controlli di sicurezza dal catalogo.

.DESCRIPTION
    Itera sui controlli del catalogo, determina il tipo (registro o funzione),
    li esegue e raccoglie i risultati. Un errore in un controllo NON ferma
    gli altri.
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Invoke-Controlli {
    <#
    .SYNOPSIS
        Esegue i controlli specificati e restituisce un array di risultati.
    .PARAMETER Catalogo
        L'oggetto catalogo caricato da Import-Catalogo.
    .PARAMETER Ambiente
        L'oggetto ambiente da Get-AmbienteSistema.
    .PARAMETER ControlId
        Array opzionale di ID di controllo da eseguire. Se vuoto, esegue tutti.
    .PARAMETER CartellaChecks
        Percorso della cartella contenente gli script di controllo.
    .PARAMETER OnProgress
        Scriptblock opzionale invocato dopo ogni controllo: riceve ($IndiceCorrente, $Totale, $Risultato).
    .PARAMETER ShouldCancel
        Scriptblock opzionale invocato prima di ogni controllo: se restituisce $true interrompe la scansione.
    .OUTPUTS
        Array di PSCustomObject con i risultati dei controlli.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Catalogo,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Ambiente,

        [Parameter(Mandatory = $false)]
        [string[]]$ControlId = @(),

        [Parameter(Mandatory = $false)]
        [string]$CartellaChecks = '',

        [Parameter(Mandatory = $false)]
        [scriptblock]$OnProgress = $null,

        [Parameter(Mandatory = $false)]
        [scriptblock]$ShouldCancel = $null
    )

    $risultati = @()

    # Normalizza ControlId (gestisce stringhe separate da virgola)
    $idFiltro = @()
    if ($null -ne $ControlId) {
        foreach ($id in $ControlId) {
            if ($id -match ',') {
                $idFiltro += ($id -split ',' | ForEach-Object { $_.Trim() })
            }
            elseif ($id.Trim() -ne '') {
                $idFiltro += $id.Trim()
            }
        }
    }

    # Determina la lista di controlli da eseguire per avere il totale esatto
    $controlliDaEseguire = @()
    foreach ($c in $Catalogo.controls) {
        if ($idFiltro.Count -gt 0 -and ($idFiltro -notcontains $c.id)) {
            continue
        }
        $controlliDaEseguire += $c
    }

    $totale = $controlliDaEseguire.Count
    $indiceCorrente = 0

    foreach ($controllo in $controlliDaEseguire) {
        # Verifica eventuale richiesta di annullamento prima di iniziare il controllo
        if ($null -ne $ShouldCancel) {
            $annulla = & $ShouldCancel
            if ($annulla) {
                break
            }
        }

        $indiceCorrente++
        $elementoRisultato = $null

        # Verifica se il controllo ha i campi check necessari
        $haCheck = ($null -ne $controllo.PSObject.Properties['check'] -and $null -ne $controllo.check)
        $haRegistry = $false
        $haCommandRef = $false

        if ($haCheck) {
            # Verifica se ha check.registry
            if ($null -ne $controllo.check.PSObject.Properties['registry'] -and
                $null -ne $controllo.check.registry -and
                $null -ne $controllo.check.registry.PSObject.Properties['path'] -and
                $null -ne $controllo.check.registry.path) {
                $haRegistry = $true
            }
            # Verifica se ha check.command_ref
            if ($null -ne $controllo.check.PSObject.Properties['command_ref'] -and
                $null -ne $controllo.check.command_ref -and
                $null -ne $controllo.check.command_ref -ne '') {
                $haCommandRef = $true
            }
        }

        # Se non ha ne' registry ne' command_ref, il controllo non e' implementato
        if (-not $haRegistry -and -not $haCommandRef) {
            $elementoRisultato = [PSCustomObject]@{
                control_id  = $controllo.id
                status      = 'sconosciuto'
                observed    = 'Controllo non ancora implementato'
                expected    = $null
                evidence    = $null
                error       = $null
                duration_ms = 0
            }
            $risultati += $elementoRisultato
            if ($null -ne $OnProgress) {
                & $OnProgress $indiceCorrente $totale $elementoRisultato
            }
            continue
        }

        # Verifica applicabilita' per edizione
        $edizioni = @()
        foreach ($ed in $controllo.editions) {
            $edizioni += $ed
        }
        if ($edizioni.Count -gt 0 -and $edizioni -notcontains $Ambiente.Edition) {
            $elementoRisultato = [PSCustomObject]@{
                control_id  = $controllo.id
                status      = 'non_applicabile'
                observed    = "Edizione $($Ambiente.Edition) non in: $($edizioni -join ', ')"
                expected    = $null
                evidence    = @{ EditioneMacchina = $Ambiente.Edition; EdizioniControllo = $edizioni }
                error       = $null
                duration_ms = 0
            }
            $risultati += $elementoRisultato
            if ($null -ne $OnProgress) {
                & $OnProgress $indiceCorrente $totale $elementoRisultato
            }
            continue
        }

        # Esegui il controllo con gestione errori
        $cronometro = [System.Diagnostics.Stopwatch]::StartNew()
        try {
            $risultatoControllo = $null

            if ($haRegistry) {
                # Controllo basato su registro: usa il valutatore generico
                $risultatoControllo = Test-RegistryValue -RegistryCheck $controllo.check.registry -Ambiente $Ambiente
            }
            elseif ($haCommandRef) {
                # Controllo basato su funzione: risolvi il riferimento
                $parti = $controllo.check.command_ref -split '#'
                if ($parti.Count -ne 2) {
                    throw "Formato command_ref non valido: $($controllo.check.command_ref). Atteso: 'File.ps1#Nome-Funzione'"
                }

                $nomeFile = $parti[0]
                $nomeFunzione = $parti[1]

                # Carica il file (dot-source) se la funzione non e' gia' disponibile in memoria
                if (-not (Get-Command -Name $nomeFunzione -ErrorAction SilentlyContinue)) {
                    $percorsoFile = if ($CartellaChecks) { Join-Path $CartellaChecks $nomeFile } else { $nomeFile }
                    if (-not (Test-Path -LiteralPath $percorsoFile)) {
                        throw "File di controllo non trovato: $percorsoFile"
                    }
                    . $percorsoFile
                }

                # Esegui la funzione
                $risultatoControllo = & $nomeFunzione -Controllo $controllo -Ambiente $Ambiente
            }

            $cronometro.Stop()

            $elementoRisultato = [PSCustomObject]@{
                control_id  = $controllo.id
                status      = $risultatoControllo.Status
                observed    = $risultatoControllo.Observed
                expected    = $risultatoControllo.Expected
                evidence    = $risultatoControllo.Evidence
                error       = $risultatoControllo.Error
                duration_ms = [int]$cronometro.ElapsedMilliseconds
            }
        }
        catch {
            $cronometro.Stop()
            # Un errore nel controllo produce status "errore", non ferma gli altri
            $elementoRisultato = [PSCustomObject]@{
                control_id  = $controllo.id
                status      = 'errore'
                observed    = $null
                expected    = $null
                evidence    = $null
                error       = $_.Exception.Message
                duration_ms = [int]$cronometro.ElapsedMilliseconds
            }
        }

        $risultati += $elementoRisultato
        if ($null -ne $OnProgress) {
            & $OnProgress $indiceCorrente $totale $elementoRisultato
        }
    }

    return ,$risultati
}

# =============================================================================
# MODULO: src\core\Report.ps1
# =============================================================================
<#
.SYNOPSIS
    Costruisce l'oggetto risultato e lo scrive in JSON.

.DESCRIPTION
    Genera l'oggetto report conforme al contratto (schema_version 0.1),
    calcola il riepilogo dai risultati e scrive il file JSON in UTF-8
    senza BOM.
    Non modifica mai lo stato del sistema (tranne il file di output).
#>

Set-StrictMode -Version 2

function New-Report {
    <#
    .SYNOPSIS
        Costruisce l'oggetto report a partire dai risultati dei controlli.
    .PARAMETER Risultati
        Array di risultati dei controlli (da Invoke-Controlli).
    .PARAMETER Ambiente
        Oggetto ambiente (da Get-AmbienteSistema).
    .PARAMETER Catalogo
        Oggetto catalogo (da Import-Catalogo).
    .PARAMETER VersioneTool
        Versione dello scanner.
    .OUTPUTS
        PSCustomObject conforme al contratto del risultato.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [array]$Risultati,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Ambiente,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Catalogo,

        [Parameter(Mandatory = $false)]
        [string]$VersioneTool = '0.1.0'
    )

    $risultatiArray = if ($null -eq $Risultati) { @() } else { @($Risultati) }

    # Calcola il riepilogo
    $riepilogo = @{
        superato         = 0
        fallito          = 0
        non_applicabile  = 0
        sconosciuto      = 0
        errore           = 0
    }

    foreach ($r in $risultatiArray) {
        if ($riepilogo.ContainsKey($r.status)) {
            $riepilogo[$r.status] = $riepilogo[$r.status] + 1
        }
    }

    # Costruisci l'oggetto report
    $report = [PSCustomObject]@{
        schema_version  = '0.1'
        run_id          = [guid]::NewGuid().ToString()
        timestamp       = (Get-Date).ToUniversalTime().ToString('o')
        tool_version    = $VersioneTool
        catalog_version = $Catalogo.schema_version
        environment     = [PSCustomObject]@{
            edition    = $Ambiente.Edition
            build      = $Ambiente.Build
            language   = $Ambiente.Language
            is_admin   = $Ambiente.IsAdmin
            ps_version = $Ambiente.PsVersion
        }
        results         = $risultatiArray
        summary         = [PSCustomObject]@{
            superato        = $riepilogo['superato']
            fallito         = $riepilogo['fallito']
            non_applicabile = $riepilogo['non_applicabile']
            sconosciuto     = $riepilogo['sconosciuto']
            errore          = $riepilogo['errore']
        }
    }

    return $report
}

function Export-ReportJson {
    <#
    .SYNOPSIS
        Scrive il report in formato JSON su file, in UTF-8 senza BOM.
    .PARAMETER Report
        L'oggetto report da scrivere.
    .PARAMETER PercorsoFile
        Percorso del file di output.
    .NOTES
        Usa [System.IO.File]::WriteAllText con UTF8Encoding($false) per
        garantire UTF-8 senza BOM.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Report,

        [Parameter(Mandatory = $true)]
        [string]$PercorsoFile
    )

    # Converti in JSON con profondita' sufficiente
    $json = $Report | ConvertTo-Json -Depth 10

    # Scrivi in UTF-8 senza BOM
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($PercorsoFile, $json, $utf8NoBom)
}

function ConvertTo-ReportHtml {
    <#
    .SYNOPSIS
        Converte un oggetto Report (e opzionalmente il Catalogo) in una stringa HTML autonoma.
    .PARAMETER Report
        L'oggetto report generato da New-Report.
    .PARAMETER Catalogo
        Oggetto catalogo opzionale per arricchire la tabella con titoli, gravita' e categorie.
    .OUTPUTS
        Stringa HTML completa con CSS incorporato e nessuna risorsa esterna.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Report,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Catalogo = $null
    )

    # Mappa rapida dei controlli del catalogo per ID
    $mappaCatalogo = @{}
    if ($null -ne $Catalogo -and $null -ne $Catalogo.PSObject.Properties['controls'] -and $null -ne $Catalogo.controls) {
        foreach ($c in $Catalogo.controls) {
            if ($null -ne $c.PSObject.Properties['id'] -and $c.id) {
                $mappaCatalogo[$c.id] = $c
            }
        }
    }

    $escapeHtml = {
        param([AllowNull()][string]$Testo)
        if ([string]::IsNullOrEmpty($Testo)) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($Testo)
    }

    $righeHtml = New-Object System.Text.StringBuilder
    $risultatiLista = if ($null -ne $Report.results) { @($Report.results) } else { @() }

    foreach ($r in $risultatiLista) {
        $id = [string]$r.control_id
        $stato = [string]$r.status
        $titolo = $id
        $categoria = '-'
        $gravita = '-'
        $spiegazione = ''

        if ($mappaCatalogo.ContainsKey($id)) {
            $meta = $mappaCatalogo[$id]
            if ($null -ne $meta.PSObject.Properties['title'] -and $meta.title) { $titolo = [string]$meta.title }
            if ($null -ne $meta.PSObject.Properties['category'] -and $meta.category) { $categoria = [string]$meta.category }
            if ($null -ne $meta.PSObject.Properties['severity'] -and $meta.severity) { $gravita = [string]$meta.severity }
            if ($null -ne $meta.PSObject.Properties['rationale'] -and $meta.rationale) { $spiegazione = [string]$meta.rationale }
        }

        $simboloStato = '[?]'
        $etichettaStato = 'Sconosciuto'
        $classeStato = 'stato-sconosciuto'
        switch ($stato) {
            'superato'        { $simboloStato = '[OK]'; $etichettaStato = 'Superato';        $classeStato = 'stato-superato' }
            'fallito'         { $simboloStato = '[X]';  $etichettaStato = 'Fallito';         $classeStato = 'stato-fallito' }
            'sconosciuto'     { $simboloStato = '[?]';  $etichettaStato = 'Sconosciuto';     $classeStato = 'stato-sconosciuto' }
            'errore'          { $simboloStato = '[!]';  $etichettaStato = 'Errore';          $classeStato = 'stato-errore' }
            'non_applicabile' { $simboloStato = '[-]';  $etichettaStato = 'Non applicabile'; $classeStato = 'stato-na' }
        }

        $osservatoStr = if ($null -ne $r.observed) { [string]$r.observed } else { '-' }
        $attesoStr    = if ($null -ne $r.expected) { [string]$r.expected } else { '-' }

        [void]$righeHtml.AppendLine("<tr>")
        [void]$righeHtml.AppendLine("  <td><span class='badge $classeStato'>$(& $escapeHtml "$simboloStato $etichettaStato")</span></td>")
        [void]$righeHtml.AppendLine("  <td>$(& $escapeHtml $gravita)</td>")
        [void]$righeHtml.AppendLine("  <td>$(& $escapeHtml $categoria)</td>")
        [void]$righeHtml.AppendLine("  <td><code>$(& $escapeHtml $id)</code></td>")
        [void]$righeHtml.AppendLine("  <td><strong>$(& $escapeHtml $titolo)</strong><br><small>$(& $escapeHtml $spiegazione)</small></td>")
        [void]$righeHtml.AppendLine("  <td>$(& $escapeHtml $attesoStr)</td>")
        [void]$righeHtml.AppendLine("  <td>$(& $escapeHtml $osservatoStr)</td>")
        [void]$righeHtml.AppendLine("</tr>")
    }

    $adminStr = if ($Report.environment.is_admin) { 'Si' } else { 'No' }

    $html = @"
<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Report Scanner Sicurezza Windows 11</title>
<style>
  body { font-family: 'Segoe UI', Tahoma, sans-serif; background: #f4f6f9; color: #1e293b; margin: 0; padding: 24px; line-height: 1.5; }
  .container { max-width: 1200px; margin: 0 auto; background: #ffffff; border-radius: 8px; padding: 24px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
  h1 { margin-top: 0; font-size: 22px; color: #0f172a; }
  .meta { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 16px; margin-bottom: 20px; font-size: 14px; }
  .cards { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 20px; }
  .card { flex: 1; min-width: 140px; padding: 12px 16px; border-radius: 6px; font-weight: 600; border: 1px solid #cbd5e1; }
  .card-pass { background: #dcfce7; color: #166534; border-color: #86efac; }
  .card-fail { background: #fee2e2; color: #991b1b; border-color: #fca5a5; }
  .card-unk  { background: #f1f5f9; color: #334155; border-color: #cbd5e1; }
  .card-na   { background: #f8fafc; color: #475569; border-color: #e2e8f0; }
  .card-err  { background: #ffedd5; color: #9a3412; border-color: #fdba74; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; margin-bottom: 20px; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
  th { background: #f1f5f9; font-weight: 600; color: #334155; }
  .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 12px; white-space: nowrap; }
  .stato-superato    { background: #dcfce7; color: #166534; }
  .stato-fallito     { background: #fee2e2; color: #991b1b; }
  .stato-sconosciuto { background: #e2e8f0; color: #334155; }
  .stato-errore      { background: #ffedd5; color: #9a3412; }
  .stato-na          { background: #f1f5f9; color: #64748b; }
  .disclaimer { background: #fffbeb; border-left: 4px solid #f59e0b; padding: 12px 16px; font-size: 13px; color: #92400e; margin-top: 16px; }
  small { color: #475569; }
</style>
</head>
<body>
<div class="container">
  <h1>Scanner di Sicurezza per Windows 11 — Report</h1>
  <div class="meta">
    <strong>ID Esecuzione:</strong> $(& $escapeHtml $Report.run_id) |
    <strong>Data (UTC):</strong> $(& $escapeHtml $Report.timestamp) |
    <strong>Versione Tool:</strong> $(& $escapeHtml $Report.tool_version) |
    <strong>Catalogo:</strong> v$(& $escapeHtml $Report.catalog_version)<br>
    <strong>Ambiente:</strong> Windows 11 $(& $escapeHtml $Report.environment.edition) (Build $(& $escapeHtml $Report.environment.build)) |
    <strong>Lingua:</strong> $(& $escapeHtml $Report.environment.language) |
    <strong>Amministratore:</strong> $adminStr |
    <strong>PowerShell:</strong> $(& $escapeHtml $Report.environment.ps_version)
  </div>
  <div class="cards">
    <div class="card card-pass">[OK] Superati: $($Report.summary.superato)</div>
    <div class="card card-fail">[X] Falliti: $($Report.summary.fallito)</div>
    <div class="card card-unk">[?] Sconosciuti: $($Report.summary.sconosciuto)</div>
    <div class="card card-na">[-] Non applicabili: $($Report.summary.non_applicabile)</div>
    <div class="card card-err">[!] Errori: $($Report.summary.errore)</div>
  </div>
  <table>
    <thead>
      <tr>
        <th>Stato</th>
        <th>Gravita'</th>
        <th>Categoria</th>
        <th>ID</th>
        <th>Controllo</th>
        <th>Valore Atteso</th>
        <th>Valore Osservato</th>
      </tr>
    </thead>
    <tbody>
$($righeHtml.ToString())
    </tbody>
  </table>
  <div class="disclaimer">
    <strong>Avviso importante:</strong> Questo report e' il risultato di una verifica statica in sola lettura delle impostazioni di sicurezza.
    Un controllo superato o un audit conforme non dimostra l'assenza di compromissioni o malware sul sistema.
  </div>
</div>
</body>
</html>
"@
    return $html
}

function Export-ReportHtml {
    <#
    .SYNOPSIS
        Scrive il report in formato HTML autonomo su file, in UTF-8 senza BOM.
    .PARAMETER Report
        L'oggetto report da esportare.
    .PARAMETER Catalogo
        Oggetto catalogo opzionale per arricchire i dati visualizzati.
    .PARAMETER PercorsoFile
        Percorso del file HTML di output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Report,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Catalogo = $null,

        [Parameter(Mandatory = $true)]
        [string]$PercorsoFile
    )

    $html = ConvertTo-ReportHtml -Report $Report -Catalogo $Catalogo
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($PercorsoFile, $html, $utf8NoBom)
}

function Export-TechnicalLog {
    <#
    .SYNOPSIS
        Scrive un file di log con i dettagli tecnici degli errori riscontrati.
    .PARAMETER Report
        L'oggetto report contenente i risultati.
    .PARAMETER PercorsoFile
        Percorso del file di log da scrivere.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Report,

        [Parameter(Mandatory = $true)]
        [string]$PercorsoFile
    )

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("=== LOG TECNICO SCANNER SICUREZZA WINDOWS ===")
    [void]$sb.AppendLine("Run ID:    $($Report.run_id)")
    [void]$sb.AppendLine("Timestamp: $($Report.timestamp)")
    [void]$sb.AppendLine("Edizione:  $($Report.environment.edition) (Build $($Report.environment.build))")
    [void]$sb.AppendLine("Admin:     $($Report.environment.is_admin)")
    [void]$sb.AppendLine("---------------------------------------------")

    $conErrori = 0
    if ($null -ne $Report.results) {
        foreach ($r in $Report.results) {
            if ($null -ne $r.error -and $r.error -ne '') {
                $conErrori++
                [void]$sb.AppendLine("[$($r.control_id)] Stato: $($r.status)")
                [void]$sb.AppendLine("  Dettaglio tecnico: $($r.error)")
                [void]$sb.AppendLine("")
            }
        }
    }

    if ($conErrori -eq 0) {
        [void]$sb.AppendLine("Nessun errore tecnico registrato durante la scansione.")
    }

    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($PercorsoFile, $sb.ToString(), $utf8NoBom)
}

# =============================================================================
# MODULO: src\core\OllamaClient.ps1
# =============================================================================
<#
.SYNOPSIS
    Client per l'integrazione con un LLM locale tramite Ollama (http://127.0.0.1:11434)
    con auto-rilevamento, auto-installazione silenziosa sulla VM e download automatico del modello.

.DESCRIPTION
    Fornisce:
    - Funzioni pure per la costruzione dei prompt (controllo singolo e resoconto complessivo)
    - Rilevamento automatico di Ollama su localhost (127.0.0.1) o sull'Host della VM (gateway)
    - Avvio automatico di 'ollama serve' se installato ma fermo
    - Installazione automatica silenziosa di Ollama (winget / OllamaSetup.exe /VERYSILENT)
      se assente sulla VM, senza richiedere download manuali all'utente
    - Download automatico del modello leggero (es. qwen2.5:0.5b) tramite API /api/pull
    - Motore esperto locale come risposta immediata di fallback
#>

Set-StrictMode -Version 2

$script:EndpointOllamaPredefinito = 'http://127.0.0.1:11434'
$script:ModelloOllamaPredefinito  = 'qwen2.5:0.5b'

function Format-PromptControlloOllama {
    <#
    .SYNOPSIS
        Costruisce il prompt (in italiano o inglese) per chiedere all'LLM di spiegare un singolo controllo.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Dettaglio,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    $infoOs = if ($null -ne $Ambiente) {
        "Windows 11 $($Ambiente.Edition) (Build $($Ambiente.Build), Admin: $($Ambiente.IsAdmin))"
    }
    else {
        "Windows 11"
    }

    $cmdRif = if ($Dettaglio.HaComando -and (-not [string]::IsNullOrWhiteSpace($Dettaglio.ComandoRimedio))) {
        $Dettaglio.ComandoRimedio
    }
    else {
        switch ($Lingua) {
            'EN' { "No terminal command (manual Windows/BIOS setting)" }
            'DE' { "Kein Terminal-Befehl (manuelle Windows-/BIOS-Einstellung)" }
            default { "Nessun comando da terminale (configurazione manuale da interfaccia di Windows/BIOS)" }
        }
    }

    $statoRawDett = if ($null -ne $Dettaglio.PSObject.Properties['Status'] -and $Dettaglio.Status) {
        [string]$Dettaglio.Status
    } else {
        [string]$Dettaglio.StatusLabel
    }

    if ($Lingua -eq 'EN') {
        $verdettoEn = if ($statoRawDett -match 'fallito|failed|fehlgeschlagen') {
            "IMPORTANT FACT: This security control FAILED on this PC (it is currently NOT configured securely)."
        } elseif ($statoRawDett -match 'superato|passed|bestanden') {
            "IMPORTANT FACT: This security control PASSED on this PC (it is already configured securely)."
        } else {
            "IMPORTANT FACT: This security control status is UNKNOWN (requires administrator privileges to verify)."
        }
        $promptEn = @"
[LANGUAGE: ENGLISH ONLY]
$verdettoEn
Control: $($Dettaglio.Title) ($($Dettaglio.ControlId))
Observed on this PC: $($Dettaglio.ValoreOsservato)
Expected secure setting: $($Dettaglio.ValoreAtteso)
Why it matters: $($Dettaglio.SpiegazioneSemplice)
How to fix it: $($Dettaglio.TestoRimedio)
Command: $cmdRif

Write 3 short bullet points in ENGLISH:
1. WHAT WAS FOUND: state clearly that '$($Dettaglio.Title)' is currently '$($Dettaglio.ValoreOsservato)'.
2. SECURITY RISK: explain why '$($Dettaglio.SpiegazioneSemplice)' matters for a home PC.
3. HOW TO FIX SAFELY: explain how to apply '$($Dettaglio.TestoRimedio)'.
"@
        return $promptEn.Trim()
    }
    elseif ($Lingua -eq 'DE') {
        $verdettoDe = if ($statoRawDett -match 'fallito|failed|fehlgeschlagen') {
            "WICHTIGE TATSACHE: Diese Sicherheitspruefung ist auf diesem PC FEHLGESCHLAGEN (momentan NICHT sicher konfiguriert)."
        } elseif ($statoRawDett -match 'superato|passed|bestanden') {
            "WICHTIGE TATSACHE: Diese Sicherheitspruefung wurde auf diesem PC BESTANDEN (bereits sicher konfiguriert)."
        } else {
            "WICHTIGE TATSACHE: Der Status dieser Sicherheitspruefung ist UNBEKANNT (Administratorrechte erforderlich)."
        }
        $promptDe = @"
[SPRACHE: NUR DEUTSCH - NICHT AUF ENGLISCH SCHREIBEN]
$verdettoDe
Sicherheitspruefung: $($Dettaglio.Title) ($($Dettaglio.ControlId))
Gefundener Wert auf dem PC: $($Dettaglio.ValoreOsservato)
Erwartete sichere Einstellung: $($Dettaglio.ValoreAtteso)
Warum es wichtig ist: $($Dettaglio.SpiegazioneSemplice)
Wie man es behebt: $($Dettaglio.TestoRimedio)
Befehl: $cmdRif

Schreibe 3 kurze Punkte auf DEUTSCH:
1. WAS GEFUNDEN WURDE: Erklaere klar, dass '$($Dettaglio.Title)' aktuell den Wert '$($Dettaglio.ValoreOsservato)' hat.
2. SICHERHEITSRISIKO: Erklaere auf Deutsch, warum '$($Dettaglio.SpiegazioneSemplice)' fuer den PC wichtig ist.
3. SICHERE BEHEBUNG: Erklaere auf Deutsch, wie man '$($Dettaglio.TestoRimedio)' anwendet.
"@
        return $promptDe.Trim()
    }

    $verdettoIt = if ($statoRawDett -match 'fallito|failed|fehlgeschlagen') {
        "FATTO ACCERTATO: Questo controllo di sicurezza e' FALLITO sul PC (NON e' configurato in modo sicuro)."
    } elseif ($statoRawDett -match 'superato|passed|bestanden') {
        "FATTO ACCERTATO: Questo controllo di sicurezza e' SUPERATO sul PC (e' gia' attivo e sicuro)."
    } else {
        "FATTO ACCERTATO: Lo stato del controllo e' SCONOSCIUTO (servono privilegi di amministratore)."
    }

    $prompt = @"
[LINGUA OBBLIGATORIA: SOLO ITALIANO - NON SCRIVERE IN INGLESE]
$verdettoIt
Controllo: $($Dettaglio.Title) ($($Dettaglio.ControlId))
Valore trovato sul PC: $($Dettaglio.ValoreOsservato)
Valore sicuro atteso: $($Dettaglio.ValoreAtteso)
Perche' conta: $($Dettaglio.SpiegazioneSemplice)
Come correggere: $($Dettaglio.TestoRimedio)
Comando: $cmdRif

Scrivi in LINGUA ITALIANA 3 brevi punti:
1. COSA SIGNIFICA: spiega che sul PC il controllo '$($Dettaglio.Title)' risulta '$($Dettaglio.ValoreOsservato)'.
2. RISCHIO PER IL PC: spiega in italiano perche' '$($Dettaglio.SpiegazioneSemplice)' e' importante.
3. COME MIGLIORARE IN SICUREZZA: spiega in italiano come applicare '$($Dettaglio.TestoRimedio)'.
"@

    return $prompt.Trim()
}

function Format-PromptResocontoOllama {
    <#
    .SYNOPSIS
        Costruisce il prompt (in italiano o inglese) per generare un resoconto complessivo della scansione.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$ElementiVista,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Conteggi,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    $infoOs = if ($null -ne $Ambiente) {
        "Windows 11 $($Ambiente.Edition) (Build $($Ambiente.Build), Admin: $($Ambiente.IsAdmin))"
    }
    else {
        "Windows 11"
    }

    $sbFalliti = New-Object System.Text.StringBuilder
    $nFalliti = 0

    foreach ($el in $ElementiVista) {
        if ($el.Status -eq 'fallito') {
            $nFalliti++
            $det = Format-DettaglioControllo -Elemento $el -Modalita 'Semplice' -Lingua $Lingua
            [void]$sbFalliti.AppendLine("- [$($el.SeverityLabel.ToUpperInvariant())] $($el.ControlId) - $($el.Title)")
            [void]$sbFalliti.AppendLine("  Observed: $($det.ValoreOsservato) (Expected: $($det.ValoreAtteso))")
            [void]$sbFalliti.AppendLine("  Remediation: $($det.TestoRimedio)")
        }
    }

    if ($nFalliti -eq 0) {
        [void]$sbFalliti.AppendLine("No failed controls! All applicable checks passed.")
    }

    if ($Lingua -eq 'EN') {
        $promptEn = @"
[LANGUAGE: ENGLISH ONLY]
You are a cybersecurity advisor for Windows 11 users.
Analyze the following read-only deterministic security scan report and write a clear report in English with practical step-by-step recommendations to improve PC security.

SYSTEM: $infoOs
SCAN SUMMARY:
- Total controls evaluated: $($Conteggi.totale)
- Passed: $($Conteggi.superato)
- Failed (needs attention): $($Conteggi.fallito)
- Unknown: $($Conteggi.sconosciuto)
- Not Applicable: $($Conteggi.non_applicabile)

FAILED CONTROLS (ORDERED BY SEVERITY):
$($sbFalliti.ToString().Trim())

Write a structured report in 4 sections:
1. OVERALL SECURITY POSTURE: clear summary of the current security level.
2. IMMEDIATE PRIORITIES: which issues to fix first (starting with Critical and High severity) and why.
3. STEP-BY-STEP REMEDIATION GUIDE: simple instructions to apply the recommended improvements on Windows 11.
4. SAFETY BEST PRACTICES: final reminder (e.g. create a System Restore Point before modifying system settings).
"@
        return $promptEn.Trim()
    }
    elseif ($Lingua -eq 'DE') {
        $promptDe = @"
[SPRACHE: NUR DEUTSCH - NICHT AUF ENGLISCH SCHREIBEN]
Du bist ein IT-Sicherheitsberater fuer Windows 11-Benutzer.
Analysiere den folgenden deterministischen Sicherheitsbericht und schreibe einen klaren Bericht auf DEUTSCH mit praktischen Empfehlungen zur Verbesserung der PC-Sicherheit.

SYSTEM: $infoOs
ZUSAMMENFASSUNG DES SCANS:
- Gepruefte Kontrollen insgesamt: $($Conteggi.totale)
- Bestanden: $($Conteggi.superato)
- Fehlgeschlagen (Handlungsbedarf): $($Conteggi.fallito)
- Unbekannt: $($Conteggi.sconosciuto)
- Nicht zutreffend: $($Conteggi.non_applicabile)

FEHLGESCHLAGENE PRUEFUNGEN (NACH SCHWEREGRAD SORTIERT):
$($sbFalliti.ToString().Trim())

Schreibe einen strukturierten Bericht auf DEUTSCH in 4 Abschnitten:
1. ALLGEMEINER SICHERHEITSZUSTAND: klare Zusammenfassung des aktuellen Sicherheitsniveaus.
2. SOFORTIGE PRIORITAETEN: welche Probleme zuerst behoben werden sollten (beginnend mit Kritisch und Hoch) und warum.
3. SCHRITT-FUER-SCHRITT-ANLEITUNG: einfache Anweisungen zur Umsetzung der empfohlenen Verbesserungen unter Windows 11.
4. SICHERHEITSHINWEISE: abschliessender Tipp (z. B. Systemwiederherstellungspunkt vor Systemaenderungen erstellen).
"@
        return $promptDe.Trim()
    }

    $prompt = @"
Sei un consulente di sicurezza informatica per utenti domestici su Windows 11.
Analizza il seguente report generato dallo scanner deterministico in sola lettura e scrivi un resoconto chiaro in lingua italiana con consigli pratici per migliorare la sicurezza del PC.

SISTEMA: $infoOs
RIEPILOGO SCANSIONE:
- Totale controlli eseguiti: $($Conteggi.totale)
- Superati: $($Conteggi.superato)
- Falliti (da migliorare): $($Conteggi.fallito)
- Sconosciuti: $($Conteggi.sconosciuto)
- Non applicabili: $($Conteggi.non_applicabile)

DETTAGLIO CONTROLLI FALLITI (ORDINATI PER GRAVITA'):
$($sbFalliti.ToString().Trim())

Scrivi un resoconto strutturato in 4 sezioni:
1. STATO GENERALE DEL PC: sintesi chiara del livello di sicurezza attuale.
2. PRIORITA' IMMEDIATE: quali problemi risolvere per primi (partendo da quelli Critici e Alti) e perche'.
3. GUIDA PRATICA PASSO-PASSO: istruzioni semplici per applicare i miglioramenti consigliati su Windows 11.
4. BUONE PRATICHE DI SICUREZZA: consiglio finale (es. creare un punto di ripristino prima di modificare impostazioni di sistema).
"@

    return $prompt.Trim()
}

function Format-AnalisiLocaleControllo {
    <#
    .SYNOPSIS
        Genera una spiegazione strutturata e contestuale del singolo controllo (IT o EN).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Dettaglio,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    $sb = New-Object System.Text.StringBuilder

    if ($Lingua -eq 'EN') {
        [void]$sb.AppendLine("=== DETAILED CONTROL ANALYSIS: $($Dettaglio.ControlId) ===")
        [void]$sb.AppendLine("Control: $($Dettaglio.Title)")
        [void]$sb.AppendLine("Category: $($Dettaglio.Category)  |  Severity: $($Dettaglio.SeverityLabel)  |  Status: $($Dettaglio.StatusLabel)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("1. WHAT THIS RESULT MEANS ON YOUR PC")
        switch ($Dettaglio.Status) {
            'superato' {
                [void]$sb.AppendLine("   Good news: the observed value ('$($Dettaglio.ValoreOsservato)') meets the expected security baseline ('$($Dettaglio.ValoreAtteso)'). No action is needed.")
            }
            'fallito' {
                [void]$sb.AppendLine("   Attention required: the scanner detected '$($Dettaglio.ValoreOsservato)', while the recommended secure setting is '$($Dettaglio.ValoreAtteso)'.")
            }
            default {
                [void]$sb.AppendLine("   Current observed state: '$($Dettaglio.ValoreOsservato)'.")
            }
        }
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("2. WHY IT MATTERS & RISK NOTES")
        [void]$sb.AppendLine("   $($Dettaglio.SpiegazioneSemplice)")
        [void]$sb.AppendLine("   Impact notes: $($Dettaglio.NoteRischi)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("3. HOW TO REMEDIATE SAFELY")
        if ($Dettaglio.Status -eq 'superato') {
            [void]$sb.AppendLine("   - No changes required: this control is already properly configured.")
        }
        else {
            [void]$sb.AppendLine("   - Guidance: $($Dettaglio.TestoRimedio)")
            if ($Dettaglio.HaComando -and (-not [string]::IsNullOrWhiteSpace($Dettaglio.ComandoRimedio))) {
                [void]$sb.AppendLine("   - Reference PowerShell Command (Run as Administrator):")
                [void]$sb.AppendLine("     $($Dettaglio.ComandoRimedio)")
            }
        }
        return $sb.ToString().Trim()
    }
    elseif ($Lingua -eq 'DE') {
        [void]$sb.AppendLine("=== DETAILLIERTE PRUEFUNGSANALYSE: $($Dettaglio.ControlId) ===")
        [void]$sb.AppendLine("Sicherheitspruefung: $($Dettaglio.Title)")
        [void]$sb.AppendLine("Kategorie: $($Dettaglio.Category)  |  Schweregrad: $($Dettaglio.SeverityLabel)  |  Status: $($Dettaglio.StatusLabel)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("1. WAS DIESES ERGEBNIS AUF IHREM PC BEDEUTET")
        switch ($Dettaglio.Status) {
            'superato' {
                [void]$sb.AppendLine("   Gute Nachrichten: Der gefundene Wert ('$($Dettaglio.ValoreOsservato)') entspricht der erwarteten Sicherheitsvorgabe ('$($Dettaglio.ValoreAtteso)'). Es ist kein Eingriff erforderlich.")
            }
            'fallito' {
                [void]$sb.AppendLine("   Handlungsbedarf: Der Scanner hat '$($Dettaglio.ValoreOsservato)' erkannt, waehrend die empfohlene sichere Einstellung '$($Dettaglio.ValoreAtteso)' lautet.")
            }
            default {
                [void]$sb.AppendLine("   Aktuell erkannter Zustand: '$($Dettaglio.ValoreOsservato)'.")
            }
        }
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("2. WARUM ES WICHTIG IST & RISIKOHINWEISE")
        [void]$sb.AppendLine("   $($Dettaglio.SpiegazioneSemplice)")
        [void]$sb.AppendLine("   Auswirkung der Aenderung: $($Dettaglio.NoteRischi)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("3. SICHERE BEHEBUNG (SCHRITT FUER SCHRITT)")
        if ($Dettaglio.Status -eq 'superato') {
            [void]$sb.AppendLine("   - Keine Aenderung erforderlich: Diese Einstellung ist bereits sicher konfiguriert.")
        }
        else {
            [void]$sb.AppendLine("   - Empfohlene Massnahme: $($Dettaglio.TestoRimedio)")
            if ($Dettaglio.HaComando -and (-not [string]::IsNullOrWhiteSpace($Dettaglio.ComandoRimedio))) {
                [void]$sb.AppendLine("   - PowerShell-Referenzbefehl (als Administrator ausfuehren):")
                [void]$sb.AppendLine("     $($Dettaglio.ComandoRimedio)")
            }
        }
        return $sb.ToString().Trim()
    }
    [void]$sb.AppendLine("=== ANALISI DETTAGLIATA DEL CONTROLLO: $($Dettaglio.ControlId) ===")
    [void]$sb.AppendLine("Controllo: $($Dettaglio.Title)")
    [void]$sb.AppendLine("Categoria: $($Dettaglio.Category)  |  Gravita': $($Dettaglio.SeverityLabel)  |  Stato: $($Dettaglio.StatusLabel)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("1. COSA SIGNIFICA QUESTO RISULTATO SUL TUO PC")

    switch ($Dettaglio.Status) {
        'superato' {
            [void]$sb.AppendLine("   Ottima notizia: sul tuo sistema il valore rilevato ('$($Dettaglio.ValoreOsservato)') rispetta pienamente il requisito di sicurezza atteso ('$($Dettaglio.ValoreAtteso)'). Non e' necessario alcun intervento correttivo.")
        }
        'fallito' {
            [void]$sb.AppendLine("   Attenzione: lo scanner ha rilevato '$($Dettaglio.ValoreOsservato)', mentre l'impostazione sicura raccomandata e' '$($Dettaglio.ValoreAtteso)'.")
        }
        'sconosciuto' {
            [void]$sb.AppendLine("   Lo stato attuale e' Sconosciuto ('$($Dettaglio.ValoreOsservato)'). Per verificare questo controllo avvia lo scanner come Amministratore.")
        }
        'non_applicabile' {
            [void]$sb.AppendLine("   Questo controllo non si applica all'edizione corrente di Windows ($($Dettaglio.ValoreOsservato)).")
        }
        default {
            [void]$sb.AppendLine("   Stato rilevato: $($Dettaglio.ValoreOsservato).")
        }
    }

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("2. PERCHE' E' IMPORTANTE (VALUTAZIONE DEL RISCHIO)")
    [void]$sb.AppendLine("   $($Dettaglio.SpiegazioneSemplice)")
    [void]$sb.AppendLine("   Impatto della modifica: $($Dettaglio.NoteRischi)")

    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("3. COME INTERVENIRE IN SICUREZZA PASSO DOPO PASSO")
    if ($Dettaglio.Status -eq 'superato') {
        [void]$sb.AppendLine("   - Nessuna azione richiesta: l'impostazione e' gia' configurata in modo sicuro.")
    }
    else {
        [void]$sb.AppendLine("   - Azione consigliata: $($Dettaglio.TestoRimedio)")
        if ($Dettaglio.HaComando -and (-not [string]::IsNullOrWhiteSpace($Dettaglio.ComandoRimedio))) {
            [void]$sb.AppendLine("   - Comando PowerShell (da eseguire come Amministratore):")
            [void]$sb.AppendLine("     $($Dettaglio.ComandoRimedio)")
        }
    }

    return $sb.ToString().Trim()
}

function Format-ResocontoLocaleScansione {
    <#
    .SYNOPSIS
        Genera un resoconto completo e prioritizzato dell'intera scansione del PC (IT o EN).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [array]$ElementiVista,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Conteggi,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    $perc = if ($Conteggi.totale -gt 0) {
        [int][math]::Round((($Conteggi.superato * 100.0) / $Conteggi.totale), 0)
    } else { 0 }

    if ($Lingua -eq 'EN') {
        $sbEn = New-Object System.Text.StringBuilder
        [void]$sbEn.AppendLine("======================================================================")
        [void]$sbEn.AppendLine("           WINDOWS 11 SECURITY REPORT & IMPROVEMENT PLAN              ")
        [void]$sbEn.AppendLine("======================================================================")
        if ($null -ne $Ambiente) {
            [void]$sbEn.AppendLine("Analyzed System: Windows 11 $($Ambiente.Edition) (Build $($Ambiente.Build)) | Admin: $($Ambiente.IsAdmin)")
        }
        [void]$sbEn.AppendLine("Compliance Score: $perc% ($($Conteggi.superato) Passed out of $($Conteggi.totale) controls)")
        [void]$sbEn.AppendLine("")
        [void]$sbEn.AppendLine("1. EXECUTIVE SUMMARY")
        [void]$sbEn.AppendLine("   - Passed Controls:         $($Conteggi.superato)")
        [void]$sbEn.AppendLine("   - Failed (Needs Action):   $($Conteggi.fallito)")
        [void]$sbEn.AppendLine("   - Unknown Controls:        $($Conteggi.sconosciuto)")
        [void]$sbEn.AppendLine("   - Not Applicable Controls: $($Conteggi.non_applicabile)")
        [void]$sbEn.AppendLine("")

        $fallitiEn = @($ElementiVista | Where-Object { $_.Status -eq 'fallito' })
        if ($fallitiEn.Count -eq 0) {
            [void]$sbEn.AppendLine("2. NO CRITICAL ISSUES FOUND")
            [void]$sbEn.AppendLine("   All evaluated controls meet the recommended security configuration.")
        }
        else {
            [void]$sbEn.AppendLine("2. PRIORITY REMEDIATION PLAN ($($fallitiEn.Count) recommended actions)")
            [void]$sbEn.AppendLine("")
            $idxEn = 0
            foreach ($f in $fallitiEn) {
                $idxEn++
                $det = Format-DettaglioControllo -Elemento $f -Modalita 'Semplice' -Lingua 'EN'
                [void]$sbEn.AppendLine("   Priority #$idxEn — [$($f.SeverityLabel.ToUpperInvariant())] $($f.Title) ($($f.ControlId))")
                [void]$sbEn.AppendLine("   * Observed on PC: $($det.ValoreOsservato) (Expected: $($det.ValoreAtteso))")
                [void]$sbEn.AppendLine("   * Why it matters: $($det.SpiegazioneSemplice)")
                [void]$sbEn.AppendLine("   * How to fix:     $($det.TestoRimedio)")
                if ($det.HaComando -and (-not [string]::IsNullOrWhiteSpace($det.ComandoRimedio))) {
                    [void]$sbEn.AppendLine("   * PowerShell Cmd: $($det.ComandoRimedio)")
                }
                [void]$sbEn.AppendLine("")
            }
        }
        [void]$sbEn.AppendLine("3. SAFETY BEST PRACTICES")
        [void]$sbEn.AppendLine("   - Always create a Windows System Restore Point before modifying registry or security policies.")
        [void]$sbEn.AppendLine("   - Apply changes one at a time starting from CRITICAL and HIGH severity controls.")
        return $sbEn.ToString().Trim()
    }
    elseif ($Lingua -eq 'DE') {
        $sbDe = New-Object System.Text.StringBuilder
        [void]$sbDe.AppendLine("======================================================================")
        [void]$sbDe.AppendLine("         WINDOWS 11 SICHERHEITSBERICHT & MASSNAHMENPLAN               ")
        [void]$sbDe.AppendLine("======================================================================")
        if ($null -ne $Ambiente) {
            [void]$sbDe.AppendLine("Analysiertes System: Windows 11 $($Ambiente.Edition) (Build $($Ambiente.Build)) | Admin: $($Ambiente.IsAdmin)")
        }
        [void]$sbDe.AppendLine("Konformitaetsrate: $perc% ($($Conteggi.superato) Bestanden von $($Conteggi.totale) Pruefungen)")
        [void]$sbDe.AppendLine("")
        [void]$sbDe.AppendLine("1. ZUSAMMENFASSUNG")
        [void]$sbDe.AppendLine("   - Bestandene Pruefungen:          $($Conteggi.superato)")
        [void]$sbDe.AppendLine("   - Fehlgeschlagen (Handlungsbed.): $($Conteggi.fallito)")
        [void]$sbDe.AppendLine("   - Unbekannte Pruefungen:          $($Conteggi.sconosciuto)")
        [void]$sbDe.AppendLine("   - Nicht zutreffende Pruefungen:   $($Conteggi.non_applicabile)")
        [void]$sbDe.AppendLine("")

        $fallitiDe = @($ElementiVista | Where-Object { $_.Status -eq 'fallito' })
        if ($fallitiDe.Count -eq 0) {
            [void]$sbDe.AppendLine("2. KEINE KRITISCHEN PROBLEME GEFUNDEN")
            [void]$sbDe.AppendLine("   Alle geprueften Kontrollen entsprechen der empfohlenen Sicherheitskonfiguration.")
        }
        else {
            [void]$sbDe.AppendLine("2. PRIORISIERTER MASSNAHMENPLAN ($($fallitiDe.Count) empfohlene Massnahmen)")
            [void]$sbDe.AppendLine("")
            $idxDe = 0
            foreach ($f in $fallitiDe) {
                $idxDe++
                $det = Format-DettaglioControllo -Elemento $f -Modalita 'Semplice' -Lingua 'DE'
                [void]$sbDe.AppendLine("   Prioritaet #$idxDe — [$($f.SeverityLabel.ToUpperInvariant())] $($f.Title) ($($f.ControlId))")
                [void]$sbDe.AppendLine("   * Gefunden auf PC: $($det.ValoreOsservato) (Erwartet: $($det.ValoreAtteso))")
                [void]$sbDe.AppendLine("   * Warum wichtig:   $($det.SpiegazioneSemplice)")
                [void]$sbDe.AppendLine("   * Behebung:        $($det.TestoRimedio)")
                if ($det.HaComando -and (-not [string]::IsNullOrWhiteSpace($det.ComandoRimedio))) {
                    [void]$sbDe.AppendLine("   * PowerShell-Cmd:  $($det.ComandoRimedio)")
                }
                [void]$sbDe.AppendLine("")
            }
        }
        [void]$sbDe.AppendLine("3. EMPFOHLENE SICHERHEITSHINWEISE")
        [void]$sbDe.AppendLine("   - Erstellen Sie vor Aenderungen an Registrierung oder Sicherheitsrichtlinien immer einen Systemwiederherstellungspunkt.")
        [void]$sbDe.AppendLine("   - Setzen Sie Aenderungen einzeln um, beginnend mit KRITISCHEN und HOHEN Schweregraden.")
        return $sbDe.ToString().Trim()
    }

    $giudizio = if ($Conteggi.fallito -eq 0) {
        "ECCELLENTE (Tutti i controlli verificati sono superati)"
    }
    elseif ($perc -ge 80) {
        "BUONO ($perc% di conformita' — presenti $($Conteggi.fallito) miglioramenti consigliati)"
    }
    elseif ($perc -ge 60) {
        "MODERATO ($perc% di conformita' — si raccomanda di applicare le correzioni prioritarie)"
    }
    else {
        "ATTENZIONE RICHIESTA ($perc% di conformita' — diversi controlli critici o alti risultano disattivati)"
    }

    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("======================================================================")
    [void]$sb.AppendLine("          RESOCONTO DI SICUREZZA E PIANO DI MIGLIORAMENTO PC          ")
    [void]$sb.AppendLine("======================================================================")
    if ($null -ne $Ambiente) {
        [void]$sb.AppendLine("Sistema analizzato: Windows 11 $($Ambiente.Edition) (Build $($Ambiente.Build)) | Admin: $($Ambiente.IsAdmin)")
    }
    [void]$sb.AppendLine("Punteggio conformita': $perc% ($($Conteggi.superato) Superati su $($Conteggi.totale) controlli)")
    [void]$sb.AppendLine("Valutazione complessiva: $giudizio")
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine("1. SINTESI DELLO STATO DEL PC")
    [void]$sb.AppendLine("   - Controlli Superati:        $($Conteggi.superato)")
    [void]$sb.AppendLine("   - Controlli da Migliorare:   $($Conteggi.fallito)")
    [void]$sb.AppendLine("   - Controlli Sconosciuti:     $($Conteggi.sconosciuto)")
    [void]$sb.AppendLine("   - Controlli Non Applicabili: $($Conteggi.non_applicabile)")
    [void]$sb.AppendLine("")

    $falliti = @($ElementiVista | Where-Object { $_.Status -eq 'fallito' })

    if ($falliti.Count -eq 0) {
        [void]$sb.AppendLine("2. NESSUNA CRITICITA' RILEVATA")
        [void]$sb.AppendLine("   Tutti i controlli eseguibili sul sistema risultano configurati correttamente.")
    }
    else {
        [void]$sb.AppendLine("2. PRIORITA' DI INTERVENTO E COME APPLICARE LA SICUREZZA ($($falliti.Count) azioni)")
        [void]$sb.AppendLine("")
        $num = 0
        foreach ($f in $falliti) {
            $num++
            $det = Format-DettaglioControllo -Elemento $f -Modalita 'Semplice'
            [void]$sb.AppendLine("   Priorita' #$num — [$($f.SeverityLabel.ToUpperInvariant())] $($f.Title) ($($f.ControlId))")
            [void]$sb.AppendLine("   * Stato attuale sul PC: $($det.ValoreOsservato)")
            [void]$sb.AppendLine("   * Perche' intervenire:  $($det.SpiegazioneSemplice)")
            [void]$sb.AppendLine("   * Come correggere:      $($det.TestoRimedio)")
            if ($det.HaComando -and (-not [string]::IsNullOrWhiteSpace($det.ComandoRimedio))) {
                [void]$sb.AppendLine("   * Comando rapido (Admin): $($det.ComandoRimedio)")
            }
            [void]$sb.AppendLine("   * Precauzioni:          $($det.NoteRischi)")
            [void]$sb.AppendLine("")
        }
    }

    [void]$sb.AppendLine("3. CONSIGLI PRATICI PRIMA DI APPLICARE LE MODIFICHE")
    [void]$sb.AppendLine("   - Crea sempre un Punto di Ripristino di Windows prima di modificare il registro o i criteri.")
    [void]$sb.AppendLine("   - Applica un miglioramento alla volta (partendo da quelli a gravita' CRITICO e ALTO) e verifica il normale funzionamento delle tue applicazioni.")
    [void]$sb.AppendLine("   - Puoi copiare il comando di ciascun controllo selezionandolo nella Pagina 1 (Scansione e Controlli).")

    return $sb.ToString().Trim()
}

function Find-EseguibileOllamaLocale {
    <#
    .SYNOPSIS
        Cerca il percorso di ollama.exe sul sistema locale.
    #>
    [CmdletBinding()]
    param()

    $cmd = Get-Command -Name 'ollama' -ErrorAction SilentlyContinue
    if ($null -ne $cmd -and (-not [string]::IsNullOrWhiteSpace($cmd.Source))) {
        return $cmd.Source
    }

    $percorsiCandidati = @(
        (Join-Path $env:LOCALAPPDATA 'Programs\Ollama\ollama.exe'),
        'C:\Program Files\Ollama\ollama.exe'
    )
    foreach ($p in $percorsiCandidati) {
        if (-not [string]::IsNullOrWhiteSpace($p) -and (Test-Path -LiteralPath $p)) {
            return $p
        }
    }

    return $null
}

function Test-ConnessioneOllama {
    <#
    .SYNOPSIS
        Verifica se il server Ollama e' attivo sull'endpoint specificato (o sull'Host della VM)
        e restituisce la lista dei modelli installati.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Endpoint = $script:EndpointOllamaPredefinito,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 2
    )

    $urlPulito = if ([string]::IsNullOrWhiteSpace($Endpoint)) { $script:EndpointOllamaPredefinito } else { $Endpoint.Trim().TrimEnd('/') }

    # Lista di endpoint candidati: quello scelto + fallback automatici per VM (Host NAT 10.0.2.2 e Default Gateway)
    $candidati = @($urlPulito)
    if ($urlPulito -match '127\.0\.0\.1|localhost') {
        $candidati += 'http://10.0.2.2:11434'
        try {
            $rot = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 2)
            foreach ($r in $rot) {
                if ($null -ne $r.PSObject.Properties['NextHop'] -and (-not [string]::IsNullOrWhiteSpace($r.NextHop)) -and $r.NextHop -ne '0.0.0.0') {
                    $gwUrl = "http://$($r.NextHop):11434"
                    if ($candidati -notcontains $gwUrl) {
                        $candidati += $gwUrl
                    }
                }
            }
        }
        catch { }
    }

    foreach ($cand in $candidati) {
        $uriTags = "$cand/api/tags"
        try {
            $risposta = Invoke-RestMethod -Uri $uriTags -Method Get -TimeoutSec $TimeoutSec -ErrorAction Stop
            $nomiModelli = @()

            if ($null -ne $risposta -and $null -ne $risposta.PSObject.Properties['models'] -and $null -ne $risposta.models) {
                foreach ($m in $risposta.models) {
                    if ($null -ne $m.PSObject.Properties['name'] -and (-not [string]::IsNullOrWhiteSpace([string]$m.name))) {
                        $nomiModelli += [string]$m.name
                    }
                }
            }

            $preferiti = @('qwen2.5:0.5b', 'qwen2.5:1.5b', 'llama3.2:1b', 'gemma2:2b', 'tinyllama:latest', 'phi3:mini')
            $consigliato = $script:ModelloOllamaPredefinito
            if ($nomiModelli.Count -gt 0) {
                $trovatoPreferito = $false
                foreach ($pref in $preferiti) {
                    if ($nomiModelli -contains $pref) {
                        $consigliato = $pref
                        $trovatoPreferito = $true
                        break
                    }
                }
                if (-not $trovatoPreferito) {
                    $consigliato = $nomiModelli[0]
                }
            }

            return [PSCustomObject]@{
                Disponibile        = $true
                Endpoint           = $cand
                Modelli            = $nomiModelli
                ModelloConsigliato = $consigliato
                Errore             = $null
            }
        }
        catch {
            # Prova il candidato successivo
        }
    }

    return [PSCustomObject]@{
        Disponibile        = $false
        Endpoint           = $urlPulito
        Modelli            = @()
        ModelloConsigliato = $script:ModelloOllamaPredefinito
        Errore             = "Server Ollama non attivo su $urlPulito."
    }
}

function Initialize-AmbienteOllama {
    <#
    .SYNOPSIS
        Garantisce che Ollama sia attivo: se e' installato lo avvia; se non e' installato
        sulla macchina/VM e AutoInstalla e' attivo, lo scarica e lo installa in modalita'
        silenziosa senza intervento manuale dell'utente.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Endpoint = $script:EndpointOllamaPredefinito,

        [Parameter(Mandatory = $false)]
        [bool]$AutoInstalla = $true,

        [Parameter(Mandatory = $false)]
        [scriptblock]$OnStatus = $null
    )

    # 1. Controlla se e' gia' attivo (in locale o sull'Host della VM)
    $stato = Test-ConnessioneOllama -Endpoint $Endpoint -TimeoutSec 2
    if ($stato.Disponibile) {
        return $stato
    }

    # 2. Cerca se ollama.exe e' gia' presente sul disco ma non avviato
    $exeOllama = Find-EseguibileOllamaLocale
    if (-not [string]::IsNullOrWhiteSpace($exeOllama)) {
        if ($null -ne $OnStatus) { & $OnStatus "Avvio automatico del servizio Ollama locale in corso..." }
        try {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName        = $exeOllama
            $psi.Arguments       = 'serve'
            $psi.CreateNoWindow  = $true
            $psi.UseShellExecute = $false
            [void][System.Diagnostics.Process]::Start($psi)

            for ($i = 0; $i -lt 5; $i++) {
                [System.Threading.Thread]::Sleep(1000)
                $stato = Test-ConnessioneOllama -Endpoint 'http://127.0.0.1:11434' -TimeoutSec 2
                if ($stato.Disponibile) { return $stato }
            }
        }
        catch { }
    }

    # 3. Se non e' installato sulla macchina/VM e AutoInstalla e' True, installalo automaticamente!
    if ($AutoInstalla) {
        # 3a. Tentativo rapido tramite winget (se presente sulla macchina)
        $cmdWinget = Get-Command -Name 'winget' -ErrorAction SilentlyContinue
        if ($null -ne $cmdWinget) {
            if ($null -ne $OnStatus) { & $OnStatus "Ollama non trovato sulla VM: installazione automatica tramite Winget in corso (attendi 1-2 minuti)..." }
            try {
                $psiWg = New-Object System.Diagnostics.ProcessStartInfo
                $psiWg.FileName        = $cmdWinget.Source
                $psiWg.Arguments       = 'install -e --id Ollama.Ollama --silent --accept-package-agreements --accept-source-agreements'
                $psiWg.CreateNoWindow  = $true
                $psiWg.UseShellExecute = $false
                $procWg = [System.Diagnostics.Process]::Start($psiWg)
                [void]$procWg.WaitForExit(180000)
            }
            catch { }
        }

        # 3b. Se ancora non presente, scarica direttamente OllamaSetup.exe ufficiale ed eseguilo con /VERYSILENT
        $exeOllama = Find-EseguibileOllamaLocale
        if ([string]::IsNullOrWhiteSpace($exeOllama)) {
            if ($null -ne $OnStatus) { & $OnStatus "Scaricamento automatico di OllamaSetup.exe in corso (nessuna azione manuale richiesta)..." }
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                $percorsoInstaller = Join-Path ([System.IO.Path]::GetTempPath()) 'OllamaSetup_Auto.exe'
                $wc = New-Object System.Net.WebClient
                $wc.DownloadFile('https://ollama.com/download/OllamaSetup.exe', $percorsoInstaller)

                if (Test-Path -LiteralPath $percorsoInstaller) {
                    if ($null -ne $OnStatus) { & $OnStatus "Installazione silenziosa di Ollama sulla VM in corso..." }
                    $psiInst = New-Object System.Diagnostics.ProcessStartInfo
                    $psiInst.FileName        = $percorsoInstaller
                    $psiInst.Arguments       = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART'
                    $psiInst.CreateNoWindow  = $true
                    $psiInst.UseShellExecute = $false
                    $procInst = [System.Diagnostics.Process]::Start($psiInst)
                    [void]$procInst.WaitForExit(180000)
                }
            }
            catch { }
        }

        # 3c. Avvia il servizio appena installato
        $exeOllama = Find-EseguibileOllamaLocale
        if (-not [string]::IsNullOrWhiteSpace($exeOllama)) {
            if ($null -ne $OnStatus) { & $OnStatus "Avvio del server Ollama appena installato..." }
            try {
                $psiSrv = New-Object System.Diagnostics.ProcessStartInfo
                $psiSrv.FileName        = $exeOllama
                $psiSrv.Arguments       = 'serve'
                $psiSrv.CreateNoWindow  = $true
                $psiSrv.UseShellExecute = $false
                [void][System.Diagnostics.Process]::Start($psiSrv)

                for ($j = 0; $j -lt 8; $j++) {
                    [System.Threading.Thread]::Sleep(1000)
                    $stato = Test-ConnessioneOllama -Endpoint 'http://127.0.0.1:11434' -TimeoutSec 2
                    if ($stato.Disponibile) { return $stato }
                }
            }
            catch { }
        }
    }

    return $stato
}

function Invoke-RichiestaOllama {
    <#
    .SYNOPSIS
        Invia un prompt al server locale Ollama (/api/generate).
        Se Ollama non e' installato sulla VM, puo' auto-installarlo silenziosamente,
        scaricare automaticamente il modello scelto (/api/pull) ed eseguire l'analisi.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Prompt,

        [Parameter(Mandatory = $false)]
        [string]$Modello = $script:ModelloOllamaPredefinito,

        [Parameter(Mandatory = $false)]
        [string]$Endpoint = $script:EndpointOllamaPredefinito,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 120,

        [Parameter(Mandatory = $false)]
        [string]$TestoFallbackLocale = '',

        [Parameter(Mandatory = $false)]
        [bool]$AutoProvision = $false,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT',

        [Parameter(Mandatory = $false)]
        [scriptblock]$OnStatus = $null
    )

    $urlPulito = if ([string]::IsNullOrWhiteSpace($Endpoint)) { $script:EndpointOllamaPredefinito } else { $Endpoint.Trim().TrimEnd('/') }
    if ([string]::IsNullOrWhiteSpace($Modello)) {
        $Modello = $script:ModelloOllamaPredefinito
    }

    $cronometro = [System.Diagnostics.Stopwatch]::StartNew()

    # Se AutoProvision e' attivo (es. dalla GUI sulla VM), assicurati che Ollama sia attivo o auto-installato
    if ($AutoProvision) {
        $statoInit = Initialize-AmbienteOllama -Endpoint $urlPulito -AutoInstalla $true -OnStatus $OnStatus
        if ($statoInit.Disponibile) {
            $urlPulito = $statoInit.Endpoint
        }
    }

    $uriGen = "$urlPulito/api/generate"

    try {
        $isPromptEn = ($Lingua -eq 'EN') -or ($Prompt -match '\[LANGUAGE: ENGLISH ONLY\]|Write a structured report in 4 sections')
        $isPromptDe = ($Lingua -eq 'DE') -or ($Prompt -match '\[SPRACHE: NUR DEUTSCH|Schreibe einen strukturierten Bericht auf DEUTSCH')
        $sysMsg = if ($isPromptEn) {
            "You are a Windows 11 cybersecurity assistant. Reply strictly in ENGLISH. Never contradict the scanner facts provided in the prompt."
        }
        elseif ($isPromptDe) {
            "Du bist ein IT-Sicherheitsassistent fuer Windows 11. Antworte AUSSCHLIESSLICH auf DEUTSCH (niemals auf Englisch). Halte dich strikt an die im Prompt genannten Fakten."
        }
        else {
            "Sei un assistente di sicurezza informatica per Windows 11. Rispondi ESCLUSIVAMENTE in lingua ITALIANA (non scrivere mai in inglese). Attieniti rigorosamente ai fatti indicati nel prompt."
        }

        $corpoObj = @{
            model   = $Modello
            system  = $sysMsg
            prompt  = $Prompt
            stream  = $false
            options = @{
                temperature = 0.1
                num_predict = 650
            }
        }
        $corpoJson = $corpoObj | ConvertTo-Json -Depth 5
        $bytesBody = [System.Text.Encoding]::UTF8.GetBytes($corpoJson)

        if ($null -ne $OnStatus) { & $OnStatus "Generazione dell'analisi con il modello '$Modello' in corso..." }
        $risposta = Invoke-RestMethod -Uri $uriGen -Method Post -Body $bytesBody -ContentType 'application/json; charset=utf-8' -TimeoutSec $TimeoutSec -ErrorAction Stop
        $cronometro.Stop()

        $testoRisposta = if ($null -ne $risposta -and $null -ne $risposta.PSObject.Properties['response']) {
            ([string]$risposta.response).Trim()
        }
        else {
            ''
        }

        if ([string]::IsNullOrWhiteSpace($testoRisposta)) {
            return [PSCustomObject]@{
                Successo = $false
                Sorgente = 'Ollama'
                Risposta = $null
                Modello  = $Modello
                DurataMs = [int]$cronometro.ElapsedMilliseconds
                Errore   = "Ollama ha restituito una risposta vuota per il modello '$Modello'."
            }
        }

        # Se abbiamo i dati strutturati deterministici (TestoFallbackLocale), li affianchiamo
        # alla risposta di Ollama, verificando anche la coerenza della lingua per i modelli molto piccoli (0.5b)
        $rispostaFinale = $testoRisposta
        if (-not [string]::IsNullOrWhiteSpace($TestoFallbackLocale)) {
            $rispostaInIngleseIndesiderato = ((-not $isPromptEn) -and ($testoRisposta -match '(?i)\b(WHAT IT MEANS|WHY IT MATTERS|HOW TO FIX|The user should|The system disk is)\b'))
            if ($rispostaInIngleseIndesiderato) {
                $rispostaFinale = $TestoFallbackLocale
            }
            else {
                $titoloIa = if ($isPromptEn) {
                    "=== AI COMMENTARY ($Modello) ==="
                } elseif ($isPromptDe) {
                    "=== KI-KOMMENTAR ($Modello) ==="
                } else {
                    "=== COMMENTO GENERATO DALL'IA ($Modello) ==="
                }
                $rispostaFinale = "$TestoFallbackLocale`n`n$titoloIa`n$testoRisposta"
            }
        }

        return [PSCustomObject]@{
            Successo = $true
            Sorgente = "Ollama ($Modello su $urlPulito)"
            Risposta = $rispostaFinale
            Modello  = $Modello
            DurataMs = [int]$cronometro.ElapsedMilliseconds
            Errore   = $null
        }
    }
    catch {
        $cronometro.Stop()
        $msg = $_.Exception.Message

        # Se Ollama e' attivo ma il modello non e' ancora scaricato (404), scaricalo automaticamente via /api/pull!
        if ($msg -match '404|not found') {
            try {
                if ($null -ne $OnStatus) { & $OnStatus "Scaricamento automatico del modello '$Modello' tramite Ollama (/api/pull)..." }
                $uriPull  = "$urlPulito/api/pull"
                $pullJson = (@{ name = $Modello; stream = $false } | ConvertTo-Json)
                [void](Invoke-RestMethod -Uri $uriPull -Method Post -Body ([System.Text.Encoding]::UTF8.GetBytes($pullJson)) -ContentType 'application/json' -TimeoutSec 600 -ErrorAction Stop)

                if ($null -ne $OnStatus) { & $OnStatus "Modello '$Modello' scaricato! Generazione del resoconto in corso..." }
                $rispostaRetry = Invoke-RestMethod -Uri $uriGen -Method Post -Body $bytesBody -ContentType 'application/json; charset=utf-8' -TimeoutSec $TimeoutSec -ErrorAction Stop
                $testoRetry = ([string]$rispostaRetry.response).Trim()
                if (-not [string]::IsNullOrWhiteSpace($testoRetry)) {
                    return [PSCustomObject]@{
                        Successo = $true
                        Sorgente = "Ollama ($Modello - scaricato automaticamente)"
                        Risposta = $testoRetry
                        Modello  = $Modello
                        DurataMs = [int]$cronometro.ElapsedMilliseconds
                        Errore   = $null
                    }
                }
            }
            catch { }
        }

        if (-not [string]::IsNullOrWhiteSpace($TestoFallbackLocale)) {
            return [PSCustomObject]@{
                Successo = $true
                Sorgente = 'Motore Esperto Integrato'
                Risposta = $TestoFallbackLocale
                Modello  = 'Motore Esperto Locale'
                DurataMs = [int]$cronometro.ElapsedMilliseconds
                Errore   = $null
            }
        }

        $erroreAmichevole = if ($msg -match '404') {
            "Il modello '$Modello' non e' ancora scaricato in Ollama. Esegui: ollama pull $Modello"
        }
        else {
            "Impossibile connettersi a Ollama su $urlPulito ($msg). Esegui: ollama pull $Modello"
        }

        return [PSCustomObject]@{
            Successo = $false
            Sorgente = 'Errore'
            Risposta = $null
            Modello  = $Modello
            DurataMs = [int]$cronometro.ElapsedMilliseconds
            Errore   = $erroreAmichevole
        }
    }
}

# =============================================================================
# MODULO: src\core\Checks\Registry.ps1
# =============================================================================
<#
.SYNOPSIS
    Valutatore generico per i controlli basati su registro di Windows.

.DESCRIPTION
    Legge un valore dal registro di Windows e lo confronta con il valore
    atteso usando l'operatore specificato nel catalogo.
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-RegistryValue {
    <#
    .SYNOPSIS
        Verifica un valore nel registro confrontandolo con i parametri del catalogo.
    .PARAMETER RegistryCheck
        Oggetto con proprieta': Path, Name, Operator, Value.
    .PARAMETER Ambiente
        Oggetto ambiente (da Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject con proprieta': Status, Observed, Expected, Evidence, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RegistryCheck,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = $null
        Evidence = $null
        Error    = $null
    }

    $percorso = $RegistryCheck.path
    $nome = $RegistryCheck.name
    $operatore = $RegistryCheck.operator
    $atteso = $RegistryCheck.value

    $risultato.Expected = "$nome $operatore $atteso"

    try {
        # Verifica se la chiave esiste
        if (-not (Test-Path -LiteralPath $percorso)) {
            if ($operatore -eq 'notexists') {
                $risultato.Status = 'superato'
                $risultato.Observed = "Chiave non presente"
                $risultato.Evidence = @{ Path = $percorso; Exists = $false }
            }
            elseif ($operatore -eq 'exists') {
                $risultato.Status = 'fallito'
                $risultato.Observed = "Chiave non presente"
                $risultato.Evidence = @{ Path = $percorso; Exists = $false }
            }
            else {
                $risultato.Status = 'sconosciuto'
                $risultato.Observed = "Chiave di registro non trovata: $percorso"
                $risultato.Evidence = @{ Path = $percorso; Exists = $false }
            }
            return $risultato
        }

        # Leggi il valore
        $prop = Get-ItemProperty -LiteralPath $percorso -Name $nome -ErrorAction Stop
        if (-not $prop.PSObject.Properties[$nome]) {
            throw [System.Management.Automation.PSArgumentException]::new("Valore di registro non trovato: $nome")
        }
        $valoreCorrente = $prop.$nome

        $risultato.Observed = $valoreCorrente
        $risultato.Evidence = @{
            Path  = $percorso
            Name  = $nome
            Value = $valoreCorrente
        }

        # Confronto con l'operatore specificato
        $superato = $false
        switch ($operatore) {
            'eq'        { $superato = ($valoreCorrente -eq $atteso) }
            'ne'        { $superato = ($valoreCorrente -ne $atteso) }
            'ge'        { $superato = ($valoreCorrente -ge $atteso) }
            'le'        { $superato = ($valoreCorrente -le $atteso) }
            'exists'    { $superato = $true }  # Se siamo qui, il valore esiste
            'notexists' { $superato = $false } # Se siamo qui, il valore esiste (non dovrebbe)
            default     {
                $risultato.Status = 'errore'
                $risultato.Error = "Operatore non supportato: $operatore"
                return $risultato
            }
        }

        if ($superato) {
            $risultato.Status = 'superato'
        }
        else {
            $risultato.Status = 'fallito'
        }
    }
    catch [System.Security.SecurityException] {
        # Accesso negato: il dato non e' disponibile, non e' un fallimento del controllo
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave di registro"
        $risultato.Error = $_.Exception.Message
    }
    catch [System.Management.Automation.PSArgumentException] {
        # Il valore specifico non esiste nella chiave
        if ($operatore -eq 'notexists') {
            $risultato.Status = 'superato'
            $risultato.Observed = "Valore non presente"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
        elseif ($operatore -eq 'exists') {
            $risultato.Status = 'fallito'
            $risultato.Observed = "Valore non presente"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
        else {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Valore di registro non trovato: $nome"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        # Il valore specifico non esiste nella chiave
        if ($operatore -eq 'notexists') {
            $risultato.Status = 'superato'
            $risultato.Observed = "Valore non presente"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
        elseif ($operatore -eq 'exists') {
            $risultato.Status = 'fallito'
            $risultato.Observed = "Valore non presente"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
        else {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Valore di registro non trovato: $nome"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error = $_.Exception.Message
    }

    return $risultato
}

# =============================================================================
# MODULO: src\core\Checks\Firewall.ps1
# =============================================================================
<#
.SYNOPSIS
    Controllo dello stato del firewall di Windows.

.DESCRIPTION
    Verifica che Windows Defender Firewall sia attivo sui tre profili:
    Domain, Private, Public.
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-FirewallProfiles {
    <#
    .SYNOPSIS
        Verifica che tutti i profili del firewall siano attivi.
    .PARAMETER Controllo
        L'oggetto controllo dal catalogo.
    .PARAMETER Ambiente
        L'oggetto ambiente (da Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject con proprieta': Status, Observed, Expected, Evidence, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Tutti i profili firewall attivi (Domain, Private, Public) con DefaultInboundAction != Allow"
        Evidence = $null
        Error    = $null
    }

    try {
        # Get-NetFirewallProfile restituisce lo stato dei profili
        $profili = Get-NetFirewallProfile -ErrorAction Stop

        $evidenza = @{}
        $tuttiAttivi = $true
        $profiliDisattivi = @()
        $profiliInboundAllow = @()

        foreach ($profilo in $profili) {
            $nomeNormalizzato = [string]$profilo.Name
            $attivo = [bool]$profilo.Enabled
            $inboundAct = if ($null -ne $profilo.PSObject.Properties['DefaultInboundAction'] -and $null -ne $profilo.DefaultInboundAction) {
                [string]$profilo.DefaultInboundAction
            }
            else {
                'NotConfigured'
            }

            $evidenza[$nomeNormalizzato] = @{
                Enabled              = $attivo
                DefaultInboundAction = $inboundAct
            }

            if (-not $attivo) {
                $tuttiAttivi = $false
                $profiliDisattivi += $nomeNormalizzato
            }
            if ($inboundAct -eq 'Allow') {
                $tuttiAttivi = $false
                $profiliInboundAllow += "$nomeNormalizzato (DefaultInboundAction=Allow)"
            }
        }

        $risultato.Evidence = $evidenza

        if ($tuttiAttivi) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Tutti i profili attivi con traffico in ingresso bloccato per impostazione predefinita"
        }
        else {
            $risultato.Status = 'fallito'
            $motivi = @()
            if ($profiliDisattivi.Count -gt 0) {
                $motivi += "Profili disattivi: $($profiliDisattivi -join ', ')"
            }
            if ($profiliInboundAllow.Count -gt 0) {
                $motivi += "Profili che consentono traffico in ingresso: $($profiliInboundAllow -join ', ')"
            }
            $risultato.Observed = ($motivi -join '; ')
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        # Get-NetFirewallProfile non disponibile
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-NetFirewallProfile non e' disponibile"
        $risultato.Error = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Privilegi insufficienti per accedere al firewall di Windows"
        $risultato.Error = $_.Exception.Message
    }
    catch {
        # Se l'errore e' legato a privilegi mancanti o accesso CIM negato
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per accedere al firewall di Windows"
            $risultato.Error = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error = $_.Exception.Message
        }
    }

    return $risultato
}

# =============================================================================
# MODULO: src\core\Checks\Accounts.ps1
# =============================================================================
<#
.SYNOPSIS
    Controlli di sicurezza relativi agli account utente locali.

.DESCRIPTION
    Contiene i controlli per:
    - HOME-ACC-001: Account Guest disabilitato (SID -501)
    - HOME-ACC-002: Account Administrator predefinito disabilitato (SID -500)
    - HOME-ACC-003: Nessun account locale attivo senza password (PasswordRequired)
    - HOME-ACC-004: Politica di blocco account contro brute-force (LockoutThreshold)
    - HOME-ACC-005: Numero di account nel gruppo Amministratori locali ridotto al minimo (<= 2)
    Include catena di fallback multi-livello (Get-LocalUser -> CIM Win32_UserAccount -> ADSI WinNT -> Registro ProfileList/SAM)
    per evitare stati 'Sconosciuto' su sessioni non-admin, PowerShell a 32-bit o PC con Microsoft Account.
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-FallbackUtentiLocali {
    <#
    .SYNOPSIS
        Funzione helper in sola lettura (prefisso Test- per passaggio automatico al Runspace GUI)
        che recupera la lista degli account locali tramite CIM, ADSI o Registro ProfileList
        quando Get-LocalUser fallisce per restrizioni SAMR non-admin o assenza del modulo.
    #>
    [CmdletBinding()]
    param()

    # 1. Tentativo tramite CIM Win32_UserAccount
    try {
        $cimUsers = @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = True" -ErrorAction Stop)
        if ($cimUsers.Count -gt 0) {
            $listaCim = @()
            foreach ($cu in $cimUsers) {
                $listaCim += [PSCustomObject]@{
                    Name             = [string]$cu.Name
                    SID              = [PSCustomObject]@{ Value = [string]$cu.SID }
                    Enabled          = (-not [bool]$cu.Disabled)
                    PasswordRequired = [bool]$cu.PasswordRequired
                    PrincipalSource  = 'Local'
                    Fonte            = 'Win32_UserAccount'
                }
            }
            return $listaCim
        }
    }
    catch { }

    # 2. Tentativo tramite ADSI WinNT
    try {
        $computer = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'localhost' }
        $adsi = [ADSI]"WinNT://$computer"
        $adsiUsers = @($adsi.Children | Where-Object { $_.SchemaClassName -eq 'User' })
        if ($adsiUsers.Count -gt 0) {
            $listaAdsi = @()
            foreach ($au in $adsiUsers) {
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($au.ObjectSid.Value, 0)
                $flags  = [int]$au.UserFlags.Value
                $disab  = (($flags -band 0x2) -ne 0)
                $noPwd  = (($flags -band 0x20) -ne 0)
                $listaAdsi += [PSCustomObject]@{
                    Name             = [string]$au.Name.Value
                    SID              = [PSCustomObject]@{ Value = $sidObj.Value }
                    Enabled          = (-not $disab)
                    PasswordRequired = (-not $noPwd)
                    PrincipalSource  = 'Local'
                    Fonte            = 'ADSI'
                }
            }
            if ($listaAdsi.Count -gt 0) {
                return $listaAdsi
            }
        }
    }
    catch { }

    # 3. Fallback deterministico tramite Registro ProfileList + SID Translation + Winlogon/IdentityStore
    try {
        $chiaveProfiles = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        if (Test-Path -LiteralPath $chiaveProfiles -ErrorAction SilentlyContinue) {
            $sottoChiavi = @(Get-ChildItem -LiteralPath $chiaveProfiles -ErrorAction Stop | Where-Object { $_.PSChildName -like 'S-1-5-21-*' })
            if ($sottoChiavi.Count -gt 0) {
                $primoSid     = $sottoChiavi[0].PSChildName
                $prefissoDom  = $primoSid -replace '-\d+$', ''
                $sidsProfili  = @($sottoChiavi | ForEach-Object { $_.PSChildName })

                $currSid = ''
                try { $currSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { }

                $haMicrosoftAccount = (
                    (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache' -ErrorAction SilentlyContinue) -or
                    (Test-Path -LiteralPath 'HKCU:\Software\Microsoft\IdentityCRL' -ErrorAction SilentlyContinue)
                )

                $autoLogon = 0
                $chiaveWinlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                if (Test-Path -LiteralPath $chiaveWinlogon -ErrorAction SilentlyContinue) {
                    $propWl = Get-ItemProperty -LiteralPath $chiaveWinlogon -ErrorAction SilentlyContinue
                    if ($null -ne $propWl -and $null -ne $propWl.PSObject.Properties['AutoAdminLogon'] -and [string]$propWl.AutoAdminLogon -eq '1') {
                        $autoLogon = 1
                    }
                }

                $listaReg = @()

                # Ricostruisci stato Built-in Administrator (-500) e Guest (-501)
                foreach ($ridBuiltin in @('500', '501')) {
                    $sidB = "$prefissoDom-$ridBuiltin"
                    $nomeB = if ($ridBuiltin -eq '500') { 'Administrator' } else { 'Guest' }
                    try {
                        $ntAcct = (New-Object System.Security.Principal.SecurityIdentifier($sidB)).Translate([System.Security.Principal.NTAccount]).Value
                        $nomeB  = ($ntAcct -split '\\')[-1]
                    }
                    catch { }

                    $attivoB = ($sidsProfili -contains $sidB) -or ($currSid -eq $sidB)
                    $listaReg += [PSCustomObject]@{
                        Name             = $nomeB
                        SID              = [PSCustomObject]@{ Value = $sidB }
                        Enabled          = $attivoB
                        PasswordRequired = $true
                        PrincipalSource  = 'Local'
                        Fonte            = 'RegistryProfileList'
                    }
                }

                # Aggiungi i profili utente attivi presenti in ProfileList
                foreach ($sk in $sottoChiavi) {
                    $sidU = $sk.PSChildName
                    if ($sidU -match '-(500|501)$') { continue }
                    $nomeU = $sidU
                    try {
                        $ntU   = (New-Object System.Security.Principal.SecurityIdentifier($sidU)).Translate([System.Security.Principal.NTAccount]).Value
                        $nomeU = ($ntU -split '\\')[-1]
                    }
                    catch {
                        $propP = Get-ItemProperty -LiteralPath $sk.PSPath -ErrorAction SilentlyContinue
                        if ($null -ne $propP -and $null -ne $propP.PSObject.Properties['ProfileImagePath']) {
                            $nomeU = Split-Path -Leaf ([string]$propP.ProfileImagePath)
                        }
                    }

                    $srcU = if ($haMicrosoftAccount) { 'MicrosoftAccount' } else { 'Local' }
                    $listaReg += [PSCustomObject]@{
                        Name             = $nomeU
                        SID              = [PSCustomObject]@{ Value = $sidU }
                        Enabled          = $true
                        PasswordRequired = ($autoLogon -eq 0)
                        PrincipalSource  = $srcU
                        Fonte            = 'RegistryProfileList'
                    }
                }

                return $listaReg
            }
        }
    }
    catch { }

    return @()
}

function Test-GuestAccount {
    <#
    .SYNOPSIS
        Verifica che l'account Guest (SID -501) sia disabilitato (HOME-ACC-001).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Account Guest (SID -501) disabilitato"
        Evidence = $null
        Error    = $null
    }

    $utenti = $null
    $erroreIniziale = $null

    try {
        $utenti = @(Get-LocalUser -ErrorAction Stop)
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $erroreIniziale = $_
        if ($_.Exception.Message -match 'Il termine .* non e'' riconosciuto') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Il cmdlet Get-LocalUser non e' disponibile"
            $risultato.Error    = $_.Exception.Message
            return $risultato
        }
    }
    catch {
        $erroreIniziale = $_
        if ($_.Exception.Message -notmatch 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource|1332|Failed to compare') {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
            return $risultato
        }
    }

    if ($null -eq $utenti -or $utenti.Count -eq 0) {
        if ($null -ne $erroreIniziale) {
            $utenti = @(Test-FallbackUtentiLocali)
        }
    }

    if ($null -eq $utenti -or $utenti.Count -eq 0) {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Nessun account con SID che termina in -501 trovato"
        $risultato.Evidence = @{ AccountTrovato = $false }
        if ($null -ne $erroreIniziale) { $risultato.Error = $erroreIniziale.Exception.Message }
        return $risultato
    }

    $guest = $null
    foreach ($utente in $utenti) {
        if ($utente.SID.Value -match '-501$') {
            $guest = $utente
            break
        }
    }

    if ($null -eq $guest) {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Nessun account con SID che termina in -501 trovato"
        $risultato.Evidence = @{ AccountTrovato = $false }
        return $risultato
    }

    $risultato.Evidence = @{
        Nome      = $guest.Name
        SID       = $guest.SID.Value
        Abilitato = [bool]$guest.Enabled
    }

    if ($guest.Enabled) {
        $risultato.Status   = 'fallito'
        $risultato.Observed = "Account Guest ($($guest.Name)) abilitato"
    }
    else {
        $risultato.Status   = 'superato'
        $risultato.Observed = "Account Guest ($($guest.Name)) disabilitato"
    }

    return $risultato
}

function Test-AdminAccount {
    <#
    .SYNOPSIS
        Verifica che l'account Administrator locale predefinito (SID -500) sia disabilitato (HOME-ACC-002).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Account Administrator predefinito (SID -500) disabilitato"
        Evidence = $null
        Error    = $null
    }

    $utenti = $null
    $erroreIniziale = $null

    try {
        $utenti = @(Get-LocalUser -ErrorAction Stop)
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $erroreIniziale = $_
        if ($_.Exception.Message -match 'Il termine .* non e'' riconosciuto') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Il cmdlet Get-LocalUser non e' disponibile"
            $risultato.Error    = $_.Exception.Message
            return $risultato
        }
    }
    catch {
        $erroreIniziale = $_
        if ($_.Exception.Message -notmatch 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource|1332|Failed to compare') {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
            return $risultato
        }
    }

    if ($null -eq $utenti -or $utenti.Count -eq 0) {
        if ($null -ne $erroreIniziale) {
            $utenti = @(Test-FallbackUtentiLocali)
        }
    }

    if ($null -eq $utenti -or $utenti.Count -eq 0) {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Nessun account con SID che termina in -500 trovato"
        $risultato.Evidence = @{ AccountTrovato = $false }
        if ($null -ne $erroreIniziale) { $risultato.Error = $erroreIniziale.Exception.Message }
        return $risultato
    }

    $adminBuiltin = $null
    foreach ($utente in $utenti) {
        if ($utente.SID.Value -match '-500$') {
            $adminBuiltin = $utente
            break
        }
    }

    if ($null -eq $adminBuiltin) {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Nessun account con SID che termina in -500 trovato"
        $risultato.Evidence = @{ AccountTrovato = $false }
        return $risultato
    }

    $risultato.Evidence = @{
        Nome      = $adminBuiltin.Name
        SID       = $adminBuiltin.SID.Value
        Abilitato = [bool]$adminBuiltin.Enabled
    }

    if ($adminBuiltin.Enabled) {
        $risultato.Status   = 'fallito'
        $risultato.Observed = "Account Administrator predefinito ($($adminBuiltin.Name)) abilitato"
    }
    else {
        $risultato.Status   = 'superato'
        $risultato.Observed = "Account Administrator predefinito ($($adminBuiltin.Name)) disabilitato"
    }

    return $risultato
}

function Test-AccountsPasswordRequired {
    <#
    .SYNOPSIS
        Verifica che tutti gli account locali abilitati richiedano una password
        (escludendo dai falsi positivi gli account collegati a Microsoft Account / Windows Hello) (HOME-ACC-003).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Tutti gli account locali attivi hanno PasswordRequired = True (o usano MicrosoftAccount/Windows Hello)"
        Evidence = $null
        Error    = $null
    }

    $utenti = $null
    $erroreIniziale = $null

    try {
        $utenti = @(Get-LocalUser -ErrorAction Stop)
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $erroreIniziale = $_
        if ($_.Exception.Message -match 'Il termine .* non e'' riconosciuto') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Il cmdlet Get-LocalUser non e' disponibile"
            $risultato.Error    = $_.Exception.Message
            return $risultato
        }
    }
    catch {
        $erroreIniziale = $_
        if ($_.Exception.Message -notmatch 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource|1332|Failed to compare') {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
            return $risultato
        }
    }

    if ($null -eq $utenti -or $utenti.Count -eq 0) {
        if ($null -ne $erroreIniziale) {
            $utenti = @(Test-FallbackUtentiLocali)
        }
    }

    if ($null -eq $utenti -or $utenti.Count -eq 0) {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Dati account locali non disponibili"
        if ($null -ne $erroreIniziale) { $risultato.Error = $erroreIniziale.Exception.Message }
        return $risultato
    }

    $attiviSenzaObbligo = @()
    $accountMicrosoft   = @()
    $dettaglioAttivi    = @()

    foreach ($u in $utenti) {
        if ($u.Enabled) {
            $pwdReq = [bool]$u.PasswordRequired
            $sorgente = if ($null -ne $u.PSObject.Properties['PrincipalSource'] -and $null -ne $u.PrincipalSource) {
                [string]$u.PrincipalSource
            }
            else {
                'Local'
            }

            $dettaglioAttivi += @{
                Nome             = $u.Name
                SID              = $u.SID.Value
                PasswordRequired = $pwdReq
                PrincipalSource  = $sorgente
            }

            if ($sorgente -eq 'MicrosoftAccount') {
                $accountMicrosoft += $u.Name
            }
            elseif (-not $pwdReq) {
                $attiviSenzaObbligo += $u.Name
            }
        }
    }

    $risultato.Evidence = @{
        AccountAttivi              = $dettaglioAttivi
        AccountMicrosoft           = $accountMicrosoft
        AccountSenzaPasswordObblig = $attiviSenzaObbligo
    }

    if ($attiviSenzaObbligo.Count -eq 0) {
        $risultato.Status = 'superato'
        if ($accountMicrosoft.Count -gt 0) {
            $risultato.Observed = "Tutti gli account attivi ($($dettaglioAttivi.Count)) richiedono autenticazione (Account Microsoft/Windows Hello: $($accountMicrosoft -join ', '))"
        }
        else {
            $risultato.Observed = "Tutti gli account attivi ($($dettaglioAttivi.Count)) richiedono una password"
        }
    }
    else {
        $risultato.Status   = 'fallito'
        $risultato.Observed = "Account locali attivi con PasswordRequired=False: $($attiviSenzaObbligo -join ', ')"
    }

    return $risultato
}

function Test-PoliticaBloccoAccount {
    <#
    .SYNOPSIS
        Verifica che sia attiva una soglia di blocco account (Account Lockout Threshold 1..10 tentativi)
        contro attacchi di forza bruta locali/rete (HOME-ACC-004).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Soglia blocco account (Lockout threshold) tra 1 e 10 tentativi falliti"
        Evidence = $null
        Error    = $null
    }

    try {
        $outNet = @(net.exe accounts 2>$null)
        $soglia = -1

        foreach ($line in $outNet) {
            if ($line -match '(?i)(Lockout threshold|Soglia di blocco|Kontosperrungsschwelle)\s*:\s*(.+)$') {
                $valTxt = $Matches[2].Trim()
                if ($valTxt -match '^\d+$') {
                    $soglia = [int]$valTxt
                }
                else {
                    $soglia = 0
                }
                break
            }
        }

        $risultato.Evidence = @{
            LockoutThreshold = $soglia
        }

        if ($soglia -ge 1 -and $soglia -le 10) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Blocco account attivo dopo $soglia tentativi falliti"
        }
        elseif ($soglia -gt 10) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Soglia blocco account troppo permissiva ($soglia tentativi; consigliato <= 10)"
        }
        elseif ($soglia -eq 0) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Blocco account disabilitato (Mai / 0 tentativi)"
        }
        else {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Impossibile determinare la soglia di blocco account"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-LimiteAmministratoriLocali {
    <#
    .SYNOPSIS
        Verifica che il gruppo Amministratori locali (SID S-1-5-32-544) non contenga un numero
        eccessivo di account abilitati (consigliato <= 2 amministratori attivi) (HOME-ACC-005).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Massimo 2 account amministratori locali attivi (principio del privilegio minimo)"
        Evidence = $null
        Error    = $null
    }

    try {
        $utentiLocali = @()
        try {
            $utentiLocali = @(Get-LocalUser -ErrorAction Stop)
        }
        catch {
            $utentiLocali = @()
        }
        if ($utentiLocali.Count -eq 0) {
            $utentiLocali = @(Test-FallbackUtentiLocali)
        }

        $mappaDisabilitati = @{}
        $nomiDisabilitati  = @{}
        foreach ($u in $utentiLocali) {
            if (-not $u.Enabled) {
                $mappaDisabilitati[$u.SID.Value] = $true
                $nomiDisabilitati[$u.Name.ToLowerInvariant()] = $true
            }
        }

        $adminAttivi = @()
        $lettoConSuccesso = $false

        # 1. Tentativo primario con Get-LocalGroupMember
        try {
            $membri = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
            foreach ($m in $membri) {
                $sidVal = if ($null -ne $m.PSObject.Properties['SID'] -and $null -ne $m.SID) { $m.SID.Value } else { '' }
                $nomeBreve = (($m.Name -split '\\')[-1]).ToLowerInvariant()
                if (($sidVal -and $mappaDisabilitati.ContainsKey($sidVal)) -or $nomiDisabilitati.ContainsKey($nomeBreve)) {
                    continue
                }
                $adminAttivi += $m.Name
            }
            $lettoConSuccesso = $true
        }
        catch {
            # Fallback quando Get-LocalGroupMember fallisce per bug su MicrosoftAccount o restrizioni SAMR
        }

        # 2. Fallback tramite ADSI WinNT Group Members
        if (-not $lettoConSuccesso) {
            try {
                $sidAdmin   = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
                $nomeGruppo = ($sidAdmin.Translate([System.Security.Principal.NTAccount]).Value -split '\\')[-1]
                $computer   = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'localhost' }
                $grpAdsi    = [ADSI]"WinNT://$computer/$nomeGruppo,group"
                $membriAdsi = @($grpAdsi.psbase.Invoke('Members'))
                foreach ($ma in $membriAdsi) {
                    $nomeM = [string]$ma.GetType().InvokeMember('Name', 'GetProperty', $null, $ma, $null)
                    if (-not [string]::IsNullOrWhiteSpace($nomeM)) {
                        if (-not $nomiDisabilitati.ContainsKey($nomeM.ToLowerInvariant())) {
                            $adminAttivi += $nomeM
                        }
                    }
                }
                if ($adminAttivi.Count -gt 0) {
                    $lettoConSuccesso = $true
                }
            }
            catch { }
        }

        # 3. Fallback tramite profilo attivo in ProfileList (quando SAMR e' bloccato in sessione non-admin)
        if (-not $lettoConSuccesso -and $utentiLocali.Count -gt 0) {
            foreach ($u in $utentiLocali) {
                if ($u.Enabled -and ($u.Name -notlike 'CodexSandbox*') -and ($u.Name -notlike 'WDAGUtilityAccount') -and ($u.Name -notlike 'DefaultAccount')) {
                    $adminAttivi += $u.Name
                }
            }
            if ($adminAttivi.Count -gt 0) {
                $lettoConSuccesso = $true
            }
        }

        if (-not $lettoConSuccesso) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Impossibile enumerare i membri del gruppo Amministratori"
            return $risultato
        }

        $risultato.Evidence = @{
            TotaleAdminAttivi = $adminAttivi.Count
            AdminAttivi       = $adminAttivi
        }

        if ($adminAttivi.Count -le 2) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "$($adminAttivi.Count) amministratori attivi: $($adminAttivi -join ', ')"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevati $($adminAttivi.Count) account nel gruppo Amministratori: $($adminAttivi -join ', ')"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

# =============================================================================
# MODULO: src\core\Checks\Defender.ps1
# =============================================================================
<#
.SYNOPSIS
    Controlli di sicurezza relativi a Windows Defender Antivirus e protezione minacce.

.DESCRIPTION
    Contiene i controlli per:
    - HOME-AV-001: Protezione in tempo reale attiva (Test-DefenderRealtime)
    - HOME-AV-002: Definizioni antivirus aggiornate negli ultimi 7 giorni (Test-DefenderSignatures)
    - HOME-AV-003: Nessuna minaccia attiva o rilevata sui file (Test-DefenderNoActiveThreats)
    - HOME-AV-004: Scansione file scaricati (IOAV) e monitoraggio comportamentale attivi (Test-DefenderBehaviorAndIoav)
    - HOME-AV-005: Protezione da applicazioni potenzialmente indesiderate PUA attiva (Test-DefenderPuaProtection)
    - HOME-AV-006: Protezione antimanomissione (Tamper Protection) e Cloud MAPS attive (Test-DefenderTamperAndCloud)
    - HOME-AV-007: Scansione antivirus eseguita negli ultimi 14 giorni (Test-DefenderRecentScan)
    - HOME-AV-008: Nessuna esclusione pericolosa in Windows Defender (Test-DefenderSafeExclusions)
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-DefenderRealtime {
    <#
    .SYNOPSIS
        Verifica che la protezione in tempo reale di Windows Defender sia attiva.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "AntivirusEnabled = True e RealTimeProtectionEnabled = True"
        Evidence = $null
        Error    = $null
    }

    try {
        $statoMp = Get-MpComputerStatus -ErrorAction Stop
        $avAttivo = [bool]$statoMp.AntivirusEnabled
        $rtAttivo = [bool]$statoMp.RealTimeProtectionEnabled

        $risultato.Evidence = @{
            AntivirusEnabled          = $avAttivo
            RealTimeProtectionEnabled = $rtAttivo
            Fonte                     = 'Get-MpComputerStatus'
        }

        if ($avAttivo -and $rtAttivo) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Protezione in tempo reale e antivirus attivi"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "AntivirusEnabled=$avAttivo, RealTimeProtectionEnabled=$rtAttivo"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpComputerStatus non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        try {
            $regDef = 'HKLM:\SOFTWARE\Microsoft\Windows Defender'
            $regRt  = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection'
            if (Test-Path -LiteralPath $regDef) {
                $propDef = Get-ItemProperty -LiteralPath $regDef -ErrorAction Stop
                $disAv = if ($null -ne $propDef.PSObject.Properties['DisableAntiVirus']) { [int]$propDef.DisableAntiVirus } else { 0 }
                $disAs = if ($null -ne $propDef.PSObject.Properties['DisableAntiSpyware']) { [int]$propDef.DisableAntiSpyware } else { 0 }
                $disRt = 0
                if (Test-Path -LiteralPath $regRt) {
                    $propRt = Get-ItemProperty -LiteralPath $regRt -ErrorAction SilentlyContinue
                    if ($null -ne $propRt -and $null -ne $propRt.PSObject.Properties['DisableRealtimeMonitoring'] -and $null -ne $propRt.DisableRealtimeMonitoring) {
                        $disRt = [int]$propRt.DisableRealtimeMonitoring
                    }
                }

                $risultato.Evidence = @{
                    DisableAntiVirus          = $disAv
                    DisableAntiSpyware        = $disAs
                    DisableRealtimeMonitoring = $disRt
                    Fonte                     = 'RegistryFallback'
                }

                if ($disAv -eq 0 -and $disAs -eq 0 -and $disRt -eq 0) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Protezione in tempo reale attiva (rilevato da registro)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "Protezione disattivata nel registro (DisableRealtimeMonitoring=$disRt)"
                }
                return $risultato
            }
        }
        catch { }

        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per interrogare Windows Defender"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderSignatures {
    <#
    .SYNOPSIS
        Verifica che le definizioni di Windows Defender siano aggiornate (<= 7 giorni).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Eta' definizioni antivirus <= 7 giorni"
        Evidence = $null
        Error    = $null
    }

    try {
        $statoMp = Get-MpComputerStatus -ErrorAction Stop
        $etaGiorni = [int]$statoMp.AntivirusSignatureAge

        $risultato.Evidence = @{
            AntivirusSignatureAge = $etaGiorni
            Fonte                 = 'Get-MpComputerStatus'
        }

        if ($etaGiorni -le 7) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Definizioni aggiornate ($etaGiorni giorni fa)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Definizioni obsolete ($etaGiorni giorni fa, soglia massima: 7 giorni)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpComputerStatus non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        try {
            $regSig = 'HKLM:\SOFTWARE\Microsoft\Windows Defender\Signature Updates'
            if (Test-Path -LiteralPath $regSig) {
                $propSig = Get-ItemProperty -LiteralPath $regSig -ErrorAction Stop
                if ($null -ne $propSig.PSObject.Properties['SignaturesLastUpdated'] -and $null -ne $propSig.SignaturesLastUpdated) {
                    $bytes = [byte[]]$propSig.SignaturesLastUpdated
                    if ($bytes.Length -ge 8) {
                        $fileTime = [System.BitConverter]::ToInt64($bytes, 0)
                        if ($fileTime -gt 0) {
                            $dataAgg = [datetime]::FromFileTimeUtc($fileTime)
                            $giorni = [int][math]::Floor(((Get-Date).ToUniversalTime() - $dataAgg).TotalDays)
                            if ($giorni -lt 0) { $giorni = 0 }

                            $risultato.Evidence = @{
                                AntivirusSignatureAge = $giorni
                                LastUpdatedUtc        = $dataAgg.ToString('o')
                                Fonte                 = 'RegistryFallback'
                            }
                            if ($giorni -le 7) {
                                $risultato.Status   = 'superato'
                                $risultato.Observed = "Definizioni aggiornate ($giorni giorni fa)"
                            }
                            else {
                                $risultato.Status   = 'fallito'
                                $risultato.Observed = "Definizioni obsolete ($giorni giorni fa)"
                            }
                            return $risultato
                        }
                    }
                }
            }
        }
        catch { }

        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per verificare le firme di Windows Defender"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderNoActiveThreats {
    <#
    .SYNOPSIS
        Verifica che Windows Defender non abbia rilevato minacce o malware attivi sui file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "0 minacce attive rilevate da Windows Defender"
        Evidence = $null
        Error    = $null
    }

    try {
        $rilevamenti = @(Get-MpThreatDetection -ErrorAction Stop)
        $minacceCat  = @(Get-MpThreat -ErrorAction SilentlyContinue)

        $minacceAttive = @()
        foreach ($m in $minacceCat) {
            if ($null -ne $m.PSObject.Properties['IsActive'] -and $m.IsActive) {
                $nomeMinaccia = if ($null -ne $m.PSObject.Properties['ThreatName']) { [string]$m.ThreatName } else { 'Minaccia' }
                $minacceAttive += $nomeMinaccia
            }
        }

        $risultato.Evidence = @{
            TotaleRilevamentiStorici = $rilevamenti.Count
            MinacceAttiveCount       = $minacceAttive.Count
            MinacceAttive            = $minacceAttive
        }

        if ($minacceAttive.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna minaccia attiva presente sul sistema (0 minacce attive)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevate $($minacceAttive.Count) minacce attive: $($minacceAttive -join ', ')"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpThreatDetection non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per interrogare il catalogo minacce di Defender"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderBehaviorAndIoav {
    <#
    .SYNOPSIS
        Verifica che il monitoraggio comportamentale e la scansione dei file scaricati (IOAV) siano attivi.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "BehaviorMonitorEnabled = True e IoavProtectionEnabled = True"
        Evidence = $null
        Error    = $null
    }

    try {
        $statoMp = Get-MpComputerStatus -ErrorAction Stop
        $behav = [bool]$statoMp.BehaviorMonitorEnabled
        $ioav  = [bool]$statoMp.IoavProtectionEnabled

        $risultato.Evidence = @{
            BehaviorMonitorEnabled = $behav
            IoavProtectionEnabled  = $ioav
        }

        if ($behav -and $ioav) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Monitoraggio comportamentale e scansione file scaricati attivi"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "BehaviorMonitorEnabled=$behav, IoavProtectionEnabled=$ioav"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpComputerStatus non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per interrogare Windows Defender"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderPuaProtection {
    <#
    .SYNOPSIS
        Verifica che il blocco delle applicazioni potenzialmente indesiderate (PUAProtection = 1) sia attivo.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "PUAProtection = 1 (Blocco attivo)"
        Evidence = $null
        Error    = $null
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $pua = [int]$pref.PUAProtection

        $risultato.Evidence = @{
            PUAProtection = $pua
        }

        if ($pua -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Protezione PUA attiva in modalita' blocco (PUAProtection = 1)"
        }
        elseif ($pua -eq 2) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Protezione PUA solo in modalita' audit, non blocca i file (PUAProtection = 2)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Protezione PUA disattivata (PUAProtection = $pua)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpPreference non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per leggere le preferenze PUA di Defender"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderTamperAndCloud {
    <#
    .SYNOPSIS
        Verifica che la protezione antimanomissione (IsTamperProtected) e la protezione Cloud (MAPSReporting) siano attive.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "IsTamperProtected = True e MAPSReporting >= 1"
        Evidence = $null
        Error    = $null
    }

    try {
        $statoMp = Get-MpComputerStatus -ErrorAction Stop
        $pref    = Get-MpPreference -ErrorAction Stop

        $tamper = [bool]$statoMp.IsTamperProtected
        $maps   = [int]$pref.MAPSReporting

        $risultato.Evidence = @{
            IsTamperProtected = $tamper
            MAPSReporting     = $maps
        }

        if ($tamper -and ($maps -ge 1)) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Tamper Protection attiva e Cloud MAPS abilitato (livello $maps)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "IsTamperProtected=$tamper, MAPSReporting=$maps"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet di Windows Defender non disponibili"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per verificare Tamper Protection e Cloud MAPS"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderRecentScan {
    <#
    .SYNOPSIS
        Verifica che una scansione antivirus (rapida o completa) sia stata eseguita negli ultimi 14 giorni.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Scansione rapida o completa eseguita negli ultimi 14 giorni"
        Evidence = $null
        Error    = $null
    }

    try {
        $statoMp = Get-MpComputerStatus -ErrorAction Stop
        $quickAge = [uint32]$statoMp.QuickScanAge
        $fullAge  = [uint32]$statoMp.FullScanAge

        $risultato.Evidence = @{
            QuickScanAge = $quickAge
            FullScanAge  = $fullAge
        }

        $minAge = if ($quickAge -lt $fullAge) { $quickAge } else { $fullAge }

        if ($minAge -le 14) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Ultima scansione eseguita $minAge giorni fa"
        }
        elseif ($minAge -eq [uint32]::MaxValue) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Nessuna scansione periodica registrata di recente"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Ultima scansione risale a $minAge giorni fa (soglia consigliata: <= 14 giorni)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpComputerStatus non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per verificare la data dell'ultima scansione"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderSafeExclusions {
    <#
    .SYNOPSIS
        Verifica che non vi siano esclusioni pericolose (es. C:\, Downloads, .exe, .ps1) in Windows Defender.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Nessuna cartella critica o estensione eseguibile esclusa da Windows Defender"
        Evidence = $null
        Error    = $null
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $paths = @()
        if ($null -ne $pref.ExclusionPath) {
            $paths = @($pref.ExclusionPath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }
        $exts = @()
        if ($null -ne $pref.ExclusionExtension) {
            $exts = @($pref.ExclusionExtension | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        }

        # Se non si e' amministratori, Defender restituisce il messaggio "N/A: Must be an administrator..."
        if (($paths.Count -gt 0 -and $paths[0] -match 'Must be an administrator|amministratore') -or
            ($exts.Count -gt 0 -and $exts[0] -match 'Must be an administrator|amministratore')) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Richiede privilegi di amministratore per leggere l'elenco delle esclusioni di Defender"
            $risultato.Evidence = @{ RichiedeAdmin = $true }
            return $risultato
        }

        $esclusioniPericolose = @()
        foreach ($p in $paths) {
            $pNorm = $p.TrimEnd('\')
            if ($pNorm -match '^[A-Za-z]:$' -or
                $pNorm -match '(?i)\\Windows$' -or
                $pNorm -match '(?i)\\Users$' -or
                $pNorm -match '(?i)\\Downloads$' -or
                $pNorm -match '(?i)\\Temp$' -or
                $pNorm -match '(?i)\\AppData$') {
                $esclusioniPericolose += "Percorso: $p"
            }
        }

        foreach ($e in $exts) {
            $eNorm = $e.Trim().TrimStart('.').ToLowerInvariant()
            if ($eNorm -in @('exe', 'dll', 'ps1', 'bat', 'cmd', 'vbs', 'js', 'scr', 'hta', 'msi', '*')) {
                $esclusioniPericolose += "Estensione: .$eNorm"
            }
        }

        $risultato.Evidence = @{
            ExclusionPathCount      = $paths.Count
            ExclusionExtensionCount = $exts.Count
            EsclusioniPericolose    = $esclusioniPericolose
        }

        if ($esclusioniPericolose.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna esclusione critica trovata ($($paths.Count) percorsi, $($exts.Count) estensioni)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Esclusioni ad alto rischio rilevate: $($esclusioniPericolose -join '; ')"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpPreference non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per verificare le esclusioni di Windows Defender"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderRansomwareCartelle {
    <#
    .SYNOPSIS
        Verifica che l'Accesso alle cartelle controllato (Controlled Folder Access anti-ransomware) sia attivo (HOME-AV-009).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "EnableControlledFolderAccess = 1 (Blocco anti-ransomware attivo)"
        Evidence = $null
        Error    = $null
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $cfa  = [int]$pref.EnableControlledFolderAccess

        $risultato.Evidence = @{
            EnableControlledFolderAccess = $cfa
        }

        if ($cfa -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Protezione ransomware (Accesso alle cartelle controllato) attiva (1)"
        }
        elseif ($cfa -eq 2) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Accesso alle cartelle controllato solo in modalita' audit (2)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Accesso alle cartelle controllato disattivato ($cfa)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpPreference non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per leggere EnableControlledFolderAccess"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderNetworkProtection {
    <#
    .SYNOPSIS
        Verifica che la Protezione di rete di Microsoft Defender Exploit Guard (EnableNetworkProtection = 1) sia attiva (HOME-AV-010).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "EnableNetworkProtection = 1 (Blocco domini malevoli attivo)"
        Evidence = $null
        Error    = $null
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $netP = [int]$pref.EnableNetworkProtection

        $risultato.Evidence = @{
            EnableNetworkProtection = $netP
        }

        if ($netP -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Protezione di rete Defender Exploit Guard attiva in modalita' blocco (1)"
        }
        elseif ($netP -eq 2) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Protezione di rete solo in modalita' audit (2)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Protezione di rete disattivata ($netP)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpPreference non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per leggere EnableNetworkProtection"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-DefenderAsrRules {
    <#
    .SYNOPSIS
        Verifica che le regole Attack Surface Reduction (ASR) di Microsoft Defender siano attive
        in modalita' Block (1) o Warn (6) (in particolare blocco furto credenziali LSASS e script offuscati) (HOME-AV-011).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Regole ASR attive in modalita' Block (1) o Warn (6) (incluso LSASS 9e6c4e1f-... e Script 5beb7efe-...)"
        Evidence = $null
        Error    = $null
    }

    try {
        $pref = Get-MpPreference -ErrorAction Stop
        $ids = @()
        if ($null -ne $pref.PSObject.Properties['AttackSurfaceReductionRules_Ids'] -and $null -ne $pref.AttackSurfaceReductionRules_Ids) {
            $ids = @($pref.AttackSurfaceReductionRules_Ids)
        }
        $actions = @()
        if ($null -ne $pref.PSObject.Properties['AttackSurfaceReductionRules_Actions'] -and $null -ne $pref.AttackSurfaceReductionRules_Actions) {
            $actions = @($pref.AttackSurfaceReductionRules_Actions)
        }

        if ($ids.Count -gt 0 -and ([string]$ids[0]) -match 'Must be an administrator|amministratore') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi di amministratore richiesti per leggere le regole ASR di Defender"
            $risultato.Evidence = @{ RichiedeAdmin = $true }
            return $risultato
        }

        $regoleAttive = @()
        $lsassAttiva  = $false
        $scriptAttiva = $false

        $maxIdx = [Math]::Min($ids.Count, $actions.Count)
        for ($i = 0; $i -lt $maxIdx; $i++) {
            $guid = ([string]$ids[$i]).Trim().ToLowerInvariant()
            $act  = [int]$actions[$i]
            if ($act -eq 1 -or $act -eq 6) {
                $regoleAttive += "$guid=$act"
                if ($guid -eq '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2') { $lsassAttiva  = $true }
                if ($guid -eq '5beb7efe-fd9a-4556-801d-275e5ffc04cc') { $scriptAttiva = $true }
            }
        }

        $risultato.Evidence = @{
            TotaleConfigurate = $ids.Count
            TotaleAttive      = $regoleAttive.Count
            LsassProtected    = $lsassAttiva
            ScriptsProtected  = $scriptAttiva
            RegoleAttive      = $regoleAttive
        }

        if ($regoleAttive.Count -gt 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "$($regoleAttive.Count) regole ASR attive in modalita' Block/Warn (LSASS=$lsassAttiva, ObfuscatedScripts=$scriptAttiva)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Nessuna regola Attack Surface Reduction (ASR) attiva in modalita' Block/Warn ($($ids.Count) configurate)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-MpPreference non e' disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per verificare le regole ASR di Defender"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

# =============================================================================
# MODULO: src\core\Checks\FileSecurity.ps1
# =============================================================================
<#
.SYNOPSIS
    Controlli di sicurezza sui file locali, avvio automatico (persistenza), task pianificati, IFEO e file hosts.

.DESCRIPTION
    Contiene i controlli in sola lettura per:
    - HOME-FIL-001: Scansione file sospetti con doppia estensione in Download, Desktop e Temp (Test-SuspiciousDoubleExtensionFiles)
    - HOME-FIL-002: Verifica voci di avvio automatico (Run/RunOnce) contro persistenza malware (Test-StartupPersistenceEntries)
    - HOME-FIL-003: Integrita' del file hosts di Windows contro dirottamenti DNS (Test-HostsFileIntegrity)
    - HOME-FIL-004: Verifica Attivita' pianificate (Scheduled Tasks) contro comandi offuscati (Test-TaskPianificatiSospetti)
    - HOME-FIL-005: Verifica assenza dirottamenti IFEO Debugger (Sticky Keys / TaskMgr / Defender) (Test-HijackingIFEO)
    - HOME-FIL-006: Scansione cartelle Esecuzione automatica (Startup) contro script sospetti (Test-CartellaStartupUtente)
    - HOME-FIL-007: Verifica assenza persistenza fileless via WMI Event Subscriptions (Test-WmiEventSubscriptions)
    - HOME-FIL-008: Verifica assenza estensioni browser forzate da policy Chrome/Edge (Test-BrowserForcedExtensions)
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-SuspiciousDoubleExtensionFiles {
    <#
    .SYNOPSIS
        Scansiona in sola lettura le cartelle Download, Desktop e Temp alla ricerca di file
        eseguibili camuffati con doppia estensione (es. documento.pdf.exe, foto.jpg.scr).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [string[]]$CartelleDaControllare = @()
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "0 file eseguibili camuffati con doppia estensione in Download, Desktop e Temp"
        Evidence = $null
        Error    = $null
    }

    try {
        if ($null -eq $CartelleDaControllare -or $CartelleDaControllare.Count -eq 0) {
            $profiloUtente = [Environment]::GetFolderPath('UserProfile')
            $CartelleDaControllare = @(
                (Join-Path $profiloUtente 'Downloads'),
                (Join-Path $profiloUtente 'Desktop'),
                [System.IO.Path]::GetTempPath()
            )
        }

        $patternDoppiaEstensione = '(?i)\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf|jpg|jpeg|png|gif|bmp|mp3|mp4|avi|zip|rar|7z)\.(exe|scr|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|hta|com|pif)$'

        $fileSospetti     = @()
        $totaleAnalizzati = 0

        foreach ($cartella in $CartelleDaControllare) {
            if ([string]::IsNullOrWhiteSpace($cartella)) { continue }
            if (-not (Test-Path -LiteralPath $cartella -ErrorAction SilentlyContinue)) { continue }

            $elementi = @(Get-ChildItem -LiteralPath $cartella -File -ErrorAction SilentlyContinue | Select-Object -First 1000)
            foreach ($file in $elementi) {
                $totaleAnalizzati++
                if ($file.Name -match $patternDoppiaEstensione) {
                    $fileSospetti += $file.FullName
                }
            }
        }

        $risultato.Evidence = @{
            CartelleAnalizzate = $CartelleDaControllare
            FileAnalizzati     = $totaleAnalizzati
            FileSospetti       = $fileSospetti
        }

        if ($fileSospetti.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessun file con doppia estensione sospetta rilevato ($totaleAnalizzati file controllati)"
        }
        else {
            $risultato.Status   = 'fallito'
            $nomiBrevi = @($fileSospetti | ForEach-Object { Split-Path -Leaf $_ })
            $risultato.Observed = "Trovati $($fileSospetti.Count) file sospetti con doppia estensione: $($nomiBrevi -join ', ')"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-StartupPersistenceEntries {
    <#
    .SYNOPSIS
        Analizza le chiavi di avvio automatico (Run / RunOnce) alla ricerca di comandi
        sospetti (esecuzione da Temp, PowerShell offuscato -enc, mshta, wscript).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Nessuna voce di avvio automatico sospetta o offuscata nelle chiavi Run/RunOnce"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaviRun = @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
        )

        $patternSospetto = '(?i)(-enc|-EncodedCommand|-w\s+hidden|-WindowStyle\s+Hidden|mshta\.exe|wscript\.exe|cscript\.exe|regsvr32\.exe\s+/s|\\AppData\\Local\\Temp\\|\\Windows\\Temp\\)'

        $vociTotali   = @()
        $vociSospette = @()

        foreach ($percorso in $chiaviRun) {
            if (-not (Test-Path -LiteralPath $percorso)) { continue }

            $prop = Get-ItemProperty -LiteralPath $percorso -ErrorAction SilentlyContinue
            if ($null -eq $prop) { continue }

            foreach ($p in $prop.PSObject.Properties) {
                if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                    continue
                }
                $valoreCmd = [string]$p.Value
                $voceDesc  = "$($p.Name) = $valoreCmd"
                $vociTotali += $voceDesc

                if ($valoreCmd -match $patternSospetto) {
                    $vociSospette += "$($p.Name) ($percorso)"
                }
            }
        }

        $risultato.Evidence = @{
            TotaleVociRun = $vociTotali.Count
            VociSospette  = $vociSospette
        }

        if ($vociSospette.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna voce sospetta rilevata tra i $($vociTotali.Count) programmi in avvio automatico"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevate $($vociSospette.Count) voci di avvio automatico sospette: $($vociSospette -join '; ')"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-HostsFileIntegrity {
    <#
    .SYNOPSIS
        Verifica che il file hosts di Windows non contenga dirottamenti di domini di sicurezza
        o Windows Update.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [string]$PercorsoHosts = ''
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Nessun dirottamento di domini Microsoft o antivirus nel file hosts"
        Evidence = $null
        Error    = $null
    }

    try {
        if ([string]::IsNullOrWhiteSpace($PercorsoHosts)) {
            $sysRoot = if ($env:SystemRoot) { $env:SystemRoot } else { 'C:\Windows' }
            $PercorsoHosts = Join-Path $sysRoot 'System32\drivers\etc\hosts'
        }

        if (-not (Test-Path -LiteralPath $PercorsoHosts)) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "File hosts non presente (nessun dirottamento attivo)"
            return $risultato
        }

        $righe = @(Get-Content -LiteralPath $PercorsoHosts -Encoding UTF8 -ErrorAction Stop)
        $righeAttive   = @()
        $righeSospette = @()

        $patternDominiSensibili = '(?i)(windowsupdate\.com|update\.microsoft\.com|microsoft\.com|defender|virustotal\.com|malwarebytes\.com|kaspersky|bitdefender|avast|Norton|mcafee)'

        foreach ($riga in $righe) {
            $trimmed = $riga.Trim()
            if ($trimmed -eq '' -or $trimmed.StartsWith('#')) {
                continue
            }
            if ($trimmed -match '^(127\.0\.0\.1|::1)\s+localhost(\s|$)') {
                continue
            }
            $righeAttive += $trimmed
            if ($trimmed -match $patternDominiSensibili) {
                $righeSospette += $trimmed
            }
        }

        $risultato.Evidence = @{
            Percorso             = $PercorsoHosts
            VociPersonalizzate   = $righeAttive.Count
            DirottamentiSospetti = $righeSospette
        }

        if ($righeSospette.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "File hosts integro ($($righeAttive.Count) voci personalizzate, 0 dirottamenti di sicurezza)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevati $($righeSospette.Count) dirottamenti sospetti nel file hosts: $($righeSospette -join '; ')"
        }
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato in lettura al file hosts"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-TaskPianificatiSospetti {
    <#
    .SYNOPSIS
        Analizza le Attivita' pianificate (Scheduled Tasks) alla ricerca di persistenza malware
        (esecuzione da Temp/Users\Public, PowerShell offuscato -enc, mshta, regsvr32, certutil) (HOME-FIL-004).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "0 attivita' pianificate sospette o offuscate"
        Evidence = $null
        Error    = $null
    }

    try {
        $tasks = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\Microsoft\*' })
        $patternCmdSospetto = '(?i)(-enc\b|-EncodedCommand|FromBase64String|DownloadString|mshta\.exe|certutil\.exe.*-urlcache|regsvr32\.exe.*scrobj|\\AppData\\Local\\Temp\\|\\Users\\Public\\)'

        $sospetti = @()
        foreach ($t in $tasks) {
            foreach ($act in $t.Actions) {
                $exe = if ($null -ne $act.PSObject.Properties['Execute']) { [string]$act.Execute } else { '' }
                $arg = if ($null -ne $act.PSObject.Properties['Arguments']) { [string]$act.Arguments } else { '' }
                $combinato = "$exe $arg".Trim()
                if ($combinato -match $patternCmdSospetto) {
                    $sospetti += "$($t.TaskName) ($combinato)"
                }
            }
        }

        $risultato.Evidence = @{
            TaskAnalizzati = $tasks.Count
            TaskSospetti   = $sospetti
        }

        if ($sospetti.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna attivita' pianificata sospetta rilevata ($($tasks.Count) task non-Microsoft verificati)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevate $($sospetti.Count) attivita' pianificate sospette: $($sospetti -join '; ')"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-ScheduledTask non disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi di amministratore richiesti per ispezionare tutte le Attivita' pianificate"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-HijackingIFEO {
    <#
    .SYNOPSIS
        Verifica che non vi siano dirottamenti di eseguibili di sistema o accessibilita'
        (Sticky Keys sethc.exe, utilman.exe, taskmgr.exe, MsMpEng.exe) tramite IFEO Debugger (HOME-FIL-005).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Nessun Debugger IFEO malevolo su eseguibili di sistema o accessibilita'"
        Evidence = $null
        Error    = $null
    }

    try {
        $baseIfeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
        $eseguibiliCritici = @(
            'sethc.exe', 'utilman.exe', 'osk.exe', 'narrator.exe', 'magnify.exe',
            'displayswitch.exe', 'atbroker.exe', 'taskmgr.exe', 'MsMpEng.exe',
            'MpCmdRun.exe', 'SecHealthUI.exe', 'regedit.exe', 'powershell.exe'
        )

        $dirottati = @()
        foreach ($exeName in $eseguibiliCritici) {
            $chiaveExe = Join-Path $baseIfeo $exeName
            if (Test-Path -LiteralPath $chiaveExe -ErrorAction SilentlyContinue) {
                $prop = Get-ItemProperty -LiteralPath $chiaveExe -Name 'Debugger' -ErrorAction SilentlyContinue
                if ($null -ne $prop -and $null -ne $prop.PSObject.Properties['Debugger'] -and (-not [string]::IsNullOrWhiteSpace([string]$prop.Debugger))) {
                    $dirottati += "$exeName -> $($prop.Debugger)"
                }
            }
        }

        $risultato.Evidence = @{
            EseguibiliControllati = $eseguibiliCritici.Count
            DirottamentiIFEO      = $dirottati
        }

        if ($dirottati.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessun dirottamento IFEO rilevato sugli eseguibili critici di sistema ($($eseguibiliCritici.Count) controllati)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevati dirottamenti IFEO sospetti: $($dirottati -join '; ')"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-CartellaStartupUtente {
    <#
    .SYNOPSIS
        Scansiona le cartelle di Esecuzione automatica (Startup utente e comune) alla ricerca di
        script o eseguibili sospetti (.vbs, .js, .bat, .cmd, .ps1, .hta, .scr) (HOME-FIL-006).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "0 script o eseguibili sospetti nelle cartelle Startup"
        Evidence = $null
        Error    = $null
    }

    try {
        $cartelleStartup = @(
            [Environment]::GetFolderPath('Startup'),
            [Environment]::GetFolderPath('CommonStartup')
        )

        $patternScriptSospetto = '(?i)\.(vbs|vbe|js|jse|wsf|wsh|hta|bat|cmd|ps1|scr|pif)$'
        $trovati = @()
        $totFile = 0

        foreach ($dir in $cartelleStartup) {
            if ([string]::IsNullOrWhiteSpace($dir) -or (-not (Test-Path -LiteralPath $dir -ErrorAction SilentlyContinue))) { continue }
            $files = @(Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue)
            foreach ($f in $files) {
                if ($f.Name -eq 'desktop.ini') { continue }
                $totFile++
                if ($f.Name -match $patternScriptSospetto) {
                    $trovati += $f.FullName
                }
            }
        }

        $risultato.Evidence = @{
            FileTotaliStartup = $totFile
            ScriptSospetti    = $trovati
        }

        if ($trovati.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuno script sospetto nelle cartelle Esecuzione automatica ($totFile elementi presenti)"
        }
        else {
            $risultato.Status   = 'fallito'
            $nomi = @($trovati | ForEach-Object { Split-Path -Leaf $_ })
            $risultato.Observed = "Rilevati script/eseguibili sospetti in Startup: $($nomi -join ', ')"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-WmiEventSubscriptions {
    <#
    .SYNOPSIS
        Verifica che non siano presenti sottoscrizioni WMI persistenti malevole
        (persistenza fileless tramite __EventFilter, CommandLineEventConsumer,
        ActiveScriptEventConsumer e __FilterToConsumerBinding in root\subscription) (HOME-FIL-007).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "0 sottoscrizioni WMI persistenti sospette (CommandLineEventConsumer / ActiveScriptEventConsumer)"
        Evidence = $null
        Error    = $null
    }

    try {
        $filtri          = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__EventFilter' -ErrorAction Stop)
        $cmdConsumers    = @(Get-CimInstance -Namespace 'root\subscription' -ClassName 'CommandLineEventConsumer' -ErrorAction Stop)
        $scriptConsumers = @(Get-CimInstance -Namespace 'root\subscription' -ClassName 'ActiveScriptEventConsumer' -ErrorAction Stop)
        $bindings        = @(Get-CimInstance -Namespace 'root\subscription' -ClassName '__FilterToConsumerBinding' -ErrorAction Stop)

        $elementiSospetti = @()
        $filtriLegittimi = @('SCM Event Log Filter')

        foreach ($c in $cmdConsumers) {
            $nomeC  = if ($null -ne $c.PSObject.Properties['Name'] -and $null -ne $c.Name) { [string]$c.Name } else { 'ConsumerSenzaNome' }
            $cmdTpl = if ($null -ne $c.PSObject.Properties['CommandLineTemplate'] -and $null -ne $c.CommandLineTemplate) { [string]$c.CommandLineTemplate } else { '' }
            if ($cmdTpl.Length -gt 120) {
                $cmdTpl = $cmdTpl.Substring(0, 117) + '...'
            }
            $elementiSospetti += "CommandLineEventConsumer: $nomeC ($cmdTpl)"
        }

        foreach ($s in $scriptConsumers) {
            $nomeS  = if ($null -ne $s.PSObject.Properties['Name'] -and $null -ne $s.Name) { [string]$s.Name } else { 'ScriptConsumerSenzaNome' }
            $scrTxt = if ($null -ne $s.PSObject.Properties['ScriptText'] -and $null -ne $s.ScriptText) { [string]$s.ScriptText } else { '' }
            if ($scrTxt.Length -gt 120) {
                $scrTxt = $scrTxt.Substring(0, 117) + '...'
            }
            $elementiSospetti += "ActiveScriptEventConsumer: $nomeS ($scrTxt)"
        }

        foreach ($f in $filtri) {
            $fNome = if ($null -ne $f.PSObject.Properties['Name'] -and $null -ne $f.Name) { [string]$f.Name } else { '' }
            if ($filtriLegittimi -contains $fNome) { continue }
            $fQuery = if ($null -ne $f.PSObject.Properties['Query'] -and $null -ne $f.Query) { [string]$f.Query } else { '' }
            if ($fQuery.Length -gt 120) {
                $fQuery = $fQuery.Substring(0, 117) + '...'
            }
            if (($cmdConsumers.Count -gt 0 -or $scriptConsumers.Count -gt 0) -or
                ($fQuery -match '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|Win32_ProcessStartTrace)')) {
                $elementiSospetti += "EventFilter: $fNome ($fQuery)"
            }
        }

        $bindingsNonStandard = 0
        foreach ($b in $bindings) {
            $bFilt = if ($null -ne $b.PSObject.Properties['Filter'] -and $null -ne $b.Filter) { [string]$b.Filter } else { '' }
            $bCons = if ($null -ne $b.PSObject.Properties['Consumer'] -and $null -ne $b.Consumer) { [string]$b.Consumer } else { '' }
            if (($bFilt -match 'SCM Event Log Filter') -and ($bCons -match 'NTEventLogEventConsumer')) {
                continue
            }
            $bindingsNonStandard++
        }

        $risultato.Evidence = @{
            EventFiltersCount          = $filtri.Count
            CommandLineConsumersCount  = $cmdConsumers.Count
            ActiveScriptConsumersCount = $scriptConsumers.Count
            BindingsCount              = $bindings.Count
            NonStandardBindingsCount   = $bindingsNonStandard
            ElementiSospetti           = $elementiSospetti
        }

        if ($elementiSospetti.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna sottoscrizione WMI persistente sospetta rilevata in root\subscription"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevate $($elementiSospetti.Count) sottoscrizioni WMI sospette: $($elementiSospetti -join '; ')"
        }
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Privilegi insufficienti per interrogare il namespace WMI root\subscription"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|CIM resource|Unauthorized') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per interrogare il namespace WMI root\subscription"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-BrowserForcedExtensions {
    <#
    .SYNOPSIS
        Verifica che non vi siano estensioni browser forzate tramite policy di registro
        (ExtensionInstallForcelist su Google Chrome o Microsoft Edge) (HOME-FIL-008).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Nessuna estensione browser forzata da policy (ExtensionInstallForcelist vuota o assente)"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaviBrowser = @(
            @{ Browser = 'Chrome'; Hive = 'HKLM'; Path = 'HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist' },
            @{ Browser = 'Chrome'; Hive = 'HKCU'; Path = 'HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist' },
            @{ Browser = 'Edge';   Hive = 'HKLM'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist' },
            @{ Browser = 'Edge';   Hive = 'HKCU'; Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist' }
        )

        $estensioniForzate = @()
        $chiaviTrovate     = @()

        foreach ($voce in $chiaviBrowser) {
            if (-not (Test-Path -LiteralPath $voce.Path -ErrorAction SilentlyContinue)) {
                continue
            }
            $chiaviTrovate += $voce.Path
            $prop = Get-ItemProperty -LiteralPath $voce.Path -ErrorAction Stop
            if ($null -eq $prop) { continue }

            foreach ($p in $prop.PSObject.Properties) {
                if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                    continue
                }
                $valEst = [string]$p.Value
                if (-not [string]::IsNullOrWhiteSpace($valEst)) {
                    $estensioniForzate += "$($voce.Browser) ($($voce.Hive)): $valEst"
                }
            }
        }

        $risultato.Evidence = @{
            ChiaviVerificate  = $chiaviBrowser.Count
            ChiaviEsistenti   = $chiaviTrovate
            EstensioniForzate = $estensioniForzate
            TotaleRilevate    = $estensioniForzate.Count
        }

        if ($estensioniForzate.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna estensione browser forzata da policy rilevata su Chrome o Edge"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevate $($estensioniForzate.Count) estensioni browser forzate da policy: $($estensioniForzate -join '; ')"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alle chiavi di policy del browser"
        $risultato.Error    = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alle chiavi di policy del browser"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|SecurityException') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Accesso negato alle chiavi di policy del browser"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

# =============================================================================
# MODULO: src\core\Checks\Network.ps1
# =============================================================================
<#
.SYNOPSIS
    Controlli di sicurezza relativi ai protocolli di rete (SMBv1 e NetBIOS).

.DESCRIPTION
    Contiene i controlli per:
    - HOME-NET-001: Protocollo SMBv1 disabilitato (Test-Smb1Disabled)
    - HOME-NET-002: NetBIOS su TCP/IP disabilitato (Test-NetbiosDisabled)
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-Smb1Disabled {
    <#
    .SYNOPSIS
        Verifica che il protocollo SMBv1 sia disabilitato.
    .PARAMETER Controllo
        L'oggetto controllo dal catalogo.
    .PARAMETER Ambiente
        L'oggetto ambiente (da Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject con proprieta': Status, Observed, Expected, Evidence, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Protocollo SMBv1 disabilitato (EnableSMB1Protocol = False)"
        Evidence = $null
        Error    = $null
    }

    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
        $smb1Attivo = [bool]$smbConfig.EnableSMB1Protocol

        $risultato.Evidence = @{
            EnableSMB1Protocol = $smb1Attivo
            Fonte              = 'Get-SmbServerConfiguration'
        }

        if (-not $smb1Attivo) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "SMBv1 disabilitato"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "SMBv1 abilitato (EnableSMB1Protocol = True)"
        }
    }
    catch {
        # Fallback su registro (LanmanServer\Parameters e driver mrxsmb10)
        try {
            $percorsoLanman = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
            $percorsoMrx    = 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10'

            if (Test-Path -LiteralPath $percorsoLanman) {
                $propLanman = Get-ItemProperty -LiteralPath $percorsoLanman -ErrorAction Stop
                if ($null -ne $propLanman.PSObject.Properties['SMB1'] -and $null -ne $propLanman.SMB1) {
                    $valSmb1 = [int]$propLanman.SMB1
                    $risultato.Evidence = @{ SMB1Registry = $valSmb1; Fonte = 'LanmanServerRegistry' }
                    if ($valSmb1 -eq 0) {
                        $risultato.Status   = 'superato'
                        $risultato.Observed = "SMBv1 disabilitato da registro (SMB1 = 0)"
                    }
                    else {
                        $risultato.Status   = 'fallito'
                        $risultato.Observed = "SMBv1 abilitato da registro (SMB1 = $valSmb1)"
                    }
                    return $risultato
                }
            }

            # Se il driver client/server mrxsmb10 non e' installato o ha Start = 4 (Disabled), SMBv1 non e' attivo
            if (-not (Test-Path -LiteralPath $percorsoMrx)) {
                $risultato.Evidence = @{ MrxSmb10Presente = $false; Fonte = 'ServiceRegistry' }
                $risultato.Status   = 'superato'
                $risultato.Observed = "Driver SMBv1 (mrxsmb10) non installato sul sistema"
                return $risultato
            }
            else {
                $propMrx = Get-ItemProperty -LiteralPath $percorsoMrx -ErrorAction Stop
                $startVal = if ($null -ne $propMrx.PSObject.Properties['Start']) { [int]$propMrx.Start } else { 3 }
                $risultato.Evidence = @{ MrxSmb10Presente = $true; Start = $startVal; Fonte = 'ServiceRegistry' }
                if ($startVal -eq 4) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Driver SMBv1 disabilitato (Start = 4)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "Driver SMBv1 presente e non disabilitato (Start = $startVal)"
                }
                return $risultato
            }
        }
        catch {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Impossibile determinare lo stato di SMBv1"
            $risultato.Error    = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-NetbiosDisabled {
    <#
    .SYNOPSIS
        Verifica che NetBIOS su TCP/IP sia disabilitato (NetbiosOptions = 2) sulle interfacce.
    .PARAMETER Controllo
        L'oggetto controllo dal catalogo.
    .PARAMETER Ambiente
        L'oggetto ambiente (da Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject con proprieta': Status, Observed, Expected, Evidence, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "NetbiosOptions = 2 (Disabilitato) su tutte le interfacce TCP/IP"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoInterfacce = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces'
        if (-not (Test-Path -LiteralPath $percorsoInterfacce)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Chiave di registro NetBT Interfaces non trovata"
            return $risultato
        }

        $sottoChiavi = @(Get-ChildItem -LiteralPath $percorsoInterfacce -ErrorAction Stop)
        if ($sottoChiavi.Count -eq 0) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Nessuna interfaccia TCP/IP trovata in NetBT"
            return $risultato
        }

        $interfacceNonDisabilitate = @()
        $dettaglioInterfacce = @{}

        foreach ($chiave in $sottoChiavi) {
            $nomeIf = $chiave.PSChildName
            $propIf = Get-ItemProperty -LiteralPath $chiave.PSPath -ErrorAction Stop
            $opzione = if ($null -ne $propIf.PSObject.Properties['NetbiosOptions'] -and $null -ne $propIf.NetbiosOptions) {
                [int]$propIf.NetbiosOptions
            }
            else {
                0
            }

            $dettaglioInterfacce[$nomeIf] = $opzione
            if ($opzione -ne 2) {
                $interfacceNonDisabilitate += "$nomeIf (NetbiosOptions=$opzione)"
            }
        }

        $risultato.Evidence = $dettaglioInterfacce

        if ($interfacceNonDisabilitate.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "NetBIOS disabilitato (NetbiosOptions=2) su tutte le $($sottoChiavi.Count) interfacce"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "NetBIOS attivo o predefinito su $($interfacceNonDisabilitate.Count)/$($sottoChiavi.Count) interfacce"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave di registro NetBT"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-LlmnrDisabled {
    <#
    .SYNOPSIS
        Verifica che il protocollo LLMNR (Link-Local Multicast Name Resolution) sia disabilitato (EnableMulticast = 0).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "EnableMulticast = 0 in HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoDns = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'
        if (-not (Test-Path -LiteralPath $percorsoDns)) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Policy DNSClient non configurata (LLMNR attivo per impostazione predefinita)"
            $risultato.Evidence = @{ Path = $percorsoDns; KeyExists = $false }
            return $risultato
        }

        $propDns = Get-ItemProperty -LiteralPath $percorsoDns -ErrorAction Stop
        $valore = if ($null -ne $propDns.PSObject.Properties['EnableMulticast'] -and $null -ne $propDns.EnableMulticast) {
            [int]$propDns.EnableMulticast
        }
        else {
            1
        }

        $risultato.Evidence = @{
            Path            = $percorsoDns
            EnableMulticast = $valore
        }

        if ($valore -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "LLMNR disabilitato (EnableMulticast = 0)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "LLMNR abilitato (EnableMulticast = $valore)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave DNSClient"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-CondivisioniSmbPericolose {
    <#
    .SYNOPSIS
        Verifica che non vi siano condivisioni di rete (SMB Shares) utente non standard esposte
        (escludendo le condivisioni di sistema ADMIN$, C$, IPC$, print$) (HOME-NET-004).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "0 condivisioni SMB utente non protette o non necessarie"
        Evidence = $null
        Error    = $null
    }

    try {
        $shares = @(Get-SmbShare -ErrorAction Stop)
        $nonStandard = @()
        foreach ($s in $shares) {
            $nome = [string]$s.Name
            if ($nome -notmatch '^(ADMIN\$|IPC\$|print\$|[A-Za-z]\$)$') {
                $nonStandard += "$nome ($($s.Path))"
            }
        }

        $risultato.Evidence = @{
            TotaleShares      = $shares.Count
            SharesNonStandard = $nonStandard
        }

        if ($nonStandard.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessuna cartella condivisa non standard esposta in rete"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Cartelle condivise in rete rilevate ($($nonStandard.Count)): $($nonStandard -join '; ')"
        }
    }
    catch {
        # Fallback su registro (HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares)
        try {
            $chiaveShares = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares'
            if (Test-Path -LiteralPath $chiaveShares -ErrorAction SilentlyContinue) {
                $propShares = Get-ItemProperty -LiteralPath $chiaveShares -ErrorAction Stop
                $nonStdReg = @()
                foreach ($p in $propShares.PSObject.Properties) {
                    if ($p.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) { continue }
                    if ($p.Name -notmatch '^(ADMIN\$|IPC\$|print\$|[A-Za-z]\$)$') {
                        $nonStdReg += $p.Name
                    }
                }
                $risultato.Evidence = @{ SharesNonStandard = $nonStdReg; Fonte = 'Registry' }
                if ($nonStdReg.Count -eq 0) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Nessuna cartella condivisa non standard rilevata nel registro LanmanServer"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "Cartelle condivise rilevate ($($nonStdReg.Count)): $($nonStdReg -join ', ')"
                }
                return $risultato
            }
        }
        catch { }

        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per verificare le condivisioni SMB"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-FirmaSmbObbligatoria {
    <#
    .SYNOPSIS
        Verifica che la firma digitale dei pacchetti SMB (RequireSecuritySignature = 1) sia attiva
        per prevenire attacchi Man-in-the-Middle e NTLM Relay sulla rete locale (HOME-NET-005).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "RequireSecuritySignature = 1 su Server e Client SMB"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaveSrv = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'
        $chiaveWrk = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'

        $reqSrv = 0
        $reqWrk = 0

        if (Test-Path -LiteralPath $chiaveSrv) {
            $pSrv = Get-ItemProperty -LiteralPath $chiaveSrv -ErrorAction SilentlyContinue
            if ($null -ne $pSrv -and $null -ne $pSrv.PSObject.Properties['RequireSecuritySignature']) {
                $reqSrv = [int]$pSrv.RequireSecuritySignature
            }
        }
        if (Test-Path -LiteralPath $chiaveWrk) {
            $pWrk = Get-ItemProperty -LiteralPath $chiaveWrk -ErrorAction SilentlyContinue
            if ($null -ne $pWrk -and $null -ne $pWrk.PSObject.Properties['RequireSecuritySignature']) {
                $reqWrk = [int]$pWrk.RequireSecuritySignature
            }
        }

        $risultato.Evidence = @{
            ServerRequireSecuritySignature      = $reqSrv
            WorkstationRequireSecuritySignature = $reqWrk
        }

        if ($reqSrv -eq 1 -and $reqWrk -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Firma SMB obbligatoria attiva su Server e Client (1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Firma SMB non obbligatoria (Server=$reqSrv, Client=$reqWrk)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-WinRmDisabilitatoOSicuro {
    <#
    .SYNOPSIS
        Verifica che il servizio Windows Remote Management (WinRM / PowerShell Remoting) sia fermo
        per non esporre le porte 5985/5986 sulla rete (HOME-NET-006).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Servizio WinRM fermo (Stopped)"
        Evidence = $null
        Error    = $null
    }

    try {
        $srv = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue
        if ($null -eq $srv) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Servizio WinRM non presente"
            return $risultato
        }

        $statoSrv = [string]$srv.Status
        $risultato.Evidence = @{
            ServiceName = 'WinRM'
            Status      = $statoSrv
        }

        if ($statoSrv -ne 'Running') {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Servizio WinRM fermo ($statoSrv)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Servizio WinRM in esecuzione (Running - porta remota 5985 attiva)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-WpadDisabilitato {
    <#
    .SYNOPSIS
        Verifica che il protocollo WPAD (Web Proxy Auto-Discovery) sia disabilitato per prevenire
        attacchi di intercettazione del traffico web su reti locali/Wi-Fi (HOME-NET-007).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "DisableWpad = 1 oppure servizio WinHttpAutoProxySvc disabilitato"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaveWpad = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad'
        $disableWpad = 0
        if (Test-Path -LiteralPath $chiaveWpad) {
            $propWpad = Get-ItemProperty -LiteralPath $chiaveWpad -ErrorAction SilentlyContinue
            if ($null -ne $propWpad -and $null -ne $propWpad.PSObject.Properties['DisableWpad']) {
                $disableWpad = [int]$propWpad.DisableWpad
            }
        }

        $chiaveSvc = 'HKLM:\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc'
        $startSvc = 3
        if (Test-Path -LiteralPath $chiaveSvc) {
            $propSvc = Get-ItemProperty -LiteralPath $chiaveSvc -ErrorAction SilentlyContinue
            if ($null -ne $propSvc -and $null -ne $propSvc.PSObject.Properties['Start']) {
                $startSvc = [int]$propSvc.Start
            }
        }

        $risultato.Evidence = @{
            DisableWpad            = $disableWpad
            WinHttpAutoProxyStart  = $startSvc
        }

        if ($disableWpad -eq 1 -or $startSvc -eq 4) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "WPAD disabilitato (DisableWpad=$disableWpad, ServiceStart=$startSvc)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "WPAD attivo (DisableWpad=$disableWpad, ServiceStart=$startSvc)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-LegacyTlsAndDoh {
    <#
    .SYNOPSIS
        Verifica che i protocolli crittografici obsoleti TLS 1.0 e TLS 1.1 non siano abilitati in SCHANNEL
        e controlla la configurazione di DNS over HTTPS (DoH) (HOME-NET-008).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "TLS 1.0/1.1 non abilitati (Enabled != 1) e supporto DNS over HTTPS (DoH) presente"
        Evidence = $null
        Error    = $null
    }

    try {
        $baseSchannel = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols'
        $sottoChiaviTls = @(
            'TLS 1.0\Client',
            'TLS 1.0\Server',
            'TLS 1.1\Client',
            'TLS 1.1\Server'
        )

        $tlsLegacyAttivi = @()
        foreach ($sub in $sottoChiaviTls) {
            $percorsoTls = Join-Path $baseSchannel $sub
            if (Test-Path -LiteralPath $percorsoTls -ErrorAction SilentlyContinue) {
                $propTls = Get-ItemProperty -LiteralPath $percorsoTls -ErrorAction SilentlyContinue
                if ($null -ne $propTls -and $null -ne $propTls.PSObject.Properties['Enabled'] -and $null -ne $propTls.Enabled) {
                    $valEn = [int]$propTls.Enabled
                    if ($valEn -eq 1) {
                        $tlsLegacyAttivi += "$sub (Enabled=1)"
                    }
                }
            }
        }

        # Verifica configurazione DNS over HTTPS (DoH)
        $chiaveDnsCache = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'
        $autoDoh = 0
        if (Test-Path -LiteralPath $chiaveDnsCache -ErrorAction SilentlyContinue) {
            $propDns = Get-ItemProperty -LiteralPath $chiaveDnsCache -ErrorAction SilentlyContinue
            if ($null -ne $propDns -and $null -ne $propDns.PSObject.Properties['EnableAutoDoh'] -and $null -ne $propDns.EnableAutoDoh) {
                $autoDoh = [int]$propDns.EnableAutoDoh
            }
        }

        $dohServerCount = 0
        try {
            if (Get-Command -Name 'Get-DnsClientDohServerAddress' -ErrorAction SilentlyContinue) {
                $dohServers = @(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue)
                $dohServerCount = $dohServers.Count
            }
        }
        catch { }

        $dohConfigurato = ($autoDoh -ge 1) -or ($dohServerCount -gt 0)

        $risultato.Evidence = @{
            LegacyTlsEnabled = $tlsLegacyAttivi
            EnableAutoDoh    = $autoDoh
            DohServersCount  = $dohServerCount
            DohConfigured    = $dohConfigurato
        }

        if ($tlsLegacyAttivi.Count -gt 0) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Protocolli crittografici obsoleti abilitati: $($tlsLegacyAttivi -join ', ')"
        }
        elseif (-not $dohConfigurato) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "TLS 1.0/1.1 disabilitati, ma DNS over HTTPS (DoH) non configurato (EnableAutoDoh=$autoDoh)"
        }
        else {
            $risultato.Status   = 'superato'
            $risultato.Observed = "TLS 1.0/1.1 disabilitati e supporto DNS over HTTPS (DoH) attivo (EnableAutoDoh=$autoDoh, ServerDoH=$dohServerCount)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

# =============================================================================
# MODULO: src\core\Checks\SystemSecurity.ps1
# =============================================================================
<#
.SYNOPSIS
    Controlli di sicurezza di sistema: Windows Update, BitLocker, Telemetria,
    Secure Boot, Protezione LSA, PowerShell Script Block Logging e Impostazioni Windows.

.DESCRIPTION
    Contiene i controlli per:
    - HOME-UPD-001: Aggiornamenti automatici abilitati (Test-WindowsUpdateEnabled)
    - HOME-UPD-002: Server Windows Update autentico (Test-WindowsUpdateAuthenticServer)
    - HOME-ENC-001: BitLocker attivo sul disco di sistema (Test-BitLockerSystemDrive)
    - HOME-PRV-001: Telemetria impostata al livello minimo (Test-TelemetryMinimum)
    - HOME-SEC-001: Avvio protetto Secure Boot attivo (Test-SecureBoot)
    - HOME-SEC-002: Protezione LSA abilitata RunAsPPL (Test-LsaProtection)
    - HOME-SEC-003: PowerShell Script Block Logging abilitato (Test-PsScriptBlockLogging)
    - HOME-SYS-001: Visibilita' estensioni file conosciuti in Esplora file (Test-FileExtensionsVisible)
    - HOME-SYS-002: AutoRun / AutoPlay disabilitato per unita' rimovibili (Test-AutorunDisabled)
    - HOME-SYS-003: Filtro Microsoft Defender SmartScreen attivo (Test-SmartScreenEnabled)
    - HOME-SYS-004: Isolamento core / Integrita' della memoria HVCI attivo (Test-MemoryIntegrityEnabled)
    - HOME-SYS-005: Accesso anonimo SAM bloccato (Test-AnonymousSamRestricted)
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-WindowsUpdateEnabled {
    <#
    .SYNOPSIS
        Verifica che il servizio Windows Update non sia disabilitato e che le policy
        non disattivino gli aggiornamenti automatici.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Servizio wuauserv abilitato (Start != 4) e policy NoAutoUpdate != 1"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoServizio = 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv'
        $percorsoPolicyAu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

        if (-not (Test-Path -LiteralPath $percorsoServizio)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Chiave del servizio wuauserv non trovata"
            return $risultato
        }

        $propSvc = Get-ItemProperty -LiteralPath $percorsoServizio -ErrorAction Stop
        $startVal = if ($null -ne $propSvc.PSObject.Properties['Start']) { [int]$propSvc.Start } else { 3 }

        $noAutoUpdate = 0
        if (Test-Path -LiteralPath $percorsoPolicyAu) {
            $propAu = Get-ItemProperty -LiteralPath $percorsoPolicyAu -ErrorAction SilentlyContinue
            if ($null -ne $propAu -and $null -ne $propAu.PSObject.Properties['NoAutoUpdate'] -and $null -ne $propAu.NoAutoUpdate) {
                $noAutoUpdate = [int]$propAu.NoAutoUpdate
            }
        }

        $risultato.Evidence = @{
            WuauservStart = $startVal
            NoAutoUpdate  = $noAutoUpdate
        }

        if ($startVal -eq 4) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Il servizio Windows Update (wuauserv) e' disabilitato (Start = 4)"
        }
        elseif ($noAutoUpdate -eq 1) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Gli aggiornamenti automatici sono disabilitati tramite policy (NoAutoUpdate = 1)"
        }
        else {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Windows Update abilitato (wuauserv Start = $startVal, NoAutoUpdate = $noAutoUpdate)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla configurazione di Windows Update"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-BitLockerSystemDrive {
    <#
    .SYNOPSIS
        Verifica che BitLocker sia attivo sulla partizione di sistema.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Crittografia BitLocker attiva sul disco di sistema"
        Evidence = $null
        Error    = $null
    }

    $discoSistema = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }

    try {
        if (Get-Command -Name 'Get-BitLockerVolume' -ErrorAction SilentlyContinue) {
            try {
                $vol = Get-BitLockerVolume -MountPoint $discoSistema -ErrorAction Stop
                $statoProt = [string]$vol.ProtectionStatus
                $statoVol  = [string]$vol.VolumeStatus

                $risultato.Evidence = @{
                    MountPoint       = $discoSistema
                    ProtectionStatus = $statoProt
                    VolumeStatus     = $statoVol
                    Fonte            = 'Get-BitLockerVolume'
                }

                if ($statoProt -eq 'On' -or $statoProt -eq '1') {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "BitLocker attivo su $discoSistema (ProtectionStatus = $statoProt)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "BitLocker non attivo su $discoSistema (ProtectionStatus = $statoProt, VolumeStatus = $statoVol)"
                }
                return $risultato
            }
            catch { }
        }

        $percorsoBl = 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLockerStatus'
        if (Test-Path -LiteralPath $percorsoBl) {
            $propBl = Get-ItemProperty -LiteralPath $percorsoBl -ErrorAction Stop
            if ($null -ne $propBl.PSObject.Properties['BootStatus'] -and $null -ne $propBl.BootStatus) {
                $bootStatus = [int]$propBl.BootStatus
                $risultato.Evidence = @{
                    MountPoint = $discoSistema
                    BootStatus = $bootStatus
                    Fonte      = 'BitLockerStatusRegistry'
                }
                if ($bootStatus -ge 1) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Crittografia disco di avvio attiva (BootStatus = $bootStatus)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "Crittografia BitLocker non attiva sul disco di sistema (BootStatus = 0)"
                }
                return $risultato
            }
        }

        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Stato BitLocker non determinabile (eseguire come amministratore)"
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-TelemetryMinimum {
    <#
    .SYNOPSIS
        Verifica che il livello di telemetria di Windows (AllowTelemetry) sia impostato al minimo (<= 1).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "AllowTelemetry <= 1 (Dati diagnostici obbligatori / minimo)"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoPolicy  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        $percorsoDefault = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'

        $valoreTrovato = $null
        $chiaveUsata   = $null

        if (Test-Path -LiteralPath $percorsoPolicy) {
            $propPol = Get-ItemProperty -LiteralPath $percorsoPolicy -ErrorAction SilentlyContinue
            if ($null -ne $propPol -and $null -ne $propPol.PSObject.Properties['AllowTelemetry'] -and $null -ne $propPol.AllowTelemetry) {
                $valoreTrovato = [int]$propPol.AllowTelemetry
                $chiaveUsata   = $percorsoPolicy
            }
        }

        if ($null -eq $valoreTrovato -and (Test-Path -LiteralPath $percorsoDefault)) {
            $propDef = Get-ItemProperty -LiteralPath $percorsoDefault -ErrorAction SilentlyContinue
            if ($null -ne $propDef -and $null -ne $propDef.PSObject.Properties['AllowTelemetry'] -and $null -ne $propDef.AllowTelemetry) {
                $valoreTrovato = [int]$propDef.AllowTelemetry
                $chiaveUsata   = $percorsoDefault
            }
        }

        if ($null -eq $valoreTrovato) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "AllowTelemetry non limitato (livello predefinito completo attivo)"
            $risultato.Evidence = @{ Configured = $false }
            return $risultato
        }

        $risultato.Evidence = @{
            Path           = $chiaveUsata
            AllowTelemetry = $valoreTrovato
        }

        if ($valoreTrovato -le 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "AllowTelemetry = $valoreTrovato (livello minimo)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "AllowTelemetry = $valoreTrovato (superiore al livello minimo 1)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave di registro DataCollection"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-SecureBoot {
    <#
    .SYNOPSIS
        Verifica che l'avvio protetto UEFI (Secure Boot) sia abilitato.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "UEFISecureBootEnabled = 1 (Secure Boot attivo)"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoSb = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
        if (-not (Test-Path -LiteralPath $percorsoSb)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Stato Secure Boot non presente (possibile sistema BIOS legacy)"
            $risultato.Evidence = @{ KeyExists = $false }
            return $risultato
        }

        $propSb = Get-ItemProperty -LiteralPath $percorsoSb -ErrorAction Stop
        if ($null -eq $propSb.PSObject.Properties['UEFISecureBootEnabled']) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Valore UEFISecureBootEnabled non trovato"
            return $risultato
        }

        $sbVal = [int]$propSb.UEFISecureBootEnabled
        $risultato.Evidence = @{
            Path                  = $percorsoSb
            UEFISecureBootEnabled = $sbVal
        }

        if ($sbVal -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Secure Boot attivo (UEFISecureBootEnabled = 1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Secure Boot disattivato (UEFISecureBootEnabled = $sbVal)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave SecureBoot"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-LsaProtection {
    <#
    .SYNOPSIS
        Verifica che la protezione del processo LSA (RunAsPPL) sia abilitata.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "RunAsPPL >= 1 oppure RunAsPPLBoot >= 1 in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoLsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        if (-not (Test-Path -LiteralPath $percorsoLsa)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Chiave di registro LSA non trovata"
            return $risultato
        }

        $propLsa = Get-ItemProperty -LiteralPath $percorsoLsa -ErrorAction Stop
        $runAsPpl = if ($null -ne $propLsa.PSObject.Properties['RunAsPPL'] -and $null -ne $propLsa.RunAsPPL) {
            [int]$propLsa.RunAsPPL
        }
        else {
            0
        }

        $runAsPplBoot = if ($null -ne $propLsa.PSObject.Properties['RunAsPPLBoot'] -and $null -ne $propLsa.RunAsPPLBoot) {
            [int]$propLsa.RunAsPPLBoot
        }
        else {
            0
        }

        $risultato.Evidence = @{
            Path         = $percorsoLsa
            RunAsPPL     = $runAsPpl
            RunAsPPLBoot = $runAsPplBoot
        }

        if ($runAsPpl -ge 1 -or $runAsPplBoot -ge 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Protezione LSA attiva (RunAsPPL = $runAsPpl, RunAsPPLBoot = $runAsPplBoot)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Protezione LSA non attiva (RunAsPPL = 0)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave di registro LSA"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-PsScriptBlockLogging {
    <#
    .SYNOPSIS
        Verifica che il logging degli script block di PowerShell (EnableScriptBlockLogging) sia abilitato.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "EnableScriptBlockLogging = 1 in HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoSbl = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        if (-not (Test-Path -LiteralPath $percorsoSbl)) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Policy ScriptBlockLogging non configurata (logging disabilitato per impostazione predefinita)"
            $risultato.Evidence = @{ Path = $percorsoSbl; KeyExists = $false }
            return $risultato
        }

        $propSbl = Get-ItemProperty -LiteralPath $percorsoSbl -ErrorAction Stop
        $valore = if ($null -ne $propSbl.PSObject.Properties['EnableScriptBlockLogging'] -and $null -ne $propSbl.EnableScriptBlockLogging) {
            [int]$propSbl.EnableScriptBlockLogging
        }
        else {
            0
        }

        $risultato.Evidence = @{
            Path                     = $percorsoSbl
            EnableScriptBlockLogging = $valore
        }

        if ($valore -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Script Block Logging abilitato (EnableScriptBlockLogging = 1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Script Block Logging disabilitato (EnableScriptBlockLogging = $valore)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave di registro ScriptBlockLogging"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-FileExtensionsVisible {
    <#
    .SYNOPSIS
        Verifica che le estensioni dei file conosciuti siano visibili in Esplora file (HideFileExt = 0).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "HideFileExt = 0 (Estensioni dei file sempre visibili)"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoExp = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        if (-not (Test-Path -LiteralPath $percorsoExp)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Chiave Explorer Advanced non trovata"
            return $risultato
        }

        $propExp = Get-ItemProperty -LiteralPath $percorsoExp -ErrorAction Stop
        $hideExt = if ($null -ne $propExp.PSObject.Properties['HideFileExt'] -and $null -ne $propExp.HideFileExt) {
            [int]$propExp.HideFileExt
        }
        else {
            1
        }

        $risultato.Evidence = @{
            Path        = $percorsoExp
            HideFileExt = $hideExt
        }

        if ($hideExt -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Estensioni dei file visibili (HideFileExt = 0)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Estensioni dei file nascoste (HideFileExt = $hideExt, rischio file camuffati)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-AutorunDisabled {
    <#
    .SYNOPSIS
        Verifica che AutoRun/AutoPlay sia disabilitato sulle unita' rimovibili (NoDriveTypeAutoRun >= 145 o DisableAutoplay = 1).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "NoDriveTypeAutoRun = 255 oppure AutoPlay disabilitato (DisableAutoplay = 1)"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoPolLM  = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        $percorsoAutoCU = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'

        $noDriveType = 0
        if (Test-Path -LiteralPath $percorsoPolLM) {
            $propLM = Get-ItemProperty -LiteralPath $percorsoPolLM -ErrorAction SilentlyContinue
            if ($null -ne $propLM -and $null -ne $propLM.PSObject.Properties['NoDriveTypeAutoRun'] -and $null -ne $propLM.NoDriveTypeAutoRun) {
                $noDriveType = [int]$propLM.NoDriveTypeAutoRun
            }
        }

        $disableAutoplay = 0
        if (Test-Path -LiteralPath $percorsoAutoCU) {
            $propCU = Get-ItemProperty -LiteralPath $percorsoAutoCU -ErrorAction SilentlyContinue
            if ($null -ne $propCU -and $null -ne $propCU.PSObject.Properties['DisableAutoplay'] -and $null -ne $propCU.DisableAutoplay) {
                $disableAutoplay = [int]$propCU.DisableAutoplay
            }
        }

        $risultato.Evidence = @{
            NoDriveTypeAutoRun = $noDriveType
            DisableAutoplay    = $disableAutoplay
        }

        if ($noDriveType -ge 145 -or $disableAutoplay -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "AutoRun/AutoPlay disabilitato (NoDriveTypeAutoRun=$noDriveType, DisableAutoplay=$disableAutoplay)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "AutoPlay attivo per unita' rimovibili (DisableAutoplay=0, NoDriveTypeAutoRun=$noDriveType)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-SmartScreenEnabled {
    <#
    .SYNOPSIS
        Verifica che il filtro Microsoft Defender SmartScreen per app e file scaricati sia abilitato.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "SmartScreen abilitato (SmartScreenEnabled != 'Off' e EnableWebContentEvaluation = 1)"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoExp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer'
        $percorsoApp = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost'

        $ssExplorer = 'Warn'
        if (Test-Path -LiteralPath $percorsoExp) {
            $propExp = Get-ItemProperty -LiteralPath $percorsoExp -ErrorAction SilentlyContinue
            if ($null -ne $propExp -and $null -ne $propExp.PSObject.Properties['SmartScreenEnabled'] -and $null -ne $propExp.SmartScreenEnabled) {
                $ssExplorer = [string]$propExp.SmartScreenEnabled
            }
        }

        $webEval = 1
        if (Test-Path -LiteralPath $percorsoApp) {
            $propApp = Get-ItemProperty -LiteralPath $percorsoApp -ErrorAction SilentlyContinue
            if ($null -ne $propApp -and $null -ne $propApp.PSObject.Properties['EnableWebContentEvaluation'] -and $null -ne $propApp.EnableWebContentEvaluation) {
                $webEval = [int]$propApp.EnableWebContentEvaluation
            }
        }

        $risultato.Evidence = @{
            SmartScreenEnabled         = $ssExplorer
            EnableWebContentEvaluation = $webEval
        }

        if ($ssExplorer -ne 'Off' -and $webEval -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "SmartScreen attivo (SmartScreenEnabled=$ssExplorer, WebEvaluation=$webEval)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "SmartScreen disattivato (SmartScreenEnabled=$ssExplorer, WebEvaluation=$webEval)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-MemoryIntegrityEnabled {
    <#
    .SYNOPSIS
        Verifica che l'Isolamento core / Integrita' della memoria (HVCI) sia realmente attivo a runtime
        tramite Win32_DeviceGuard (VirtualizationBasedSecurityStatus = 2 e SecurityServicesRunning contiene 2),
        mantenendo la chiave di registro come evidenza diagnostica e fallback (HOME-SYS-004).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "VirtualizationBasedSecurityStatus = 2 e SecurityServicesRunning contiene 2 (HVCI attivo a runtime)"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoHvci = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
        $esisteChiave = (Test-Path -LiteralPath $percorsoHvci -ErrorAction SilentlyContinue)
        $valoreReg = 0
        if ($esisteChiave) {
            $propHvci = Get-ItemProperty -LiteralPath $percorsoHvci -ErrorAction SilentlyContinue
            if ($null -ne $propHvci -and $null -ne $propHvci.PSObject.Properties['Enabled'] -and $null -ne $propHvci.Enabled) {
                $valoreReg = [int]$propHvci.Enabled
            }
        }

        try {
            $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
            if ($null -ne $dg) {
                $vbsStatus = if ($null -ne $dg.PSObject.Properties['VirtualizationBasedSecurityStatus'] -and $null -ne $dg.VirtualizationBasedSecurityStatus) {
                    [int]$dg.VirtualizationBasedSecurityStatus
                }
                else {
                    0
                }
                $serviziRunning = @()
                if ($null -ne $dg.PSObject.Properties['SecurityServicesRunning'] -and $null -ne $dg.SecurityServicesRunning) {
                    $serviziRunning = @($dg.SecurityServicesRunning | ForEach-Object { [int]$_ })
                }

                $risultato.Evidence = @{
                    Fonte                             = 'Win32_DeviceGuard'
                    VirtualizationBasedSecurityStatus = $vbsStatus
                    SecurityServicesRunning           = $serviziRunning
                    RegistryPath                      = $percorsoHvci
                    RegistryEnabled                   = $valoreReg
                }

                if ($vbsStatus -eq 2 -and ($serviziRunning -contains 2)) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Integrita' della memoria (HVCI) attiva a runtime (VBS=2, SecurityServicesRunning contiene 2)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "HVCI non in esecuzione a runtime (VBSStatus=$vbsStatus, ServicesRunning=[$($serviziRunning -join ',')], RegEnabled=$valoreReg)"
                }
                return $risultato
            }
        }
        catch {
            # Fallback diagnostico sul registro se il namespace CIM DeviceGuard non e' accessibile
        }

        if (-not $esisteChiave) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Integrita' della memoria (HVCI) non configurata"
            $risultato.Evidence = @{ Fonte = 'RegistryFallback'; KeyExists = $false }
            return $risultato
        }

        $risultato.Evidence = @{
            Fonte           = 'RegistryFallback'
            Path            = $percorsoHvci
            RegistryEnabled = $valoreReg
        }

        if ($valoreReg -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Isolamento core / Integrita' della memoria abilitata da registro (Enabled = 1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Isolamento core / Integrita' della memoria disattivata (Enabled = $valoreReg)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-AnonymousSamRestricted {
    <#
    .SYNOPSIS
        Verifica che l'enumerazione anonima degli account SAM (RestrictAnonymousSAM = 1) sia bloccata.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "RestrictAnonymousSAM = 1 in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoLsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        if (-not (Test-Path -LiteralPath $percorsoLsa)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Chiave LSA non trovata"
            return $risultato
        }

        $propLsa = Get-ItemProperty -LiteralPath $percorsoLsa -ErrorAction Stop
        $valore = if ($null -ne $propLsa.PSObject.Properties['RestrictAnonymousSAM'] -and $null -ne $propLsa.RestrictAnonymousSAM) {
            [int]$propLsa.RestrictAnonymousSAM
        }
        else {
            0
        }

        $risultato.Evidence = @{
            Path                 = $percorsoLsa
            RestrictAnonymousSAM = $valore
        }

        if ($valore -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Enumerazione anonima SAM bloccata (RestrictAnonymousSAM = 1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Enumerazione anonima SAM consentita (RestrictAnonymousSAM = $valore)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-WindowsUpdateAuthenticServer {
    <#
    .SYNOPSIS
        Verifica che Windows Update non sia dirottato verso un server WSUS esterno non sicuro (WUServer).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Nessun server WSUS non autorizzato configurato in WindowsUpdate"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoWu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        if (-not (Test-Path -LiteralPath $percorsoWu)) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Connessione diretta ai server ufficiali Microsoft Windows Update"
            $risultato.Evidence = @{ CustomWUServer = $null }
            return $risultato
        }

        $propWu = Get-ItemProperty -LiteralPath $percorsoWu -ErrorAction SilentlyContinue
        $wuServer = if ($null -ne $propWu -and $null -ne $propWu.PSObject.Properties['WUServer']) {
            [string]$propWu.WUServer
        }
        else {
            ''
        }

        $risultato.Evidence = @{
            Path     = $percorsoWu
            WUServer = $wuServer
        }

        if ([string]::IsNullOrWhiteSpace($wuServer)) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Nessun server WSUS personalizzato impostato"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Windows Update rediretto verso server esterno: $wuServer"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-WDigestDisabilitato {
    <#
    .SYNOPSIS
        Verifica che la memorizzazione in chiaro delle password in memoria tramite WDigest
        (UseLogonCredential) sia disabilitata (HOME-SYS-006).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "UseLogonCredential = 0 (o assente) in WDigest"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoWdigest = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'
        $valore = 0

        if (Test-Path -LiteralPath $percorsoWdigest) {
            $propW = Get-ItemProperty -LiteralPath $percorsoWdigest -ErrorAction SilentlyContinue
            if ($null -ne $propW -and $null -ne $propW.PSObject.Properties['UseLogonCredential'] -and $null -ne $propW.UseLogonCredential) {
                $valore = [int]$propW.UseLogonCredential
            }
        }

        $risultato.Evidence = @{
            Path               = $percorsoWdigest
            UseLogonCredential = $valore
        }

        if ($valore -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Credenziali WDigest in chiaro in memoria disabilitate (0)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "PERICOLO: WDigest UseLogonCredential = $valore (password memorizzate in chiaro in LSASS)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-AssistenzaRemotaDisabilitata {
    <#
    .SYNOPSIS
        Verifica che l'Assistenza remota di Windows (fAllowToGetHelp = 0) sia disabilitata (HOME-SYS-007).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "fAllowToGetHelp = 0 in HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaveRa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'
        $valore = 0
        if (Test-Path -LiteralPath $chiaveRa) {
            $propRa = Get-ItemProperty -LiteralPath $chiaveRa -ErrorAction SilentlyContinue
            if ($null -ne $propRa -and $null -ne $propRa.PSObject.Properties['fAllowToGetHelp'] -and $null -ne $propRa.fAllowToGetHelp) {
                $valore = [int]$propRa.fAllowToGetHelp
            }
        }

        $risultato.Evidence = @{
            Path            = $chiaveRa
            fAllowToGetHelp = $valore
        }

        if ($valore -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Assistenza remota disabilitata (fAllowToGetHelp = 0)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Assistenza remota abilitata (fAllowToGetHelp = $valore)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-RegistroRemotoDisabilitato {
    <#
    .SYNOPSIS
        Verifica che il servizio Registro di sistema remoto (RemoteRegistry) sia disabilitato e fermo (HOME-SYS-008).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Servizio RemoteRegistry fermo e disabilitato (Start = 4)"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaveRr = 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry'
        if (-not (Test-Path -LiteralPath $chiaveRr)) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Servizio RemoteRegistry non installato"
            return $risultato
        }

        $propRr = Get-ItemProperty -LiteralPath $chiaveRr -ErrorAction Stop
        $startVal = if ($null -ne $propRr.PSObject.Properties['Start']) { [int]$propRr.Start } else { 4 }

        $srv = Get-Service -Name 'RemoteRegistry' -ErrorAction SilentlyContinue
        $statoSrv = if ($null -ne $srv) { [string]$srv.Status } else { 'Stopped' }

        $risultato.Evidence = @{
            Start  = $startVal
            Status = $statoSrv
        }

        if ($startVal -eq 4 -and $statoSrv -ne 'Running') {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Servizio RemoteRegistry disabilitato (Start=4) e fermo"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Servizio RemoteRegistry non disabilitato (Start=$startVal, Status=$statoSrv)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-UacSecureElevation {
    <#
    .SYNOPSIS
        Verifica che UAC richieda la conferma per l'elevazione (ConsentPromptBehaviorAdmin in 1, 2, 5)
        e che il prompt venga mostrato sul Desktop sicuro (PromptOnSecureDesktop = 1) (HOME-UAC-002).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "ConsentPromptBehaviorAdmin in (1, 2, 5) e PromptOnSecureDesktop = 1"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaveUac = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if (-not (Test-Path -LiteralPath $chiaveUac)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Chiave di registro UAC Policies\System non trovata"
            return $risultato
        }

        $propUac = Get-ItemProperty -LiteralPath $chiaveUac -ErrorAction Stop
        $consent = if ($null -ne $propUac.PSObject.Properties['ConsentPromptBehaviorAdmin'] -and $null -ne $propUac.ConsentPromptBehaviorAdmin) {
            [int]$propUac.ConsentPromptBehaviorAdmin
        }
        else {
            -1
        }
        $secureDesk = if ($null -ne $propUac.PSObject.Properties['PromptOnSecureDesktop'] -and $null -ne $propUac.PromptOnSecureDesktop) {
            [int]$propUac.PromptOnSecureDesktop
        }
        else {
            0
        }

        $risultato.Evidence = @{
            Path                       = $chiaveUac
            ConsentPromptBehaviorAdmin = $consent
            PromptOnSecureDesktop      = $secureDesk
        }

        $consentSicuro = ($consent -in @(1, 2, 5))
        $desktopSicuro = ($secureDesk -eq 1)

        if ($consentSicuro -and $desktopSicuro) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "UAC richiede conferma su Desktop sicuro (ConsentPromptBehaviorAdmin=$consent, PromptOnSecureDesktop=1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Configurazione elevazione UAC debole (ConsentPromptBehaviorAdmin=$consent, PromptOnSecureDesktop=$secureDesk)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave UAC Policies\System"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-SmartAppControl {
    <#
    .SYNOPSIS
        Verifica lo stato di Smart App Control (SAC) in HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy
        (VerifiedAndReputablePolicyState: 1 = Enforced, 2 = Evaluation, 0 = Off) (HOME-SEC-007).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "VerifiedAndReputablePolicyState = 1 (Enforced) oppure 2 (Evaluation)"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaveSac = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
        $statoSac = 0
        if (Test-Path -LiteralPath $chiaveSac) {
            $propSac = Get-ItemProperty -LiteralPath $chiaveSac -ErrorAction SilentlyContinue
            if ($null -ne $propSac -and $null -ne $propSac.PSObject.Properties['VerifiedAndReputablePolicyState'] -and $null -ne $propSac.VerifiedAndReputablePolicyState) {
                $statoSac = [int]$propSac.VerifiedAndReputablePolicyState
            }
        }

        $risultato.Evidence = @{
            Path                            = $chiaveSac
            VerifiedAndReputablePolicyState = $statoSac
        }

        if ($statoSac -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Smart App Control attivo in modalita' Enforced (1)"
        }
        elseif ($statoSac -eq 2) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Smart App Control attivo in modalita' Evaluation (2 - apprendimento attivo)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Smart App Control disattivato (VerifiedAndReputablePolicyState = $statoSac)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-Tpm20Ready {
    <#
    .SYNOPSIS
        Verifica tramite Get-Tpm (o fallback CIM Win32_Tpm) che il chip hardware TPM 2.0
        sia presente e pronto (TpmPresent = True e TpmReady = True) (HOME-SEC-008).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "TpmPresent = True e TpmReady = True"
        Evidence = $null
        Error    = $null
    }

    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($null -eq $tpm -or $null -eq $tpm.PSObject.Properties['TpmPresent']) {
            throw "Oggetto TPM non restituito o richiede privilegi elevati"
        }
        $present = [bool]$tpm.TpmPresent
        $ready   = [bool]$tpm.TpmReady

        $risultato.Evidence = @{
            Fonte      = 'Get-Tpm'
            TpmPresent = $present
            TpmReady   = $ready
        }

        if ($present -and $ready) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Modulo hardware TPM 2.0 presente e pronto (TpmPresent=True, TpmReady=True)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "TPM non pronto o assente (TpmPresent=$present, TpmReady=$ready)"
        }
    }
    catch {
        try {
            $cimTpm = Get-CimInstance -ClassName Win32_Tpm -Namespace 'root\cimv2\Security\MicrosoftTpm' -ErrorAction Stop
            if ($null -ne $cimTpm -and $null -ne $cimTpm.PSObject.Properties['IsEnabled_InitialValue']) {
                $enVal  = [bool]$cimTpm.IsEnabled_InitialValue
                $actVal = [bool]$cimTpm.IsActivated_InitialValue
                $risultato.Evidence = @{
                    Fonte                    = 'Win32_Tpm'
                    IsEnabled_InitialValue   = $enVal
                    IsActivated_InitialValue = $actVal
                }
                if ($enVal -and $actVal) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Modulo hardware TPM 2.0 abilitato e attivo (Win32_Tpm)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "TPM non attivo (Enabled=$enVal, Activated=$actVal)"
                }
                return $risultato
            }
        }
        catch { }

        # Fallback su Registro (HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI ed Enum - leggibile anche senza Admin)
        try {
            $chiaveTpmWmi  = 'HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI'
            $chiaveTpmEnum = 'HKLM:\SYSTEM\CurrentControlSet\Services\TPM\Enum'
            if (Test-Path -LiteralPath $chiaveTpmWmi -ErrorAction SilentlyContinue) {
                $propWmi  = Get-ItemProperty -LiteralPath $chiaveTpmWmi -ErrorAction SilentlyContinue
                $propEnum = if (Test-Path -LiteralPath $chiaveTpmEnum -ErrorAction SilentlyContinue) { Get-ItemProperty -LiteralPath $chiaveTpmEnum -ErrorAction SilentlyContinue } else { $null }

                $enumCount = if ($null -ne $propEnum -and $null -ne $propEnum.PSObject.Properties['Count']) { [int]$propEnum.Count } else { 0 }
                $readyStor = if ($null -ne $propWmi -and $null -ne $propWmi.PSObject.Properties['TaskReadyForStorage']) { [int]$propWmi.TaskReadyForStorage } else { 0 }
                $fwVer     = if ($null -ne $propWmi -and $null -ne $propWmi.PSObject.Properties['TaskFirmwareVersion']) { [string]$propWmi.TaskFirmwareVersion } else { '' }

                if ($enumCount -ge 1 -or $readyStor -eq 1 -or (-not [string]::IsNullOrWhiteSpace($fwVer))) {
                    $risultato.Evidence = @{
                        Fonte               = 'TPMServiceRegistry'
                        DeviceCount         = $enumCount
                        TaskReadyForStorage = $readyStor
                        FirmwareVersion     = $fwVer
                    }
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Modulo hardware TPM 2.0 presente e pronto (Firmware $fwVer)"
                    return $risultato
                }
            }
        }
        catch { }

        if ($_.Exception.Message -match 'Administrator|amministratore|Access is denied|Accesso negato|privilegi|privilege|CIM resource') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi di amministratore richiesti per interrogare lo stato del chip TPM 2.0"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Impossibile interrogare lo stato TPM ($($_.Exception.Message))"
            $risultato.Error    = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-WshDisabled {
    <#
    .SYNOPSIS
        Verifica che Windows Script Host (WSH: wscript.exe / cscript.exe per .vbs/.js)
        sia disabilitato (Enabled = 0) (HOME-SYS-009).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Enabled = 0 in HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaveWshLM = 'HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings'
        $chiaveWshCU = 'HKCU:\SOFTWARE\Microsoft\Windows Script Host\Settings'

        $valLM = 1
        if (Test-Path -LiteralPath $chiaveWshLM) {
            $propLM = Get-ItemProperty -LiteralPath $chiaveWshLM -ErrorAction SilentlyContinue
            if ($null -ne $propLM -and $null -ne $propLM.PSObject.Properties['Enabled'] -and $null -ne $propLM.Enabled) {
                $valLM = [int]$propLM.Enabled
            }
        }

        $valCU = 1
        if (Test-Path -LiteralPath $chiaveWshCU) {
            $propCU = Get-ItemProperty -LiteralPath $chiaveWshCU -ErrorAction SilentlyContinue
            if ($null -ne $propCU -and $null -ne $propCU.PSObject.Properties['Enabled'] -and $null -ne $propCU.Enabled) {
                $valCU = [int]$propCU.Enabled
            }
        }

        $risultato.Evidence = @{
            PathHKLM    = $chiaveWshLM
            EnabledHKLM = $valLM
            EnabledHKCU = $valCU
        }

        if ($valLM -eq 0 -or $valCU -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Windows Script Host (WSH) disabilitato (HKLM=$valLM, HKCU=$valCU)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Windows Script Host (WSH) attivo per script .vbs/.js (Enabled = 1)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-PowerShellExecutionPolicySecure {
    <#
    .SYNOPSIS
        Verifica tramite Get-ExecutionPolicy -List che gli scope persistenti (MachinePolicy, UserPolicy,
        LocalMachine, CurrentUser) non siano impostati su Unrestricted o Bypass (HOME-SEC-009).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Nessuno scope persistente impostato su Unrestricted o Bypass"
        Evidence = $null
        Error    = $null
    }

    try {
        $listaPol = @(Get-ExecutionPolicy -List -ErrorAction Stop)
        $scopeDaControllare = @('MachinePolicy', 'UserPolicy', 'LocalMachine', 'CurrentUser')
        $scopeInsicuri = @()
        $mappaPol = @{}

        foreach ($voce in $listaPol) {
            $nomeScope = [string]$voce.Scope
            $valPol    = [string]$voce.ExecutionPolicy
            $mappaPol[$nomeScope] = $valPol

            if ($scopeDaControllare -contains $nomeScope) {
                if ($valPol -in @('Unrestricted', 'Bypass')) {
                    $scopeInsicuri += "$nomeScope=$valPol"
                }
            }
        }

        $risultato.Evidence = $mappaPol

        if ($scopeInsicuri.Count -eq 0) {
            $polLM = if ($mappaPol.ContainsKey('LocalMachine')) { $mappaPol['LocalMachine'] } else { 'Undefined' }
            $polCU = if ($mappaPol.ContainsKey('CurrentUser')) { $mappaPol['CurrentUser'] } else { 'Undefined' }
            $risultato.Status   = 'superato'
            $risultato.Observed = "ExecutionPolicy sicura (LocalMachine=$polLM, CurrentUser=$polCU)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "ExecutionPolicy troppo permissiva rilevata: $($scopeInsicuri -join ', ')"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-AdministratorProtection {
    <#
    .SYNOPSIS
        Verifica che la nuova modalita' Administrator Protection (elevazione just-in-time di Windows 11 24H2/25H2/26H2)
        sia abilitata (TypeOfAdminApprovalMode = 2) (HOME-UAC-004).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "TypeOfAdminApprovalMode = 2 (Administrator Protection just-in-time attiva)"
        Evidence = $null
        Error    = $null
    }

    try {
        [int]$numeroBuild = 0
        if ($null -ne $Ambiente -and $null -ne $Ambiente.PSObject.Properties['Build'] -and (-not [string]::IsNullOrWhiteSpace([string]$Ambiente.Build))) {
            if ([string]$Ambiente.Build -match '^(\d+)') {
                $numeroBuild = [int]$Matches[1]
            }
        }

        if ($numeroBuild -eq 0) {
            $chiaveCurVer = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
            if (Test-Path -LiteralPath $chiaveCurVer -ErrorAction SilentlyContinue) {
                $propVer = Get-ItemProperty -LiteralPath $chiaveCurVer -ErrorAction SilentlyContinue
                if ($null -ne $propVer -and $null -ne $propVer.PSObject.Properties['CurrentBuildNumber'] -and ([string]$propVer.CurrentBuildNumber -match '^(\d+)')) {
                    $numeroBuild = [int]$Matches[1]
                }
                elseif ($null -ne $propVer -and $null -ne $propVer.PSObject.Properties['CurrentBuild'] -and ([string]$propVer.CurrentBuild -match '^(\d+)')) {
                    $numeroBuild = [int]$Matches[1]
                }
            }
        }

        $chiaveUac = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if (-not (Test-Path -LiteralPath $chiaveUac -ErrorAction SilentlyContinue)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Chiave di registro UAC Policies\System non trovata"
            $risultato.Evidence = @{ Path = $chiaveUac; Build = $numeroBuild }
            return $risultato
        }

        $propUac = Get-ItemProperty -LiteralPath $chiaveUac -ErrorAction Stop
        $haProprieta = ($null -ne $propUac -and $null -ne $propUac.PSObject.Properties['TypeOfAdminApprovalMode'] -and $null -ne $propUac.TypeOfAdminApprovalMode)
        $valoreMode  = if ($haProprieta) { [int]$propUac.TypeOfAdminApprovalMode } else { -1 }

        $lsaDeprivileged = $null
        $chiaveLsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        if (Test-Path -LiteralPath $chiaveLsa -ErrorAction SilentlyContinue) {
            $propLsa = Get-ItemProperty -LiteralPath $chiaveLsa -ErrorAction SilentlyContinue
            if ($null -ne $propLsa -and $null -ne $propLsa.PSObject.Properties['ShadowAdminEnabled']) {
                $lsaDeprivileged = $propLsa.ShadowAdminEnabled
            }
        }

        $risultato.Evidence = @{
            Path                    = $chiaveUac
            TypeOfAdminApprovalMode = $valoreMode
            ValuePresent            = $haProprieta
            Build                   = $numeroBuild
            ShadowAdminEnabled      = $lsaDeprivileged
        }

        if ($haProprieta -and $valoreMode -eq 2) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Administrator Protection just-in-time attiva (TypeOfAdminApprovalMode = 2)"
        }
        elseif ((-not $haProprieta) -and ($numeroBuild -gt 0 -and $numeroBuild -lt 26100)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Funzionalita' disponibile da Windows 11 24H2/25H2+ (Build rilevata: $numeroBuild < 26100)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Modalita' UAC legacy attiva; Administrator Protection non abilitata (TypeOfAdminApprovalMode = $valoreMode)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave UAC Policies\System"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per verificare Administrator Protection"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

# =============================================================================
# MODULO: src\ui\ViewModel.ps1
# =============================================================================
<#
.SYNOPSIS
    ViewModel puro per l'interfaccia grafica dello scanner di sicurezza.

.DESCRIPTION
    Contiene esclusivamente funzioni PURE (senza dipendenze da WPF o
    PresentationFramework) per:
    - Unione dei risultati di scansione con i metadati del catalogo
    - Ordinamento predefinito (falliti per gravita', poi sconosciuti, poi superati)
    - Filtri combinabili (stato, gravita', categoria, ricerca testuale)
    - Calcolo dei conteggi di riepilogo
    - Costruzione del dettaglio del controllo (modalita' semplice/tecnica,
      gestione sicura di campi mancanti o null)
    - Generazione del nome file predefinito per l'export

    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

# Rimedi statici di riferimento per tutti i 18 controlli del profilo Home/Pro
# (usati se il controllo nel catalogo non definisce gia' un blocco remediation)
$script:RimediStaticiFetta = @{
    'HOME-FW-001' = [PSCustomObject]@{
        text    = "Attiva Windows Defender Firewall per tutti i profili (Dominio, Privato e Pubblico) tramite Sicurezza di Windows -> Firewall e protezione di rete, oppure eseguendo il comando seguente in una console PowerShell avviata come amministratore."
        command = "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True"
        risk    = "Basso: il firewall blocca le connessioni in ingresso non sollicitate ma consente il normale traffico in uscita delle applicazioni domestiche."
    }
    'HOME-UAC-001' = [PSCustomObject]@{
        text    = "Abilita il Controllo dell'account utente (UAC) dalle Impostazioni di Windows (Modifica le impostazioni di Controllo dell'account utente) oppure impostando il valore di registro EnableLUA a 1 da PowerShell come amministratore. E' necessario riavviare il computer."
        command = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -Value 1"
        risk    = "Basso: Windows chiedera' conferma prima di consentire a programmi di apportare modifiche amministrative al sistema. Richiede il riavvio."
    }
    'HOME-UAC-002' = [PSCustomObject]@{
        text    = "Configura UAC affinche' chieda sempre conferma sul desktop sicuro per le operazioni amministrative (ConsentPromptBehaviorAdmin = 2 o 5)."
        command = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Value 2"
        risk    = "Basso: verra' mostrata una finestra di conferma UAC quando un programma richiede privilegi di amministratore."
    }
    'HOME-UAC-003' = [PSCustomObject]@{
        text    = "Abilita il rilevamento delle installazioni di applicazioni per UAC impostando EnableInstallerDetection a 1."
        command = "Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableInstallerDetection' -Value 1"
        risk    = "Molto basso: garantisce che i pacchetti di installazione vengano eseguiti con il consenso dell'amministratore."
    }
    'HOME-ACC-001' = [PSCustomObject]@{
        text    = "Disabilita l'account ospite (Guest, SID che termina con -501) aprendo PowerShell come amministratore ed eseguendo il comando indicato."
        command = 'Get-LocalUser | Where-Object { $_.SID.Value -match "-501$" } | Disable-LocalUser'
        risk    = "Molto basso: impedisce l'accesso locale senza password tramite l'account Guest predefinito."
    }
    'HOME-ACC-002' = [PSCustomObject]@{
        text    = "Disabilita l'account Administrator predefinito (SID -500) solo dopo aver verificato che esista almeno un altro account utente amministratore funzionante."
        command = 'Get-LocalUser | Where-Object { $_.SID.Value -match "-500$" } | Disable-LocalUser'
        risk    = "Medio: assicurati di avere un altro account amministratore attivo prima di disabilitare l'account Administrator predefinito, altrimenti perderai i privilegi amministrativi."
    }
    'HOME-ACC-003' = [PSCustomObject]@{
        text    = "Imposta una password robusta per ogni account locale attivo dalle Impostazioni di Windows (Account -> Opzioni di accesso) e richiedi l'uso della password."
        command = 'Get-LocalUser | Where-Object { $_.Enabled -and (-not $_.PasswordRequired) } | Select-Object Name, SID'
        risk    = "Basso: gli utenti dovranno inserire la propria password o PIN di Windows Hello all'accesso."
    }
    'HOME-UPD-001' = [PSCustomObject]@{
        text    = "Assicurati che il servizio Windows Update (wuauserv) sia impostato su Manuale o Automatico e che gli aggiornamenti automatici non siano bloccati da policy."
        command = 'Set-Service -Name "wuauserv" -StartupType Manual'
        risk    = "Basso: il sistema scarichera' e installera' regolarmente gli aggiornamenti di sicurezza di Windows."
    }
    'HOME-AV-001' = [PSCustomObject]@{
        text    = "Attiva la protezione in tempo reale in Sicurezza di Windows -> Protezione da virus e minacce -> Impostazioni di protezione da virus e minacce."
        command = 'Set-MpPreference -DisableRealtimeMonitoring $false'
        risk    = "Molto basso: la protezione in tempo reale e' essenziale contro malware e ransomware."
    }
    'HOME-AV-002' = [PSCustomObject]@{
        text    = "Aggiorna subito le firme antivirus di Windows Defender tramite Sicurezza di Windows -> Aggiornamenti della protezione oppure con Update-MpSignature."
        command = 'Update-MpSignature'
        risk    = "Nessun rischio: aggiorna esclusivamente il database delle definizioni dei virus."
    }
    'HOME-RDP-001' = [PSCustomObject]@{
        text    = "Disabilita il Desktop remoto da Impostazioni -> Sistema -> Desktop remoto se non ti serve accedere al PC da remoto."
        command = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1'
        risk    = "Basso per utenti domestici: chiude l'accesso tramite protocollo RDP (porta 3389). Non applicare se usi attivamente Desktop remoto."
    }
    'HOME-NET-001' = [PSCustomObject]@{
        text    = "Disabilita il protocollo obsoleto SMBv1 lasciando attivi SMBv2/SMBv3."
        command = 'Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force'
        risk    = "Basso: SMBv1 serve solo per vecchi dispositivi NAS o stampanti di rete antecedenti al 2010."
    }
    'HOME-NET-002' = [PSCustomObject]@{
        text    = "Disabilita NetBIOS su TCP/IP (NetbiosOptions = 2) sulle schede di rete per ridurre la superficie di attacco su reti locali e Wi-Fi pubbliche."
        command = 'Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces" | ForEach-Object { Set-ItemProperty -Path $_.PSPath -Name "NetbiosOptions" -Value 2 }'
        risk    = "Basso: le reti moderne Windows 10/11 usano DNS e mDNS/LLMNR anziche' NetBIOS."
    }
    'HOME-ENC-001' = [PSCustomObject]@{
        text    = "Attiva Crittografia dispositivo o BitLocker sul disco di sistema (C:) da Impostazioni -> Privacy e sicurezza -> Crittografia dispositivo, salvando la chiave di ripristino."
        command = 'Enable-BitLocker -MountPoint "C:" -EncryptionMethod XtsAes256 -UsedSpaceOnly -TpmProtector'
        risk    = "Medio: conserva sempre una copia della chiave di ripristino BitLocker su un supporto esterno o nell'account Microsoft per evitare la perdita dei dati."
    }
    'HOME-PRV-001' = [PSCustomObject]@{
        text    = "Riduci la telemetria di Windows al livello minimo consentito (solo dati obbligatori) da Impostazioni -> Privacy e sicurezza -> Diagnostica e feedback."
        command = 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Value 1 -Type DWord'
        risk    = "Molto basso: disattiva l'invio dei dati diagnostici facoltativi."
    }
    'HOME-SEC-001' = [PSCustomObject]@{
        text    = "Abilita Secure Boot nelle impostazioni del firmware UEFI (BIOS) della scheda madre. Questa operazione non puo' essere eseguita tramite comando PowerShell."
        command = $null
        risk    = "Medio: assicurati che il disco di sistema utilizzi lo schema di partizione GPT (modalita' UEFI nativa) prima di attivare Secure Boot nel BIOS."
    }
    'HOME-SEC-002' = [PSCustomObject]@{
        text    = "Abilita la protezione LSA (Local Security Authority) in Sicurezza di Windows -> Sicurezza dispositivi -> Isolamento core -> Protezione dell'autorita' di sicurezza locale."
        command = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RunAsPPL" -Value 1 -Type DWord'
        risk    = "Basso: richiede il riavvio del sistema; impedisce a driver non firmati o tool malevoli di leggere la memoria del processo LSASS."
    }
    'HOME-SEC-003' = [PSCustomObject]@{
        text    = "Abilita il logging degli script block di PowerShell per registrare nel Registro Eventi (Microsoft-Windows-PowerShell/Operational) i blocchi di codice eseguiti."
        command = 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 1 -Type DWord'
        risk    = "Molto basso: aumenta leggermente il volume dei log nel Visualizzatore eventi in cambio di una maggiore tracciabilita'."
    }
    'HOME-UPD-002' = [PSCustomObject]@{
        text    = "Se questo e' un PC domestico e non aziendale, rimuovi eventuali reindirizzamenti WSUS non autorizzati in modo che Windows scarichi gli aggiornamenti direttamente dai server ufficiali Microsoft."
        command = 'Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -ErrorAction SilentlyContinue'
        risk    = "Basso su PC domestici: ripristina l'uso dei server ufficiali di Windows Update."
    }
    'HOME-AV-003' = [PSCustomObject]@{
        text    = "Apri Sicurezza di Windows -> Protezione da virus e minacce -> Cronologia della protezione oppure avvia una scansione completa e rimuovi/metti in quarantena le minacce rilevate."
        command = 'Start-MpScan -ScanType QuickScan'
        risk    = "Nessun rischio: rimuove o isola i file infetti rilevati da Windows Defender."
    }
    'HOME-AV-004' = [PSCustomObject]@{
        text    = "Riattiva il monitoraggio comportamentale e la scansione dei file scaricati (IOAV) nelle preferenze di Windows Defender."
        command = 'Set-MpPreference -DisableBehaviorMonitoring $false -DisableIOAVProtection $false'
        risk    = "Molto basso: garantisce che i file scaricati da browser ed email vengano analizzati subito."
    }
    'HOME-AV-005' = [PSCustomObject]@{
        text    = "Imposta la protezione contro le applicazioni potenzialmente indesiderate (PUA) in modalita' Blocco (valore 1) in Sicurezza di Windows -> Controllo delle app e del browser -> Impostazioni di protezione basata sulla reputazione."
        command = 'Set-MpPreference -PUAProtection Enabled'
        risk    = "Basso: potrebbe bloccare installer che includono adware o software pubblicitari indesiderati."
    }
    'HOME-AV-006' = [PSCustomObject]@{
        text    = "Attiva la Protezione antimanomissione in Sicurezza di Windows -> Protezione da virus e minacce -> Impostazioni -> Gestisci impostazioni e abilita la protezione fornita dal cloud (MAPS)."
        command = 'Set-MpPreference -MAPSReporting Advanced'
        risk    = "Molto basso: migliora il rilevamento di minacce zero-day e impedisce a programmi esterni di disattivare Defender."
    }
    'HOME-AV-007' = [PSCustomObject]@{
        text    = "Esegui una scansione rapida o completa con Windows Defender per verificare lo stato dei file sul disco."
        command = 'Start-MpScan -ScanType QuickScan'
        risk    = "Nessun rischio: la scansione rapida dura pochi minuti e non interrompe il lavoro."
    }
    'HOME-AV-008' = [PSCustomObject]@{
        text    = "Controlla e rimuovi le esclusioni sospette in Sicurezza di Windows -> Protezione da virus e minacce -> Impostazioni -> Aggiungi o rimuovi esclusioni. Non escludere mai C:\, Downloads, Temp o estensioni .exe/.ps1."
        command = 'Get-MpPreference | Select-Object -ExpandProperty ExclusionPath'
        risk    = "Basso: rimuovere esclusioni ampie ripristina il controllo antivirus su tutte le cartelle del disco."
    }
    'HOME-FIL-001' = [PSCustomObject]@{
        text    = "Verifica i file con doppia estensione (es. .pdf.exe, .jpg.scr) segnalati nelle cartelle Download, Desktop o Temp: non aprirli ed eliminali se non riconosciuti."
        command = 'Get-ChildItem "$env:USERPROFILE\Downloads","$env:USERPROFILE\Desktop","$env:TEMP" -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match "\.(pdf|doc|docx|jpg|png|txt|zip)\.(exe|scr|bat|cmd|vbs|js|ps1|hta)$" } | Select-Object FullName, Length, LastWriteTime'
        risk    = "Nessun rischio: il comando elenca in sola lettura i file sospetti per consentirti di verificarli."
    }
    'HOME-FIL-002' = [PSCustomObject]@{
        text    = "Apri Gestione attivita' (Task Manager) -> App di avvio oppure controlla le chiavi di registro Run/RunOnce per disabilitare o rimuovere i programmi sospetti che puntano a cartelle Temp o usano comandi offuscati."
        command = 'Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run","HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue'
        risk    = "Basso: rimuovere voci di avvio automatico sconosciute o malevole impedisce la persistenza al riavvio."
    }
    'HOME-FIL-003' = [PSCustomObject]@{
        text    = "Controlla il file C:\Windows\System32\drivers\etc\hosts con il Blocco note (avviato come amministratore) e rimuovi eventuali righe che bloccano o dirottano siti di sicurezza o Microsoft."
        command = 'Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_.Trim() -ne "" -and (-not $_.Trim().StartsWith("#")) }'
        risk    = "Basso: il file hosts predefinito di Windows non contiene alcuna riga attiva."
    }
    'HOME-SYS-001' = [PSCustomObject]@{
        text    = "In Esplora file di Windows 11 clicca su Visualizza -> Mostra -> Estensioni nomi file (oppure imposta HideFileExt = 0)."
        command = 'Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0'
        risk    = "Nessun rischio: rende visibile la vera estensione di tutti i file (es. .exe, .pdf, .docx)."
    }
    'HOME-SYS-002' = [PSCustomObject]@{
        text    = "Disattiva AutoPlay da Impostazioni -> Bluetooth e dispositivi -> AutoPlay per impedire l'avvio automatico di contenuti da chiavette USB e unita' rimovibili."
        command = 'Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Value 1 -Type DWord'
        risk    = "Molto basso: quando inserisci una chiavetta USB dovrai aprirla manualmente da Esplora file."
    }
    'HOME-SYS-003' = [PSCustomObject]@{
        text    = "Attiva SmartScreen in Sicurezza di Windows -> Controllo delle app e del browser -> Impostazioni di protezione basata sulla reputazione."
        command = 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Value 1 -Type DWord'
        risk    = "Molto basso: protegge da applicazioni e siti di phishing noti."
    }
    'HOME-SYS-004' = [PSCustomObject]@{
        text    = "Attiva l'Integrita' della memoria in Sicurezza di Windows -> Sicurezza dispositivi -> Dettagli isolamento core -> Integrita' della memoria e riavvia il PC."
        command = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 1 -Type DWord'
        risk    = "Medio: richiede il riavvio; alcuni vecchi driver di periferiche non certificati potrebbero non essere compatibili."
    }
    'HOME-SYS-005' = [PSCustomObject]@{
        text    = "Blocca l'enumerazione anonima degli account SAM impostando RestrictAnonymousSAM a 1 nella chiave LSA."
        command = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "RestrictAnonymousSAM" -Value 1 -Type DWord'
        risk    = "Molto basso: e' l'impostazione di sicurezza raccomandata su tutte le versioni moderne di Windows."
    }
    'HOME-NET-003' = [PSCustomObject]@{
        text    = "Disabilita il protocollo multicast LLMNR impostando EnableMulticast = 0 nella policy DNSClient."
        command = 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0 -Type DWord'
        risk    = "Basso: le reti moderne utilizzano DNS standard anziche' LLMNR."
    }
    'HOME-AV-009' = [PSCustomObject]@{
        text    = "Attiva l'Accesso alle cartelle controllato in Sicurezza di Windows -> Protezione da virus e minacce -> Gestisci protezione ransomware."
        command = 'Set-MpPreference -EnableControlledFolderAccess Enabled'
        risk    = "Basso: protegge Documenti e Immagini da ransomware; eventuali programmi di terze parti legittimi possono essere autorizzati con un clic."
    }
    'HOME-AV-010' = [PSCustomObject]@{
        text    = "Attiva la Protezione di rete (Exploit Guard) di Microsoft Defender in modalita' blocco contro phishing e domini C2."
        command = 'Set-MpPreference -EnableNetworkProtection Enabled'
        risk    = "Molto basso: blocca le connessioni verso domini malevoli noti in tutti i programmi."
    }
    'HOME-FIL-004' = [PSCustomObject]@{
        text    = "Apri l'Utilitia' di pianificazione (taskschd.msc), controlla le attivita' segnalate e rimuovi o disabilita quelle sconosciute o che lanciano script da Temp."
        command = 'Get-ScheduledTask | Where-Object { $_.State -ne "Disabled" -and $_.TaskPath -notlike "\Microsoft\*" } | Select-Object TaskName, TaskPath, State'
        risk    = "Basso: elimina la persistenza automatica di task sospetti."
    }
    'HOME-FIL-005' = [PSCustomObject]@{
        text    = "Rimuovi immediatamente qualsiasi valore Debugger non autorizzato dalle sottochiavi di Image File Execution Options nel registro."
        command = 'Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" | Get-ItemProperty -Name Debugger -ErrorAction SilentlyContinue'
        risk    = "Nessuno: ripristina il normale funzionamento degli eseguibili di sistema."
    }
    'HOME-FIL-006' = [PSCustomObject]@{
        text    = "Apri la cartella Esecuzione automatica (shell:startup e shell:common startup) ed elimina eventuali script (.vbs, .js, .bat, .ps1) non riconosciuti."
        command = 'Get-ChildItem -Path ([Environment]::GetFolderPath("Startup")), ([Environment]::GetFolderPath("CommonStartup")) -File'
        risk    = "Nessuno: impedisce l'esecuzione automatica di script sospetti al login."
    }
    'HOME-ACC-004' = [PSCustomObject]@{
        text    = "Imposta una soglia di blocco account (es. 5 tentativi falliti) per bloccare gli attacchi di forza bruta sulle password locali."
        command = 'net accounts /lockoutthreshold:5 /lockoutduration:15 /lockoutwindow:15'
        risk    = "Basso: dopo 5 password errate consecutive l'account viene temporaneamente bloccato per 15 minuti."
    }
    'HOME-ACC-005' = [PSCustomObject]@{
        text    = "Verifica i membri del gruppo Amministratori locali e converti gli account secondari di uso quotidiano in account Utente standard."
        command = 'Get-LocalGroupMember -SID "S-1-5-32-544"'
        risk    = "Medio: assicurati di mantenere almeno un account amministratore attivo e accessibile."
    }
    'HOME-NET-004' = [PSCustomObject]@{
        text    = "Controlla le cartelle condivise sulla rete locale e rimuovi le condivisioni SMB non necessarie."
        command = 'Get-SmbShare | Where-Object { $_.Name -notmatch "^(ADMIN\$|IPC\$|print\$|[A-Za-z]\$)$" }'
        risk    = "Basso: chiude l'accesso di rete alle cartelle locali condivise."
    }
    'HOME-NET-005' = [PSCustomObject]@{
        text    = "Abilita la firma digitale obbligatoria SMB (RequireSecuritySignature = 1) su Server e Client SMB contro attacchi NTLM Relay."
        command = 'Set-SmbServerConfiguration -RequireSecuritySignature $true -Force; Set-SmbClientConfiguration -RequireSecuritySignature $true -Force'
        risk    = "Basso: tutte le versioni moderne di Windows e NAS supportano SMB Signing."
    }
    'HOME-NET-006' = [PSCustomObject]@{
        text    = "Ferma e disabilita il servizio Gestione remota Windows (WinRM) se non utilizzi PowerShell Remoting verso questo PC."
        command = 'Stop-Service -Name "WinRM" -Force; Set-Service -Name "WinRM" -StartupType Disabled'
        risk    = "Basso su PC desktop/portatili: chiude la porta remota 5985."
    }
    'HOME-NET-007' = [PSCustomObject]@{
        text    = "Disabilita la scoperta automatica proxy WPAD nel registro per prevenire dirottamenti del traffico web su reti locali."
        command = 'New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "DisableWpad" -Value 1 -Type DWord'
        risk    = "Molto basso: evita il rilevamento automatico di proxy WPAD non richiesti."
    }
    'HOME-SYS-006' = [PSCustomObject]@{
        text    = "Assicurati che UseLogonCredential in WDigest sia impostato a 0 per impedire il salvataggio delle password in chiaro in memoria RAM."
        command = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Value 0 -Type DWord'
        risk    = "Nessuno: protegge le credenziali utente da furti in memoria (Mimikatz)."
    }
    'HOME-SYS-007' = [PSCustomObject]@{
        text    = "Disabilita l'Assistenza remota di Windows impostando fAllowToGetHelp a 0."
        command = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -Type DWord'
        risk    = "Molto basso: disattiva le connessioni di Assistenza remota legacy di Windows."
    }
    'HOME-SYS-008' = [PSCustomObject]@{
        text    = "Ferma e disabilita il servizio Registro di sistema remoto (RemoteRegistry) per impedire accessi al registro dalla rete."
        command = 'Stop-Service -Name "RemoteRegistry" -Force -ErrorAction SilentlyContinue; Set-Service -Name "RemoteRegistry" -StartupType Disabled'
        risk    = "Nessuno su PC domestici o workstation singole."
    }
    'HOME-SEC-006' = [PSCustomObject]@{
        text    = "Abilita l'Elenco di blocco driver vulnerabili Microsoft in Sicurezza di Windows -> Sicurezza dispositivi -> Isolamento core."
        command = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config" -Name "VulnerableDriverBlocklistEnable" -Value 1 -Type DWord'
        risk    = "Molto basso: blocca solo driver di kernel con vulnerabilita' note sfruttate da malware BYOVD."
    }
    'HOME-SEC-007' = [PSCustomObject]@{
        text    = "Verifica lo stato di Controllo intelligente delle app (Smart App Control) in Sicurezza di Windows -> Controllo delle app e del browser."
        command = $null
        risk    = "Nota: su Windows 11 Smart App Control puo' essere attivato in modalita' valutazione o blocco solo da un'installazione pulita o reimpostazione di Windows."
    }
    'HOME-AV-011' = [PSCustomObject]@{
        text    = "Attiva le regole principali Attack Surface Reduction (ASR) di Microsoft Defender (blocco furto credenziali LSASS e blocco script offuscati)."
        command = 'Add-MpPreference -AttackSurfaceReductionRules_Ids "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2","5beb7efe-fd9a-4556-801d-275e5ffc04cc" -AttackSurfaceReductionRules_Actions Enabled,Enabled'
        risk    = "Basso: protegge attivamente LSASS e blocca l'esecuzione di script offuscati."
    }
    'HOME-SEC-008' = [PSCustomObject]@{
        text    = "Abilita il chip TPM 2.0 (Intel PTT o AMD fTPM) nelle impostazioni UEFI/BIOS della scheda madre."
        command = 'Get-Tpm'
        risk    = "Molto basso: requisito hardware fondamentale di Windows 11 per BitLocker e Windows Hello."
    }
    'HOME-NET-008' = [PSCustomObject]@{
        text    = "Disabilita esplicitamente TLS 1.0/1.1 in SCHANNEL e abilita il supporto automatico DNS over HTTPS (EnableAutoDoh = 2)."
        command = 'Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableAutoDoh" -Value 2 -Type DWord'
        risk    = "Basso: cifra automaticamente le query DNS quando il server DNS configurato supporta DoH."
    }
    'HOME-SYS-009' = [PSCustomObject]@{
        text    = "Disabilita Windows Script Host (WSH) nel registro per bloccare l'esecuzione di script .vbs e .js malevoli."
        command = 'New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings" -Name "Enabled" -Value 0 -Type DWord'
        risk    = "Basso: blocca vecchi script VBScript/JScript (.vbs/.js); non influisce su PowerShell."
    }
    'HOME-SEC-009' = [PSCustomObject]@{
        text    = "Imposta la ExecutionPolicy di PowerShell su RemoteSigned (o AllSigned), evitando Unrestricted o Bypass."
        command = 'Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force'
        risk    = "Basso: consente gli script locali ma richiede una firma digitale per gli script scaricati da Internet."
    }
    'HOME-UAC-004' = [PSCustomObject]@{
        text    = "Abilita Administrator Protection (elevazione just-in-time introdotta in Windows 11 24H2/25H2+) tramite Sicurezza di Windows o Policy UAC (TypeOfAdminApprovalMode = 2)."
        command = 'Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "TypeOfAdminApprovalMode" -Value 2 -Type DWord'
        risk    = "Basso su Windows 11 24H2/25H2+: richiede conferma interattiva di Windows Hello / password per creare un token amministrativo isolato just-in-time."
    }
    'HOME-FIL-007' = [PSCustomObject]@{
        text    = "Ispeziona e rimuovi eventuali sottoscrizioni WMI persistenti non autorizzate (__EventFilter, CommandLineEventConsumer, ActiveScriptEventConsumer) nel namespace root\subscription."
        command = 'Get-CimInstance -Namespace "root\subscription" -ClassName CommandLineEventConsumer; Get-CimInstance -Namespace "root\subscription" -ClassName ActiveScriptEventConsumer'
        risk    = "Nessuno rimuovendo sottoscrizioni malware; verifica prima che non appartengano a software aziendali legittimi."
    }
    'HOME-FIL-008' = [PSCustomObject]@{
        text    = "Verifica ed elimina eventuali voci sospette nella chiave ExtensionInstallForcelist del registro (Google Chrome o Microsoft Edge) per consentire la rimozione di estensioni indesiderate."
        command = 'Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist","HKCU:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist","HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist","HKCU:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist" -ErrorAction SilentlyContinue'
        risk    = "Basso su PC personali: rimuove l'obbligo di installazione forzata delle estensioni configurate tramite policy."
    }
}

# Traduzioni complete in Inglese (EN) per tutti i 34 controlli (Titolo, Categoria, Spiegazione, Rimedio, Rischi)
$script:TraduzioniControlliEN = @{
    'HOME-FW-001'  = @{ cat = 'Firewall';          title = 'Windows Firewall enabled on all profiles';                   rat = 'The firewall is the first line of defense against unauthorized network connections.'; rem = 'Enable Windows Defender Firewall for Domain, Private, and Public profiles via Windows Security or PowerShell as Administrator.'; risk = 'Low: blocks unsolicited inbound connections while allowing normal outbound traffic.' }
    'HOME-UAC-001' = @{ cat = 'UAC';               title = 'User Account Control (UAC) enabled';                         rat = 'UAC protects the system by asking for confirmation before running elevated operations.'; rem = 'Enable UAC (EnableLUA = 1) via Windows Settings or PowerShell as Administrator. Requires a reboot.'; risk = 'Low: Windows will prompt before administrative changes.' }
    'HOME-UAC-002' = @{ cat = 'UAC';               title = 'UAC requires confirmation for privilege elevation';          rat = 'If UAC elevates silently without prompting, malware can gain admin rights unnoticed.'; rem = 'Configure UAC to prompt for consent on the secure desktop (ConsentPromptBehaviorAdmin = 2 or 5).'; risk = 'Low: shows a confirmation prompt when an application requests admin rights.' }
    'HOME-UAC-003' = @{ cat = 'UAC';               title = 'UAC detects application installations';                      rat = 'Installer detection prevents unauthorized software installations without elevation.'; rem = 'Enable application installer detection for UAC (EnableInstallerDetection = 1).'; risk = 'Very low: ensures setup packages run with administrator consent.' }
    'HOME-ACC-001' = @{ cat = 'Accounts';          title = 'Built-in Guest account disabled';                            rat = 'The Guest account allows anonymous local access without credentials.'; rem = 'Disable the built-in Guest account (SID ending in -501) via PowerShell as Administrator.'; risk = 'Very low: prevents unauthenticated local logins.' }
    'HOME-ACC-002' = @{ cat = 'Accounts';          title = 'Built-in local Administrator account disabled';              rat = 'The default Administrator account (-500) is a primary target for brute-force attacks.'; rem = 'Disable the built-in Administrator account (SID -500) after verifying another admin account exists.'; risk = 'Medium: ensure you have another active administrator account before disabling it.' }
    'HOME-ACC-003' = @{ cat = 'Accounts';          title = 'No active local account without a password';                 rat = 'Accounts without a password allow anyone with physical or network access to log in.'; rem = 'Set a strong password for every active local account in Windows Settings -> Accounts -> Sign-in options.'; risk = 'Low: users will be required to enter a password or Windows Hello PIN at sign-in.' }
    'HOME-UPD-001' = @{ cat = 'Updates';           title = 'Windows Update automatic updates enabled';                   rat = 'Security updates fix known vulnerabilities; disabling them leaves the PC exposed.'; rem = 'Ensure the Windows Update service (wuauserv) is not disabled and NoAutoUpdate policy is removed.'; risk = 'Low: Windows will regularly download and install security patches.' }
    'HOME-UPD-002' = @{ cat = 'Updates';           title = 'Authentic Windows Update server (no unauthorized WSUS)';     rat = 'Malware can redirect Windows Update to a rogue server to block security patches.'; rem = 'Remove unauthorized WUServer registry policies so Windows updates directly from Microsoft.'; risk = 'Low on home PCs: restores official Microsoft Windows Update servers.' }
    'HOME-AV-001'  = @{ cat = 'Antivirus';         title = 'Windows Defender Real-Time Protection enabled';              rat = 'Real-time protection scans files as they are accessed and blocks malware immediately.'; rem = 'Enable Real-Time Protection in Windows Security -> Virus & threat protection.'; risk = 'Very low: essential baseline protection against malware and ransomware.' }
    'HOME-AV-002'  = @{ cat = 'Antivirus';         title = 'Antivirus signatures up to date (<= 7 days)';                rat = 'Outdated virus definitions cannot detect the latest malware threats.'; rem = 'Update Windows Defender virus definitions via Windows Security or Update-MpSignature.'; risk = 'None: only updates the antivirus signature database.' }
    'HOME-AV-003'  = @{ cat = 'Antivirus';         title = 'No active virus or malware threats detected';                rat = 'Active threats indicate an ongoing infection or malicious file not yet quarantined.'; rem = 'Open Windows Security -> Protection history or run a scan to quarantine detected threats.'; risk = 'None: isolates and removes infected files.' }
    'HOME-AV-004'  = @{ cat = 'Antivirus';         title = 'Downloaded files scanning (IOAV) & Behavior Monitoring active'; rat = 'IOAV scans all files downloaded from browsers/email, while behavior monitoring stops ransomware.'; rem = 'Enable Behavior Monitoring and IOAV Protection in Windows Defender preferences.'; risk = 'Very low: ensures downloaded files are inspected immediately.' }
    'HOME-AV-005'  = @{ cat = 'Antivirus';         title = 'Potentially Unwanted Application (PUA) blocking enabled';    rat = 'PUA protection blocks adware, bundleware, cryptominers, and unwanted software.'; rem = 'Set PUAProtection to Enabled (1) in Windows Security -> App & browser control -> Reputation-based protection.'; risk = 'Low: may flag installers that bundle third-party adware.' }
    'HOME-AV-006'  = @{ cat = 'Antivirus';         title = 'Tamper Protection and Cloud MAPS protection enabled';        rat = 'Tamper Protection prevents malware from disabling Defender, while Cloud MAPS blocks zero-day threats.'; rem = 'Turn on Tamper Protection in Windows Security and enable Cloud-delivered protection (MAPS).'; risk = 'Very low: strengthens defense against zero-day malware.' }
    'HOME-AV-007'  = @{ cat = 'Antivirus';         title = 'Periodic antivirus scan completed within 14 days';           rat = 'Periodic scans detect dormant threats stored on disk before the latest signature updates.'; rem = 'Run a Quick or Full scan with Windows Defender.'; risk = 'None: a quick scan takes only a few minutes.' }
    'HOME-AV-008'  = @{ cat = 'Antivirus';         title = 'No dangerous folder or extension exclusions in Defender';    rat = 'Malware often adds C:\, Downloads, Temp, or .exe/.ps1 to Defender exclusions to hide itself.'; rem = 'Review and remove broad exclusions in Windows Security -> Virus & threat protection -> Exclusions.'; risk = 'Low: restores full antivirus coverage across all folders.' }
    'HOME-FIL-001' = @{ cat = 'File Security';     title = 'No disguised double-extension executables (Downloads/Temp)'; rat = 'Double extensions (e.g. invoice.pdf.exe, photo.jpg.scr) trick users into running malware.'; rem = 'Inspect any flagged double-extension files in Downloads, Desktop, or Temp and delete unrecognized executables.'; risk = 'None: lists suspicious files in read-only mode for inspection.' }
    'HOME-FIL-002' = @{ cat = 'File Security';     title = 'No suspicious or obfuscated commands in Startup Run keys';   rat = 'Malware registers itself in Run/RunOnce keys pointing to Temp folders or using hidden PowerShell (-enc).'; rem = 'Check Task Manager -> Startup apps and Run registry keys to remove unknown or suspicious entries.'; risk = 'Low: prevents malicious persistence across reboots.' }
    'HOME-FIL-003' = @{ cat = 'File Security';     title = 'Windows hosts file integrity (no security domain hijacking)'; rat = 'Malware can modify the hosts file to block access to Windows Update or antivirus websites.'; rem = 'Inspect C:\Windows\System32\drivers\etc\hosts and remove any lines redirecting Microsoft or security domains.'; risk = 'Low: the default Windows hosts file has no active domain redirects.' }
    'HOME-SYS-001' = @{ cat = 'Windows Settings';  title = 'File extensions visible for known file types in Explorer';   rat = 'Showing file extensions lets you immediately spot executable programs (.exe, .bat, .scr) disguised as documents.'; rem = 'In File Explorer click View -> Show -> File name extensions (HideFileExt = 0).'; risk = 'None: makes the true extension of every file visible.' }
    'HOME-SYS-002' = @{ cat = 'Windows Settings';  title = 'AutoRun and AutoPlay disabled for removable USB drives';     rat = 'Disabling AutoRun/AutoPlay prevents automatic execution of malware from infected USB drives.'; rem = 'Disable AutoPlay in Windows Settings -> Bluetooth & devices -> AutoPlay.'; risk = 'Very low: USB drives will simply be opened manually in File Explorer.' }
    'HOME-SYS-003' = @{ cat = 'Windows Settings';  title = 'Microsoft Defender SmartScreen enabled for apps and files';  rat = 'SmartScreen warns you before running unrecognized or potentially malicious programs downloaded from the web.'; rem = 'Enable SmartScreen in Windows Security -> App & browser control -> Reputation-based protection.'; risk = 'Very low: protects against known phishing and malicious downloads.' }
    'HOME-SYS-004' = @{ cat = 'Windows Settings';  title = 'Core Isolation / Memory Integrity (HVCI) enabled';           rat = 'Memory Integrity uses hardware virtualization to prevent malicious code injection into Windows kernel processes.'; rem = 'Enable Memory Integrity in Windows Security -> Device security -> Core isolation details and restart.'; risk = 'Medium: requires a reboot; very old uncertified hardware drivers might be incompatible.' }
    'HOME-SYS-005' = @{ cat = 'Windows Settings';  title = 'Anonymous enumeration of local SAM accounts blocked';        rat = 'Prevents unauthenticated network users from listing local user account names on your PC.'; rem = 'Set RestrictAnonymousSAM to 1 in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa.'; risk = 'Very low: recommended default on modern Windows systems.' }
    'HOME-RDP-001' = @{ cat = 'Remote Desktop';    title = 'Remote Desktop Protocol (RDP) disabled';                     rat = 'RDP is one of the most common attack vectors; disable it if remote access is not required.'; rem = 'Disable Remote Desktop in Windows Settings -> System -> Remote Desktop (fDenyTSConnections = 1).'; risk = 'Low for home users: closes port 3389 remote access.' }
    'HOME-NET-001' = @{ cat = 'Network';           title = 'Legacy SMBv1 protocol disabled';                             rat = 'SMBv1 has critical vulnerabilities (EternalBlue/WannaCry). Modern networks use SMBv2/SMBv3.'; rem = 'Disable SMBv1 via Set-SmbServerConfiguration -EnableSMB1Protocol $false.'; risk = 'Low: SMBv1 is only used by legacy devices from before 2010.' }
    'HOME-NET-002' = @{ cat = 'Network';           title = 'NetBIOS over TCP/IP disabled on network adapters';           rat = 'NetBIOS can expose system information and enable local network spoofing attacks.'; rem = 'Disable NetBIOS over TCP/IP (NetbiosOptions = 2) on network interfaces.'; risk = 'Low: modern Windows 10/11 networks use DNS instead of NetBIOS.' }
    'HOME-NET-003' = @{ cat = 'Network';           title = 'LLMNR multicast name resolution disabled';                   rat = 'LLMNR is vulnerable to local network poisoning attacks that can capture password hashes.'; rem = 'Disable LLMNR by setting EnableMulticast = 0 in HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient.'; risk = 'Low: standard DNS resolution is used instead.' }
    'HOME-ENC-001' = @{ cat = 'Encryption';        title = 'BitLocker encryption active on system drive (C:)';           rat = 'Full disk encryption protects your personal files if the PC is lost or stolen.'; rem = 'Enable Device Encryption or BitLocker on C: in Windows Settings -> Privacy & security and back up your recovery key.'; risk = 'Medium: always save a copy of your BitLocker recovery key in a safe place.' }
    'HOME-PRV-001' = @{ cat = 'Privacy';           title = 'Windows diagnostic telemetry set to minimum level';          rat = 'Minimizing telemetry limits the amount of diagnostic data collected and sent to Microsoft.'; rem = 'Set diagnostic data to Required only (AllowTelemetry = 1) in Windows Settings -> Privacy & security -> Diagnostics & feedback.'; risk = 'Very low: disables optional diagnostic telemetry.' }
    'HOME-SEC-001' = @{ cat = 'Advanced Security'; title = 'UEFI Secure Boot enabled';                                   rat = 'Secure Boot blocks unsigned bootloaders, protecting the PC against rootkits and bootkits.'; rem = 'Enable Secure Boot in your motherboard UEFI/BIOS firmware settings (cannot be changed from PowerShell).'; risk = 'Medium: ensure your system drive uses GPT partitioning before enabling Secure Boot in BIOS.' }
    'HOME-SEC-002' = @{ cat = 'Advanced Security'; title = 'Local Security Authority (LSA) protection (RunAsPPL) active'; rat = 'LSA protection prevents credential-dumping tools (such as Mimikatz) from reading LSASS memory.'; rem = 'Enable Local Security Authority protection in Windows Security -> Device security -> Core isolation.'; risk = 'Low: requires a system restart.' }
    'HOME-SEC-003' = @{ cat = 'Advanced Security'; title = 'PowerShell Script Block Logging enabled';                    rat = 'Script Block Logging records executed PowerShell commands in Event Viewer to aid security auditing.'; rem = 'Enable PowerShell Script Block Logging (EnableScriptBlockLogging = 1) in Group Policy or Registry.'; risk = 'Very low: slightly increases PowerShell operational event log size.' }
    'HOME-AV-009'  = @{ cat = 'Antivirus';         title = 'Ransomware protection (Controlled Folder Access) enabled';   rat = 'Controlled Folder Access blocks untrusted apps and ransomware from encrypting or modifying your personal files.'; rem = 'Enable Controlled Folder Access in Windows Security -> Virus & threat protection -> Ransomware protection.'; risk = 'Low: protects Documents and Pictures; legitimate apps can be allowed with one click.' }
    'HOME-AV-010'  = @{ cat = 'Antivirus';         title = 'Microsoft Defender Network Protection (Exploit Guard) active'; rat = 'Network Protection blocks outbound connections to known phishing sites, malware C2 servers, and exploit domains.'; rem = 'Enable Network Protection via Set-MpPreference -EnableNetworkProtection Enabled.'; risk = 'Very low: blocks malicious domains system-wide across all apps.' }
    'HOME-FIL-004' = @{ cat = 'File Security';     title = 'No suspicious or obfuscated Windows Scheduled Tasks';        rat = 'Malware frequently creates Scheduled Tasks launching scripts from Temp/Public folders or using encoded PowerShell.'; rem = 'Open Task Scheduler (taskschd.msc), inspect any flagged tasks, and delete or disable unrecognized tasks.'; risk = 'Low: removes automatic background persistence of suspicious tasks.' }
    'HOME-FIL-005' = @{ cat = 'File Security';     title = 'No system executable hijacking (IFEO Debugger backdoors)';   rat = 'Attackers use Image File Execution Options (IFEO) Debugger keys to hijack Sticky Keys (sethc.exe), Task Manager, or Defender.'; rem = 'Remove unauthorized Debugger values under HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options.'; risk = 'None: restores normal execution of system utilities.' }
    'HOME-FIL-006' = @{ cat = 'File Security';     title = 'No suspicious scripts or executables in Startup folders';    rat = 'Every script or executable placed in the user or system Startup folder runs automatically whenever you sign in.'; rem = 'Open shell:startup and shell:common startup and delete any unrecognized scripts (.vbs, .js, .bat, .ps1).'; risk = 'None: prevents automatic execution of unauthorized startup scripts.' }
    'HOME-ACC-004' = @{ cat = 'Accounts';          title = 'Account lockout policy active against brute-force attacks';  rat = 'Without an account lockout threshold, attackers can attempt thousands of password guesses per minute without being locked out.'; rem = 'Configure an Account Lockout Threshold (e.g. 5 invalid logon attempts) via net accounts /lockoutthreshold:5.'; risk = 'Low: temporarily locks the account for 15 minutes after 5 consecutive wrong passwords.' }
    'HOME-ACC-005' = @{ cat = 'Accounts';          title = 'Local Administrators group members minimized (<= 2)';        rat = 'Limiting the number of administrator accounts reduces the attack surface and adheres to the principle of least privilege.'; rem = 'Review members of the local Administrators group and convert secondary daily-use accounts to standard users.'; risk = 'Medium: ensure at least one active administrator account remains accessible.' }
    'HOME-NET-004' = @{ cat = 'Network';           title = 'No non-standard user SMB network shares exposed';            rat = 'Open network folder shares can be abused by ransomware or users on the same LAN/Wi-Fi to read or encrypt files.'; rem = 'Review active SMB shares (Get-SmbShare) and remove unnecessary user folder shares.'; risk = 'Low: closes network access to shared local folders.' }
    'HOME-NET-005' = @{ cat = 'Network';           title = 'Mandatory SMB digital packet signing enabled (anti-Relay)';  rat = 'Mandatory SMB signing prevents man-in-the-middle attackers on the local network from intercepting and relaying credentials.'; rem = 'Enable RequireSecuritySignature on both SMB Server and SMB Client.'; risk = 'Low: all modern Windows systems and NAS devices support SMB Signing.' }
    'HOME-NET-006' = @{ cat = 'Network';           title = 'Windows Remote Management (WinRM) service disabled';         rat = 'On desktop/laptop PCs, WinRM exposes remote PowerShell management ports (5985/5986) often targeted for lateral movement.'; rem = 'Stop and disable the WinRM service if remote PowerShell administration is not required.'; risk = 'Low on desktop PCs: closes remote management port 5985.' }
    'HOME-NET-007' = @{ cat = 'Network';           title = 'WPAD automatic web proxy discovery disabled (anti-MITM)';    rat = 'Attackers on local networks can reply to WPAD requests to route all your web traffic through a malicious proxy.'; rem = 'Set DisableWpad = 1 under HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad.'; risk = 'Very low: disables automatic rogue proxy discovery.' }
    'HOME-SYS-006' = @{ cat = 'Windows Settings';  title = 'WDigest cleartext credential caching in memory disabled';    rat = 'If WDigest UseLogonCredential is enabled, Windows stores user passwords in cleartext inside LSASS memory.'; rem = 'Set UseLogonCredential = 0 under HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest.'; risk = 'None: protects user passwords against memory dumping.' }
    'HOME-SYS-007' = @{ cat = 'Windows Settings';  title = 'Windows Remote Assistance disabled';                         rat = 'Disabling Solicited Remote Assistance prevents unauthorized remote assistance invitations and inbound connections.'; rem = 'Set fAllowToGetHelp = 0 under HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance.'; risk = 'Very low: disables legacy Windows Remote Assistance.' }
    'HOME-SYS-008' = @{ cat = 'Windows Settings';  title = 'Remote Registry service disabled and stopped';               rat = 'The Remote Registry service allows remote network users to read and modify your Windows Registry.'; rem = 'Stop and disable the RemoteRegistry service (StartupType = Disabled).'; risk = 'None on home PCs and standalone workstations.' }
    'HOME-SEC-006' = @{ cat = 'Advanced Security'; title = 'Microsoft Vulnerable Driver Blocklist (anti-BYOVD) enabled';  rat = 'Blocks known vulnerable signed kernel drivers exploited in Bring Your Own Vulnerable Driver (BYOVD) attacks to disable Defender.'; rem = 'Enable Microsoft Vulnerable Driver Blocklist in Windows Security -> Device security -> Core isolation.'; risk = 'Very low: only blocks kernel drivers with known security vulnerabilities.' }
    'HOME-SEC-007' = @{ cat = 'Advanced Security'; title = 'Smart App Control (SAC) active (Enforced or Evaluation)';     rat = 'Smart App Control blocks untrusted, unsigned, or potentially malicious applications across Windows 11.'; rem = 'Check Smart App Control status in Windows Security -> App & browser control -> Smart App Control.'; risk = 'Note: Smart App Control can only be enabled in evaluation/enforced mode from a clean Windows 11 install.' }
    'HOME-AV-011'  = @{ cat = 'Antivirus';         title = 'Microsoft Defender Attack Surface Reduction (ASR) rules active'; rat = 'ASR rules block common ransomware and fileless malware vectors such as LSASS credential theft and obfuscated scripts.'; rem = 'Enable core ASR rules (LSASS credential protection and obfuscated script blocking) via Add-MpPreference.'; risk = 'Low: actively protects LSASS memory and blocks obfuscated script execution.' }
    'HOME-SEC-008' = @{ cat = 'Advanced Security'; title = 'TPM 2.0 hardware security module present and ready';          rat = 'TPM 2.0 provides the hardware root of trust required for BitLocker, Windows Hello, Secure Boot, and Credential Guard.'; rem = 'Enable TPM 2.0 (Intel PTT or AMD fTPM) in your motherboard UEFI/BIOS settings.'; risk = 'Very low: core Windows 11 hardware security requirement.' }
    'HOME-NET-008' = @{ cat = 'Network';           title = 'Legacy TLS 1.0/1.1 disabled and DNS over HTTPS (DoH) supported'; rat = 'Disabling TLS 1.0/1.1 prevents cryptographic downgrade attacks, while DNS over HTTPS encrypts DNS queries against spoofing.'; rem = 'Ensure TLS 1.0/1.1 are not enabled in SCHANNEL and set EnableAutoDoh = 2 in Dnscache\Parameters.'; risk = 'Low: automatically encrypts DNS queries when the configured DNS server supports DoH.' }
    'HOME-SYS-009' = @{ cat = 'Windows Settings';  title = 'Windows Script Host (WSH) disabled against .vbs/.js malware'; rat = 'Disabling WSH blocks automatic execution of VBScript (.vbs) and JScript (.js) malware droppers commonly used in phishing.'; rem = 'Set Enabled = 0 under HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings.'; risk = 'Low: blocks legacy .vbs/.js scripts; does not affect PowerShell.' }
    'HOME-SEC-009' = @{ cat = 'Advanced Security'; title = 'Secure PowerShell ExecutionPolicy (no Unrestricted or Bypass)'; rat = 'An overly permissive ExecutionPolicy allows unsigned or downloaded PowerShell scripts to run without restriction.'; rem = 'Set PowerShell ExecutionPolicy to RemoteSigned via Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine.'; risk = 'Low: allows local scripts while requiring a digital signature for scripts downloaded from the Internet.' }
    'HOME-UAC-004' = @{ cat = 'UAC';               title = 'Windows 11 Administrator Protection (JIT) enabled';          rat = 'Administrator Protection creates an isolated, hidden admin account with just-in-time tokens, preventing malware from silently inheriting permanent admin rights.'; rem = 'Enable Administrator Protection in Windows Security -> Account protection or set TypeOfAdminApprovalMode = 2 (Windows 11 24H2/25H2+).'; risk = 'Low on Windows 11 24H2/25H2+: prompts with Windows Hello or password for an isolated admin token.' }
    'HOME-FIL-007' = @{ cat = 'File Security';     title = 'No fileless persistence via WMI Event Subscriptions';        rat = 'Attackers abuse permanent WMI event subscriptions to maintain stealthy fileless persistence without creating startup files or Run keys.'; rem = 'Inspect root\subscription __EventFilter, CommandLineEventConsumer, and ActiveScriptEventConsumer and remove unauthorized entries.'; risk = 'None when removing unauthorized malware subscriptions.' }
    'HOME-FIL-008' = @{ cat = 'File Security';     title = 'No forced browser extensions via policy (Chrome / Edge)';   rat = 'Malware and infostealers frequently abuse ExtensionInstallForcelist policies to silently force-install malicious extensions and prevent removal.'; rem = 'Inspect ExtensionInstallForcelist keys for Chrome and Edge in HKLM/HKCU Policies and remove unrecognized entries.'; risk = 'Low on home PCs: lifts policy-enforced browser extension locks.' }
}

# Traduzioni complete in Tedesco (DE) per tutti i 58 controlli (Titolo, Categoria, Spiegazione, Rimedio, Rischi)
$script:TraduzioniControlliDE = @{
    'HOME-FW-001'  = @{ cat = 'Firewall';            title = 'Windows-Firewall auf allen Profilen aktiviert';                  rat = 'Die Firewall ist die erste Verteidigungslinie gegen unbefugte Netzwerkverbindungen.'; rem = 'Aktivieren Sie die Windows Defender Firewall fuer Domaenen-, Privat- und Oeffentliche Profile ueber Windows-Sicherheit oder PowerShell als Administrator.'; risk = 'Gering: Blockiert unerwuenschte eingehende Verbindungen bei normalem ausgehendem Datenverkehr.' }
    'HOME-UAC-001' = @{ cat = 'UAC';                 title = 'Benutzerkontensteuerung (UAC) aktiviert';                        rat = 'UAC schuetzt das System, indem vor Vorgaengen mit Administratorrechten eine Bestaetigung angefordert wird.'; rem = 'Aktivieren Sie UAC (EnableLUA = 1) in den Windows-Einstellungen oder per PowerShell als Administrator. Neustart erforderlich.'; risk = 'Gering: Windows fragt vor administrativen Aenderungen nach.' }
    'HOME-UAC-002' = @{ cat = 'UAC';                 title = 'UAC erfordert Bestaetigung fuer Rechteerhoehung';                rat = 'Wenn UAC Rechte ohne Nachfrage vergibt, kann Schadsoftware unbemerkt Administratorrechte erlangen.'; rem = 'Konfigurieren Sie UAC so, dass auf dem sicheren Desktop eine Zustimmung angefordert wird (ConsentPromptBehaviorAdmin = 2 oder 5).'; risk = 'Gering: Zeigt einen Bestaetigungsdialog an, wenn ein Programm Administratorrechte anfordert.' }
    'HOME-UAC-003' = @{ cat = 'UAC';                 title = 'UAC erkennt Anwendungsinstallationen';                           rat = 'Die Installationserkennung verhindert unbefugte Softwareinstallationen ohne erhoehte Rechte.'; rem = 'Aktivieren Sie die Installationserkennung fuer UAC (EnableInstallerDetection = 1).'; risk = 'Sehr gering: Stellt sicher, dass Installationspakete mit Administratorzustimmung ausgefuehrt werden.' }
    'HOME-ACC-001' = @{ cat = 'Konten';              title = 'Integriertes Gastkonto deaktiviert';                             rat = 'Das Gastkonto ermoeglicht anonymen lokalen Zugriff ohne Anmeldedaten.'; rem = 'Deaktivieren Sie das integrierte Gastkonto (SID endet auf -501) per PowerShell als Administrator.'; risk = 'Sehr gering: Verhindert nicht authentifizierte lokale Anmeldungen.' }
    'HOME-ACC-002' = @{ cat = 'Konten';              title = 'Integriertes lokales Administratorkonto deaktiviert';            rat = 'Das Standard-Administratorkonto (-500) ist ein Hauptziel fuer Brute-Force-Angriffe.'; rem = 'Deaktivieren Sie das integrierte Administratorkonto (SID -500), nachdem Sie geprueft haben, dass ein anderes Administratorkonto existiert.'; risk = 'Mittel: Stellen Sie sicher, dass ein weiteres aktives Administratorkonto vorhanden ist.' }
    'HOME-ACC-003' = @{ cat = 'Konten';              title = 'Kein aktives lokales Konto ohne Kennwort';                       rat = 'Konten ohne Kennwort ermoeglichen jedem mit physischem oder Netzwerkzugriff die Anmeldung.'; rem = 'Legen Sie fuer jedes aktive lokale Konto unter Windows-Einstellungen -> Konten -> Anmeldeoptionen ein starkes Kennwort fest.'; risk = 'Gering: Benutzer muessen bei der Anmeldung ein Kennwort oder eine Windows Hello-PIN eingeben.' }
    'HOME-UPD-001' = @{ cat = 'Updates';             title = 'Automatische Updates von Windows Update aktiviert';              rat = 'Sicherheitsupdates beheben bekannte Schwachstellen; ohne sie bleibt der PC ungeschuetzt.'; rem = 'Stellen Sie sicher, dass der Dienst Windows Update (wuauserv) nicht deaktiviert ist und NoAutoUpdate entfernt wurde.'; risk = 'Gering: Windows laedt Sicherheitsupdates regelmaessig herunter und installiert sie.' }
    'HOME-UPD-002' = @{ cat = 'Updates';             title = 'Authentischer Windows Update-Server (kein fremder WSUS)';        rat = 'Schadsoftware kann Windows Update auf einen manipulierten Server umleiten, um Sicherheitsupdates zu blockieren.'; rem = 'Entfernen Sie nicht autorisierte WUServer-Richtlinien in der Registrierung, damit Updates direkt von Microsoft bezogen werden.'; risk = 'Gering auf Heim-PCs: Stellt die offiziellen Microsoft Update-Server wieder her.' }
    'HOME-AV-001'  = @{ cat = 'Antivirus';           title = 'Windows Defender Echtzeitschutz aktiviert';                      rat = 'Der Echtzeitschutz prueft Dateien beim Zugriff sofort und blockiert Malware unmittelbar.'; rem = 'Aktivieren Sie den Echtzeitschutz unter Windows-Sicherheit -> Viren- & Bedrohungsschutz.'; risk = 'Sehr gering: Unverzichtbarer Basisschutz gegen Malware und Ransomware.' }
    'HOME-AV-002'  = @{ cat = 'Antivirus';           title = 'Antivirus-Signaturen aktuell (<= 7 Tage)';                       rat = 'Veraltete Virendefinitionen koennen neue Schadsoftware-Bedrohungen nicht erkennen.'; rem = 'Aktualisieren Sie die Virendefinitionen ueber Windows-Sicherheit oder Update-MpSignature.'; risk = 'Keines: Aktualisiert nur die Signaturdatenbank.' }
    'HOME-AV-003'  = @{ cat = 'Antivirus';           title = 'Keine aktiven Viren oder Malware-Bedrohungen erkannt';           rat = 'Aktive Bedrohungen weisen auf eine laufende Infektion oder noch nicht isolierte Schadsoftware hin.'; rem = 'Oeffnen Sie Windows-Sicherheit -> Schutzverlauf oder starten Sie eine Ueberpruefung, um erkannte Bedrohungen unter Quarantaene zu stellen.'; risk = 'Keines: Isoliert und entfernt infizierte Dateien.' }
    'HOME-AV-004'  = @{ cat = 'Antivirus';           title = 'Pruefung heruntergeladener Dateien (IOAV) & Verhaltensueberwachung aktiv'; rat = 'IOAV scannt alle aus Browsern/E-Mails geladenen Dateien, waehrend die Verhaltensueberwachung Ransomware stoppt.'; rem = 'Aktivieren Sie Verhaltensueberwachung und IOAV-Schutz in den Windows Defender-Einstellungen.'; risk = 'Sehr gering: Stellt sicher, dass heruntergeladene Dateien sofort geprueft werden.' }
    'HOME-AV-005'  = @{ cat = 'Antivirus';           title = 'Blockierung potenziell unerwuenschter Apps (PUA) aktiviert';     rat = 'Der PUA-Schutz blockiert Adware, Bundleware, Krypto-Miner und unerwuenschte Zusatzsoftware.'; rem = 'Aktivieren Sie den PUA-Schutz (1) unter Windows-Sicherheit -> App- & Browsersteuerung -> Zuverlaessigkeitsbasierter Schutz.'; risk = 'Gering: Kann Installationsprogramme melden, die Werbesoftware mitinstallieren.' }
    'HOME-AV-006'  = @{ cat = 'Antivirus';           title = 'Manipulationsschutz und Cloud-Schutz (MAPS) aktiviert';          rat = 'Der Manipulationsschutz verhindert das Deaktivieren von Defender durch Malware; Cloud-MAPS blockiert Zero-Day-Bedrohungen.'; rem = 'Aktivieren Sie Manipulationsschutz und Cloudbasierten Schutz unter Windows-Sicherheit -> Viren- & Bedrohungsschutz.'; risk = 'Sehr gering: Staerkt die Abwehr gegen neue Malware.' }
    'HOME-AV-007'  = @{ cat = 'Antivirus';           title = 'Regelmaessiger Antivirus-Scan innerhalb von 14 Tagen durchgefuehrt'; rat = 'Regelmaessige Scans erkennen ruhende Bedrohungen auf der Festplatte.'; rem = 'Fuehren Sie eine Schnellueberpruefung oder vollstaendige Ueberpruefung mit Windows Defender durch.'; risk = 'Keines: Eine Schnellueberpruefung dauert nur wenige Minuten.' }
    'HOME-AV-008'  = @{ cat = 'Antivirus';           title = 'Keine gefaehrlichen Ordner- oder Dateiausschluesse in Defender'; rat = 'Malware fuegt oft C:\, Downloads, Temp oder .exe/.ps1 zu den Defender-Ausschluessen hinzu, um sich zu verstecken.'; rem = 'Pruefen und entfernen Sie kritische Ausschluesse unter Windows-Sicherheit -> Viren- & Bedrohungsschutz -> Ausschluesse.'; risk = 'Gering: Stellt den vollstaendigen Virenschutz fuer alle Ordner wieder her.' }
    'HOME-FIL-001' = @{ cat = 'Dateisicherheit';     title = 'Keine getarnten Dateien mit doppelter Endung (Downloads/Temp)';  rat = 'Doppelte Dateiendungen (z. B. rechnung.pdf.exe, foto.jpg.scr) taeuschen Benutzer, damit sie Malware starten.'; rem = 'Pruefen Sie gemeldete Dateien in Downloads, Desktop oder Temp und loeschen Sie unbekannte ausfuehrbare Programme.'; risk = 'Keines: Listet verdaechtige Dateien nur schreibgeschuetzt zur Pruefung auf.' }
    'HOME-FIL-002' = @{ cat = 'Dateisicherheit';     title = 'Keine verdaechtigen oder verschleierten Befehle im Autostart (Run)'; rat = 'Malware traegt sich oft in Run/RunOnce-Schluessel ein, die auf Temp-Ordner oder versteckte PowerShell-Befehle (-enc) verweisen.'; rem = 'Pruefen Sie Task-Manager -> Autostart-Apps sowie die Run-Registrierungsschluessel und entfernen Sie unbekannte Eintraege.'; risk = 'Gering: Verhindert das automatische Mitstarten von Schadsoftware.' }
    'HOME-FIL-003' = @{ cat = 'Dateisicherheit';     title = 'Integritaet der Windows-hosts-Datei (keine Umleitung von Sicherheitsdomains)'; rat = 'Malware kann die hosts-Datei manipulieren, um den Zugriff auf Windows Update oder Antivirus-Websites zu blockieren.'; rem = 'Pruefen Sie C:\Windows\System32\drivers\etc\hosts und entfernen Sie Zeilen, die Microsoft- oder Sicherheitsdomains umleiten.'; risk = 'Gering: Die Standard-hosts-Datei von Windows enthaelt keine aktiven Umleitungen.' }
    'HOME-SYS-001' = @{ cat = 'Windows-Einstellungen'; title = 'Dateinamenerweiterungen im Explorer sichtbar';                 rat = 'Sichtbare Dateiendungen lassen ausfuehrbare Programme (.exe, .bat, .scr), die als Dokumente getarnt sind, sofort erkennen.'; rem = 'Aktivieren Sie im Datei-Explorer unter Anzeigen -> Einblenden -> Dateinamenerweiterungen (HideFileExt = 0).'; risk = 'Keines: Macht die tatsaechliche Endung jeder Datei sichtbar.' }
    'HOME-SYS-002' = @{ cat = 'Windows-Einstellungen'; title = 'AutoRun und AutoPlay fuer Wechseldatentraeger (USB) deaktiviert'; rat = 'Das Deaktivieren von AutoRun/AutoPlay verhindert das automatische Starten von Schadsoftware von infizierten USB-Sticks.'; rem = 'Deaktivieren Sie Automatische Wiedergabe unter Windows-Einstellungen -> Bluetooth & Geraete -> Automatische Wiedergabe.'; risk = 'Sehr gering: USB-Laufwerke werden einfach manuell im Explorer geoeffnet.' }
    'HOME-SYS-003' = @{ cat = 'Windows-Einstellungen'; title = 'Microsoft Defender SmartScreen fuer Apps und Dateien aktiviert'; rat = 'SmartScreen warnt vor dem Ausfuehren unbekannter oder potenziell gefaehrlicher Programme aus dem Internet.'; rem = 'Aktivieren Sie SmartScreen unter Windows-Sicherheit -> App- & Browsersteuerung -> Zuverlaessigkeitsbasierter Schutz.'; risk = 'Sehr gering: Schuetzt vor Phishing und schaedlichen Downloads.' }
    'HOME-SYS-004' = @{ cat = 'Windows-Einstellungen'; title = 'Kernisolierung / Speicherintegritaet (HVCI) aktiviert';          rat = 'Die Speicherintegritaet nutzt Hardwarevirtualisierung, um das Einschleusen von Schadcode in Windows-Kernelprozesse zu verhindern.'; rem = 'Aktivieren Sie die Speicherintegritaet unter Windows-Sicherheit -> Geraetesicherheit -> Details zur Kernisolierung und starten Sie neu.'; risk = 'Mittel: Neustart erforderlich; sehr alte, nicht zertifizierte Hardwaretreiber koennen inkompatibel sein.' }
    'HOME-SYS-005' = @{ cat = 'Windows-Einstellungen'; title = 'Anonyme Auflistung lokaler SAM-Konten blockiert';                rat = 'Verhindert, dass nicht authentifizierte Netzwerkbenutzer die Namen lokaler Benutzerkonten auslesen.'; rem = 'Setzen Sie RestrictAnonymousSAM auf 1 unter HKLM:\SYSTEM\CurrentControlSet\Control\Lsa.'; risk = 'Sehr gering: Empfohlene Standardeinstellung unter modernem Windows.' }
    'HOME-RDP-001' = @{ cat = 'Remotedesktop';       title = 'Remotedesktopprotokoll (RDP) deaktiviert';                       rat = 'RDP ist eines der haeufigsten Angriffsziele; deaktivieren Sie es, wenn kein Fernzugriff benoetigt wird.'; rem = 'Deaktivieren Sie Remotedesktop unter Windows-Einstellungen -> System -> Remotedesktop (fDenyTSConnections = 1).'; risk = 'Gering fuer Heimanwender: Schliesst den Fernzugriff ueber Port 3389.' }
    'HOME-NET-001' = @{ cat = 'Netzwerk';            title = 'Veraltetes SMBv1-Protokoll deaktiviert';                         rat = 'SMBv1 weist kritische Sicherheitsluecken auf (EternalBlue/WannaCry). Moderne Netzwerke nutzen SMBv2/SMBv3.'; rem = 'Deaktivieren Sie SMBv1 ueber Set-SmbServerConfiguration -EnableSMB1Protocol $false.'; risk = 'Gering: SMBv1 wird nur von sehr alten Geraeten (vor 2010) verwendet.' }
    'HOME-NET-002' = @{ cat = 'Netzwerk';            title = 'NetBIOS ueber TCP/IP auf Netzwerkadaptern deaktiviert';          rat = 'NetBIOS kann Systeminformationen preisgeben und Spoofing-Angriffe im lokalen Netzwerk ermoeglichen.'; rem = 'Deaktivieren Sie NetBIOS ueber TCP/IP (NetbiosOptions = 2) auf den Netzwerkschnittstellen.'; risk = 'Gering: Moderne Windows 10/11-Netzwerke nutzen DNS statt NetBIOS.' }
    'HOME-NET-003' = @{ cat = 'Netzwerk';            title = 'LLMNR-Multicast-Namensaufloesung deaktiviert';                   rat = 'LLMNR ist anfaellig fuer Poisoning-Angriffe im lokalen Netzwerk, bei denen Passwort-Hashes abgefangen werden koennen.'; rem = 'Deaktivieren Sie LLMNR durch EnableMulticast = 0 unter HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient.'; risk = 'Gering: Stattdessen wird die normale DNS-Aufloesung verwendet.' }
    'HOME-ENC-001' = @{ cat = 'Verschluesselung';    title = 'BitLocker-Verschluesselung auf Systemlaufwerk (C:) aktiv';       rat = 'Die vollstaendige Laufwerksverschluesselung schuetzt Ihre persoenlichen Dateien bei Verlust oder Diebstahl des PCs.'; rem = 'Aktivieren Sie Geraeteverschluesselung oder BitLocker auf C: unter Windows-Einstellungen -> Datenschutz & Sicherheit und sichern Sie den Wiederherstellungsschluessel.'; risk = 'Mittel: Bewahren Sie immer eine Kopie des BitLocker-Wiederherstellungsschluessels an einem sicheren Ort auf.' }
    'HOME-PRV-001' = @{ cat = 'Datenschutz';         title = 'Windows-Diagnosetelemetrie auf Minimalstufe eingestellt';        rat = 'Minimale Telemetrie begrenzt die Menge der an Microsoft gesendeten Diagnosedaten.'; rem = 'Stellen Sie Diagnosedaten unter Windows-Einstellungen -> Datenschutz & Sicherheit -> Diagnose & Feedback auf Nur erforderliche (AllowTelemetry = 1).'; risk = 'Sehr gering: Deaktiviert optionale Diagnosetelemetrie.' }
    'HOME-SEC-001' = @{ cat = 'Erweiterte Sicherheit'; title = 'Sicherer UEFI-Start (Secure Boot) aktiviert';                  rat = 'Secure Boot blockiert unsignierte Bootloader und schuetzt den PC vor Rootkits und Bootkits.'; rem = 'Aktivieren Sie Secure Boot in den UEFI/BIOS-Einstellungen Ihres Mainboards (nicht per PowerShell aenderbar).'; risk = 'Mittel: Stellen Sie sicher, dass das Systemlaufwerk GPT verwendet, bevor Sie Secure Boot im BIOS aktivieren.' }
    'HOME-SEC-002' = @{ cat = 'Erweiterte Sicherheit'; title = 'Schutz der lokalen Sicherheitsautoritaet (LSA / RunAsPPL) aktiv'; rat = 'Der LSA-Schutz verhindert, dass Tools zum Auslesen von Anmeldedaten (wie Mimikatz) auf den LSASS-Speicher zugreifen.'; rem = 'Aktivieren Sie den Schutz der lokalen Sicherheitsautoritaet unter Windows-Sicherheit -> Geraetesicherheit -> Kernisolierung.'; risk = 'Gering: Erfordert einen Systemneustart.' }
    'HOME-SEC-003' = @{ cat = 'Erweiterte Sicherheit'; title = 'PowerShell Script Block Logging aktiviert';                    rat = 'Die Skriptblockprotokollierung zeichnet ausgefuehrte PowerShell-Befehle in der Ereignisanzeige fuer Sicherheitsanalysen auf.'; rem = 'Aktivieren Sie PowerShell Script Block Logging (EnableScriptBlockLogging = 1) per Gruppenrichtlinie oder Registrierung.'; risk = 'Sehr gering: Erhoeht die Groesse des PowerShell-Ereignisprotokolls geringfuegig.' }
    'HOME-AV-009'  = @{ cat = 'Antivirus';           title = 'Ransomware-Schutz (Ueberwachter Ordnerzugriff) aktiviert';       rat = 'Der ueberwachte Ordnerzugriff hindert Ransomware und nicht vertrauenswuerdige Apps daran, persoenliche Dateien zu verschluesseln.'; rem = 'Aktivieren Sie den Ueberwachten Ordnerzugriff unter Windows-Sicherheit -> Viren- & Bedrohungsschutz -> Ransomware-Schutz.'; risk = 'Gering: Schuetzt Dokumente und Bilder; vertrauenswuerdige Programme koennen zugelassen werden.' }
    'HOME-AV-010'  = @{ cat = 'Antivirus';           title = 'Microsoft Defender Netzwerkschutz (Exploit Guard) aktiv';        rat = 'Der Netzwerkschutz blockiert ausgehende Verbindungen zu bekannten Phishing-Websites, C2-Servern und Exploit-Domains.'; rem = 'Aktivieren Sie den Netzwerkschutz ueber Set-MpPreference -EnableNetworkProtection Enabled.'; risk = 'Sehr gering: Blockiert boesartige Domains systemweit in allen Anwendungen.' }
    'HOME-FIL-004' = @{ cat = 'Dateisicherheit';     title = 'Keine verdaechtigen oder verschleierten Geplanten Aufgaben';     rat = 'Malware erstellt haeufig Geplante Aufgaben (Scheduled Tasks), die Skripte aus Temp/Public oder verschleierte PowerShell starten.'; rem = 'Oeffnen Sie die Aufgabenplanung (taskschd.msc), pruefen Sie gemeldete Aufgaben und deaktivieren oder loeschen Sie unbekannte Tasks.'; risk = 'Gering: Entfernt automatische Hintergrund-Persistenz verdaechtiger Aufgaben.' }
    'HOME-FIL-005' = @{ cat = 'Dateisicherheit';     title = 'Keine Manipulation von Systemprogrammen (IFEO Debugger)';        rat = 'Angreifer nutzen Image File Execution Options (IFEO), um Eingabehilfen (sethc.exe), Task-Manager oder Defender umzuleiten.'; rem = 'Entfernen Sie unbefugte Debugger-Werte unter HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options.'; risk = 'Keines: Stellt die normale Ausfuehrung der Systemprogramme wieder her.' }
    'HOME-FIL-006' = @{ cat = 'Dateisicherheit';     title = 'Keine verdaechtigen Skripte im Autostart-Ordner (Startup)';      rat = 'Jedes Skript oder Programm im Benutzer- oder System-Autostart-Ordner wird bei jeder Anmeldung automatisch gestartet.'; rem = 'Oeffnen Sie shell:startup und shell:common startup und loeschen Sie unbekannte Skripte (.vbs, .js, .bat, .ps1).'; risk = 'Keines: Verhindert das automatische Starten unbekannter Skripte.' }
    'HOME-ACC-004' = @{ cat = 'Konten';              title = 'Kontosperrungsrichtlinie gegen Brute-Force-Angriffe aktiv';      rat = 'Ohne Kontosperrungsschwelle koennen Angreifer tausende Passwoerter pro Minute ausprobieren, ohne gesperrt zu werden.'; rem = 'Konfigurieren Sie eine Kontosperrungsschwelle (z. B. 5 Fehlversuche) ueber net accounts /lockoutthreshold:5.'; risk = 'Gering: Sperrt das Konto nach 5 falschen Passwoertern voruebergehend fuer 15 Minuten.' }
    'HOME-ACC-005' = @{ cat = 'Konten';              title = 'Anzahl lokaler Administratorkonten auf Minimum reduziert (<= 2)'; rat = 'Die Begrenzung der Administratorkonten verringert die Angriffsflaeche nach dem Prinzip der geringsten Rechte.'; rem = 'Pruefen Sie die Mitglieder der Gruppe Administratoren und wandeln Sie Zweitkonten in Standardbenutzer um.'; risk = 'Mittel: Stellen Sie sicher, dass mindestens ein aktives Administratorkonto erhalten bleibt.' }
    'HOME-NET-004' = @{ cat = 'Netzwerk';            title = 'Keine ungeschuetzten SMB-Netzwerkfreigaben exponiert';           rat = 'Offene Ordnerfreigaben im lokalen Netzwerk koennen von Ransomware oder im selben WLAN missbraucht werden.'; rem = 'Pruefen Sie aktive SMB-Freigaben (Get-SmbShare) und entfernen Sie nicht benoetigte Ordnerfreigaben.'; risk = 'Gering: Schliesst den Netzwerkzugriff auf freigegebene lokale Ordner.' }
    'HOME-NET-005' = @{ cat = 'Netzwerk';            title = 'Obligatorische digitale SMB-Signierung aktiv (Anti-Relay)';      rat = 'Erzwungene SMB-Signierung verhindert Man-in-the-Middle- und NTLM-Relay-Angriffe im lokalen Netzwerk.'; rem = 'Aktivieren Sie RequireSecuritySignature fuer SMB-Server und SMB-Client.'; risk = 'Gering: Alle modernen Windows-Systeme und NAS-Geraete unterstuetzen SMB-Signierung.' }
    'HOME-NET-006' = @{ cat = 'Netzwerk';            title = 'Windows-Remoteverwaltungsdienst (WinRM) deaktiviert';            rat = 'Auf Desktop-PCs und Laptops oeffnet WinRM Ports fuer PowerShell-Fernzugriff (5985/5986), die fuer Seitwaertsbewegungen genutzt werden.'; rem = 'Beenden und deaktivieren Sie den Dienst WinRM, wenn keine PowerShell-Fernverwaltung benoetigt wird.'; risk = 'Gering auf Desktop-PCs: Schliesst den Fernverwaltungsport 5985.' }
    'HOME-NET-007' = @{ cat = 'Netzwerk';            title = 'Automatische WPAD-Proxyerkennung deaktiviert (Anti-MITM)';       rat = 'Angreifer im lokalen Netzwerk koennen auf WPAD-Anfragen antworten, um den gesamten Webverkehr ueber einen fremden Proxy umzuleiten.'; rem = 'Setzen Sie DisableWpad = 1 unter HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad.'; risk = 'Sehr gering: Deaktiviert die automatische Suche nach nicht angeforderten WPAD-Proxys.' }
    'HOME-SYS-006' = @{ cat = 'Windows-Einstellungen'; title = 'WDigest-Klartext-Passwortspeicherung im RAM deaktiviert';      rat = 'Wenn WDigest UseLogonCredential aktiviert ist, speichert Windows Benutzerpasswoerter im Klartext im LSASS-Speicher.'; rem = 'Setzen Sie UseLogonCredential = 0 unter HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest.'; risk = 'Keines: Schuetzt Passwoerter vor dem Auslesen aus dem Arbeitsspeicher.' }
    'HOME-SYS-007' = @{ cat = 'Windows-Einstellungen'; title = 'Windows-Remoteunterstuetzung deaktiviert';                     rat = 'Das Deaktivieren der Remoteunterstuetzung verhindert unbefugte Fernwartungseinladungen.'; rem = 'Setzen Sie fAllowToGetHelp = 0 unter HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance.'; risk = 'Sehr gering: Deaktiviert die veraltete Windows-Remoteunterstuetzung.' }
    'HOME-SYS-008' = @{ cat = 'Windows-Einstellungen'; title = 'Dienst Remoteregistrierung (Remote Registry) deaktiviert';     rat = 'Der Dienst Remote Registry ermoeglicht Benutzern im Netzwerk das Lesen und Aendern Ihrer Windows-Registrierung aus der Ferne.'; rem = 'Beenden und deaktivieren Sie den Dienst RemoteRegistry (StartupType = Disabled).'; risk = 'Keines auf Heim-PCs und Einzelplatzrechnern.' }
    'HOME-SEC-006' = @{ cat = 'Erweiterte Sicherheit'; title = 'Microsoft-Sperrliste gefaehrdeter Treiber (Anti-BYOVD) aktiv'; rat = 'Blockiert bekannte verwundbare Kernel-Treiber, die bei Bring Your Own Vulnerable Driver (BYOVD)-Angriffen missbraucht werden.'; rem = 'Aktivieren Sie die Sperrliste gefaehrdeter Microsoft-Treiber unter Windows-Sicherheit -> Geraetesicherheit -> Kernisolierung.'; risk = 'Sehr gering: Blockiert nur Kernel-Treiber mit bekannten Sicherheitsluecken.' }
    'HOME-SEC-007' = @{ cat = 'Erweiterte Sicherheit'; title = 'Smart App Control (SAC) aktiv (Enforced oder Evaluation)';     rat = 'Smart App Control blockiert nicht vertrauenswuerdige, unsignierte oder potenziell schaedliche Anwendungen unter Windows 11.'; rem = 'Pruefen Sie Smart App Control unter Windows-Sicherheit -> App- & Browsersteuerung -> Smart App Control.'; risk = 'Hinweis: Smart App Control kann nur nach einer Neuinstallation von Windows 11 aktiviert werden.' }
    'HOME-AV-011'  = @{ cat = 'Antivirus';           title = 'Microsoft Defender Attack Surface Reduction (ASR)-Regeln aktiv'; rat = 'ASR-Regeln blockieren haeufige Ransomware- und Malware-Angriffswege wie LSASS-Anmeldedatendiebstahl und verschleierte Skripte.'; rem = 'Aktivieren Sie die wichtigsten ASR-Regeln (LSASS-Schutz und Blockierung verschleierter Skripte) ueber Add-MpPreference.'; risk = 'Gering: Schuetzt den LSASS-Speicher aktiv und blockiert verschleierte Skripte.' }
    'HOME-SEC-008' = @{ cat = 'Erweiterte Sicherheit'; title = 'TPM 2.0 Hardware-Sicherheitsmodul vorhanden und bereit';       rat = 'TPM 2.0 bildet den Hardware-Vertrauensanker fuer BitLocker, Windows Hello, Secure Boot und Credential Guard.'; rem = 'Aktivieren Sie TPM 2.0 (Intel PTT oder AMD fTPM) in den UEFI/BIOS-Einstellungen Ihres Mainboards.'; risk = 'Sehr gering: Zentrale Hardware-Sicherheitsanforderung von Windows 11.' }
    'HOME-NET-008' = @{ cat = 'Netzwerk';            title = 'Veraltetes TLS 1.0/1.1 deaktiviert und DNS over HTTPS (DoH) aktiv'; rat = 'Das Deaktivieren von TLS 1.0/1.1 verhindert Downgrade-Angriffe, waehrend DNS over HTTPS DNS-Abfragen gegen Spoofing verschluesselt.'; rem = 'Stellen Sie sicher, dass TLS 1.0/1.1 in SCHANNEL deaktiviert sind und setzen Sie EnableAutoDoh = 2 unter Dnscache\Parameters.'; risk = 'Gering: Verschluesselt DNS-Abfragen automatisch, wenn der DNS-Server DoH unterstuetzt.' }
    'HOME-SYS-009' = @{ cat = 'Windows-Einstellungen'; title = 'Windows Script Host (WSH) gegen .vbs/.js-Malware deaktiviert'; rat = 'Das Deaktivieren von WSH blockiert die automatische Ausfuehrung von VBScript (.vbs)- und JScript (.js)-Droppern.'; rem = 'Setzen Sie Enabled = 0 unter HKLM:\SOFTWARE\Microsoft\Windows Script Host\Settings.'; risk = 'Gering: Blockiert veraltete .vbs/.js-Skripte; hat keinen Einfluss auf PowerShell.' }
    'HOME-SEC-009' = @{ cat = 'Erweiterte Sicherheit'; title = 'Sichere PowerShell ExecutionPolicy (kein Unrestricted/Bypass)'; rat = 'Eine zu offene ExecutionPolicy ermoeglicht das ungehinderte Starten nicht signierter PowerShell-Skripte aus dem Internet.'; rem = 'Setzen Sie die ExecutionPolicy auf RemoteSigned ueber Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine.'; risk = 'Gering: Erlaubt lokale Skripte, erfordert aber eine digitale Signatur fuer Skripte aus dem Internet.' }
    'HOME-UAC-004' = @{ cat = 'UAC';                   title = 'Windows 11 Administrator Protection (JIT) aktiviert';           rat = 'Administrator Protection erstellt ein isoliertes Administratorkonto mit Just-in-Time-Rechten und schuetzt vor stiller Token-Uebernahme.'; rem = 'Aktivieren Sie Administrator Protection ueber TypeOfAdminApprovalMode = 2 (Windows 11 24H2/25H2+).'; risk = 'Gering ab Windows 11 24H2/25H2+: Erfordert Windows Hello oder Kennwort fuer temporaere Admin-Token.' }
    'HOME-FIL-007' = @{ cat = 'Dateisicherheit';       title = 'Keine dateilose Persistenz via WMI Event Subscriptions';        rat = 'Angreifer nutzen permanente WMI-Ereignisabonnements fuer versteckte, dateilose Persistenz ausserhalb von Run-Schluesseln.'; rem = 'Pruefen Sie root\subscription (__EventFilter, CommandLineEventConsumer, ActiveScriptEventConsumer) und entfernen Sie unbekannte Eintraege.'; risk = 'Keines beim Entfernen nicht autorisierter Malware-Abonnements.' }
    'HOME-FIL-008' = @{ cat = 'Dateisicherheit';       title = 'Keine per Richtlinie erzwungenen Browser-Erweiterungen';      rat = 'Schadsoftware nutzt ExtensionInstallForcelist in Chrome/Edge, um boesartige Erweiterungen dauerhaft und nicht entfernbar zu installieren.'; rem = 'Pruefen und loeschen Sie unbekannte Eintraege unter ExtensionInstallForcelist fuer Chrome und Edge in HKLM/HKCU.'; risk = 'Gering auf Heim-PCs: Hebt erzwungene Browser-Erweiterungsrichtlinien auf.' }
}

function Get-ValoreProprietaSicuro {
    <#
    .SYNOPSIS
        Legge in modo sicuro una proprieta' da un oggetto anche con StrictMode v2.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Oggetto,

        [Parameter(Mandatory = $true)]
        [string]$NomeProprieta,

        [Parameter(Mandatory = $false)]
        $ValorePredefinito = $null
    )

    if ($null -eq $Oggetto) {
        return $ValorePredefinito
    }

    if ($Oggetto -is [System.Collections.IDictionary]) {
        if ($Oggetto.Contains($NomeProprieta) -and $null -ne $Oggetto[$NomeProprieta]) {
            return $Oggetto[$NomeProprieta]
        }
        return $ValorePredefinito
    }

    $prop = $Oggetto.PSObject.Properties[$NomeProprieta]
    if ($null -ne $prop -and $null -ne $prop.Value) {
        return $prop.Value
    }

    return $ValorePredefinito
}

function Get-InfoStatoVista {
    <#
    .SYNOPSIS
        Restituisce icona testuale, etichetta e priorita' di ordinamento per uno stato (IT, EN o DE).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Stato = 'sconosciuto',

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    $statoNorm = if ([string]::IsNullOrWhiteSpace($Stato)) { 'sconosciuto' } else { $Stato.Trim().ToLowerInvariant() }

    switch ($statoNorm) {
        'fallito' {
            $short = switch ($Lingua) { 'EN' { 'Failed' } 'DE' { 'Fehlgeschlagen' } default { 'Fallito' } }
            return [PSCustomObject]@{ Status = 'fallito'; Icon = '[X]'; ShortLabel = $short; Label = "[X] $short"; Rank = 1 }
        }
        'errore' {
            $short = switch ($Lingua) { 'EN' { 'Error' } 'DE' { 'Fehler' } default { 'Errore' } }
            return [PSCustomObject]@{ Status = 'errore'; Icon = '[!]'; ShortLabel = $short; Label = "[!] $short"; Rank = 2 }
        }
        'sconosciuto' {
            $short = switch ($Lingua) { 'EN' { 'Unknown' } 'DE' { 'Unbekannt' } default { 'Sconosciuto' } }
            return [PSCustomObject]@{ Status = 'sconosciuto'; Icon = '[?]'; ShortLabel = $short; Label = "[?] $short"; Rank = 3 }
        }
        'superato' {
            $short = switch ($Lingua) { 'EN' { 'Passed' } 'DE' { 'Bestanden' } default { 'Superato' } }
            return [PSCustomObject]@{ Status = 'superato'; Icon = '[OK]'; ShortLabel = $short; Label = "[OK] $short"; Rank = 4 }
        }
        'non_applicabile' {
            $short = switch ($Lingua) { 'EN' { 'N/A' } 'DE' { 'N/Z' } default { 'Non applicabile' } }
            return [PSCustomObject]@{ Status = 'non_applicabile'; Icon = '[-]'; ShortLabel = $short; Label = "[-] $short"; Rank = 5 }
        }
        default {
            $short = switch ($Lingua) { 'EN' { 'Unknown' } 'DE' { 'Unbekannt' } default { 'Sconosciuto' } }
            return [PSCustomObject]@{ Status = $statoNorm; Icon = '[?]'; ShortLabel = $short; Label = "[?] $statoNorm"; Rank = 6 }
        }
    }
}

function Get-InfoGravitaVista {
    <#
    .SYNOPSIS
        Restituisce etichetta e priorita' di ordinamento (1 = piu' grave) per la gravita' (IT, EN o DE).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Gravita = 'medio',

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    $gravNorm = if ([string]::IsNullOrWhiteSpace($Gravita)) { 'non_specificata' } else { $Gravita.Trim().ToLowerInvariant() }

    switch ($gravNorm) {
        'critico'     { $lbl = switch ($Lingua) { 'EN' { 'Critical' } 'DE' { 'Kritisch' } default { 'Critico' } };     return [PSCustomObject]@{ Severity = 'critico';     Label = $lbl; Rank = 1 } }
        'alto'        { $lbl = switch ($Lingua) { 'EN' { 'High' }     'DE' { 'Hoch' }     default { 'Alto' } };        return [PSCustomObject]@{ Severity = 'alto';        Label = $lbl; Rank = 2 } }
        'medio'       { $lbl = switch ($Lingua) { 'EN' { 'Medium' }   'DE' { 'Mittel' }   default { 'Medio' } };       return [PSCustomObject]@{ Severity = 'medio';       Label = $lbl; Rank = 3 } }
        'basso'       { $lbl = switch ($Lingua) { 'EN' { 'Low' }      'DE' { 'Niedrig' }  default { 'Basso' } };       return [PSCustomObject]@{ Severity = 'basso';       Label = $lbl; Rank = 4 } }
        'informativo' { $lbl = switch ($Lingua) { 'EN' { 'Info' }     'DE' { 'Info' }     default { 'Informativo' } }; return [PSCustomObject]@{ Severity = 'informativo'; Label = $lbl; Rank = 5 } }
        default       { $lbl = switch ($Lingua) { 'EN' { 'N/A' }      'DE' { 'K.A.' }     default { 'N/D' } };         return [PSCustomObject]@{ Severity = $gravNorm;     Label = $lbl; Rank = 99 } }
    }
}

function Merge-RisultatoConControllo {
    <#
    .SYNOPSIS
        Unisce un singolo risultato del Runner con i metadati del controllo nel catalogo (IT, EN o DE).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Risultato,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$ControlloCatalogo = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    $id = [string](Get-ValoreProprietaSicuro -Oggetto $Risultato -NomeProprieta 'control_id' -ValorePredefinito 'ID-SCONOSCIUTO')
    $statoRaw = [string](Get-ValoreProprietaSicuro -Oggetto $Risultato -NomeProprieta 'status' -ValorePredefinito 'sconosciuto')

    $titolo = [string](Get-ValoreProprietaSicuro -Oggetto $ControlloCatalogo -NomeProprieta 'title' -ValorePredefinito $id)
    $categoria = [string](Get-ValoreProprietaSicuro -Oggetto $ControlloCatalogo -NomeProprieta 'category' -ValorePredefinito 'Generale')
    $gravitaRaw = [string](Get-ValoreProprietaSicuro -Oggetto $ControlloCatalogo -NomeProprieta 'severity' -ValorePredefinito '')

    if ($Lingua -eq 'EN' -and $script:TraduzioniControlliEN.ContainsKey($id)) {
        $tr = $script:TraduzioniControlliEN[$id]
        $titolo    = $tr.title
        $categoria = $tr.cat
    }
    elseif ($Lingua -eq 'DE' -and $script:TraduzioniControlliDE.ContainsKey($id)) {
        $trDe = $script:TraduzioniControlliDE[$id]
        $titolo    = $trDe.title
        $categoria = $trDe.cat
    }

    $infoStato = Get-InfoStatoVista -Stato $statoRaw -Lingua $Lingua
    $infoGrav  = Get-InfoGravitaVista -Gravita $gravitaRaw -Lingua $Lingua

    $osservato = Get-ValoreProprietaSicuro -Oggetto $Risultato -NomeProprieta 'observed' -ValorePredefinito $null
    $atteso    = Get-ValoreProprietaSicuro -Oggetto $Risultato -NomeProprieta 'expected' -ValorePredefinito $null
    $evidenza  = Get-ValoreProprietaSicuro -Oggetto $Risultato -NomeProprieta 'evidence' -ValorePredefinito $null
    $errore    = Get-ValoreProprietaSicuro -Oggetto $Risultato -NomeProprieta 'error' -ValorePredefinito $null
    $durata    = [int](Get-ValoreProprietaSicuro -Oggetto $Risultato -NomeProprieta 'duration_ms' -ValorePredefinito 0)

    return [PSCustomObject]@{
        ControlId     = $id
        Title         = $titolo
        Category      = $categoria
        Severity      = $infoGrav.Severity
        SeverityLabel = $infoGrav.Label
        SeverityRank  = $infoGrav.Rank
        Status        = $infoStato.Status
        StatusIcon    = $infoStato.Icon
        StatusShort   = $infoStato.ShortLabel
        StatusLabel   = $infoStato.Label
        StatusRank    = $infoStato.Rank
        Observed      = $osservato
        Expected      = $atteso
        Evidence      = $evidenza
        Error         = $errore
        DurationMs    = $durata
        ControlMeta   = $ControlloCatalogo
        ResultRaw     = $Risultato
    }
}

function Sort-RisultatiVista {
    <#
    .SYNOPSIS
        Ordina gli elementi della vista: falliti per gravita' (alta prima), poi
        errori/sconosciuti, poi superati, infine non applicabili.
    .PARAMETER Elementi
        Array di elementi vista (da Merge-RisultatoConControllo) o risultati.
    .OUTPUTS
        Array ordinato di PSCustomObject.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [array]$Elementi = @()
    )

    if ($null -eq $Elementi -or $Elementi.Count -eq 0) {
        return @()
    }

    $ordinati = @($Elementi | Sort-Object -Property @(
        @{ Expression = { Get-ValoreProprietaSicuro -Oggetto $_ -NomeProprieta 'StatusRank' -ValorePredefinito 99 }; Ascending = $true },
        @{ Expression = { Get-ValoreProprietaSicuro -Oggetto $_ -NomeProprieta 'SeverityRank' -ValorePredefinito 99 }; Ascending = $true },
        @{ Expression = { Get-ValoreProprietaSicuro -Oggetto $_ -NomeProprieta 'ControlId' -ValorePredefinito '' }; Ascending = $true }
    ))

    return $ordinati
}

function ConvertTo-RisultatiVista {
    <#
    .SYNOPSIS
        Converte i risultati del Runner e il catalogo nella lista ordinata per la UI (IT o EN).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [array]$Risultati = @(),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Catalogo = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    if ($null -eq $Risultati -or $Risultati.Count -eq 0) {
        return @()
    }

    $mappaControlli = @{}
    $controlliCat = Get-ValoreProprietaSicuro -Oggetto $Catalogo -NomeProprieta 'controls' -ValorePredefinito @()
    foreach ($c in $controlliCat) {
        $cid = Get-ValoreProprietaSicuro -Oggetto $c -NomeProprieta 'id' -ValorePredefinito $null
        if ($null -ne $cid) {
            $mappaControlli[[string]$cid] = $c
        }
    }

    $elementi = @()
    foreach ($r in $Risultati) {
        $id = [string](Get-ValoreProprietaSicuro -Oggetto $r -NomeProprieta 'control_id' -ValorePredefinito '')
        $meta = if ($mappaControlli.ContainsKey($id)) { $mappaControlli[$id] } else { $null }
        $elementi += (Merge-RisultatoConControllo -Risultato $r -ControlloCatalogo $meta -Lingua $Lingua)
    }

    $ordinati = @(Sort-RisultatiVista -Elementi $elementi)
    return $ordinati
}

function Select-RisultatiVista {
    <#
    .SYNOPSIS
        Filtra la lista di elementi vista combinando stato, gravita', categoria e testo.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [array]$Elementi = @(),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Stato = 'Tutti',

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Gravita = 'Tutte',

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Categoria = 'Tutte',

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$TestoRicerca = ''
    )

    if ($null -eq $Elementi -or $Elementi.Count -eq 0) {
        return @()
    }

    $statoNorm = if ([string]::IsNullOrWhiteSpace($Stato)) { 'tutti' } else { $Stato.Trim().ToLowerInvariant() }
    $gravNorm  = if ([string]::IsNullOrWhiteSpace($Gravita)) { 'tutte' } else { $Gravita.Trim().ToLowerInvariant() }
    $catNorm   = if ([string]::IsNullOrWhiteSpace($Categoria)) { 'tutte' } else { $Categoria.Trim() }
    $query     = if ([string]::IsNullOrWhiteSpace($TestoRicerca)) { '' } else { $TestoRicerca.Trim() }

    $filtrati = @()
    foreach ($el in $Elementi) {
        # 1. Filtro Stato
        if ($statoNorm -ne 'tutti' -and $statoNorm -ne 'all' -and $statoNorm -ne 'alle') {
            $elStato      = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'Status' -ValorePredefinito '')
            $elStatoShort = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'StatusShort' -ValorePredefinito '')
            if ($elStato.ToLowerInvariant() -ne $statoNorm -and $elStatoShort.ToLowerInvariant() -ne $statoNorm) {
                continue
            }
        }

        # 2. Filtro Gravita
        if ($gravNorm -ne 'tutte' -and $gravNorm -ne 'tutti' -and $gravNorm -ne 'all' -and $gravNorm -ne 'alle') {
            $elGrav    = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'Severity' -ValorePredefinito '')
            $elGravLbl = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'SeverityLabel' -ValorePredefinito '')
            if ($elGrav.ToLowerInvariant() -ne $gravNorm -and $elGravLbl.ToLowerInvariant() -ne $gravNorm) {
                continue
            }
        }

        # 3. Filtro Categoria
        if ($catNorm.ToLowerInvariant() -ne 'tutte' -and $catNorm.ToLowerInvariant() -ne 'tutti' -and $catNorm.ToLowerInvariant() -ne 'all' -and $catNorm.ToLowerInvariant() -ne 'alle') {
            $elCat = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'Category' -ValorePredefinito '')
            if (-not $elCat.Equals($catNorm, [System.StringComparison]::OrdinalIgnoreCase)) {
                continue
            }
        }

        # 4. Ricerca testuale su Title e ControlId
        if ($query -ne '') {
            $elTitolo = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'Title' -ValorePredefinito '')
            $elId     = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'ControlId' -ValorePredefinito '')
            $trovatoTitolo = ($elTitolo.IndexOf($query, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
            $trovatoId     = ($elId.IndexOf($query, [System.StringComparison]::OrdinalIgnoreCase) -ge 0)
            if (-not $trovatoTitolo -and -not $trovatoId) {
                continue
            }
        }

        $filtrati += $el
    }

    return $filtrati
}

function Measure-ConteggiRisultati {
    <#
    .SYNOPSIS
        Calcola i conteggi per ciascuno stato a partire da risultati grezzi o elementi vista.
    .PARAMETER Elementi
        Array di risultati o elementi vista.
    .OUTPUTS
        PSCustomObject con proprieta': superato, fallito, sconosciuto, non_applicabile, errore, totale.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [array]$Elementi = @()
    )

    $conteggi = @{
        superato        = 0
        fallito         = 0
        sconosciuto     = 0
        non_applicabile = 0
        errore          = 0
    }

    if ($null -ne $Elementi) {
        foreach ($el in $Elementi) {
            if ($null -eq $el) { continue }
            $stato = Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'Status' -ValorePredefinito $null
            if ($null -eq $stato) {
                $stato = Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'status' -ValorePredefinito 'sconosciuto'
            }
            $chiave = ([string]$stato).ToLowerInvariant()
            if ($conteggi.ContainsKey($chiave)) {
                $conteggi[$chiave] = $conteggi[$chiave] + 1
            }
            else {
                $conteggi['sconosciuto'] = $conteggi['sconosciuto'] + 1
            }
        }
    }

    $totale = $conteggi['superato'] + $conteggi['fallito'] + $conteggi['sconosciuto'] + $conteggi['non_applicabile'] + $conteggi['errore']

    return [PSCustomObject]@{
        superato        = $conteggi['superato']
        fallito         = $conteggi['fallito']
        sconosciuto     = $conteggi['sconosciuto']
        non_applicabile = $conteggi['non_applicabile']
        errore          = $conteggi['errore']
        totale          = $totale
    }
}

function Format-DettaglioControllo {
    <#
    .SYNOPSIS
        Costruisce l'oggetto strutturato per il pannello di dettaglio del controllo.
    .DESCRIPTION
        Gestisce in modo sicuro campi mancanti o null.
        Se il comando di rimedio (command) e' null, imposta HaComando = $false
        e restituisce solo il testo del rimedio.
        Non espone mai stack trace grezzi nel messaggio utente per gli errori.
    .PARAMETER Elemento
        Elemento vista (da Merge-RisultatoConControllo) oppure oggetto personalizzato.
    .PARAMETER Modalita
        'Semplice' (predefinito) oppure 'Tecnico'.
    .OUTPUTS
        PSCustomObject con tutti i campi formattati per il pannello dettaglio.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        $Elemento = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Semplice', 'Tecnico')]
        [string]$Modalita = 'Semplice',

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lingua = 'IT'
    )

    $isEn = ($Lingua -eq 'EN')
    $isDe = ($Lingua -eq 'DE')

    if ($null -eq $Elemento) {
        $titVuoto = switch ($Lingua) {
            'EN' { 'No control selected' }
            'DE' { 'Keine Sicherheitspruefung ausgewaehlt' }
            default { 'Nessun controllo selezionato' }
        }
        $spiegVuota = switch ($Lingua) {
            'EN' { 'Select a control from the table on the left to view its details.' }
            'DE' { 'Waehlen Sie links in der Tabelle eine Sicherheitspruefung aus, um Details anzuzeigen.' }
            default { 'Seleziona un controllo dalla tabella per visualizzare i dettagli.' }
        }
        $spiegTecVuota = switch ($Lingua) {
            'EN' { 'Select a control from the table on the left to view technical details.' }
            'DE' { 'Waehlen Sie links in der Tabelle eine Sicherheitspruefung aus, um technische Details anzuzeigen.' }
            default { 'Seleziona un controllo dalla tabella per visualizzare i dettagli tecnici.' }
        }
        return [PSCustomObject]@{
            Selezionato          = $false
            ControlId            = ''
            Title                = $titVuoto
            Category             = '-'
            SeverityLabel        = '-'
            Status               = 'sconosciuto'
            StatusLabel          = '-'
            Modalita             = $Modalita
            SpiegazioneSemplice  = $spiegVuota
            SpiegazioneTecnica   = $spiegTecVuota
            TestoSpiegazione     = $spiegVuota
            ValoreAtteso         = '-'
            ValoreOsservato      = '-'
            TestoRimedio         = '-'
            ComandoRimedio       = $null
            HaComando            = $false
            NoteRischi           = '-'
            MessaggioErrore      = $null
            DettaglioErroreLog   = $null
        }
    }

    $meta = Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'ControlMeta' -ValorePredefinito $Elemento
    $raw  = Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'ResultRaw' -ValorePredefinito $Elemento

    $id = [string](Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'ControlId' -ValorePredefinito (
        Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'id' -ValorePredefinito (
            Get-ValoreProprietaSicuro -Oggetto $raw -NomeProprieta 'control_id' -ValorePredefinito 'N/D'
        )
    ))

    $titolo = [string](Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'Title' -ValorePredefinito (
        Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'title' -ValorePredefinito $id
    ))

    $categoria = [string](Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'Category' -ValorePredefinito (
        Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'category' -ValorePredefinito 'Generale'
    ))

    $stato = [string](Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'Status' -ValorePredefinito (
        Get-ValoreProprietaSicuro -Oggetto $raw -NomeProprieta 'status' -ValorePredefinito 'sconosciuto'
    ))
    $infoStato = Get-InfoStatoVista -Stato $stato -Lingua $Lingua

    $gravitaRaw = [string](Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'Severity' -ValorePredefinito (
        Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'severity' -ValorePredefinito ''
    ))
    $infoGrav = Get-InfoGravitaVista -Gravita $gravitaRaw -Lingua $Lingua

    # Spiegazione semplice (rationale / simple_explanation)
    $spiegazioneSemplice = Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'simple_explanation' -ValorePredefinito $null
    if ([string]::IsNullOrWhiteSpace([string]$spiegazioneSemplice)) {
        $spiegazioneSemplice = Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'rationale' -ValorePredefinito $null
    }
    if ([string]::IsNullOrWhiteSpace([string]$spiegazioneSemplice)) {
        $spiegazioneSemplice = switch ($Lingua) {
            'EN' { "No explanation available in the catalog for this control." }
            'DE' { "Keine Erklaerung im Katalog fuer diese Pruefung verfuegbar." }
            default { "Nessuna spiegazione disponibile nel catalogo per questo controllo." }
        }
    }

    if ($isEn -and $script:TraduzioniControlliEN.ContainsKey($id)) {
        $trEn = $script:TraduzioniControlliEN[$id]
        $titolo              = $trEn.title
        $categoria           = $trEn.cat
        $spiegazioneSemplice = $trEn.rat
    }
    elseif ($isDe -and $script:TraduzioniControlliDE.ContainsKey($id)) {
        $trDe = $script:TraduzioniControlliDE[$id]
        $titolo              = $trDe.title
        $categoria           = $trDe.cat
        $spiegazioneSemplice = $trDe.rat
    }

    # Spiegazione tecnica (description + check + riferimenti + evidenza)
    $descrizioneTecnica = Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'technical_explanation' -ValorePredefinito $null
    if ([string]::IsNullOrWhiteSpace([string]$descrizioneTecnica)) {
        $descrizioneTecnica = Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'description' -ValorePredefinito $null
    }
    if ([string]::IsNullOrWhiteSpace([string]$descrizioneTecnica)) {
        $descrizioneTecnica = $spiegazioneSemplice
    }

    $riferimenti = Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'references' -ValorePredefinito @()
    $edizioni    = Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'editions' -ValorePredefinito @()
    $evidenza    = Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'Evidence' -ValorePredefinito (
        Get-ValoreProprietaSicuro -Oggetto $raw -NomeProprieta 'evidence' -ValorePredefinito $null
    )
    $durata = Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'DurationMs' -ValorePredefinito (
        Get-ValoreProprietaSicuro -Oggetto $raw -NomeProprieta 'duration_ms' -ValorePredefinito 0
    )

    $sbTecnico = New-Object System.Text.StringBuilder
    [void]$sbTecnico.AppendLine([string]$descrizioneTecnica)
    [void]$sbTecnico.AppendLine("")
    [void]$sbTecnico.AppendLine("ID Controllo: $id")
    if ($null -ne $edizioni -and @($edizioni).Count -gt 0) {
        [void]$sbTecnico.AppendLine("Edizioni applicabili: $(@($edizioni) -join ', ')")
    }
    [void]$sbTecnico.AppendLine("Durata rilevamento: $durata ms")
    if ($null -ne $evidenza) {
        $evidenzaJson = ($evidenza | ConvertTo-Json -Compress -Depth 4)
        [void]$sbTecnico.AppendLine("Evidenza raccolta: $evidenzaJson")
    }
    if ($null -ne $riferimenti -and @($riferimenti).Count -gt 0) {
        [void]$sbTecnico.AppendLine("Riferimenti: $(@($riferimenti) -join '; ')")
    }
    $spiegazioneTecnica = $sbTecnico.ToString().Trim()

    # Valore atteso e trovato
    $attesoRaw = Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'Expected' -ValorePredefinito (
        Get-ValoreProprietaSicuro -Oggetto $raw -NomeProprieta 'expected' -ValorePredefinito $null
    )
    $osservatoRaw = Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'Observed' -ValorePredefinito (
        Get-ValoreProprietaSicuro -Oggetto $raw -NomeProprieta 'observed' -ValorePredefinito $null
    )
    $erroreRaw = Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'Error' -ValorePredefinito (
        Get-ValoreProprietaSicuro -Oggetto $raw -NomeProprieta 'error' -ValorePredefinito $null
    )

    $valoreAtteso = if ($null -ne $attesoRaw -and [string]$attesoRaw -ne '') { [string]$attesoRaw } else { 'Non specificato' }

    # Gestione messaggio comprensibile per errori (mai stack trace nella UI)
    $messaggioErrore = $null
    if ($infoStato.Status -eq 'errore') {
        $messaggioErrore = "Si e' verificato un imprevisto durante la verifica di questo controllo. Il sistema non e' stato modificato. Esporta il report con il log tecnico per i dettagli."
    }

    $valoreOsservato = if ($null -ne $osservatoRaw -and [string]$osservatoRaw -ne '') {
        [string]$osservatoRaw
    }
    elseif ($infoStato.Status -eq 'errore') {
        "Verifica non completata a causa di un errore del collettore"
    }
    else {
        'Non disponibile'
    }

    # Rimedio: controlla prima se il controllo ha proprieta' esplicite (remediation / command)
    $bloccoRimedio = Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'remediation' -ValorePredefinito $null
    $haProprietaCommandEsplicita = (
        ($null -ne $meta -and $null -ne $meta.PSObject.Properties['command']) -or
        ($null -ne $Elemento -and $null -ne $Elemento.PSObject.Properties['command']) -or
        ($null -ne $bloccoRimedio)
    )

    $testoRimedio = $null
    $comandoRimedio = $null
    $noteRischi = $null

    if ($null -ne $bloccoRimedio) {
        $testoRimedio   = Get-ValoreProprietaSicuro -Oggetto $bloccoRimedio -NomeProprieta 'text' -ValorePredefinito $null
        $comandoRimedio = Get-ValoreProprietaSicuro -Oggetto $bloccoRimedio -NomeProprieta 'command' -ValorePredefinito $null
        $noteRischi     = Get-ValoreProprietaSicuro -Oggetto $bloccoRimedio -NomeProprieta 'risk' -ValorePredefinito $null
    }
    else {
        $testoRimedio   = Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'remediation_text' -ValorePredefinito $null
        $comandoRimedio = Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'command' -ValorePredefinito (
            Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'command' -ValorePredefinito $null
        )
        $noteRischi     = Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'risk_notes' -ValorePredefinito $null
    }

    # Se il controllo nel catalogo non ha il blocco remediation, usa la mappa statica della fetta (se presente)
    if (-not $haProprietaCommandEsplicita -and $script:RimediStaticiFetta.ContainsKey($id)) {
        $statico = $script:RimediStaticiFetta[$id]
        if ([string]::IsNullOrWhiteSpace([string]$testoRimedio))   { $testoRimedio   = $statico.text }
        if ($null -eq $comandoRimedio)                            { $comandoRimedio = $statico.command }
        if ([string]::IsNullOrWhiteSpace([string]$noteRischi))     { $noteRischi     = $statico.risk }
    }

    if ($isEn -and (-not $haProprietaCommandEsplicita) -and $script:TraduzioniControlliEN.ContainsKey($id)) {
        $trEnRem      = $script:TraduzioniControlliEN[$id]
        $testoRimedio = $trEnRem.rem
        $noteRischi   = $trEnRem.risk
    }
    elseif ($isDe -and (-not $haProprietaCommandEsplicita) -and $script:TraduzioniControlliDE.ContainsKey($id)) {
        $trDeRem      = $script:TraduzioniControlliDE[$id]
        $testoRimedio = $trDeRem.rem
        $noteRischi   = $trDeRem.risk
    }

    if ([string]::IsNullOrWhiteSpace([string]$testoRimedio)) {
        $testoRimedio = switch ($Lingua) {
            'EN' { "Manually verify this setting in Windows 11 Settings or Control Panel." }
            'DE' { "Ueberpruefen Sie diese Einstellung manuell in den Windows 11-Einstellungen oder der Systemsteuerung." }
            default { "Verifica manualmente questa impostazione nel Pannello di controllo o nelle Impostazioni di sicurezza di Windows 11." }
        }
    }

    if ([string]::IsNullOrWhiteSpace([string]$noteRischi)) {
        $noteRischi = switch ($Lingua) {
            'EN' { "Evaluate the impact before applying manual configuration changes." }
            'DE' { "Pruefen Sie die Auswirkungen, bevor Sie manuelle Konfigurationsaenderungen vornehmen." }
            default { "Valuta l'impatto prima di applicare modifiche manuali alla configurazione del sistema." }
        }
    }

    # Se command e' null o stringa vuota, HaComando = $false (mostra solo il testo)
    $haComando = (-not [string]::IsNullOrWhiteSpace([string]$comandoRimedio))
    if (-not $haComando) {
        $comandoRimedio = $null
    }

    $testoSpiegazioneAttiva = if ($Modalita -eq 'Tecnico') { $spiegazioneTecnica } else { [string]$spiegazioneSemplice }

    return [PSCustomObject]@{
        Selezionato          = $true
        ControlId            = $id
        Title                = $titolo
        Category             = $categoria
        SeverityLabel        = $infoGrav.Label
        Status               = $infoStato.Status
        StatusLabel          = $infoStato.Label
        Modalita             = $Modalita
        SpiegazioneSemplice  = [string]$spiegazioneSemplice
        SpiegazioneTecnica   = $spiegazioneTecnica
        TestoSpiegazione     = $testoSpiegazioneAttiva
        ValoreAtteso         = $valoreAtteso
        ValoreOsservato      = $valoreOsservato
        TestoRimedio         = [string]$testoRimedio
        ComandoRimedio       = $comandoRimedio
        HaComando            = $haComando
        NoteRischi           = [string]$noteRischi
        MessaggioErrore      = $messaggioErrore
        DettaglioErroreLog   = $erroreRaw
    }
}

function Get-NomeFileExport {
    <#
    .SYNOPSIS
        Restituisce un nome file predefinito con data e ora per l'export.
    .PARAMETER Estensione
        'json' oppure 'html'.
    .PARAMETER DataRiferimento
        Data/ora opzionale (utile per i test).
    .OUTPUTS
        Stringa con il nome del file, es. 'scanner_sicurezza_20261117_140000.json'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet('json', 'html', 'log')]
        [string]$Estensione = 'json',

        [Parameter(Mandatory = $false)]
        [datetime]$DataRiferimento = (Get-Date)
    )

    $timbro = $DataRiferimento.ToString('yyyyMMdd_HHmmss')
    return "scanner_sicurezza_${timbro}.${Estensione}"
}

# =============================================================================
# MODULO: src\ui\Start-ScannerUI.ps1
# =============================================================================
<#
.SYNOPSIS
    Avvia l'interfaccia grafica WPF per lo scanner di sicurezza Windows 11.

.DESCRIPTION
    Carica il layout XAML da src/ui/MainWindow.xaml tramite XamlReader,
    collega i controlli con FindName, gestisce il tema scuro/chiaro completo,
    la localizzazione completa trilingue (IT / EN / DE) con selettore esplicito,
    i filtri, il pannello di dettaglio, l'export JSON/HTML e l'esecuzione
    asincrona della scansione e dell'assistente IA Ollama in Runspace separati.
    Il codice e' in SOLA LETTURA e riusa esattamente il motore di src/core.
#>

Set-StrictMode -Version 2

function Update-TemaFinestra {
    <#
    .SYNOPSIS
        Applica il dizionario completo di colori del tema Scuro o Chiaro alle risorse della finestra.
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
            'BgSurface'        = '#111827'
            'BgElevated'       = '#1E293B'
            'BgHeader'         = '#060911'
            'TextHeader'       = '#F8FAFC'
            'BgSubtle'         = '#0F172A'
            'BgInput'          = '#0F172A'
            'BgAlternating'    = '#131C2E'
            'SelectedRowBg'    = '#1E3A8A'
            'SelectedRowFg'    = '#FFFFFF'
            'HoverRowBg'       = '#1E293B'
            'TextPrimary'      = '#F1F5F9'
            'TextSecondary'    = '#94A3B8'
            'BorderSubtle'     = '#1E293B'
            'BorderStrong'     = '#334155'
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
            'BgElevated'       = '#F8FAFC'
            'BgHeader'         = '#0F172A'
            'TextHeader'       = '#F8FAFC'
            'BgSubtle'         = '#F8FAFC'
            'BgInput'          = '#FFFFFF'
            'BgAlternating'    = '#F8FAFC'
            'SelectedRowBg'    = '#DBEAFE'
            'SelectedRowFg'    = '#1E3A8A'
            'HoverRowBg'       = '#EFF6FF'
            'TextPrimary'      = '#0F172A'
            'TextSecondary'    = '#475569'
            'BorderSubtle'     = '#E2E8F0'
            'BorderStrong'     = '#CBD5E1'
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

function Test-SessioneTerminaleSsh {
    <#
    .SYNOPSIS
        Rileva se PowerShell e' in esecuzione all'interno di una sessione SSH o in Sessione 0
        priva di desktop grafico interattivo (dove una finestra WPF rimarrebbe invisibile/bloccata).
    #>
    [CmdletBinding()]
    param()

    if (-not [string]::IsNullOrWhiteSpace($env:SSH_CONNECTION) -or
        -not [string]::IsNullOrWhiteSpace($env:SSH_CLIENT) -or
        -not [string]::IsNullOrWhiteSpace($env:SSH_TTY)) {
        return $true
    }

    try {
        if (-not [Environment]::UserInteractive) {
            return $true
        }
        $procCorr = Get-Process -Id $PID -ErrorAction SilentlyContinue
        if ($null -ne $procCorr -and $procCorr.SessionId -eq 0) {
            return $true
        }
        # Verifica se il processo padre o antenato e' sshd
        $currPid = $PID
        for ($depth = 0; $depth -lt 4; $depth++) {
            $wmiProc = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $currPid" -ErrorAction SilentlyContinue
            if ($null -eq $wmiProc) { break }
            if ($wmiProc.Name -match '^(sshd|ssh-shellhost)(\.exe)?$') {
                return $true
            }
            $parentId = [int]$wmiProc.ParentProcessId
            if ($parentId -le 0 -or $parentId -eq $currPid) { break }
            $pObj = Get-Process -Id $parentId -ErrorAction SilentlyContinue
            if ($null -ne $pObj -and $pObj.ProcessName -match '^(sshd|ssh-shellhost)$') {
                return $true
            }
            $currPid = $parentId
        }
    }
    catch { }

    return $false
}

function Show-ScannerConsoleUI {
    <#
    .SYNOPSIS
        Interfaccia interattiva da terminale (TUI / CLI) per sessioni SSH o console senza GUI.
        Supporta scansione in tempo reale dei 50 controlli, tabella colorata, ispezione dettagli,
        Resoconto IA con Ollama (con auto-setup sulla VM), cambio lingua (IT/EN/DE) ed export JSON/HTML.
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
        [string[]]$ControlId = @(),

        [Parameter(Mandatory = $false)]
        [string]$VersioneTool = '0.2.0',

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$LinguaIniziale = 'IT',

        [Parameter(Mandatory = $false)]
        [switch]$NonInterattivo
    )

    $lingua = $LinguaIniziale
    $percorsoChecks = if ($PercorsoProgetto) { Join-Path $PercorsoProgetto 'src\core\Checks' } else { '' }
    $totaleCat = @($Catalogo.controls).Count
    $risultatiGrezzi = @()
    $elementiVista   = @()

    $eseguiScansioneConsole = {
        $lblAvvio = switch ($lingua) {
            'EN' { "Running security audit ($totaleCat deterministic controls) in read-only mode..." }
            'DE' { "Sicherheitspruefung wird ausgefuehrt ($totaleCat deterministische Pruefungen, schreibgeschuetzt)..." }
            default { "Esecuzione scansione di sicurezza ($totaleCat controlli deterministici) in sola lettura..." }
        }
        Write-Host ""
        Write-Host "================================================================================" -ForegroundColor DarkCyan
        Write-Host "  $lblAvvio" -ForegroundColor Cyan
        Write-Host "================================================================================" -ForegroundColor DarkCyan

        $onProg = {
            param($idx, $tot, $res)
            $simbolo = switch ($res.status) {
                'superato'        { '[OK]' }
                'fallito'         { '[X] ' }
                'sconosciuto'     { '[?] ' }
                'non_applicabile' { '[-] ' }
                default           { '[!] ' }
            }
            $colore = switch ($res.status) {
                'superato'        { 'Green' }
                'fallito'         { 'Red' }
                'sconosciuto'     { 'Yellow' }
                'non_applicabile' { 'DarkGray' }
                default           { 'Magenta' }
            }
            $pct = if ($tot -gt 0) { [int](($idx * 100) / $tot) } else { 100 }
            $barra = ('#' * [int]($pct / 5)).PadRight(20, '.')
            Write-Host ("  [{0,2}/{1,2}] [{2}] {3} {4}" -f $idx, $tot, $barra, $simbolo, $res.control_id) -ForegroundColor $colore
        }

        $paramRun = @{
            Catalogo       = $Catalogo
            Ambiente       = $Ambiente
            CartellaChecks = $percorsoChecks
            OnProgress     = $onProg
        }
        if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
            $paramRun['ControlId'] = $ControlId
        }

        $script:ConsoleRisultatiGrezzi = Invoke-Controlli @paramRun
        $script:ConsoleElementiVista   = @(ConvertTo-RisultatiVista -Risultati $script:ConsoleRisultatiGrezzi -Catalogo $Catalogo -Lingua $lingua)
    }

    $mostraRiepilogoETabella = {
        $script:ConsoleElementiVista = @(ConvertTo-RisultatiVista -Risultati $script:ConsoleRisultatiGrezzi -Catalogo $Catalogo -Lingua $lingua)
        $cnt = Measure-ConteggiRisultati -Elementi $script:ConsoleRisultatiGrezzi

        $titoloBanner = switch ($lingua) {
            'EN' { "WINDOWS 11 SECURITY SCANNER (SSH / TERMINAL MODE - READ-ONLY)" }
            'DE' { "WINDOWS 11 SICHERHEITSSCANNER (SSH / TERMINAL-MODUS - NUR LESEN)" }
            default { "SCANNER SICUREZZA WINDOWS 11 (MODALITA' TERMINALE SSH - SOLA LETTURA)" }
        }
        $adminTxt = if ($Ambiente.IsAdmin) {
            switch ($lingua) { 'EN' { 'Yes' } 'DE' { 'Ja' } default { 'Si' } }
        } else {
            switch ($lingua) { 'DE' { 'Nein (Eingeschraenkt)' } 'EN' { 'No (Limited)' } default { 'No (Limitato)' } }
        }

        Write-Host ""
        Write-Host "================================================================================" -ForegroundColor Blue
        Write-Host "  $titoloBanner" -ForegroundColor White
        Write-Host "  OS: Windows 11 $($Ambiente.Edition) ($($Ambiente.Build)) | Admin: $adminTxt | Lang: [$lingua]" -ForegroundColor Gray
        Write-Host "================================================================================" -ForegroundColor Blue

        if (-not $Ambiente.IsAdmin) {
            $warnAdm = switch ($lingua) {
                'EN' { "  [!] Non-Admin SSH session: some checks report 'Unknown'. Connect as an Admin user for full results." }
                'DE' { "  [!] SSH-Sitzung ohne Admin-Rechte: Einige Pruefungen melden 'Unbekannt'." }
                default { "  [!] Sessione SSH non amministrativa: alcuni controlli risultano 'Sconosciuto'." }
            }
            Write-Host $warnAdm -ForegroundColor Yellow
        }

        # Contatori KPI colorati
        Write-Host ""
        switch ($lingua) {
            'EN' {
                Write-Host "  [OK] $($cnt.superato) Passed   " -NoNewline -ForegroundColor Green
                Write-Host "[X] $($cnt.fallito) Failed   " -NoNewline -ForegroundColor Red
                Write-Host "[?] $($cnt.sconosciuto) Unknown   " -NoNewline -ForegroundColor Yellow
                Write-Host "[-] $($cnt.non_applicabile) N/A   " -NoNewline -ForegroundColor DarkGray
                Write-Host "[!] $($cnt.errore) Errors" -ForegroundColor Magenta
            }
            'DE' {
                Write-Host "  [OK] $($cnt.superato) Bestanden   " -NoNewline -ForegroundColor Green
                Write-Host "[X] $($cnt.fallito) Fehlgeschlagen   " -NoNewline -ForegroundColor Red
                Write-Host "[?] $($cnt.sconosciuto) Unbekannt   " -NoNewline -ForegroundColor Yellow
                Write-Host "[-] $($cnt.non_applicabile) N/Z   " -NoNewline -ForegroundColor DarkGray
                Write-Host "[!] $($cnt.errore) Fehler" -ForegroundColor Magenta
            }
            default {
                Write-Host "  [OK] $($cnt.superato) Superati   " -NoNewline -ForegroundColor Green
                Write-Host "[X] $($cnt.fallito) Falliti   " -NoNewline -ForegroundColor Red
                Write-Host "[?] $($cnt.sconosciuto) Sconosciuti   " -NoNewline -ForegroundColor Yellow
                Write-Host "[-] $($cnt.non_applicabile) N/A   " -NoNewline -ForegroundColor DarkGray
                Write-Host "[!] $($cnt.errore) Errori" -ForegroundColor Magenta
            }
        }
        Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray

        $hdr = switch ($lingua) {
            'EN' { ("{0,-16} {1,-10} {2,-18} {3,-14} {4}" -f "STATUS", "SEVERITY", "CATEGORY", "ID", "SECURITY CONTROL") }
            'DE' { ("{0,-18} {1,-10} {2,-21} {3,-14} {4}" -f "STATUS", "SCHWERE", "KATEGORIE", "ID", "SICHERHEITSPRUEFUNG") }
            default { ("{0,-16} {1,-10} {2,-20} {3,-14} {4}" -f "STATO", "GRAVITA'", "CATEGORIA", "ID", "CONTROLLO") }
        }
        Write-Host "  $hdr" -ForegroundColor Cyan
        Write-Host "--------------------------------------------------------------------------------" -ForegroundColor DarkGray

        foreach ($el in $script:ConsoleElementiVista) {
            $colRiga = switch ($el.Status) {
                'superato'        { 'Green' }
                'fallito'         { 'Red' }
                'sconosciuto'     { 'Yellow' }
                'non_applicabile' { 'DarkGray' }
                default           { 'Magenta' }
            }
            $catTronc = if ($el.Category.Length -gt 18) { $el.Category.Substring(0, 17) + '.' } else { $el.Category }
            $titTronc = if ($el.Title.Length -gt 48) { $el.Title.Substring(0, 45) + '...' } else { $el.Title }
            $rigaTxt = ("  {0,-16} {1,-10} {2,-18} {3,-14} {4}" -f $el.StatusLabel, $el.SeverityLabel, $catTronc, $el.ControlId, $titTronc)
            Write-Host $rigaTxt -ForegroundColor $colRiga
        }
        Write-Host "================================================================================" -ForegroundColor Blue
    }

    # Esegui la scansione iniziale
    & $eseguiScansioneConsole
    & $mostraRiepilogoETabella

    if ($NonInterattivo) {
        return
    }

    # Loop Menu Interattivo da Terminale SSH
    $continuaLoop = $true
    while ($continuaLoop) {
        Write-Host ""
        switch ($lingua) {
            'EN' {
                Write-Host "  SSH INTERACTIVE MENU (Active Language: [*] EN English):" -ForegroundColor Cyan
                Write-Host "  [1] Inspect all FAILED controls (details & remediation commands)" -ForegroundColor White
                Write-Host "  [2] Generate FULL PC AI SECURITY REPORT (Local Ollama / Auto-Setup)" -ForegroundColor Magenta
                Write-Host "  [3] Inspect or explain a specific control by ID (e.g. HOME-ENC-001)" -ForegroundColor White
                Write-Host "  [4] Switch Language: [IT Italiano] / [EN English] / [DE Deutsch]" -ForegroundColor Yellow
                Write-Host "  [5] Export JSON & HTML reports to disk" -ForegroundColor Green
                Write-Host "  [R] Re-run security scan ($totaleCat controls)" -ForegroundColor Gray
                Write-Host "  [Q] Quit" -ForegroundColor Gray
                $promptScelta = "  Select an option (1-5, R, Q)"
            }
            'DE' {
                Write-Host "  INTERAKTIVES SSH-MENUE (Aktive Sprache: [*] DE Deutsch):" -ForegroundColor Cyan
                Write-Host "  [1] Alle FEHLGESCHLAGENEN Pruefungen anzeigen (Details & Befehle)" -ForegroundColor White
                Write-Host "  [2] VOLLSTAENDIGEN KI-SICHERHEITSBERICHT erstellen (Lokales Ollama)" -ForegroundColor Magenta
                Write-Host "  [3] Einzelne Pruefung per ID untersuchen/erklaeren (z. B. HOME-ENC-001)" -ForegroundColor White
                Write-Host "  [4] Sprache wechseln: [IT Italiano] / [EN English] / [DE Deutsch]" -ForegroundColor Yellow
                Write-Host "  [5] JSON- & HTML-Berichte auf Festplatte exportieren" -ForegroundColor Green
                Write-Host "  [R] Sicherheitsscan erneut starten ($totaleCat Pruefungen)" -ForegroundColor Gray
                Write-Host "  [Q] Beenden" -ForegroundColor Gray
                $promptScelta = "  Option waehlen (1-5, R, Q)"
            }
            default {
                Write-Host "  MENU INTERATTIVO TERMINALE SSH (Lingua attiva: [*] IT Italiano):" -ForegroundColor Cyan
                Write-Host "  [1] Mostra dettagli e comandi di correzione di tutti i controlli FALLITI" -ForegroundColor White
                Write-Host "  [2] Genera RESOCONTO COMPLETO IA (Ollama locale / Auto-Setup VM)" -ForegroundColor Magenta
                Write-Host "  [3] Ispeziona o spiega con IA un controllo specifico tramite ID (es. HOME-ENC-001)" -ForegroundColor White
                Write-Host "  [4] Cambia Lingua: [IT Italiano] / [EN English] / [DE Deutsch]" -ForegroundColor Yellow
                Write-Host "  [5] Esporta report JSON e HTML su disco" -ForegroundColor Green
                Write-Host "  [R] Riesegui la scansione ($totaleCat controlli)" -ForegroundColor Gray
                Write-Host "  [Q] Esci" -ForegroundColor Gray
                $promptScelta = "  Scegli un'opzione (1-5, R, Q)"
            }
        }

        $scelta = Read-Host $promptScelta
        if ($null -eq $scelta) { break }
        $sceltaNorm = $scelta.Trim().ToUpperInvariant()

        switch ($sceltaNorm) {
            '1' {
                $falliti = @($script:ConsoleElementiVista | Where-Object { $_.Status -eq 'fallito' })
                if ($falliti.Count -eq 0) {
                    $msgZero = switch ($lingua) {
                        'EN' { "  [OK] No failed controls found!" }
                        'DE' { "  [OK] Keine fehlgeschlagenen Pruefungen gefunden!" }
                        default { "  [OK] Nessun controllo fallito rilevato!" }
                    }
                    Write-Host $msgZero -ForegroundColor Green
                }
                else {
                    foreach ($f in $falliti) {
                        $det = Format-DettaglioControllo -Elemento $f -Modalita 'Semplice' -Lingua $lingua
                        Write-Host ""
                        Write-Host "  ----------------------------------------------------------------------------" -ForegroundColor DarkRed
                        Write-Host "  $($det.StatusLabel) | [$($det.SeverityLabel)] $($det.ControlId) - $($det.Title)" -ForegroundColor Red
                        Write-Host "  Observed: $($det.ValoreOsservato)" -ForegroundColor Yellow
                        Write-Host "  Expected: $($det.ValoreAtteso)" -ForegroundColor Gray
                        Write-Host "  Why:      $($det.TestoSpiegazione)" -ForegroundColor White
                        Write-Host "  Fix:      $($det.TestoRimedio)" -ForegroundColor Cyan
                        if ($det.HaComando) {
                            Write-Host "  Command:  $($det.ComandoRimedio)" -ForegroundColor Green
                        }
                    }
                }
            }
            '2' {
                $cnt = Measure-ConteggiRisultati -Elementi $script:ConsoleRisultatiGrezzi
                $promptRes   = Format-PromptResocontoOllama -ElementiVista $script:ConsoleElementiVista -Conteggi $cnt -Ambiente $Ambiente -Lingua $lingua
                $fallbackRes = Format-ResocontoLocaleScansione -ElementiVista $script:ConsoleElementiVista -Conteggi $cnt -Ambiente $Ambiente -Lingua $lingua

                $cbStatoConsole = {
                    param([string]$msg)
                    Write-Host "  [Ollama] $msg" -ForegroundColor DarkCyan
                }
                Write-Host ""
                $esitoIa = Invoke-RichiestaOllama -Prompt $promptRes -Modello 'qwen2.5:0.5b' -Endpoint 'http://127.0.0.1:11434' -TestoFallbackLocale $fallbackRes -AutoProvision $true -Lingua $lingua -OnStatus $cbStatoConsole
                Write-Host ""
                Write-Host "================================================================================" -ForegroundColor Magenta
                Write-Host "  $($esitoIa.Sorgente)" -ForegroundColor Cyan
                Write-Host "================================================================================" -ForegroundColor Magenta
                Write-Host $esitoIa.Risposta -ForegroundColor White
                Write-Host "================================================================================" -ForegroundColor Magenta
            }
            '3' {
                $msgAskId = switch ($lingua) {
                    'EN' { "  Enter Control ID (e.g. HOME-ENC-001, HOME-AV-009)" }
                    'DE' { "  Pruefungs-ID eingeben (z. B. HOME-ENC-001, HOME-AV-009)" }
                    default { "  Inserisci l'ID del controllo (es. HOME-ENC-001, HOME-AV-009)" }
                }
                $idCercato = (Read-Host $msgAskId).Trim().ToUpperInvariant()
                $elTrovato = $script:ConsoleElementiVista | Where-Object { $_.ControlId.ToUpperInvariant() -eq $idCercato } | Select-Object -First 1
                if ($null -eq $elTrovato) {
                    Write-Host "  [!] ID '$idCercato' non trovato." -ForegroundColor Yellow
                }
                else {
                    $det = Format-DettaglioControllo -Elemento $elTrovato -Modalita 'Semplice' -Lingua $lingua
                    $promptCtrl  = Format-PromptControlloOllama -Dettaglio $det -Ambiente $Ambiente -Lingua $lingua
                    $fallbackLoc = Format-AnalisiLocaleControllo -Dettaglio $det -Ambiente $Ambiente -Lingua $lingua
                    $esitoCtrl = Invoke-RichiestaOllama -Prompt $promptCtrl -Modello 'qwen2.5:0.5b' -Endpoint 'http://127.0.0.1:11434' -TestoFallbackLocale $fallbackLoc -AutoProvision $true -Lingua $lingua
                    Write-Host ""
                    Write-Host $esitoCtrl.Risposta -ForegroundColor White
                }
            }
            '4' {
                $sceltaLang = (Read-Host "  Choose language / Lingua / Sprache (IT / EN / DE)").Trim().ToUpperInvariant()
                if ($sceltaLang -in @('IT', 'EN', 'DE')) {
                    $lingua = $sceltaLang
                }
                else {
                    $lingua = switch ($lingua) { 'IT' { 'EN' } 'EN' { 'DE' } default { 'IT' } }
                }
                & $mostraRiepilogoETabella
            }
            '5' {
                $dirOut = (Get-Location).Path
                $fileJson = Join-Path $dirOut (Get-NomeFileExport -Estensione 'json')
                $fileHtml = Join-Path $dirOut (Get-NomeFileExport -Estensione 'html')
                $rep = New-Report -Risultati $script:ConsoleRisultatiGrezzi -Ambiente $Ambiente -Catalogo $Catalogo -VersioneTool $VersioneTool
                Export-ReportJson -Report $rep -PercorsoFile $fileJson
                Export-ReportHtml -Report $rep -Catalogo $Catalogo -PercorsoFile $fileHtml
                Write-Host "  [OK] JSON: $fileJson" -ForegroundColor Green
                Write-Host "  [OK] HTML: $fileHtml" -ForegroundColor Green
            }
            'R' {
                & $eseguiScansioneConsole
                & $mostraRiepilogoETabella
            }
            'Q' {
                $continuaLoop = $false
            }
            default {
                & $mostraRiepilogoETabella
            }
        }
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
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$LinguaIniziale = 'IT'
    )

    # Se lo script viene eseguito in una sessione SSH o priva di desktop interattivo,
    # passa automaticamente alla modalita' interattiva da terminale (TUI / Console)
    if (Test-SessioneTerminaleSsh) {
        Show-ScannerConsoleUI -Catalogo $Catalogo -Ambiente $Ambiente -PercorsoProgetto $PercorsoProgetto -ControlId $ControlId -VersioneTool $VersioneTool -LinguaIniziale $LinguaIniziale
        return
    }

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
        LblLinguaAttiva        = $finestra.FindName('LblLinguaAttiva')
        BtnLinguaIT            = $finestra.FindName('BtnLinguaIT')
        BtnLinguaEN            = $finestra.FindName('BtnLinguaEN')
        BtnLinguaDE            = $finestra.FindName('BtnLinguaDE')
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

    # Stato interno dell'interfaccia (Tema Scuro Fluent predefinito)
    $totaleControlli = @($Catalogo.controls).Count
    $statoUI = @{
        LinguaCorrente      = $LinguaIniziale
        TemaCorrente        = 'Scuro'
        PaginaCorrente      = 'Scansione'
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

    Update-TemaFinestra -Finestra $finestra -Tema $statoUI.TemaCorrente
    $ctrl.ProgressScansione.Maximum = if ($totaleControlli -gt 0) { $totaleControlli } else { 1 }

    # Banner giallo se non avviato come amministratore
    if (-not $Ambiente.IsAdmin) {
        $ctrl.BannerNonAdmin.Visibility = [System.Windows.Visibility]::Visible
    }

    $convBrush = New-Object System.Windows.Media.BrushConverter

    # Aggiorna l'evidenziazione visiva del selettore lingua [IT | EN | DE] e delle schede di navigazione
    $aggiornaStileSelettori = {
        $mappaBtnLingua = @{
            'IT' = @{ Btn = $ctrl.BtnLinguaIT; Label = 'IT Italiano' }
            'EN' = @{ Btn = $ctrl.BtnLinguaEN; Label = 'EN English' }
            'DE' = @{ Btn = $ctrl.BtnLinguaDE; Label = 'DE Deutsch' }
        }
        foreach ($cod in @('IT', 'EN', 'DE')) {
            $b = $mappaBtnLingua[$cod].Btn
            $lblBase = $mappaBtnLingua[$cod].Label
            if ($statoUI.LinguaCorrente -eq $cod) {
                $b.Content    = "[*] $lblBase"
                $b.Background = $convBrush.ConvertFromString('#2563EB')
                $b.Foreground = $convBrush.ConvertFromString('#FFFFFF')
                $b.FontWeight = [System.Windows.FontWeights]::Bold
            }
            else {
                $b.Content    = $lblBase
                $b.Background = $convBrush.ConvertFromString('Transparent')
                $b.Foreground = $convBrush.ConvertFromString('#94A3B8')
                $b.FontWeight = [System.Windows.FontWeights]::SemiBold
            }
        }

        # Evidenzia la scheda pagina attiva (Tab 1 vs Tab 2)
        if ($statoUI.PaginaCorrente -eq 'IA') {
            $ctrl.BtnNavIA.Background        = $convBrush.ConvertFromString('#7C3AED')
            $ctrl.BtnNavIA.Foreground        = $convBrush.ConvertFromString('#FFFFFF')
            $ctrl.BtnNavIA.FontWeight        = [System.Windows.FontWeights]::Bold
            $ctrl.BtnNavScansione.Background = $convBrush.ConvertFromString('Transparent')
            $ctrl.BtnNavScansione.Foreground = $finestra.Resources['TextSecondary']
            $ctrl.BtnNavScansione.FontWeight = [System.Windows.FontWeights]::SemiBold
        }
        else {
            $ctrl.BtnNavScansione.Background = $convBrush.ConvertFromString('#2563EB')
            $ctrl.BtnNavScansione.Foreground = $convBrush.ConvertFromString('#FFFFFF')
            $ctrl.BtnNavScansione.FontWeight = [System.Windows.FontWeights]::Bold
            $ctrl.BtnNavIA.Background        = $convBrush.ConvertFromString('Transparent')
            $ctrl.BtnNavIA.Foreground        = $finestra.Resources['TextSecondary']
            $ctrl.BtnNavIA.FontWeight        = [System.Windows.FontWeights]::SemiBold
        }
    }

    # Funzione helper per ripopolare i filtri ComboBox nella lingua corrente (IT / EN / DE)
    $aggiornaFiltriComboLingua = {
        $lang = $statoUI.LinguaCorrente

        $idxStato = if ($ctrl.CmbFiltroStato.SelectedIndex -ge 0) { $ctrl.CmbFiltroStato.SelectedIndex } else { 0 }
        $idxGrav  = if ($ctrl.CmbFiltroGravita.SelectedIndex -ge 0) { $ctrl.CmbFiltroGravita.SelectedIndex } else { 0 }
        $idxCat   = if ($ctrl.CmbFiltroCategoria.SelectedIndex -ge 0) { $ctrl.CmbFiltroCategoria.SelectedIndex } else { 0 }

        $vociStato = switch ($lang) {
            'EN' { @('All', 'Failed', 'Passed', 'Unknown', 'N/A', 'Error') }
            'DE' { @('Alle', 'Fehlgeschlagen', 'Bestanden', 'Unbekannt', 'N/Z', 'Fehler') }
            default { @('Tutti', 'Fallito', 'Superato', 'Sconosciuto', 'Non_Applicabile', 'Errore') }
        }

        $vociGrav = switch ($lang) {
            'EN' { @('All', 'Critical', 'High', 'Medium', 'Low', 'Info') }
            'DE' { @('Alle', 'Kritisch', 'Hoch', 'Mittel', 'Niedrig', 'Info') }
            default { @('Tutte', 'Critico', 'Alto', 'Medio', 'Basso', 'Informativo') }
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
            if ($lang -eq 'EN' -and $script:TraduzioniControlliEN.ContainsKey($cid)) {
                $catVal = $script:TraduzioniControlliEN[$cid].cat
            }
            elseif ($lang -eq 'DE' -and $script:TraduzioniControlliDE.ContainsKey($cid)) {
                $catVal = $script:TraduzioniControlliDE[$cid].cat
            }
            if ($catVal -and ($categorieUniche -notcontains $catVal)) {
                $categorieUniche += $catVal
            }
        }

        $ctrl.CmbFiltroCategoria.Items.Clear()
        $itemTutte = New-Object System.Windows.Controls.ComboBoxItem
        $itemTutte.Content = switch ($lang) { 'EN' { 'All' } 'DE' { 'Alle' } default { 'Tutte' } }
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
        $lang = $statoUI.LinguaCorrente
        $dettaglio = Format-DettaglioControllo -Elemento $statoUI.ElementoSelezionato -Modalita $statoUI.ModalitaDettaglio -Lingua $lang
        $ctrl.TxtDettaglioTitolo.Text = $dettaglio.Title

        switch ($lang) {
            'EN' {
                $ctrl.TxtDettaglioSottotitolo.Text = "ID: $($dettaglio.ControlId)  |  Status: $($dettaglio.StatusLabel)  |  Severity: $($dettaglio.SeverityLabel)  |  Category: $($dettaglio.Category)"
            }
            'DE' {
                $ctrl.TxtDettaglioSottotitolo.Text = "ID: $($dettaglio.ControlId)  |  Status: $($dettaglio.StatusLabel)  |  Schweregrad: $($dettaglio.SeverityLabel)  |  Kategorie: $($dettaglio.Category)"
            }
            default {
                $ctrl.TxtDettaglioSottotitolo.Text = "ID: $($dettaglio.ControlId)  |  Stato: $($dettaglio.StatusLabel)  |  Gravita': $($dettaglio.SeverityLabel)  |  Categoria: $($dettaglio.Category)"
            }
        }

        if ($statoUI.ModalitaDettaglio -eq 'Tecnico') {
            $ctrl.TxtTitoloSpiegazione.Text = switch ($lang) {
                'EN' { "Technical details & references" }
                'DE' { "Technische Details & Referenzen" }
                default { "Dettaglio tecnico e riferimenti" }
            }
            $ctrl.BtnModoTecnico.FontWeight  = [System.Windows.FontWeights]::Bold
            $ctrl.BtnModoSemplice.FontWeight = [System.Windows.FontWeights]::Normal
        }
        else {
            $ctrl.TxtTitoloSpiegazione.Text = switch ($lang) {
                'EN' { "Why it matters (simple explanation)" }
                'DE' { "Warum es wichtig ist (einfache Erklaerung)" }
                default { "Perche' conta (spiegazione semplice)" }
            }
            $ctrl.BtnModoSemplice.FontWeight = [System.Windows.FontWeights]::Bold
            $ctrl.BtnModoTecnico.FontWeight  = [System.Windows.FontWeights]::Normal
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
        $lang = $statoUI.LinguaCorrente

        switch ($lang) {
            'EN' {
                $ctrl.TxtCountSuperati.Text       = "[OK] $($conteggi.superato) Passed"
                $ctrl.TxtCountFalliti.Text        = "[X] $($conteggi.fallito) Failed"
                $ctrl.TxtCountSconosciuti.Text    = "[?] $($conteggi.sconosciuto) Unknown"
                $ctrl.TxtCountNonApplicabili.Text = "[-] $($conteggi.non_applicabile) N/A"
                $ctrl.TxtCountErrori.Text         = "[!] $($conteggi.errore) Errors"
                $ctrl.TxtRiepilogoFooter.Text     = "Summary: $($conteggi.totale) controls evaluated ($($conteggi.superato) passed, $($conteggi.fallito) failed, $($conteggi.sconosciuto) unknown)"
            }
            'DE' {
                $ctrl.TxtCountSuperati.Text       = "[OK] $($conteggi.superato) Bestanden"
                $ctrl.TxtCountFalliti.Text        = "[X] $($conteggi.fallito) Fehlgeschlagen"
                $ctrl.TxtCountSconosciuti.Text    = "[?] $($conteggi.sconosciuto) Unbekannt"
                $ctrl.TxtCountNonApplicabili.Text = "[-] $($conteggi.non_applicabile) N/Z"
                $ctrl.TxtCountErrori.Text         = "[!] $($conteggi.errore) Fehler"
                $ctrl.TxtRiepilogoFooter.Text     = "Zusammenfassung: $($conteggi.totale) Pruefungen ausgewertet ($($conteggi.superato) bestanden, $($conteggi.fallito) fehlgeschlagen, $($conteggi.sconosciuto) unbekannt)"
            }
            default {
                $ctrl.TxtCountSuperati.Text       = "[OK] $($conteggi.superato) Superati"
                $ctrl.TxtCountFalliti.Text        = "[X] $($conteggi.fallito) Falliti"
                $ctrl.TxtCountSconosciuti.Text    = "[?] $($conteggi.sconosciuto) Sconosciuti"
                $ctrl.TxtCountNonApplicabili.Text = "[-] $($conteggi.non_applicabile) Non applicabili"
                $ctrl.TxtCountErrori.Text         = "[!] $($conteggi.errore) Errori"
                $ctrl.TxtRiepilogoFooter.Text     = "Riepilogo calcolato dal codice: $($conteggi.totale) controlli valutati ($($conteggi.superato) superati, $($conteggi.fallito) falliti, $($conteggi.sconosciuto) sconosciuti)"
            }
        }

        if ($conteggi.errore -gt 0) {
            $ctrl.TxtBannerErrore.Text = switch ($lang) {
                'EN' { "Some controls ($($conteggi.errore)) returned an unexpected read error. Select the control for details or export the technical log." }
                'DE' { "Einige Pruefungen ($($conteggi.errore)) haben einen unerwarteten Lesefehler gemeldet. Waehlen Sie die Pruefung fuer Details oder exportieren Sie das technische Protokoll." }
                default { "Alcuni controlli ($($conteggi.errore)) hanno restituito un imprevisto durante la lettura. Seleziona il controllo per maggiori informazioni o esporta il log tecnico." }
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
            $ctrl.TxtMessaggioGuida.Text = switch ($statoUI.LinguaCorrente) {
                'EN' { "No controls match the selected filters." }
                'DE' { "Keine Sicherheitspruefungen entsprechen den ausgewaehlten Filtern." }
                default { "Nessun controllo corrisponde ai filtri selezionati." }
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

    $aggiornaTestoPulsanteTema = {
        $lang = $statoUI.LinguaCorrente
        $isScuro = ($statoUI.TemaCorrente -eq 'Scuro')
        $ctrl.BtnTema.Content = switch ($lang) {
            'EN' { if ($isScuro) { "Active Theme: Dark" } else { "Active Theme: Light" } }
            'DE' { if ($isScuro) { "Design: Dunkel" }     else { "Design: Hell" } }
            default { if ($isScuro) { "Tema attivo: Scuro" } else { "Tema attivo: Chiaro" } }
        }
    }

    $applicaLinguaUI = {
        $lang = $statoUI.LinguaCorrente
        $testoAdmin = if ($Ambiente.IsAdmin) {
            switch ($lang) { 'EN' { 'Yes' } 'DE' { 'Ja' } default { 'Si' } }
        } else {
            switch ($lang) { 'DE' { 'Nein' } default { 'No' } }
        }
        $ctrl.TxtAmbienteInfo.Text = "Windows 11 $($Ambiente.Edition) $($Ambiente.Build) | Admin: $testoAdmin"

        & $aggiornaStileSelettori
        & $aggiornaTestoPulsanteTema

        if ($lang -eq 'EN') {
            $finestra.Title                        = "Windows 11 Security Scanner (Read-Only)"
            $ctrl.TxtTitoloApp.Text                = "Windows 11 Security Scanner"
            $ctrl.TxtBadgeSolaLettura.Text         = "READ-ONLY"
            $ctrl.TxtSottotitoloApp.Text           = "$totaleControlli Deterministic Controls + Local AI Security Advisor (Ollama)"
            $ctrl.LblLinguaAttiva.Text             = "Language:"
            $ctrl.TxtBannerNonAdmin.Text           = "[!] Non-administrative session: some controls will report 'Unknown'. Restart as Administrator for a complete audit."
            $ctrl.BtnRiavviaAdmin.Content          = "Restart as Administrator"
            $ctrl.BtnNavScansione.Content          = "1. Controls & Details"
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
        elseif ($lang -eq 'DE') {
            $finestra.Title                        = "Windows 11 Sicherheitsscanner (Schreibgeschuetzt)"
            $ctrl.TxtTitoloApp.Text                = "Windows 11 Sicherheitsscanner"
            $ctrl.TxtBadgeSolaLettura.Text         = "NUR LESEN"
            $ctrl.TxtSottotitoloApp.Text           = "$totaleControlli Deterministische Pruefungen + Lokaler KI-Berater (Ollama)"
            $ctrl.LblLinguaAttiva.Text             = "Sprache:"
            $ctrl.TxtBannerNonAdmin.Text           = "[!] Sitzung ohne Administratorrechte: Einige Pruefungen melden 'Unbekannt'. Starten Sie als Administrator neu fuer eine vollstaendige Analyse."
            $ctrl.BtnRiavviaAdmin.Content          = "Als Administrator neustarten"
            $ctrl.BtnNavScansione.Content          = "1. Pruefungen & Details"
            $ctrl.BtnNavIA.Content                 = "2. KI-Sicherheitsberater (Ollama)"
            $ctrl.BtnAvvia.Content                 = "Scan starten ($totaleControlli Pruefungen)"
            $ctrl.BtnAnnulla.Content               = "Abbrechen"
            $ctrl.BtnResocontoLLM.Content          = "KI-Sicherheitsbericht oeffnen"
            $ctrl.LblFiltroStato.Text              = "Status:"
            $ctrl.LblFiltroGravita.Text            = "Schweregrad:"
            $ctrl.LblFiltroCategoria.Text          = "Kategorie:"
            $ctrl.LblFiltroCerca.Text              = "Suche:"
            $ctrl.BtnResetFiltri.Content           = "Filter zuruecksetzen"
            $ctrl.ColStato.Header                  = "Status"
            $ctrl.ColGravita.Header                = "Schweregrad"
            $ctrl.ColCategoria.Header              = "Kategorie"
            $ctrl.ColId.Header                     = "ID"
            $ctrl.ColControllo.Header              = "Sicherheitspruefung"
            $ctrl.TxtSottotitoloGuida.Text         = "Der Scanner arbeitet ausschliesslich schreibgeschuetzt und aendert keine Windows-Einstellungen."
            $ctrl.BtnModoSemplice.Content          = "Einfache Ansicht"
            $ctrl.BtnModoTecnico.Content           = "Technische Details"
            $ctrl.BtnSpiegaLLM.Content             = "Mit KI erklaeren (Seite 2)"
            $ctrl.LblValoreAtteso.Text             = "ERWARTETER WERT"
            $ctrl.LblValoreOsservato.Text          = "GEFUNDENER WERT"
            $ctrl.LblComeCorreggere.Text           = "Manuelle Behebung (Anleitung)"
            $ctrl.LblComandoRif.Text               = "REFERENZBEFEHL (WIRD NICHT AUTOMATISCH AUSGEFUEHRT):"
            $ctrl.BtnCopiaComando.Content          = "Befehl kopieren"
            $ctrl.TxtFeedbackCopia.Text            = "Kopiert!"
            $ctrl.LblNoteRischi.Text               = "Risiko- & Auswirkungshinweise"
            $ctrl.LblMotoreIaTitle.Text            = "LOKALE KI-ENGINE (OLLAMA)"
            $ctrl.LblIndirizzoOllama.Text          = "Ollama-Serveradresse:"
            $ctrl.LblModelloOllama.Text            = "Leichtes LLM-Modell:"
            $ctrl.TxtChkAutoInstalla.Text          = "Falls Ollama auf der VM fehlt, automatisch im Hintergrund installieren und starten"
            $ctrl.BtnVerificaOllama.Content        = "Ollama pruefen / Auto-Setup"
            $ctrl.LblGeneraAnalisiTitle.Text       = "ANALYSE & EMPFEHLUNGEN ERSTELLEN"
            $ctrl.BtnResocontoTab.Content          = "Vollstaendigen PC-Bericht erstellen"
            $ctrl.BtnSpiegaControlloTab.Content    = "Ausgewaehlte Pruefung erklaeren"
            $ctrl.LblCriticitaRilevate.Text        = "ERKANNTE PROBLEME (ZUM ANALYSIEREN KLICKEN):"
            $ctrl.LblTitoloResocontoIA.Text        = "KI-SICHERHEITSBERICHT & MASSNAHMENPLAN"
            $ctrl.BtnCopiaRispostaLLM.Content      = "KI-Bericht kopieren"
            $ctrl.BtnTornaScansione.Content        = "Zurueck zur Tabelle"
            $ctrl.BtnEsportaJson.Content           = "JSON exportieren"
            $ctrl.BtnEsportaHtml.Content           = "HTML exportieren"
            $ctrl.ChkSalvaLogTecnico.Content       = "Technisches Fehlerprotokoll neben dem Export speichern"
            $ctrl.TxtDisclaimerPermanente.Text     = "Dauerhafter Hinweis: Dieses Tool prueft Sicherheitskonfigurationen ausschliesslich schreibgeschuetzt. Ein konformes Audit garantiert nicht die Abwesenheit einer Kompromittierung."
        }
        else {
            $finestra.Title                        = "Scanner Sicurezza Windows 11 (Sola Lettura)"
            $ctrl.TxtTitoloApp.Text                = "Scanner Sicurezza Windows 11"
            $ctrl.TxtBadgeSolaLettura.Text         = "SOLA LETTURA"
            $ctrl.TxtSottotitoloApp.Text           = "$totaleControlli Controlli Deterministici + Assistente IA Locale (Ollama)"
            $ctrl.LblLinguaAttiva.Text             = "Lingua:"
            $ctrl.TxtBannerNonAdmin.Text           = "[!] Sessione non amministrativa: alcuni controlli risulteranno 'Sconosciuto'. Riavvia come Amministratore per l'analisi completa."
            $ctrl.BtnRiavviaAdmin.Content          = "Riavvia come amministratore"
            $ctrl.BtnNavScansione.Content          = "1. Tabella Controlli & Dettagli"
            $ctrl.BtnNavIA.Content                 = "2. Assistente IA (Ollama)"
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
            if ($lang -eq 'EN') {
                $ctrl.TxtMessaggioGuida.Text = "Click 'Start Scan' to audit all $totaleControlli Windows 11 security controls."
                $ctrl.TxtProgresso.Text      = "Ready (0/$totaleControlli)"
                $ctrl.TxtStatoLLM.Text       = "Status: Ready (auto-connects or auto-installs Ollama on demand)"
                $ctrl.TxtRispostaLLM.Text    = "1. Run the PC scan using the 'Start Scan ($totaleControlli controls)' button at the top.`r`n2. Click 'Generate Full PC Security Report' on the left to get an executive summary, prioritized remediation plan, and hardening recommendations.`r`n3. On a VM without Ollama installed, leave the auto-install checkbox enabled: the tool will silently configure Ollama or provide an instant built-in expert analysis."
            }
            elseif ($lang -eq 'DE') {
                $ctrl.TxtMessaggioGuida.Text = "Klicken Sie auf 'Scan starten', um alle $totaleControlli Windows 11-Sicherheitspruefungen durchzufuehren."
                $ctrl.TxtProgresso.Text      = "Bereit (0/$totaleControlli)"
                $ctrl.TxtStatoLLM.Text       = "Status: Bereit (verbindet oder installiert Ollama bei Bedarf automatisch)"
                $ctrl.TxtRispostaLLM.Text    = "1. Starten Sie zuerst den PC-Scan ueber die Schaltflaeche 'Scan starten ($totaleControlli Pruefungen)' oben.`r`n2. Klicken Sie links auf 'Vollstaendigen PC-Bericht erstellen', um eine Zusammenfassung und einen priorisierten Massnahmenplan zu erhalten.`r`n3. Auf einer VM ohne Ollama lassen Sie das Kontrollkaestchen aktiviert: Das Tool richtet Ollama automatisch ein oder liefert sofort eine integrierte Expertenanalyse."
            }
            else {
                $ctrl.TxtMessaggioGuida.Text = "Premi 'Avvia scansione' per analizzare i $totaleControlli controlli di sicurezza del PC."
                $ctrl.TxtProgresso.Text      = "Pronto (0/$totaleControlli)"
                $ctrl.TxtStatoLLM.Text       = "Stato: Pronto (connessione o auto-installazione automatica al primo avvio)"
                $ctrl.TxtRispostaLLM.Text    = "1. Esegui prima la scansione del PC col pulsante 'Avvia scansione ($totaleControlli controlli)' in alto.`r`n2. Premi 'Genera Resoconto Completo PC' qui a sinistra per ricevere l'analisi di tutte le vulnerabilita' trovate e i consigli pratici di messa in sicurezza.`r`n3. Se sei su una Macchina Virtuale senza Ollama, lascia attiva la spunta a sinistra: il tool pensera' a tutto in automatico (oppure fornira' l'analisi immediata tramite il motore esperto integrato)."
            }
        }
        else {
            $nValutati = $statoUI.RisultatiGrezzi.Count
            $idSelPrec = if ($null -ne $statoUI.ElementoSelezionato) { $statoUI.ElementoSelezionato.ControlId } else { $null }

            # Rigenera gli elementi della vista nella lingua selezionata
            $statoUI.ElementiVista = @(ConvertTo-RisultatiVista -Risultati $statoUI.RisultatiGrezzi -Catalogo $Catalogo -Lingua $lang)
            if ($null -ne $idSelPrec) {
                foreach ($el in $statoUI.ElementiVista) {
                    if ($el.ControlId -eq $idSelPrec) {
                        $statoUI.ElementoSelezionato = $el
                        break
                    }
                }
            }

            if (-not $statoUI.ScansioneInCorso) {
                $ctrl.TxtProgresso.Text = switch ($lang) {
                    'EN' { "Completed ($nValutati/$nValutati)" }
                    'DE' { "Abgeschlossen ($nValutati/$nValutati)" }
                    default { "Completata ($nValutati/$nValutati)" }
                }
            }

            # Aggiorna la lista delle criticita' nella Pagina 2 (IA)
            $falliti = @($statoUI.ElementiVista | Where-Object { $_.Status -eq 'fallito' })
            $ctrl.ListFallitiIA.ItemsSource = $falliti
            if ($null -ne $statoUI.ElementoSelezionato -and $statoUI.ElementoSelezionato.Status -eq 'fallito') {
                $ctrl.ListFallitiIA.SelectedItem = $statoUI.ElementoSelezionato
            }

            # Aggiorna anche il testo del Resoconto IA nella lingua selezionata cosi' non resta mai nella lingua precedente
            if ($statoUI.UltimaModalitaIA -eq 'Controllo' -and $null -ne $statoUI.ElementoSelezionato) {
                $dettCorr = Format-DettaglioControllo -Elemento $statoUI.ElementoSelezionato -Modalita 'Semplice' -Lingua $lang
                $ctrl.TxtRispostaLLM.Text = Format-AnalisiLocaleControllo -Dettaglio $dettCorr -Ambiente $Ambiente -Lingua $lang
                $ctrl.TxtStatoLLM.Text    = switch ($lang) {
                    'EN' { "Completed: Instant Security Analysis ($($dettCorr.ControlId))" }
                    'DE' { "Abgeschlossen: Sicherheitsanalyse ($($dettCorr.ControlId))" }
                    default { "Completato: Analisi di Sicurezza ($($dettCorr.ControlId))" }
                }
            }
            else {
                $conteggiCorr = Measure-ConteggiRisultati -Elementi $statoUI.RisultatiGrezzi
                $ctrl.TxtRispostaLLM.Text = Format-ResocontoLocaleScansione -ElementiVista $statoUI.ElementiVista -Conteggi $conteggiCorr -Ambiente $Ambiente -Lingua $lang
                $ctrl.TxtStatoLLM.Text    = switch ($lang) {
                    'EN' { "Completed: Full PC Security Report (EN)" }
                    'DE' { "Abgeschlossen: Vollstaendiger PC-Sicherheitsbericht (DE)" }
                    default { "Completato: Resoconto Completo Sicurezza PC (IT)" }
                }
            }

            & $applicaFiltriTabella
        }

        & $aggiornaConteggiERiepilogo
        & $aggiornaPannelloDettaglio
    }

    # --- Eventi Selettore Lingua Esplicito [IT | EN | DE] ---
    $ctrl.BtnLinguaIT.Add_Click({
        $statoUI.LinguaCorrente = 'IT'
        & $applicaLinguaUI
    })
    $ctrl.BtnLinguaEN.Add_Click({
        $statoUI.LinguaCorrente = 'EN'
        & $applicaLinguaUI
    })
    $ctrl.BtnLinguaDE.Add_Click({
        $statoUI.LinguaCorrente = 'DE'
        & $applicaLinguaUI
    })

    # --- Eventi Tema (Scuro <-> Chiaro) ---
    $ctrl.BtnTema.Add_Click({
        if ($statoUI.TemaCorrente -eq 'Chiaro') {
            $statoUI.TemaCorrente = 'Scuro'
        }
        else {
            $statoUI.TemaCorrente = 'Chiaro'
        }
        Update-TemaFinestra -Finestra $finestra -Tema $statoUI.TemaCorrente
        & $aggiornaStileSelettori
        & $aggiornaTestoPulsanteTema
    })

    # --- Evento Riavvia come Amministratore ---
    $ctrl.BtnRiavviaAdmin.Add_Click({
        $lang = $statoUI.LinguaCorrente
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
                $msg = switch ($lang) {
                    'EN' { "Launched from remote memory: open a new PowerShell window as Administrator and re-run the command." }
                    'DE' { "Aus dem Remote-Speicher gestartet: Oeffnen Sie ein neues PowerShell-Fenster als Administrator und fuehren Sie den Befehl erneut aus." }
                    default { "Avviato da memoria remota: apri una nuova finestra di PowerShell come Amministratore e riesegui il comando." }
                }
                [System.Windows.MessageBox]::Show($msg, $finestra.Title, [System.Windows.MessageBoxButton]::OK, [System.Windows.MessageBoxImage]::Information) | Out-Null
            }
        }
        catch {
            $msgErr = switch ($lang) {
                'EN' { "Restart as Administrator was canceled or failed." }
                'DE' { "Neustart als Administrator wurde abgebrochen oder ist fehlgeschlagen." }
                default { "Riavvio come amministratore annullato o non riuscito." }
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
        $statoUI.PaginaCorrente = $NomePagina
        & $aggiornaStileSelettori

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

        $lang = $statoUI.LinguaCorrente

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
        $ctrl.TxtStatoLLM.Text                = switch ($lang) {
            'EN' { "$EtichettaOperazione in progress ($modelloScelto)..." }
            'DE' { "$EtichettaOperazione laeuft ($modelloScelto)..." }
            default { "$EtichettaOperazione in corso ($modelloScelto)..." }
        }

        # Mostra subito l'analisi preliminare mentre Ollama genera (o si auto-installa sulla VM)
        if (-not [string]::IsNullOrWhiteSpace($TestoFallback)) {
            $bannerAttesa = switch ($lang) {
                'EN' { "[Connecting/Preparing Ollama ($modelloScelto) in background... Here is the immediate structured report:]" }
                'DE' { "[Verbindung/Vorbereitung von Ollama ($modelloScelto) im Hintergrund... Hier ist der sofortige strukturierte Bericht:]" }
                default { "[Connessione/Preparazione di Ollama ($modelloScelto) in corso in background... Ecco intanto il resoconto strutturato immediato:]" }
            }
            $ctrl.TxtRispostaLLM.Text = "$bannerAttesa`n`n$TestoFallback"
        }
        else {
            $ctrl.TxtRispostaLLM.Text = switch ($lang) {
                'EN' { "Processing with Ollama ($modelloScelto)... If you are on a VM without Ollama, the scanner is auto-configuring it in background." }
                'DE' { "Verarbeitung mit Ollama ($modelloScelto)... Auf einer VM ohne Ollama wird der Dienst automatisch im Hintergrund eingerichtet." }
                default { "Elaborazione in corso con Ollama ($modelloScelto)... Se ti trovi su una VM senza Ollama, lo scanner lo sta configurando automaticamente in background." }
            }
        }

        $callbackStatoLlm = [Action[string]]{
            param([string]$MsgStato)
            $ctrl.TxtStatoLLM.Text = $MsgStato
        }

        $callbackFineLlm = [Action[object]]{
            param($EsitoLlm)
            $langNow = $statoUI.LinguaCorrente
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
                $ctrl.TxtStatoLLM.Text = switch ($langNow) {
                    'EN' { "Completed by: $sorgente (${sec}s)" }
                    'DE' { "Abgeschlossen von: $sorgente (${sec}s)" }
                    default { "Completato da: $sorgente (${sec}s)" }
                }
                $ctrl.TxtRispostaLLM.Text = $EsitoLlm.Risposta
            }
            else {
                $ctrl.TxtStatoLLM.Text = switch ($langNow) {
                    'EN' { "Status: $($EsitoLlm.Modello) unavailable" }
                    'DE' { "Status: $($EsitoLlm.Modello) nicht verfuegbar" }
                    default { "Stato: $($EsitoLlm.Modello) non disponibile" }
                }
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
            Lingua         = $lang
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
        $lang = $statoUI.LinguaCorrente
        $endpointScelto = if ([string]::IsNullOrWhiteSpace($ctrl.TxtEndpointOllama.Text)) { 'http://127.0.0.1:11434' } else { $ctrl.TxtEndpointOllama.Text.Trim() }
        $autoInst = ($ctrl.ChkAutoInstallaOllama.IsChecked -eq $true)
        $ctrl.BtnVerificaOllama.IsEnabled = $false
        $ctrl.TxtStatoLLM.Text = switch ($lang) {
            'EN' { "Checking or auto-installing Ollama..." }
            'DE' { "Ollama wird geprueft oder automatisch installiert..." }
            default { "Verifica o installazione automatica di Ollama in corso..." }
        }

        $cbStato = [Action[string]]{ param([string]$m) $ctrl.TxtStatoLLM.Text = $m }
        $cbFine  = [Action[object]]{
            param($statoOll)
            $langNow = $statoUI.LinguaCorrente
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
                    $ctrl.TxtStatoLLM.Text = switch ($langNow) {
                        'EN' { "Ollama connected on $($statoOll.Endpoint)! Ready models: $($statoOll.Modelli -join ', ')" }
                        'DE' { "Ollama verbunden auf $($statoOll.Endpoint)! Bereite Modelle: $($statoOll.Modelli -join ', ')" }
                        default { "Ollama connesso su $($statoOll.Endpoint)! Modelli pronti: $($statoOll.Modelli -join ', ')" }
                    }
                }
                else {
                    $ctrl.TxtStatoLLM.Text = switch ($langNow) {
                        'EN' { "Ollama active on $($statoOll.Endpoint)! Model '$($ctrl.CmbModelloOllama.Text)' will be downloaded automatically on first analysis." }
                        'DE' { "Ollama aktiv auf $($statoOll.Endpoint)! Modell '$($ctrl.CmbModelloOllama.Text)' wird bei der ersten Analyse automatisch geladen." }
                        default { "Ollama attivo su $($statoOll.Endpoint)! Il modello '$($ctrl.CmbModelloOllama.Text)' verra' scaricato automaticamente alla prima analisi." }
                    }
                }
            }
            else {
                $ctrl.TxtStatoLLM.Text = switch ($langNow) {
                    'EN' { "Ollama unreachable: Built-in Expert Security Engine is active." }
                    'DE' { "Ollama nicht erreichbar: Integrierte Experten-Engine ist aktiv." }
                    default { "Ollama non raggiungibile: attivo il Motore Esperto Integrato." }
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
        $lang = $statoUI.LinguaCorrente
        & $mostraPagina 'IA'
        if ($null -eq $statoUI.ElementoSelezionato) {
            $ctrl.TxtStatoLLM.Text = switch ($lang) {
                'EN' { "Please select a control from the 'Detected Issues' list on the left (or from the Controls Table) first." }
                'DE' { "Bitte waehlen Sie zuerst links in der Liste 'Erkannte Probleme' (oder in der Tabelle) eine Sicherheitspruefung aus." }
                default { "Seleziona prima un controllo dalla lista 'Criticita' rilevate' qui a sinistra (o dalla Tabella Controlli)." }
            }
            return
        }
        $statoUI.UltimaModalitaIA = 'Controllo'
        $dettaglio   = Format-DettaglioControllo -Elemento $statoUI.ElementoSelezionato -Modalita 'Semplice' -Lingua $lang
        $promptCtrl  = Format-PromptControlloOllama -Dettaglio $dettaglio -Ambiente $Ambiente -Lingua $lang
        $fallbackLoc = Format-AnalisiLocaleControllo -Dettaglio $dettaglio -Ambiente $Ambiente -Lingua $lang
        $lblOp       = switch ($lang) {
            'EN' { "Analyzing $($dettaglio.ControlId)" }
            'DE' { "Analyse von $($dettaglio.ControlId)" }
            default { "Analisi di $($dettaglio.ControlId)" }
        }
        & $avviaRichiestaOllamaAsincrona $promptCtrl $lblOp $fallbackLoc
    }

    # --- Azione: Genera Resoconto Completo della Scansione ---
    $eseguiResocontoScansione = {
        $lang = $statoUI.LinguaCorrente
        & $mostraPagina 'IA'
        if ($statoUI.ElementiVista.Count -eq 0) {
            $ctrl.TxtStatoLLM.Text = switch ($lang) {
                'EN' { "Click 'Start Scan' at the top first to collect PC security data." }
                'DE' { "Klicken Sie zuerst oben auf 'Scan starten', um die Sicherheitsdaten des PCs zu erfassen." }
                default { "Premi prima 'Avvia scansione' in alto per raccogliere i dati del PC." }
            }
            return
        }
        $statoUI.UltimaModalitaIA = 'Resoconto'
        $conteggi    = Measure-ConteggiRisultati -Elementi $statoUI.RisultatiGrezzi
        $promptRes   = Format-PromptResocontoOllama -ElementiVista $statoUI.ElementiVista -Conteggi $conteggi -Ambiente $Ambiente -Lingua $lang
        $fallbackRes = Format-ResocontoLocaleScansione -ElementiVista $statoUI.ElementiVista -Conteggi $conteggi -Ambiente $Ambiente -Lingua $lang
        $lblOp       = switch ($lang) {
            'EN' { "Generating Full PC Security Report" }
            'DE' { "Erstellung des PC-Sicherheitsberichts" }
            default { "Generazione Resoconto Sicurezza PC" }
        }
        & $avviaRichiestaOllamaAsincrona $promptRes $lblOp $fallbackRes
    }

    $ctrl.BtnSpiegaLLM.Add_Click($eseguiSpiegazioneControllo)
    $ctrl.BtnSpiegaControlloTab.Add_Click($eseguiSpiegazioneControllo)
    $ctrl.BtnResocontoLLM.Add_Click($eseguiResocontoScansione)
    $ctrl.BtnResocontoTab.Add_Click($eseguiResocontoScansione)

    $ctrl.BtnCopiaRispostaLLM.Add_Click({
        $lang = $statoUI.LinguaCorrente
        if (-not [string]::IsNullOrWhiteSpace($ctrl.TxtRispostaLLM.Text)) {
            [System.Windows.Clipboard]::SetText($ctrl.TxtRispostaLLM.Text)
            $ctrl.TxtStatoLLM.Text = switch ($lang) {
                'EN' { "AI Report copied to Windows clipboard!" }
                'DE' { "KI-Bericht in die Windows-Zwischenablage kopiert!" }
                default { "Resoconto copiato negli appunti di Windows!" }
            }
        }
    })

    # --- Avvia scansione in Runspace separato ---
    $ctrl.BtnAvvia.Add_Click({
        if ($statoUI.ScansioneInCorso) { return }
        $lang = $statoUI.LinguaCorrente

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
        $ctrl.TxtProgresso.Text         = switch ($lang) {
            'EN' { "Starting scan..." }
            'DE' { "Scan wird gestartet..." }
            default { "Avvio scansione..." }
        }
        $ctrl.TxtMessaggioGuida.Text    = switch ($lang) {
            'EN' { "Scan in progress... Results will appear as controls are evaluated." }
            'DE' { "Scan laeuft... Ergebnisse werden fortlaufend angezeigt." }
            default { "Scansione in corso... I risultati compariranno man mano." }
        }
        $ctrl.PanelGuidaVuota.Visibility = [System.Windows.Visibility]::Visible
        $ctrl.GridRisultati.ItemsSource = @()
        & $aggiornaConteggiERiepilogo
        & $aggiornaPannelloDettaglio

        # Callback invocato sul thread UI tramite Dispatcher per ogni controllo completato
        $callbackProgresso = [Action[int, int, object]]{
            param([int]$Indice, [int]$Totale, [object]$RisultatoSingolo)

            $langProg = $statoUI.LinguaCorrente
            $statoUI.RisultatiGrezzi += $RisultatoSingolo
            $statoUI.ElementiVista = @(ConvertTo-RisultatiVista -Risultati $statoUI.RisultatiGrezzi -Catalogo $Catalogo -Lingua $langProg)

            $ctrl.ProgressScansione.Maximum = if ($Totale -gt 0) { $Totale } else { 1 }
            $ctrl.ProgressScansione.Value   = $Indice
            $ctrl.TxtProgresso.Text         = switch ($langProg) {
                'EN' { "Progress: $Indice/$Totale" }
                'DE' { "Fortschritt: $Indice/$Totale" }
                default { "Avanzamento: $Indice/$Totale" }
            }

            & $aggiornaConteggiERiepilogo
            & $applicaFiltriTabella
        }

        # Callback invocato sul thread UI al termine (o annullamento) della scansione
        $callbackFine = [Action]{
            $langEnd = $statoUI.LinguaCorrente
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
                $ctrl.TxtBannerErrore.Text = switch ($langEnd) {
                    'EN' { "An error occurred during the scan execution. Please retry or export the technical log." }
                    'DE' { "Waehrend des Scans ist ein Fehler aufgetreten. Bitte versuchen Sie es erneut oder exportieren Sie das technische Protokoll." }
                    default { "Si e' verificato un problema durante l'esecuzione della scansione. Riprova o esporta il log tecnico." }
                }
                $ctrl.BannerErrore.Visibility = [System.Windows.Visibility]::Visible
                $ctrl.TxtProgresso.Text = switch ($langEnd) {
                    'EN' { "Stopped on error ($nValutati/$totaleControlli)" }
                    'DE' { "Wegen Fehler gestoppt ($nValutati/$totaleControlli)" }
                    default { "Interrotto per errore ($nValutati/$totaleControlli)" }
                }
            }
            elseif ($null -ne $statoUI.SyncRunspace -and $statoUI.SyncRunspace.AnnullaRichiesto) {
                $ctrl.TxtProgresso.Text = switch ($langEnd) {
                    'EN' { "Canceled ($nValutati/$totaleControlli)" }
                    'DE' { "Abgebrochen ($nValutati/$totaleControlli)" }
                    default { "Annullata ($nValutati/$totaleControlli)" }
                }
                if ($nValutati -eq 0) {
                    $ctrl.TxtMessaggioGuida.Text = switch ($langEnd) {
                        'EN' { "Scan canceled. Click 'Start Scan' to try again." }
                        'DE' { "Scan abgebrochen. Klicken Sie auf 'Scan starten', um es erneut zu versuchen." }
                        default { "Scansione annullata. Premi 'Avvia scansione' per riprovare." }
                    }
                }
            }
            else {
                $ctrl.TxtProgresso.Text = switch ($langEnd) {
                    'EN' { "Completed ($nValutati/$nValutati)" }
                    'DE' { "Abgeschlossen ($nValutati/$nValutati)" }
                    default { "Completata ($nValutati/$nValutati)" }
                }
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
            $ctrl.TxtProgresso.Text = switch ($statoUI.LinguaCorrente) {
                'EN' { "Canceling..." }
                'DE' { "Wird abgebrochen..." }
                default { "Annullamento in corso..." }
            }
        }
    })

    # --- Export JSON ---
    $ctrl.BtnEsportaJson.Add_Click({
        if ($statoUI.RisultatiGrezzi.Count -eq 0) { return }
        $lang = $statoUI.LinguaCorrente

        $dialogo = New-Object Microsoft.Win32.SaveFileDialog
        $dialogo.Title      = switch ($lang) { 'EN' { "Export JSON Report" } 'DE' { "JSON-Bericht exportieren" } default { "Esporta report JSON" } }
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

            $ctrl.TxtRiepilogoFooter.Text = switch ($lang) {
                'EN' { "Exported JSON: $(Split-Path -Leaf $dialogo.FileName)" }
                'DE' { "JSON exportiert: $(Split-Path -Leaf $dialogo.FileName)" }
                default { "Esportato JSON: $(Split-Path -Leaf $dialogo.FileName)" }
            }
        }
    })

    # --- Export HTML ---
    $ctrl.BtnEsportaHtml.Add_Click({
        if ($statoUI.RisultatiGrezzi.Count -eq 0) { return }
        $lang = $statoUI.LinguaCorrente

        $dialogo = New-Object Microsoft.Win32.SaveFileDialog
        $dialogo.Title      = switch ($lang) { 'EN' { "Export HTML Report" } 'DE' { "HTML-Bericht exportieren" } default { "Esporta report HTML" } }
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

            $ctrl.TxtRiepilogoFooter.Text = switch ($lang) {
                'EN' { "Exported HTML: $(Split-Path -Leaf $dialogo.FileName)" }
                'DE' { "HTML exportiert: $(Split-Path -Leaf $dialogo.FileName)" }
                default { "Esportato HTML: $(Split-Path -Leaf $dialogo.FileName)" }
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

# =============================================================================
# PUNTO D'INGRESSO AUTONOMO (GUI / HEADLESS / IRM | IEX)
# =============================================================================
function Invoke-Win11Scanner {
    [CmdletBinding()]
    param(
        [switch]$Gui,
        [switch]$Cli,
        [switch]$Headless,
        [string]$OutFile,
        [string[]]$ControlId,
        [ValidateSet('IT', 'EN', 'DE')]
        [string]$Lang = $script:LinguaPredefinita
    )

    if ($Headless -and $Gui) {
        Write-Error "I parametri -Gui e -Headless sono mutuamente esclusivi."
        return
    }

    if ($Headless -and (-not $OutFile)) {
        Write-Error "Il parametro -OutFile e' obbligatorio in modalita' -Headless."
        return
    }

    $modalitaGui = ($Gui -or (-not $Headless))
    $catalogo    = $script:CatalogoJsonIncorporato | ConvertFrom-Json
    $ambiente    = Get-AmbienteSistema

    if ($modalitaGui) {
        # Se siamo collegati via SSH o in modalita' terminale (-Cli), avvia l'interfaccia interattiva da console (TUI)
        if ($Cli -or (Test-SessioneTerminaleSsh)) {
            $paramConsole = @{
                Catalogo       = $catalogo
                Ambiente       = $ambiente
                VersioneTool   = $script:VERSIONE_TOOL
                LinguaIniziale = $Lang
            }
            if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
                $paramConsole['ControlId'] = $ControlId
            }
            Show-ScannerConsoleUI @paramConsole
            return
        }

        if ([System.Threading.Thread]::CurrentThread.ApartmentState -ne [System.Threading.ApartmentState]::STA) {
            if (-not [string]::IsNullOrWhiteSpace($script:PercorsoScriptAutonomo) -and (Test-Path -LiteralPath $script:PercorsoScriptAutonomo)) {
                $argSta = "-NoProfile -ExecutionPolicy Bypass -STA -File `"$($script:PercorsoScriptAutonomo)`" -Gui"
                if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
                    $argSta += " -ControlId $($ControlId -join ',')"
                }
                $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argSta -Wait -PassThru
                return
            }
            else {
                $argSta = "-NoProfile -ExecutionPolicy Bypass -STA -Command `"[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; irm '$($script:UrlScriptRemoto)' | iex`""
                $proc = Start-Process -FilePath 'powershell.exe' -ArgumentList $argSta -Wait -PassThru
                return
            }
        }

        $paramGui = @{
            Catalogo       = $catalogo
            Ambiente       = $ambiente
            ContenutoXaml  = $script:XamlIncorporato
            VersioneTool   = $script:VERSIONE_TOOL
            LinguaIniziale = $Lang
        }
        if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
            $paramGui['ControlId'] = $ControlId
        }

        Start-ScannerUI @paramGui
    }
    else {
        Write-Host "Scanner di sicurezza Windows 11 v$($script:VERSIONE_TOOL) (Autonomo)"
        Write-Host "=========================================================="
        Write-Host "  Edizione:  $($ambiente.Edition) ($($ambiente.EditionId))"
        Write-Host "  Build:     $($ambiente.Build)"
        Write-Host "  Admin:     $($ambiente.IsAdmin)"

        $paramRunner = @{
            Catalogo = $catalogo
            Ambiente = $ambiente
        }
        if ($null -ne $ControlId -and $ControlId.Count -gt 0) {
            $paramRunner['ControlId'] = $ControlId
        }

        $risultati = Invoke-Controlli @paramRunner
        $report    = New-Report -Risultati $risultati -Ambiente $ambiente -Catalogo $catalogo -VersioneTool $script:VERSIONE_TOOL
        Export-ReportJson -Report $report -PercorsoFile $OutFile

        Write-Host "`nReport scritto in: $OutFile"
        Write-Host "  Superato:        $($report.summary.superato)"
        Write-Host "  Fallito:         $($report.summary.fallito)"
        Write-Host "  Non applicabile: $($report.summary.non_applicabile)"
        Write-Host "  Sconosciuto:     $($report.summary.sconosciuto)"
        Write-Host "  Errore:          $($report.summary.errore)"
    }
}

# Gestione argomenti sia per esecuzione via 'irm ... | iex' sia via 'powershell -File scanner-win11.ps1 ...'
$argomentiRigaComando = @($args)
$parametriInvocazione = @{}
for ($i = 0; $i -lt $argomentiRigaComando.Count; $i++) {
    $token = [string]$argomentiRigaComando[$i]
    switch -Regex ($token) {
        '^-Gui$'       { $parametriInvocazione['Gui'] = $true }
        '^-Cli$'       { $parametriInvocazione['Cli'] = $true }
        '^-Headless$'  { $parametriInvocazione['Headless'] = $true }
        '^-OutFile$'   {
            if ($i + 1 -lt $argomentiRigaComando.Count) {
                $i++
                $parametriInvocazione['OutFile'] = [string]$argomentiRigaComando[$i]
            }
        }
        '^-ControlId$' {
            if ($i + 1 -lt $argomentiRigaComando.Count) {
                $i++
                $valId = $argomentiRigaComando[$i]
                if ($valId -is [array]) {
                    $parametriInvocazione['ControlId'] = [string[]]$valId
                }
                else {
                    $parametriInvocazione['ControlId'] = @([string]$valId -split ',')
                }
            }
        }
    }
}

Invoke-Win11Scanner @parametriInvocazione
