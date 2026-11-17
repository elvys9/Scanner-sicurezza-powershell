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
      "title": "UAC richiede conferma per elevazione",
      "category": "UAC",
      "severity": "alto",
      "editions": [
        "Home",
        "Pro"
      ],
      "description": "Verifica che UAC richieda il consenso dell'utente per le operazioni con privilegi elevati (ConsentPromptBehaviorAdmin diverso da 0).",
      "rationale": "Se UAC e' impostato per non chiedere conferma, i programmi malevoli possono ottenere privilegi elevati senza che l'utente se ne accorga.",
      "check": {
        "registry": {
          "path": "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
          "name": "ConsentPromptBehaviorAdmin",
          "operator": "ne",
          "value": 0
        }
      },
      "references": [
        "CIS Benchmark Windows 11 - 2.3.17.1"
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
      "title": "BitLocker attivo sul disco di sistema",
      "category": "Crittografia",
      "severity": "alto",
      "editions": [
        "Pro"
      ],
      "description": "Verifica che BitLocker sia attivo sulla partizione di sistema.",
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
    }
  ]
}
'@

# --- LAYOUT XAML INCORPORATO ---
$script:XamlIncorporato = @'
<Window xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
        xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
        Title="Scanner sicurezza Windows"
        Width="1120" Height="740"
        MinWidth="900" MinHeight="600"
        WindowStartupLocation="CenterScreen"
        ResizeMode="CanResize"
        UseLayoutRounding="True"
        SnapsToDevicePixels="True"
        TextOptions.TextFormattingMode="Ideal"
        FontFamily="Segoe UI"
        FontSize="13"
        Background="{DynamicResource BgPrimary}"
        Foreground="{DynamicResource TextPrimary}">

    <Window.Resources>
        <ResourceDictionary>
            <!-- Colori predefiniti (Tema Chiaro) aggiornabili a runtime via codice per Tema Scuro -->
            <SolidColorBrush x:Key="BgPrimary" Color="#F4F6F9"/>
            <SolidColorBrush x:Key="BgSurface" Color="#FFFFFF"/>
            <SolidColorBrush x:Key="BgHeader" Color="#0F172A"/>
            <SolidColorBrush x:Key="TextHeader" Color="#F8FAFC"/>
            <SolidColorBrush x:Key="BgSubtle" Color="#F8FAFC"/>
            <SolidColorBrush x:Key="TextPrimary" Color="#1E293B"/>
            <SolidColorBrush x:Key="TextSecondary" Color="#475569"/>
            <SolidColorBrush x:Key="BorderSubtle" Color="#CBD5E1"/>
            <SolidColorBrush x:Key="AccentBrush" Color="#2563EB"/>
            <SolidColorBrush x:Key="AccentText" Color="#FFFFFF"/>

            <!-- Colori per stato (sempre accompagnati da simbolo + testo) -->
            <SolidColorBrush x:Key="PassBg" Color="#DCFCE7"/>
            <SolidColorBrush x:Key="PassFg" Color="#166534"/>
            <SolidColorBrush x:Key="PassBorder" Color="#86EFAC"/>

            <SolidColorBrush x:Key="FailBg" Color="#FEE2E2"/>
            <SolidColorBrush x:Key="FailFg" Color="#991B1B"/>
            <SolidColorBrush x:Key="FailBorder" Color="#FCA5A5"/>

            <SolidColorBrush x:Key="UnknownBg" Color="#E2E8F0"/>
            <SolidColorBrush x:Key="UnknownFg" Color="#334155"/>
            <SolidColorBrush x:Key="UnknownBorder" Color="#94A3B8"/>

            <SolidColorBrush x:Key="NaBg" Color="#F1F5F9"/>
            <SolidColorBrush x:Key="NaFg" Color="#475569"/>
            <SolidColorBrush x:Key="NaBorder" Color="#CBD5E1"/>

            <SolidColorBrush x:Key="ErrorBg" Color="#FFEDD5"/>
            <SolidColorBrush x:Key="ErrorFg" Color="#9A3412"/>
            <SolidColorBrush x:Key="ErrorBorder" Color="#FDBA74"/>

            <!-- Banner Avviso Admin -->
            <SolidColorBrush x:Key="WarnBannerBg" Color="#FEF3C7"/>
            <SolidColorBrush x:Key="WarnBannerFg" Color="#92400E"/>
            <SolidColorBrush x:Key="WarnBannerBorder" Color="#F59E0B"/>
        </ResourceDictionary>
    </Window.Resources>

    <Grid>
        <Grid.RowDefinitions>
            <!-- 0: Header -->
            <RowDefinition Height="Auto"/>
            <!-- 1: Banner Non-Admin (opzionale) -->
            <RowDefinition Height="Auto"/>
            <!-- 2: Banner Errore generale (opzionale) -->
            <RowDefinition Height="Auto"/>
            <!-- 3: Barra azioni e avanzamento -->
            <RowDefinition Height="Auto"/>
            <!-- 4: Conteggi riepilogo -->
            <RowDefinition Height="Auto"/>
            <!-- 5: Barra filtri -->
            <RowDefinition Height="Auto"/>
            <!-- 6: Contenuto principale (Tabella + Dettaglio) -->
            <RowDefinition Height="*"/>
            <!-- 7: Barra inferiore (Export + Disclaimer permanente) -->
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <!-- 0. INTESTAZIONE -->
        <Border Grid.Row="0" Background="{DynamicResource BgHeader}" Padding="16,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="&#xE72E;" FontFamily="Segoe MDL2 Assets" FontSize="18"
                               Foreground="#60A5FA" VerticalAlignment="Center" Margin="0,0,10,0"/>
                    <TextBlock Text="Scanner sicurezza Windows" FontSize="17" FontWeight="SemiBold"
                               Foreground="{DynamicResource TextHeader}" VerticalAlignment="Center"/>
                    <TextBlock Text=" (Sola lettura)" FontSize="12" Foreground="#94A3B8"
                               VerticalAlignment="Center" Margin="6,2,0,0"/>
                </StackPanel>

                <Border Grid.Column="1" Background="#1E293B" CornerRadius="4" Padding="10,4" Margin="0,0,10,0"
                        VerticalAlignment="Center" BorderBrush="#334155" BorderThickness="1">
                    <TextBlock x:Name="TxtAmbienteInfo"
                               Text="Windows 11 | Admin: --"
                               Foreground="#E2E8F0" FontSize="12" VerticalAlignment="Center"/>
                </Border>

                <Button x:Name="BtnTema" Grid.Column="2" Content="Tema: Scuro"
                        Padding="10,4" MinWidth="105" Cursor="Hand"
                        TabIndex="1"
                        ToolTip="Cambia tra tema chiaro e tema scuro (Alt+T)"/>
            </Grid>
        </Border>

        <!-- 1. BANNER AVVISO UTENTE NON AMMINISTRATORE -->
        <Border x:Name="BannerNonAdmin" Grid.Row="1"
                Background="{DynamicResource WarnBannerBg}"
                BorderBrush="{DynamicResource WarnBannerBorder}"
                BorderThickness="0,0,0,1" Padding="16,8" Visibility="Collapsed">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <TextBlock Text="[!]" FontWeight="Bold" Foreground="{DynamicResource WarnBannerFg}" Margin="0,0,8,0"/>
                    <TextBlock Foreground="{DynamicResource WarnBannerFg}" TextWrapping="Wrap" VerticalAlignment="Center"
                               Text="Avviato senza privilegi di amministratore. I controlli che richiedono privilegi elevati (es. Firewall, Account locali) risulteranno 'Sconosciuto' e mai 'Fallito'."/>
                </StackPanel>
                <Button x:Name="BtnRiavviaAdmin" Grid.Column="1" Content="Riavvia come amministratore"
                        Padding="10,4" Margin="12,0,0,0" Cursor="Hand" FontWeight="SemiBold"
                        TabIndex="2"
                        ToolTip="Rilancia lo scanner richiedendo i privilegi di amministratore tramite UAC"/>
            </Grid>
        </Border>

        <!-- 2. BANNER ERRORE SCANSIONE -->
        <Border x:Name="BannerErrore" Grid.Row="2"
                Background="{DynamicResource ErrorBg}"
                BorderBrush="{DynamicResource ErrorBorder}"
                BorderThickness="0,0,0,1" Padding="16,8" Visibility="Collapsed">
            <TextBlock x:Name="TxtBannerErrore"
                       Foreground="{DynamicResource ErrorFg}"
                       TextWrapping="Wrap" FontWeight="SemiBold"
                       Text="Si e' verificato un problema durante l'esecuzione di alcuni controlli."/>
        </Border>

        <!-- 3. BARRA AZIONI E AVANZAMENTO -->
        <Border Grid.Row="3" Background="{DynamicResource BgSurface}"
                BorderBrush="{DynamicResource BorderSubtle}" BorderThickness="0,0,0,1" Padding="16,10">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>

                <Button x:Name="BtnAvvia" Grid.Column="0" Content="_Avvia scansione"
                        Padding="16,6" FontWeight="SemiBold" Cursor="Hand"
                        Background="{DynamicResource AccentBrush}" Foreground="{DynamicResource AccentText}"
                        TabIndex="3"
                        ToolTip="Avvia l'analisi di sicurezza in sola lettura (Alt+A)"/>

                <Button x:Name="BtnAnnulla" Grid.Column="1" Content="A_nnulla"
                        Padding="14,6" Margin="10,0,0,0" IsEnabled="False" Cursor="Hand"
                        TabIndex="4"
                        ToolTip="Interrompe la scansione in corso al termine del controllo attuale (Alt+N)"/>

                <ProgressBar x:Name="ProgressScansione" Grid.Column="2"
                             Height="18" Margin="20,0,12,0" Minimum="0" Maximum="18" Value="0"
                             VerticalAlignment="Center"/>

                <TextBlock x:Name="TxtProgresso" Grid.Column="3"
                           Text="Pronto (0/18)" FontWeight="SemiBold"
                           Foreground="{DynamicResource TextSecondary}"
                           VerticalAlignment="Center" MinWidth="135" TextAlignment="Right"/>
            </Grid>
        </Border>

        <!-- 4. SCHEDE RIEPILOGO CONTEGGI -->
        <Border Grid.Row="4" Background="{DynamicResource BgPrimary}" Padding="16,8,16,4">
            <UniformGrid Rows="1" Columns="5">
                <Border Background="{DynamicResource PassBg}" BorderBrush="{DynamicResource PassBorder}"
                        BorderThickness="1" CornerRadius="4" Padding="10,6" Margin="0,0,6,0">
                    <TextBlock x:Name="TxtCountSuperati" Text="[OK] 0 Superati"
                               Foreground="{DynamicResource PassFg}" FontWeight="Bold" HorizontalAlignment="Center"/>
                </Border>
                <Border Background="{DynamicResource FailBg}" BorderBrush="{DynamicResource FailBorder}"
                        BorderThickness="1" CornerRadius="4" Padding="10,6" Margin="3,0,6,0">
                    <TextBlock x:Name="TxtCountFalliti" Text="[X] 0 Falliti"
                               Foreground="{DynamicResource FailFg}" FontWeight="Bold" HorizontalAlignment="Center"/>
                </Border>
                <Border Background="{DynamicResource UnknownBg}" BorderBrush="{DynamicResource UnknownBorder}"
                        BorderThickness="1" CornerRadius="4" Padding="10,6" Margin="3,0,6,0">
                    <TextBlock x:Name="TxtCountSconosciuti" Text="[?] 0 Sconosciuti"
                               Foreground="{DynamicResource UnknownFg}" FontWeight="Bold" HorizontalAlignment="Center"/>
                </Border>
                <Border Background="{DynamicResource NaBg}" BorderBrush="{DynamicResource NaBorder}"
                        BorderThickness="1" CornerRadius="4" Padding="10,6" Margin="3,0,6,0">
                    <TextBlock x:Name="TxtCountNonApplicabili" Text="[-] 0 Non applicabili"
                               Foreground="{DynamicResource NaFg}" FontWeight="Bold" HorizontalAlignment="Center"/>
                </Border>
                <Border Background="{DynamicResource ErrorBg}" BorderBrush="{DynamicResource ErrorBorder}"
                        BorderThickness="1" CornerRadius="4" Padding="10,6" Margin="3,0,0,0">
                    <TextBlock x:Name="TxtCountErrori" Text="[!] 0 Errori"
                               Foreground="{DynamicResource ErrorFg}" FontWeight="Bold" HorizontalAlignment="Center"/>
                </Border>
            </UniformGrid>
        </Border>

        <!-- 5. BARRA FILTRI E RICERCA -->
        <Border Grid.Row="5" Background="{DynamicResource BgSurface}"
                BorderBrush="{DynamicResource BorderSubtle}" BorderThickness="0,1,0,1" Padding="16,8" Margin="0,4,0,0">
            <WrapPanel Orientation="Horizontal" VerticalAlignment="Center">
                <TextBlock Text="Stato:" VerticalAlignment="Center" Margin="0,0,6,0" FontWeight="SemiBold"/>
                <ComboBox x:Name="CmbFiltroStato" Width="135" Margin="0,0,14,0" SelectedIndex="0" TabIndex="5">
                    <ComboBoxItem Content="Tutti"/>
                    <ComboBoxItem Content="fallito"/>
                    <ComboBoxItem Content="superato"/>
                    <ComboBoxItem Content="sconosciuto"/>
                    <ComboBoxItem Content="non_applicabile"/>
                    <ComboBoxItem Content="errore"/>
                </ComboBox>

                <TextBlock Text="Gravita':" VerticalAlignment="Center" Margin="0,0,6,0" FontWeight="SemiBold"/>
                <ComboBox x:Name="CmbFiltroGravita" Width="120" Margin="0,0,14,0" SelectedIndex="0" TabIndex="6">
                    <ComboBoxItem Content="Tutte"/>
                    <ComboBoxItem Content="critico"/>
                    <ComboBoxItem Content="alto"/>
                    <ComboBoxItem Content="medio"/>
                    <ComboBoxItem Content="basso"/>
                    <ComboBoxItem Content="informativo"/>
                </ComboBox>

                <TextBlock Text="Categoria:" VerticalAlignment="Center" Margin="0,0,6,0" FontWeight="SemiBold"/>
                <ComboBox x:Name="CmbFiltroCategoria" Width="150" Margin="0,0,14,0" SelectedIndex="0" TabIndex="7">
                    <ComboBoxItem Content="Tutte"/>
                </ComboBox>

                <TextBlock Text="Cerca:" VerticalAlignment="Center" Margin="0,0,6,0" FontWeight="SemiBold"/>
                <TextBox x:Name="TxtRicerca" Width="180" Padding="4,2" Margin="0,0,10,0" TabIndex="8"
                         ToolTip="Filtra per titolo o ID del controllo (es. HOME-FW-001)"/>

                <Button x:Name="BtnResetFiltri" Content="Reimposta filtri" Padding="8,2" Cursor="Hand" TabIndex="9"/>
            </WrapPanel>
        </Border>

        <!-- 6. AREA PRINCIPALE: TABELLA RISULTATI + PANNELLO DETTAGLIO -->
        <Grid Grid.Row="6" Margin="16,10,16,10">
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="3*" MinWidth="420"/>
                <ColumnDefinition Width="8"/>
                <ColumnDefinition Width="2*" MinWidth="320"/>
            </Grid.ColumnDefinitions>

            <!-- Colonna sinistra: Tabella + Messaggio guida iniziale -->
            <Grid Grid.Column="0">
                <DataGrid x:Name="GridRisultati"
                          AutoGenerateColumns="False"
                          IsReadOnly="True"
                          SelectionMode="Single"
                          SelectionUnit="FullRow"
                          HeadersVisibility="Column"
                          GridLinesVisibility="Horizontal"
                          HorizontalGridLinesBrush="{DynamicResource BorderSubtle}"
                          Background="{DynamicResource BgSurface}"
                          RowBackground="{DynamicResource BgSurface}"
                          AlternatingRowBackground="{DynamicResource BgSubtle}"
                          Foreground="{DynamicResource TextPrimary}"
                          BorderBrush="{DynamicResource BorderSubtle}"
                          BorderThickness="1"
                          RowHeaderWidth="0"
                          CanUserAddRows="False"
                          CanUserDeleteRows="False"
                          CanUserReorderColumns="False"
                          TabIndex="10">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Stato" Binding="{Binding StatusLabel}" Width="125"/>
                        <DataGridTextColumn Header="Gravita'" Binding="{Binding SeverityLabel}" Width="85"/>
                        <DataGridTextColumn Header="Categoria" Binding="{Binding Category}" Width="115"/>
                        <DataGridTextColumn Header="ID" Binding="{Binding ControlId}" Width="115"/>
                        <DataGridTextColumn Header="Controllo" Binding="{Binding Title}" Width="*"/>
                    </DataGrid.Columns>
                </DataGrid>

                <!-- Messaggio guida quando la tabella e' vuota -->
                <Border x:Name="PanelGuidaVuota"
                        Background="{DynamicResource BgSurface}"
                        BorderBrush="{DynamicResource BorderSubtle}"
                        BorderThickness="1" Padding="24"
                        HorizontalAlignment="Stretch" VerticalAlignment="Stretch">
                    <StackPanel VerticalAlignment="Center" HorizontalAlignment="Center">
                        <TextBlock Text="&#xE721;" FontFamily="Segoe MDL2 Assets" FontSize="36"
                                   Foreground="{DynamicResource TextSecondary}" HorizontalAlignment="Center" Margin="0,0,0,10"/>
                        <TextBlock x:Name="TxtMessaggioGuida"
                                   Text="Premi 'Avvia scansione' per analizzare la sicurezza del sistema."
                                   FontSize="15" FontWeight="SemiBold"
                                   Foreground="{DynamicResource TextPrimary}"
                                   TextAlignment="Center" TextWrapping="Wrap"/>
                        <TextBlock Text="La scansione e' in sola lettura e non apporta alcuna modifica a Windows."
                                   FontSize="12" Foreground="{DynamicResource TextSecondary}"
                                   TextAlignment="Center" Margin="0,6,0,0"/>
                    </StackPanel>
                </Border>
            </Grid>

            <GridSplitter Grid.Column="1" Width="8" HorizontalAlignment="Stretch" Background="Transparent"/>

            <!-- Colonna destra: Pannello Dettaglio -->
            <Border Grid.Column="2" Background="{DynamicResource BgSurface}"
                    BorderBrush="{DynamicResource BorderSubtle}" BorderThickness="1" CornerRadius="4" Padding="14">
                <ScrollViewer VerticalScrollBarVisibility="Auto" HorizontalScrollBarVisibility="Disabled">
                    <StackPanel>
                        <TextBlock Text="DETTAGLIO CONTROLLO" FontSize="11" FontWeight="Bold"
                                   Foreground="{DynamicResource TextSecondary}" Margin="0,0,0,4"/>

                        <TextBlock x:Name="TxtDettaglioTitolo"
                                   Text="Seleziona un controllo dalla tabella"
                                   FontSize="16" FontWeight="Bold"
                                   Foreground="{DynamicResource TextPrimary}" TextWrapping="Wrap"/>

                        <TextBlock x:Name="TxtDettaglioSottotitolo"
                                   Text="ID: - | Stato: - | Gravita': -"
                                   FontSize="12" Foreground="{DynamicResource TextSecondary}"
                                   Margin="0,4,0,10" TextWrapping="Wrap"/>

                        <!-- Selettore Modalita' Semplice / Tecnico -->
                        <StackPanel Orientation="Horizontal" Margin="0,0,0,10">
                            <Button x:Name="BtnModoSemplice" Content="Semplice" Padding="12,3"
                                    FontWeight="SemiBold" Cursor="Hand" TabIndex="11"
                                    ToolTip="Mostra la spiegazione pensata per utenti domestici"/>
                            <Button x:Name="BtnModoTecnico" Content="Tecnico" Padding="12,3" Margin="6,0,0,0"
                                    Cursor="Hand" TabIndex="12"
                                    ToolTip="Mostra dettagli tecnici, ID, riferimenti CIS ed evidenze"/>
                        </StackPanel>

                        <!-- Sezione: Perche' conta / Spiegazione -->
                        <TextBlock x:Name="TxtTitoloSpiegazione" Text="Perche' conta (spiegazione semplice)"
                                   FontWeight="SemiBold" Foreground="{DynamicResource TextPrimary}" Margin="0,2,0,4"/>
                        <Border Background="{DynamicResource BgSubtle}" BorderBrush="{DynamicResource BorderSubtle}"
                                BorderThickness="1" CornerRadius="4" Padding="10,8" Margin="0,0,0,10">
                            <TextBlock x:Name="TxtDettaglioSpiegazione"
                                       Text="Seleziona una riga nella tabella a sinistra per leggere la spiegazione del controllo."
                                       TextWrapping="Wrap" Foreground="{DynamicResource TextPrimary}"/>
                        </Border>

                        <!-- Banner errore specifico del controllo (comprensibile, senza stack trace) -->
                        <Border x:Name="BannerDettaglioErrore"
                                Background="{DynamicResource ErrorBg}" BorderBrush="{DynamicResource ErrorBorder}"
                                BorderThickness="1" CornerRadius="4" Padding="10,8" Margin="0,0,0,10"
                                Visibility="Collapsed">
                            <TextBlock x:Name="TxtDettaglioErrore"
                                       Foreground="{DynamicResource ErrorFg}" TextWrapping="Wrap"
                                       Text=""/>
                        </Border>

                        <!-- Sezione: Valore Atteso / Valore Trovato -->
                        <Grid Margin="0,0,0,10">
                            <Grid.ColumnDefinitions>
                                <ColumnDefinition Width="*"/>
                                <ColumnDefinition Width="8"/>
                                <ColumnDefinition Width="*"/>
                            </Grid.ColumnDefinitions>
                            <Border Grid.Column="0" Background="{DynamicResource BgSubtle}"
                                    BorderBrush="{DynamicResource BorderSubtle}" BorderThickness="1"
                                    CornerRadius="4" Padding="8,6">
                                <StackPanel>
                                    <TextBlock Text="Valore atteso" FontSize="11" FontWeight="Bold"
                                               Foreground="{DynamicResource TextSecondary}"/>
                                    <TextBlock x:Name="TxtDettaglioAtteso" Text="-" TextWrapping="Wrap"
                                               Margin="0,2,0,0" FontWeight="SemiBold"/>
                                </StackPanel>
                            </Border>
                            <Border Grid.Column="2" Background="{DynamicResource BgSubtle}"
                                    BorderBrush="{DynamicResource BorderSubtle}" BorderThickness="1"
                                    CornerRadius="4" Padding="8,6">
                                <StackPanel>
                                    <TextBlock Text="Valore trovato" FontSize="11" FontWeight="Bold"
                                               Foreground="{DynamicResource TextSecondary}"/>
                                    <TextBlock x:Name="TxtDettaglioOsservato" Text="-" TextWrapping="Wrap"
                                               Margin="0,2,0,0" FontWeight="SemiBold"/>
                                </StackPanel>
                            </Border>
                        </Grid>

                        <!-- Sezione: Come correggere -->
                        <TextBlock Text="Come correggere (indicazione manuale)" FontWeight="SemiBold"
                                   Foreground="{DynamicResource TextPrimary}" Margin="0,0,0,4"/>
                        <TextBlock x:Name="TxtDettaglioRimedio"
                                   Text="-" TextWrapping="Wrap"
                                   Foreground="{DynamicResource TextPrimary}" Margin="0,0,0,8"/>

                        <!-- Blocco Comando di rimedio (visibile solo se command non e' null) -->
                        <StackPanel x:Name="PanelComandoRimedio" Visibility="Collapsed" Margin="0,0,0,10">
                            <TextBlock Text="Comando PowerShell di riferimento (sola copia, non eseguito):"
                                       FontSize="11" Foreground="{DynamicResource TextSecondary}" Margin="0,0,0,4"/>
                            <TextBox x:Name="TxtComandoRimedio"
                                     IsReadOnly="True"
                                     FontFamily="Consolas" FontSize="12"
                                     Background="{DynamicResource BgSubtle}"
                                     Foreground="{DynamicResource TextPrimary}"
                                     BorderBrush="{DynamicResource BorderSubtle}"
                                     Padding="8,6" TextWrapping="Wrap"/>
                            <StackPanel Orientation="Horizontal" Margin="0,6,0,0">
                                <Button x:Name="BtnCopiaComando" Content="_Copia comando"
                                        Padding="10,4" Cursor="Hand" TabIndex="13"
                                        ToolTip="Copia il comando negli appunti di Windows"/>
                                <TextBlock x:Name="TxtFeedbackCopia" Text="Copiato negli appunti!"
                                           Foreground="{DynamicResource PassFg}" FontWeight="SemiBold"
                                           VerticalAlignment="Center" Margin="10,0,0,0" Visibility="Collapsed"/>
                            </StackPanel>
                        </StackPanel>

                        <!-- Note sui rischi -->
                        <TextBlock Text="Note sui rischi" FontWeight="SemiBold"
                                   Foreground="{DynamicResource TextPrimary}" Margin="0,2,0,2"/>
                        <TextBlock x:Name="TxtDettaglioRischi"
                                   Text="-" TextWrapping="Wrap" FontSize="12"
                                   Foreground="{DynamicResource TextSecondary}" Margin="0,0,0,14"/>

                        <!-- Sezione Assistente IA Locale (Ollama) -->
                        <Border Background="{DynamicResource BgSubtle}"
                                BorderBrush="{DynamicResource BorderSubtle}"
                                BorderThickness="1" CornerRadius="4" Padding="10,8" Margin="0,2,0,4">
                            <StackPanel>
                                <TextBlock Text="ASSISTENTE IA LOCALE (OLLAMA - SOLA SPIEGAZIONE)"
                                           FontSize="11" FontWeight="Bold"
                                           Foreground="{DynamicResource TextSecondary}" Margin="0,0,0,6"/>

                                <WrapPanel Orientation="Horizontal" VerticalAlignment="Center" Margin="0,0,0,8">
                                    <TextBlock Text="Modello:" VerticalAlignment="Center" Margin="0,0,6,4" FontSize="12" FontWeight="SemiBold"/>
                                    <ComboBox x:Name="CmbModelloOllama" Width="145" IsEditable="True" SelectedIndex="0" Margin="0,0,8,4"
                                              ToolTip="Seleziona o digita il nome di un modello Ollama locale (consigliato per test: qwen2.5:0.5b)">
                                        <ComboBoxItem Content="qwen2.5:0.5b"/>
                                        <ComboBoxItem Content="qwen2.5:1.5b"/>
                                        <ComboBoxItem Content="llama3.2:1b"/>
                                        <ComboBoxItem Content="gemma2:2b"/>
                                        <ComboBoxItem Content="phi3:mini"/>
                                    </ComboBox>
                                    <Button x:Name="BtnVerificaOllama" Content="Rileva modelli" Padding="8,3" Margin="0,0,0,4"
                                            Cursor="Hand" ToolTip="Controlla i modelli installati su http://localhost:11434"/>
                                </WrapPanel>

                                <WrapPanel Orientation="Horizontal" Margin="0,0,0,6">
                                    <Button x:Name="BtnSpiegaLLM"
                                            Content="Spiega controllo con LLM"
                                            IsEnabled="True"
                                            Cursor="Hand"
                                            Background="{DynamicResource AccentBrush}"
                                            Foreground="{DynamicResource AccentText}"
                                            FontWeight="SemiBold"
                                            ToolTip="Chiede al modello Ollama locale di spiegare questo controllo e come intervenire"
                                            Padding="10,5" Margin="0,0,8,4"/>

                                    <Button x:Name="BtnResocontoLLM"
                                            Content="Resoconto IA scansione"
                                            IsEnabled="False"
                                            Cursor="Hand"
                                            FontWeight="SemiBold"
                                            ToolTip="Genera con Ollama un resoconto complessivo della scansione e i consigli prioritari"
                                            Padding="10,5" Margin="0,0,0,4"/>
                                </WrapPanel>

                                <TextBlock x:Name="TxtStatoLLM"
                                           Text="Pronto (richiede Ollama attivo su localhost:11434)"
                                           FontSize="11" Foreground="{DynamicResource TextSecondary}"
                                           TextWrapping="Wrap" Margin="0,0,0,4"/>

                                <TextBox x:Name="TxtRispostaLLM"
                                         IsReadOnly="True"
                                         TextWrapping="Wrap"
                                         VerticalScrollBarVisibility="Auto"
                                         MinHeight="110"
                                         MaxHeight="260"
                                         Padding="8,6"
                                         FontSize="12"
                                         Background="{DynamicResource BgSurface}"
                                         Foreground="{DynamicResource TextPrimary}"
                                         BorderBrush="{DynamicResource BorderSubtle}"
                                         Visibility="Collapsed"/>
                            </StackPanel>
                        </Border>
                    </StackPanel>
                </ScrollViewer>
            </Border>
        </Grid>

        <!-- 7. BARRA INFERIORE: EXPORT + RIEPILOGO + AVVISO PERMANENTE -->
        <Border Grid.Row="7" Background="{DynamicResource BgSurface}"
                BorderBrush="{DynamicResource BorderSubtle}" BorderThickness="0,1,0,0" Padding="16,8">
            <Grid>
                <Grid.RowDefinitions>
                    <RowDefinition Height="Auto"/>
                    <RowDefinition Height="Auto"/>
                </Grid.RowDefinitions>

                <Grid Grid.Row="0">
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="Auto"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>

                    <Button x:Name="BtnEsportaJson" Grid.Column="0" Content="Esporta _JSON"
                            Padding="12,5" Cursor="Hand" IsEnabled="False" TabIndex="14"
                            ToolTip="Salva il report JSON conforme al contratto 0.1"/>

                    <Button x:Name="BtnEsportaHtml" Grid.Column="1" Content="Esporta _HTML"
                            Padding="12,5" Margin="8,0,0,0" Cursor="Hand" IsEnabled="False" TabIndex="15"
                            ToolTip="Salva un report HTML autonomo leggibile nel browser"/>

                    <CheckBox x:Name="ChkSalvaLogTecnico" Grid.Column="2"
                              Content="Includi file di log tecnico accanto all'export"
                              VerticalAlignment="Center" Margin="14,0,0,0" TabIndex="16"
                              ToolTip="Se selezionato, crea un file .log con i dettagli tecnici di eventuali errori"/>

                    <TextBlock x:Name="TxtRiepilogoFooter" Grid.Column="3"
                               Text="Riepilogo calcolato dal codice: nessuna scansione eseguita"
                               Foreground="{DynamicResource TextSecondary}"
                               VerticalAlignment="Center" HorizontalAlignment="Right" FontSize="12"/>
                </Grid>

                <TextBlock x:Name="TxtDisclaimerPermanente" Grid.Row="1"
                           Margin="0,6,0,0" FontSize="11"
                           Foreground="{DynamicResource TextSecondary}" TextWrapping="Wrap"
                           Text="Avviso permanente: questo strumento verifica solo alcune configurazioni di sicurezza in sola lettura. Un audit conforme non dimostra l'assenza di compromissioni sul sistema."/>
            </Grid>
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
    Client per l'integrazione con un LLM locale tramite Ollama (http://localhost:11434).

.DESCRIPTION
    Fornisce funzioni pure per la costruzione dei prompt (controllo singolo e
    resoconto complessivo della scansione) e funzioni di chiamata all'API REST
    locale di Ollama (/api/tags e /api/generate).
    Rispetta il principio architetturale D3: il rilevamento e' deterministico;
    l'LLM spiega i risultati e fornisce consigli di miglioramento senza mai
    decidere o modificare lo stato dei controlli ne' eseguire comandi sul sistema.
#>

Set-StrictMode -Version 2

$script:EndpointOllamaPredefinito = 'http://localhost:11434'
$script:ModelloOllamaPredefinito  = 'qwen2.5:0.5b'

function Format-PromptControlloOllama {
    <#
    .SYNOPSIS
        Costruisce il prompt in italiano per chiedere all'LLM di spiegare un singolo controllo.
    .PARAMETER Dettaglio
        Oggetto prodotto da Format-DettaglioControllo (ViewModel.ps1).
    .PARAMETER Ambiente
        Oggetto ambiente opzionale (da Get-AmbienteSistema).
    .OUTPUTS
        Stringa con il prompt strutturato per Ollama.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Dettaglio,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Ambiente = $null
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
        "Nessun comando da terminale (configurazione manuale da interfaccia di Windows/BIOS)"
    }

    $prompt = @"
Sei un assistente esperto di sicurezza informatica per utenti domestici Windows 11.
Rispondi SOLO in lingua italiana, in modo chiaro, conciso e pratico.
Non inventare dati e non cambiare lo stato del controllo (che e' gia' stato verificato in modo deterministico dallo scanner).

CONTESTO SISTEMA: $infoOs
CONTROLLO ANALIZZATO:
- ID: $($Dettaglio.ControlId)
- Titolo: $($Dettaglio.Title)
- Categoria: $($Dettaglio.Category)
- Gravita': $($Dettaglio.SeverityLabel)
- Stato rilevato: $($Dettaglio.StatusLabel)
- Valore atteso: $($Dettaglio.ValoreAtteso)
- Valore trovato sul PC: $($Dettaglio.ValoreOsservato)
- Spiegazione base: $($Dettaglio.SpiegazioneSemplice)
- Rimedio consigliato: $($Dettaglio.TestoRimedio)
- Comando di riferimento: $cmdRif
- Note sui rischi: $($Dettaglio.NoteRischi)

Fornisci una risposta strutturata in 3 brevi punti:
1. COSA SIGNIFICA: spiega in parole semplici cosa e' stato trovato sul PC.
2. PERCHE' E' IMPORTANTE: spiega il rischio concreto per l'utente domestico.
3. COME MIGLIORARE IN SICUREZZA: spiega passo dopo passo cosa fare (se lo stato e' Fallito o Sconosciuto) o conferma che l'impostazione e' gia' ottimale (se Superato), ricordando eventuali precauzioni.
"@

    return $prompt.Trim()
}

function Format-PromptResocontoOllama {
    <#
    .SYNOPSIS
        Costruisce il prompt in italiano per generare un resoconto complessivo della scansione
        e un piano di miglioramento prioritario.
    .PARAMETER ElementiVista
        Array di elementi vista (da ConvertTo-RisultatiVista).
    .PARAMETER Conteggi
        Oggetto conteggi (da Measure-ConteggiRisultati).
    .PARAMETER Ambiente
        Oggetto ambiente (da Get-AmbienteSistema).
    .OUTPUTS
        Stringa con il prompt completo per il resoconto IA.
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
        [PSCustomObject]$Ambiente = $null
    )

    $infoOs = if ($null -ne $Ambiente) {
        "Windows 11 $($Ambiente.Edition) (Build $($Ambiente.Build), Eseguito come Admin: $($Ambiente.IsAdmin))"
    }
    else {
        "Windows 11"
    }

    $sbFalliti = New-Object System.Text.StringBuilder
    $nFalliti = 0

    foreach ($el in $ElementiVista) {
        if ($el.Status -eq 'fallito') {
            $nFalliti++
            $det = Format-DettaglioControllo -Elemento $el -Modalita 'Semplice'
            [void]$sbFalliti.AppendLine("- [$($el.SeverityLabel.ToUpperInvariant())] $($el.ControlId) - $($el.Title)")
            [void]$sbFalliti.AppendLine("  Trovato: $($det.ValoreOsservato) (Atteso: $($det.ValoreAtteso))")
            [void]$sbFalliti.AppendLine("  Come correggere: $($det.TestoRimedio)")
        }
    }

    if ($nFalliti -eq 0) {
        [void]$sbFalliti.AppendLine("Nessun controllo fallito! Tutti i controlli applicabili sono superati o richiedono verifica con privilegi amministrativi.")
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

function Test-ConnessioneOllama {
    <#
    .SYNOPSIS
        Verifica se il server locale Ollama e' attivo e restituisce la lista dei modelli installati.
    .PARAMETER Endpoint
        URL base del server Ollama (predefinito: http://localhost:11434).
    .PARAMETER TimeoutSec
        Timeout in secondi (predefinito: 4).
    .OUTPUTS
        PSCustomObject con Disponibile, Modelli, ModelloConsigliato, Errore.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Endpoint = $script:EndpointOllamaPredefinito,

        [Parameter(Mandatory = $false)]
        [int]$TimeoutSec = 4
    )

    $urlPulito = $Endpoint.TrimEnd('/')
    $uriTags   = "$urlPulito/api/tags"

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

        # Preferenza per modelli leggeri ideali per test rapidi
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
            Endpoint           = $urlPulito
            Modelli            = $nomiModelli
            ModelloConsigliato = $consigliato
            Errore             = $null
        }
    }
    catch {
        return [PSCustomObject]@{
            Disponibile        = $false
            Endpoint           = $urlPulito
            Modelli            = @()
            ModelloConsigliato = $script:ModelloOllamaPredefinito
            Errore             = "Ollama non raggiungibile su $urlPulito. Assicurati che Ollama sia installato ('winget install Ollama.Ollama') e avvia un modello leggero con: ollama run qwen2.5:0.5b"
        }
    }
}

function Invoke-RichiestaOllama {
    <#
    .SYNOPSIS
        Invia un prompt al server locale Ollama (/api/generate) e restituisce la risposta testuale.
    .PARAMETER Prompt
        Testo del prompt da inviare.
    .PARAMETER Modello
        Nome del modello Ollama (es. 'qwen2.5:0.5b', 'llama3.2:1b').
    .PARAMETER Endpoint
        URL base di Ollama (predefinito: http://localhost:11434).
    .PARAMETER TimeoutSec
        Timeout massimo per la generazione in secondi (predefinito: 120).
    .OUTPUTS
        PSCustomObject con Successo, Risposta, Modello, DurataMs, Errore.
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
        [int]$TimeoutSec = 120
    )

    $urlPulito = $Endpoint.TrimEnd('/')
    $uriGen    = "$urlPulito/api/generate"

    if ([string]::IsNullOrWhiteSpace($Modello)) {
        $Modello = $script:ModelloOllamaPredefinito
    }

    $cronometro = [System.Diagnostics.Stopwatch]::StartNew()

    try {
        $corpoObj = @{
            model   = $Modello
            prompt  = $Prompt
            stream  = $false
            options = @{
                temperature = 0.2
                num_predict = 700
            }
        }
        $corpoJson = $corpoObj | ConvertTo-Json -Depth 5
        $bytesBody = [System.Text.Encoding]::UTF8.GetBytes($corpoJson)

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
                Risposta = $null
                Modello  = $Modello
                DurataMs = [int]$cronometro.ElapsedMilliseconds
                Errore   = "Ollama ha restituito una risposta vuota per il modello '$Modello'."
            }
        }

        return [PSCustomObject]@{
            Successo = $true
            Risposta = $testoRisposta
            Modello  = $Modello
            DurataMs = [int]$cronometro.ElapsedMilliseconds
            Errore   = $null
        }
    }
    catch {
        $cronometro.Stop()
        $msg = $_.Exception.Message

        $erroreAmichevole = if ($msg -match '404') {
            "Il modello '$Modello' non e' ancora scaricato in Ollama. Apri il terminale ed esegui:`nollama pull $Modello"
        }
        elseif ($msg -match 'Unable to connect|Impossibile stabilire la connessione|timed out|rifiutata') {
            "Impossibile connettersi a Ollama su $urlPulito.`n1. Verifica che Ollama sia in esecuzione.`n2. Se non hai ancora scaricato il modello leggero di test, esegui in PowerShell:`n   ollama pull $Modello"
        }
        else {
            "Errore durante la comunicazione con Ollama ($Modello): $msg"
        }

        return [PSCustomObject]@{
            Successo = $false
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
        Expected = "Tutti i profili firewall attivi (Domain, Private, Public)"
        Evidence = $null
        Error    = $null
    }

    try {
        # Get-NetFirewallProfile restituisce lo stato dei profili
        $profili = Get-NetFirewallProfile -ErrorAction Stop

        $evidenza = @{}
        $tuttiAttivi = $true

        foreach ($profilo in $profili) {
            $nomeNormalizzato = $profilo.Name
            $attivo = [bool]$profilo.Enabled
            $evidenza[$nomeNormalizzato] = $attivo

            if (-not $attivo) {
                $tuttiAttivi = $false
            }
        }

        $risultato.Evidence = $evidenza

        if ($tuttiAttivi) {
            $risultato.Status = 'superato'
            $risultato.Observed = "Tutti i profili attivi"
        }
        else {
            $risultato.Status = 'fallito'
            $profiliDisattivi = @()
            foreach ($chiave in $evidenza.Keys) {
                if (-not $evidenza[$chiave]) {
                    $profiliDisattivi += $chiave
                }
            }
            $risultato.Observed = "Profili disattivi: $($profiliDisattivi -join ', ')"
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
    Usa i SID e le proprieta' degli oggetti, mai nomi localizzati.
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-GuestAccount {
    <#
    .SYNOPSIS
        Verifica che l'account Guest (SID -501) sia disabilitato.
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
        Expected = "Account Guest (SID -501) disabilitato"
        Evidence = $null
        Error    = $null
    }

    try {
        $utenti = Get-LocalUser -ErrorAction Stop
        $guest = $null

        foreach ($utente in $utenti) {
            if ($utente.SID.Value -match '-501$') {
                $guest = $utente
                break
            }
        }

        if ($null -eq $guest) {
            $risultato.Status = 'sconosciuto'
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
            $risultato.Status = 'fallito'
            $risultato.Observed = "Account Guest ($($guest.Name)) abilitato"
        }
        else {
            $risultato.Status = 'superato'
            $risultato.Observed = "Account Guest ($($guest.Name)) disabilitato"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-LocalUser non e' disponibile"
        $risultato.Error = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Privilegi insufficienti per accedere agli account locali"
        $risultato.Error = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource') {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Dati account locali non disponibili o privilegi insufficienti"
            $risultato.Error = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-AdminAccount {
    <#
    .SYNOPSIS
        Verifica che l'account Administrator locale predefinito (SID -500) sia disabilitato.
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
        Expected = "Account Administrator predefinito (SID -500) disabilitato"
        Evidence = $null
        Error    = $null
    }

    try {
        $utenti = Get-LocalUser -ErrorAction Stop
        $adminBuiltin = $null

        foreach ($utente in $utenti) {
            if ($utente.SID.Value -match '-500$') {
                $adminBuiltin = $utente
                break
            }
        }

        if ($null -eq $adminBuiltin) {
            $risultato.Status = 'sconosciuto'
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
            $risultato.Status = 'fallito'
            $risultato.Observed = "Account Administrator predefinito ($($adminBuiltin.Name)) abilitato"
        }
        else {
            $risultato.Status = 'superato'
            $risultato.Observed = "Account Administrator predefinito ($($adminBuiltin.Name)) disabilitato"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-LocalUser non e' disponibile"
        $risultato.Error = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Privilegi insufficienti per accedere agli account locali"
        $risultato.Error = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource') {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Dati account locali non disponibili o privilegi insufficienti"
            $risultato.Error = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-AccountsPasswordRequired {
    <#
    .SYNOPSIS
        Verifica che tutti gli account locali abilitati richiedano una password.
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
        Expected = "Tutti gli account locali attivi hanno PasswordRequired = True"
        Evidence = $null
        Error    = $null
    }

    try {
        $utenti = @(Get-LocalUser -ErrorAction Stop)
        $attiviSenzaObbligo = @()
        $dettaglioAttivi = @()

        foreach ($u in $utenti) {
            if ($u.Enabled) {
                $pwdReq = [bool]$u.PasswordRequired
                $dettaglioAttivi += @{
                    Nome             = $u.Name
                    SID              = $u.SID.Value
                    PasswordRequired = $pwdReq
                }
                if (-not $pwdReq) {
                    $attiviSenzaObbligo += $u.Name
                }
            }
        }

        $risultato.Evidence = @{
            AccountAttivi              = $dettaglioAttivi
            AccountSenzaPasswordObblig = $attiviSenzaObbligo
        }

        if ($attiviSenzaObbligo.Count -eq 0) {
            $risultato.Status = 'superato'
            $risultato.Observed = "Tutti gli account attivi ($($dettaglioAttivi.Count)) richiedono una password"
        }
        else {
            $risultato.Status = 'fallito'
            $risultato.Observed = "Account attivi con PasswordRequired=False: $($attiviSenzaObbligo -join ', ')"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-LocalUser non e' disponibile"
        $risultato.Error = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Privilegi insufficienti per accedere agli account locali"
        $risultato.Error = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource') {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Dati account locali non disponibili o privilegi insufficienti"
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

# =============================================================================
# MODULO: src\core\Checks\FileSecurity.ps1
# =============================================================================
<#
.SYNOPSIS
    Controlli di sicurezza sui file locali, avvio automatico (persistenza) e file hosts.

.DESCRIPTION
    Contiene i controlli in sola lettura per:
    - HOME-FIL-001: Scansione file sospetti con doppia estensione in Download, Desktop e Temp (Test-SuspiciousDoubleExtensionFiles)
    - HOME-FIL-002: Verifica voci di avvio automatico (Run/RunOnce) contro persistenza malware (Test-StartupPersistenceEntries)
    - HOME-FIL-003: Integrita' del file hosts di Windows contro dirottamenti DNS (Test-HostsFileIntegrity)
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

        # Pattern doppia estensione: (estensione documento/media/archivio) seguita da (estensione eseguibile/script)
        $patternDoppiaEstensione = '(?i)\.(pdf|doc|docx|xls|xlsx|ppt|pptx|txt|rtf|jpg|jpeg|png|gif|bmp|mp3|mp4|avi|zip|rar|7z)\.(exe|scr|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|hta|com|pif)$'

        $fileSospetti   = @()
        $totaleAnalizzati = 0

        foreach ($cartella in $CartelleDaControllare) {
            if ([string]::IsNullOrWhiteSpace($cartella)) { continue }
            if (-not (Test-Path -LiteralPath $cartella)) { continue }

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
        $righeAttive = @()
        $righeSospette = @()

        $patternDominiSensibili = '(?i)(windowsupdate\.com|update\.microsoft\.com|microsoft\.com|defender|virustotal\.com|malwarebytes\.com|kaspersky|bitdefender|avast|Norton|mcafee)'

        foreach ($riga in $righe) {
            $trimmed = $riga.Trim()
            if ($trimmed -eq '' -or $trimmed.StartsWith('#')) {
                continue
            }
            # Ignora le voci standard di localhost
            if ($trimmed -match '^(127\.0\.0\.1|::1)\s+localhost(\s|$)') {
                continue
            }
            $righeAttive += $trimmed
            if ($trimmed -match $patternDominiSensibili) {
                $righeSospette += $trimmed
            }
        }

        $risultato.Evidence = @{
            Percorso            = $PercorsoHosts
            VociPersonalizzate  = $righeAttive.Count
            DirottamentiSospetti= $righeSospette
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
        Verifica che l'Isolamento core / Integrita' della memoria (HVCI) sia abilitato.
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
        Expected = "HypervisorEnforcedCodeIntegrity Enabled = 1"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoHvci = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity'
        if (-not (Test-Path -LiteralPath $percorsoHvci)) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Integrita' della memoria (HVCI) non configurata"
            $risultato.Evidence = @{ KeyExists = $false }
            return $risultato
        }

        $propHvci = Get-ItemProperty -LiteralPath $percorsoHvci -ErrorAction Stop
        $valore = if ($null -ne $propHvci.PSObject.Properties['Enabled'] -and $null -ne $propHvci.Enabled) {
            [int]$propHvci.Enabled
        }
        else {
            0
        }

        $risultato.Evidence = @{
            Path    = $percorsoHvci
            Enabled = $valore
        }

        if ($valore -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Isolamento core / Integrita' della memoria attiva (Enabled = 1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Isolamento core / Integrita' della memoria disattivata (Enabled = $valore)"
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
        Restituisce icona testuale, etichetta e priorita' di ordinamento per uno stato.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Stato = 'sconosciuto'
    )

    $statoNorm = if ([string]::IsNullOrWhiteSpace($Stato)) { 'sconosciuto' } else { $Stato.Trim().ToLowerInvariant() }

    # Ordinamento predefinito richiesto:
    # 1. fallito
    # 2. errore / sconosciuto
    # 3. superato
    # 4. non_applicabile
    switch ($statoNorm) {
        'fallito' {
            return [PSCustomObject]@{
                Status      = 'fallito'
                Icon        = '[X]'
                ShortLabel  = 'Fallito'
                Label       = '[X] Fallito'
                Rank        = 1
            }
        }
        'errore' {
            return [PSCustomObject]@{
                Status      = 'errore'
                Icon        = '[!]'
                ShortLabel  = 'Errore'
                Label       = '[!] Errore'
                Rank        = 2
            }
        }
        'sconosciuto' {
            return [PSCustomObject]@{
                Status      = 'sconosciuto'
                Icon        = '[?]'
                ShortLabel  = 'Sconosciuto'
                Label       = '[?] Sconosciuto'
                Rank        = 3
            }
        }
        'superato' {
            return [PSCustomObject]@{
                Status      = 'superato'
                Icon        = '[OK]'
                ShortLabel  = 'Superato'
                Label       = '[OK] Superato'
                Rank        = 4
            }
        }
        'non_applicabile' {
            return [PSCustomObject]@{
                Status      = 'non_applicabile'
                Icon        = '[-]'
                ShortLabel  = 'Non applicabile'
                Label       = '[-] Non applicabile'
                Rank        = 5
            }
        }
        default {
            return [PSCustomObject]@{
                Status      = $statoNorm
                Icon        = '[?]'
                ShortLabel  = 'Sconosciuto'
                Label       = "[?] $statoNorm"
                Rank        = 6
            }
        }
    }
}

function Get-InfoGravitaVista {
    <#
    .SYNOPSIS
        Restituisce etichetta e priorita' di ordinamento (1 = piu' grave) per la gravita'.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Gravita = 'medio'
    )

    $gravNorm = if ([string]::IsNullOrWhiteSpace($Gravita)) { 'non_specificata' } else { $Gravita.Trim().ToLowerInvariant() }

    switch ($gravNorm) {
        'critico'     { return [PSCustomObject]@{ Severity = 'critico';     Label = 'Critico';     Rank = 1 } }
        'alto'        { return [PSCustomObject]@{ Severity = 'alto';        Label = 'Alto';        Rank = 2 } }
        'medio'       { return [PSCustomObject]@{ Severity = 'medio';       Label = 'Medio';       Rank = 3 } }
        'basso'       { return [PSCustomObject]@{ Severity = 'basso';       Label = 'Basso';       Rank = 4 } }
        'informativo' { return [PSCustomObject]@{ Severity = 'informativo'; Label = 'Informativo'; Rank = 5 } }
        default       { return [PSCustomObject]@{ Severity = $gravNorm;     Label = 'N/D';         Rank = 99 } }
    }
}

function Merge-RisultatoConControllo {
    <#
    .SYNOPSIS
        Unisce un singolo risultato del Runner con i metadati del controllo nel catalogo.
    .PARAMETER Risultato
        Oggetto risultato prodotto da Invoke-Controlli.
    .PARAMETER ControlloCatalogo
        Oggetto controllo corrispondente dal catalogo (opzionale).
    .OUTPUTS
        PSCustomObject pronto per la visualizzazione e il filtraggio.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Risultato,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$ControlloCatalogo = $null
    )

    $id = [string](Get-ValoreProprietaSicuro -Oggetto $Risultato -NomeProprieta 'control_id' -ValorePredefinito 'ID-SCONOSCIUTO')
    $statoRaw = [string](Get-ValoreProprietaSicuro -Oggetto $Risultato -NomeProprieta 'status' -ValorePredefinito 'sconosciuto')

    $titolo = [string](Get-ValoreProprietaSicuro -Oggetto $ControlloCatalogo -NomeProprieta 'title' -ValorePredefinito $id)
    $categoria = [string](Get-ValoreProprietaSicuro -Oggetto $ControlloCatalogo -NomeProprieta 'category' -ValorePredefinito 'Generale')
    $gravitaRaw = [string](Get-ValoreProprietaSicuro -Oggetto $ControlloCatalogo -NomeProprieta 'severity' -ValorePredefinito '')

    $infoStato = Get-InfoStatoVista -Stato $statoRaw
    $infoGrav = Get-InfoGravitaVista -Gravita $gravitaRaw

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
        Converte i risultati del Runner e il catalogo nella lista ordinata per la UI.
    .PARAMETER Risultati
        Array di risultati (da Invoke-Controlli).
    .PARAMETER Catalogo
        Oggetto catalogo (da Import-Catalogo).
    .OUTPUTS
        Array ordinato di elementi vista.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [array]$Risultati = @(),

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$Catalogo = $null
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
        $elementi += (Merge-RisultatoConControllo -Risultato $r -ControlloCatalogo $meta)
    }

    $ordinati = @(Sort-RisultatiVista -Elementi $elementi)
    return $ordinati
}

function Select-RisultatiVista {
    <#
    .SYNOPSIS
        Filtra la lista di elementi vista combinando stato, gravita', categoria e testo.
    .PARAMETER Elementi
        Array di elementi vista.
    .PARAMETER Stato
        Stato da filtrare ('Tutti' oppure 'superato', 'fallito', 'sconosciuto', 'non_applicabile', 'errore').
    .PARAMETER Gravita
        Gravita' da filtrare ('Tutte' oppure 'critico', 'alto', 'medio', 'basso', 'informativo').
    .PARAMETER Categoria
        Categoria da filtrare ('Tutte' oppure nome della categoria).
    .PARAMETER TestoRicerca
        Sottostringa da cercare (case-insensitive) su Title e ControlId.
    .OUTPUTS
        Array filtrato di elementi vista.
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
        if ($statoNorm -ne 'tutti' -and $statoNorm -ne 'all') {
            $elStato = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'Status' -ValorePredefinito '')
            if ($elStato.ToLowerInvariant() -ne $statoNorm) {
                continue
            }
        }

        # 2. Filtro Gravita
        if ($gravNorm -ne 'tutte' -and $gravNorm -ne 'tutti' -and $gravNorm -ne 'all') {
            $elGrav = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'Severity' -ValorePredefinito '')
            if ($elGrav.ToLowerInvariant() -ne $gravNorm) {
                continue
            }
        }

        # 3. Filtro Categoria
        if ($catNorm.ToLowerInvariant() -ne 'tutte' -and $catNorm.ToLowerInvariant() -ne 'tutti' -and $catNorm.ToLowerInvariant() -ne 'all') {
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
        [string]$Modalita = 'Semplice'
    )

    if ($null -eq $Elemento) {
        return [PSCustomObject]@{
            Selezionato          = $false
            ControlId            = ''
            Title                = 'Nessun controllo selezionato'
            Category             = '-'
            SeverityLabel        = '-'
            Status               = 'sconosciuto'
            StatusLabel          = '-'
            Modalita             = $Modalita
            SpiegazioneSemplice  = 'Seleziona un controllo dalla tabella per visualizzare i dettagli.'
            SpiegazioneTecnica   = 'Seleziona un controllo dalla tabella per visualizzare i dettagli tecnici.'
            TestoSpiegazione     = 'Seleziona un controllo dalla tabella per visualizzare i dettagli.'
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
    $infoStato = Get-InfoStatoVista -Stato $stato

    $gravitaRaw = [string](Get-ValoreProprietaSicuro -Oggetto $Elemento -NomeProprieta 'Severity' -ValorePredefinito (
        Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'severity' -ValorePredefinito ''
    ))
    $infoGrav = Get-InfoGravitaVista -Gravita $gravitaRaw

    # Spiegazione semplice (rationale / simple_explanation)
    $spiegazioneSemplice = Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'simple_explanation' -ValorePredefinito $null
    if ([string]::IsNullOrWhiteSpace([string]$spiegazioneSemplice)) {
        $spiegazioneSemplice = Get-ValoreProprietaSicuro -Oggetto $meta -NomeProprieta 'rationale' -ValorePredefinito $null
    }
    if ([string]::IsNullOrWhiteSpace([string]$spiegazioneSemplice)) {
        $spiegazioneSemplice = "Nessuna spiegazione disponibile nel catalogo per questo controllo."
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

    if ([string]::IsNullOrWhiteSpace([string]$testoRimedio)) {
        $testoRimedio = "Verifica manualmente questa impostazione nel Pannello di controllo o nelle Impostazioni di sicurezza di Windows 11."
    }

    if ([string]::IsNullOrWhiteSpace([string]$noteRischi)) {
        $noteRischi = "Valuta l'impatto prima di applicare modifiche manuali alla configurazione del sistema."
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
    collega i controlli con FindName, gestisce il tema chiaro/scuro,
    i filtri, il pannello di dettaglio, l'export JSON/HTML e l'esecuzione
    asincrona della scansione in un Runspace separato con aggiornamento
    tramite Dispatcher.
    Il codice e' in SOLA LETTURA e riusa esattamente il motore di src/core.
#>

Set-StrictMode -Version 2

function Update-TemaFinestra {
    <#
    .SYNOPSIS
        Applica il dizionario di colori del tema Chiaro o Scuro alle risorse della finestra.
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
            'BgPrimary'        = '#0F172A'
            'BgSurface'        = '#1E293B'
            'BgHeader'         = '#020617'
            'TextHeader'       = '#F8FAFC'
            'BgSubtle'         = '#0F172A'
            'TextPrimary'      = '#F1F5F9'
            'TextSecondary'    = '#94A3B8'
            'BorderSubtle'     = '#334155'
            'AccentBrush'      = '#3B82F6'
            'AccentText'       = '#FFFFFF'
            'PassBg'           = '#064E3B'
            'PassFg'           = '#A7F3D0'
            'PassBorder'       = '#059669'
            'FailBg'           = '#7F1D1D'
            'FailFg'           = '#FECACA'
            'FailBorder'       = '#DC2626'
            'UnknownBg'        = '#334155'
            'UnknownFg'        = '#E2E8F0'
            'UnknownBorder'    = '#64748B'
            'NaBg'             = '#1E293B'
            'NaFg'             = '#94A3B8'
            'NaBorder'         = '#475569'
            'ErrorBg'          = '#7C2D12'
            'ErrorFg'          = '#FED7AA'
            'ErrorBorder'      = '#EA580C'
            'WarnBannerBg'     = '#78350F'
            'WarnBannerFg'     = '#FEF3C7'
            'WarnBannerBorder' = '#D97706'
        }
    }
    else {
        $mappaColori = @{
            'BgPrimary'        = '#F4F6F9'
            'BgSurface'        = '#FFFFFF'
            'BgHeader'         = '#0F172A'
            'TextHeader'       = '#F8FAFC'
            'BgSubtle'         = '#F8FAFC'
            'TextPrimary'      = '#1E293B'
            'TextSecondary'    = '#475569'
            'BorderSubtle'     = '#CBD5E1'
            'AccentBrush'      = '#2563EB'
            'AccentText'       = '#FFFFFF'
            'PassBg'           = '#DCFCE7'
            'PassFg'           = '#166534'
            'PassBorder'       = '#86EFAC'
            'FailBg'           = '#FEE2E2'
            'FailFg'           = '#991B1B'
            'FailBorder'       = '#FCA5A5'
            'UnknownBg'        = '#E2E8F0'
            'UnknownFg'        = '#334155'
            'UnknownBorder'    = '#94A3B8'
            'NaBg'             = '#F1F5F9'
            'NaFg'             = '#475569'
            'NaBorder'         = '#CBD5E1'
            'ErrorBg'          = '#FFEDD5'
            'ErrorFg'          = '#9A3412'
            'ErrorBorder'      = '#FDBA74'
            'WarnBannerBg'     = '#FEF3C7'
            'WarnBannerFg'     = '#92400E'
            'WarnBannerBorder' = '#F59E0B'
        }
    }

    foreach ($chiave in $mappaColori.Keys) {
        $pennello = $convertitore.ConvertFromString($mappaColori[$chiave])
        $Finestra.Resources[$chiave] = $pennello
    }
}

function Start-ScannerUI {
    <#
    .SYNOPSIS
        Costruisce e mostra la finestra WPF dello scanner di sicurezza.
    .PARAMETER Catalogo
        Oggetto catalogo caricato da Import-Catalogo.
    .PARAMETER Ambiente
        Oggetto ambiente rilevato da Get-AmbienteSistema.
    .PARAMETER PercorsoProgetto
        Percorso radice del repository (opzionale in modalita' standalone singolo file).
    .PARAMETER ContenutoXaml
        Stringa XAML opzionale (usata nella versione compilata in singolo file in stile winutil).
    .PARAMETER ControlId
        Filtro opzionale di ID di controllo passato da riga di comando.
    .PARAMETER VersioneTool
        Versione dello scanner (es. '0.1.0').
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
        [string]$VersioneTool = '0.1.0'
    )

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
        TxtAmbienteInfo        = $finestra.FindName('TxtAmbienteInfo')
        BtnTema                = $finestra.FindName('BtnTema')
        BannerNonAdmin         = $finestra.FindName('BannerNonAdmin')
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
        CmbFiltroStato         = $finestra.FindName('CmbFiltroStato')
        CmbFiltroGravita       = $finestra.FindName('CmbFiltroGravita')
        CmbFiltroCategoria     = $finestra.FindName('CmbFiltroCategoria')
        TxtRicerca             = $finestra.FindName('TxtRicerca')
        BtnResetFiltri         = $finestra.FindName('BtnResetFiltri')
        GridRisultati          = $finestra.FindName('GridRisultati')
        PanelGuidaVuota        = $finestra.FindName('PanelGuidaVuota')
        TxtMessaggioGuida      = $finestra.FindName('TxtMessaggioGuida')
        TxtDettaglioTitolo     = $finestra.FindName('TxtDettaglioTitolo')
        TxtDettaglioSottotitolo= $finestra.FindName('TxtDettaglioSottotitolo')
        BtnModoSemplice        = $finestra.FindName('BtnModoSemplice')
        BtnModoTecnico         = $finestra.FindName('BtnModoTecnico')
        TxtTitoloSpiegazione   = $finestra.FindName('TxtTitoloSpiegazione')
        TxtDettaglioSpiegazione= $finestra.FindName('TxtDettaglioSpiegazione')
        BannerDettaglioErrore  = $finestra.FindName('BannerDettaglioErrore')
        TxtDettaglioErrore     = $finestra.FindName('TxtDettaglioErrore')
        TxtDettaglioAtteso     = $finestra.FindName('TxtDettaglioAtteso')
        TxtDettaglioOsservato  = $finestra.FindName('TxtDettaglioOsservato')
        TxtDettaglioRimedio    = $finestra.FindName('TxtDettaglioRimedio')
        PanelComandoRimedio    = $finestra.FindName('PanelComandoRimedio')
        TxtComandoRimedio      = $finestra.FindName('TxtComandoRimedio')
        BtnCopiaComando        = $finestra.FindName('BtnCopiaComando')
        TxtFeedbackCopia       = $finestra.FindName('TxtFeedbackCopia')
        TxtDettaglioRischi     = $finestra.FindName('TxtDettaglioRischi')
        CmbModelloOllama       = $finestra.FindName('CmbModelloOllama')
        BtnVerificaOllama      = $finestra.FindName('BtnVerificaOllama')
        BtnSpiegaLLM           = $finestra.FindName('BtnSpiegaLLM')
        BtnResocontoLLM        = $finestra.FindName('BtnResocontoLLM')
        TxtStatoLLM            = $finestra.FindName('TxtStatoLLM')
        TxtRispostaLLM         = $finestra.FindName('TxtRispostaLLM')
        BtnEsportaJson         = $finestra.FindName('BtnEsportaJson')
        BtnEsportaHtml         = $finestra.FindName('BtnEsportaHtml')
        ChkSalvaLogTecnico     = $finestra.FindName('ChkSalvaLogTecnico')
        TxtRiepilogoFooter     = $finestra.FindName('TxtRiepilogoFooter')
    }

    # Stato interno dell'interfaccia
    $totaleControlli = @($Catalogo.controls).Count
    $statoUI = @{
        TemaCorrente        = 'Chiaro'
        ModalitaDettaglio   = 'Semplice'
        RisultatiGrezzi     = @()
        ElementiVista       = @()
        ElementoSelezionato = $null
        ScansioneInCorso    = $false
        SyncRunspace        = $null
        PsInstance          = $null
        Runspace            = $null
    }

    # Popola informazioni ambiente nell'intestazione
    $testoAdmin = if ($Ambiente.IsAdmin) { 'Si' } else { 'No' }
    $ctrl.TxtAmbienteInfo.Text = "Windows 11 $($Ambiente.Edition) $($Ambiente.Build) | Admin: $testoAdmin"
    $ctrl.ProgressScansione.Maximum = if ($totaleControlli -gt 0) { $totaleControlli } else { 1 }
    $ctrl.TxtProgresso.Text = "Pronto (0/$totaleControlli)"

    # Banner giallo se non avviato come amministratore
    if (-not $Ambiente.IsAdmin) {
        $ctrl.BannerNonAdmin.Visibility = [System.Windows.Visibility]::Visible
    }

    # Popola le categorie nel filtro Categoria
    $categorieUniche = @()
    foreach ($c in $Catalogo.controls) {
        if ($null -ne $c.PSObject.Properties['category'] -and $c.category) {
            if ($categorieUniche -notcontains $c.category) {
                $categorieUniche += $c.category
            }
        }
    }
    foreach ($cat in ($categorieUniche | Sort-Object)) {
        $itemCat = New-Object System.Windows.Controls.ComboBoxItem
        $itemCat.Content = $cat
        [void]$ctrl.CmbFiltroCategoria.Items.Add($itemCat)
    }

    # --- Funzioni di aggiornamento UI ---
    $aggiornaPannelloDettaglio = {
        $dettaglio = Format-DettaglioControllo -Elemento $statoUI.ElementoSelezionato -Modalita $statoUI.ModalitaDettaglio
        $ctrl.TxtDettaglioTitolo.Text = $dettaglio.Title
        $ctrl.TxtDettaglioSottotitolo.Text = "ID: $($dettaglio.ControlId)  |  Stato: $($dettaglio.StatusLabel)  |  Gravita': $($dettaglio.SeverityLabel)  |  Categoria: $($dettaglio.Category)"

        if ($statoUI.ModalitaDettaglio -eq 'Tecnico') {
            $ctrl.TxtTitoloSpiegazione.Text = "Dettaglio tecnico e riferimenti"
            $ctrl.BtnModoTecnico.FontWeight = [System.Windows.FontWeights]::Bold
            $ctrl.BtnModoSemplice.FontWeight = [System.Windows.FontWeights]::Normal
        }
        else {
            $ctrl.TxtTitoloSpiegazione.Text = "Perche' conta (spiegazione semplice)"
            $ctrl.BtnModoSemplice.FontWeight = [System.Windows.FontWeights]::Bold
            $ctrl.BtnModoTecnico.FontWeight = [System.Windows.FontWeights]::Normal
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
        $ctrl.TxtCountSuperati.Text       = "[OK] $($conteggi.superato) Superati"
        $ctrl.TxtCountFalliti.Text        = "[X] $($conteggi.fallito) Falliti"
        $ctrl.TxtCountSconosciuti.Text    = "[?] $($conteggi.sconosciuto) Sconosciuti"
        $ctrl.TxtCountNonApplicabili.Text = "[-] $($conteggi.non_applicabile) Non applicabili"
        $ctrl.TxtCountErrori.Text         = "[!] $($conteggi.errore) Errori"

        $ctrl.TxtRiepilogoFooter.Text = "Riepilogo calcolato dal codice: $($conteggi.totale) controlli valutati ($($conteggi.superato) superati, $($conteggi.fallito) falliti, $($conteggi.sconosciuto) sconosciuti)"

        if ($conteggi.errore -gt 0) {
            $ctrl.TxtBannerErrore.Text = "Alcuni controlli ($($conteggi.errore)) hanno restituito un imprevisto durante la lettura. Seleziona il controllo per maggiori informazioni o esporta il log tecnico."
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
            $ctrl.TxtMessaggioGuida.Text = "Nessun controllo corrisponde ai filtri selezionati."
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

    # --- Eventi Tema ---
    $ctrl.BtnTema.Add_Click({
        if ($statoUI.TemaCorrente -eq 'Chiaro') {
            $statoUI.TemaCorrente = 'Scuro'
            Update-TemaFinestra -Finestra $finestra -Tema 'Scuro'
            $ctrl.BtnTema.Content = 'Tema: Chiaro'
        }
        else {
            $statoUI.TemaCorrente = 'Chiaro'
            Update-TemaFinestra -Finestra $finestra -Tema 'Chiaro'
            $ctrl.BtnTema.Content = 'Tema: Scuro'
        }
    })

    # --- Evento Riavvia come Amministratore ---
    $ctrl.BtnRiavviaAdmin.Add_Click({
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
                [System.Windows.MessageBox]::Show(
                    "Avviato da memoria remota: apri una nuova finestra di PowerShell come Amministratore e riesegui il comando.",
                    "Scanner sicurezza Windows",
                    [System.Windows.MessageBoxButton]::OK,
                    [System.Windows.MessageBoxImage]::Information
                ) | Out-Null
            }
        }
        catch {
            [System.Windows.MessageBox]::Show(
                "Riavvio come amministratore annullato o non riuscito.",
                "Scanner sicurezza Windows",
                [System.Windows.MessageBoxButton]::OK,
                [System.Windows.MessageBoxImage]::Information
            ) | Out-Null
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

    # --- Funzione asincrona per eseguire una richiesta Ollama in un Runspace ---
    $avviaRichiestaOllamaAsincrona = {
        param([string]$PromptDaInviare, [string]$EtichettaOperazione)

        $modelloScelto = $ctrl.CmbModelloOllama.Text
        if ([string]::IsNullOrWhiteSpace($modelloScelto)) {
            $modelloScelto = 'qwen2.5:0.5b'
        }

        $ctrl.BtnSpiegaLLM.IsEnabled    = $false
        $ctrl.BtnResocontoLLM.IsEnabled = $false
        $ctrl.TxtStatoLLM.Text          = "$EtichettaOperazione in corso con '$modelloScelto'..."
        $ctrl.TxtRispostaLLM.Text       = "Generazione della risposta da parte di Ollama ($modelloScelto) in corso... Attendi qualche secondo."
        $ctrl.TxtRispostaLLM.Visibility = [System.Windows.Visibility]::Visible

        $callbackFineLlm = [Action[object]]{
            param($EsitoLlm)
            $ctrl.BtnSpiegaLLM.IsEnabled = $true
            if ($statoUI.RisultatiGrezzi.Count -gt 0) {
                $ctrl.BtnResocontoLLM.IsEnabled = $true
            }

            if ($EsitoLlm.Successo) {
                $sec = [math]::Round(($EsitoLlm.DurataMs / 1000.0), 1)
                $ctrl.TxtStatoLLM.Text    = "Completato da $($EsitoLlm.Modello) in ${sec}s"
                $ctrl.TxtRispostaLLM.Text = $EsitoLlm.Risposta
            }
            else {
                $ctrl.TxtStatoLLM.Text    = "Ollama non disponibile o modello mancante"
                $ctrl.TxtRispostaLLM.Text = $EsitoLlm.Errore
            }
        }

        $syncLlm = [hashtable]::Synchronized(@{
            Finestra     = $finestra
            Prompt       = $PromptDaInviare
            Modello      = $modelloScelto
            CallbackFine = $callbackFineLlm
        })

        $issLlm = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $fnOllama = Get-Command -Name 'Invoke-RichiestaOllama' -ErrorAction SilentlyContinue
        if ($null -ne $fnOllama) {
            $entryOllama = New-Object System.Management.Automation.Runspaces.SessionStateFunctionEntry($fnOllama.Name, $fnOllama.Definition)
            [void]$issLlm.Commands.Add($entryOllama)
        }

        $rsLlm = [runspacefactory]::CreateRunspace($issLlm)
        $rsLlm.ApartmentState = 'STA'
        $rsLlm.ThreadOptions  = 'ReuseThread'
        $rsLlm.Open()
        $rsLlm.SessionStateProxy.SetVariable('SyncLlm', $syncLlm)

        $psLlm = [powershell]::Create()
        $psLlm.Runspace = $rsLlm
        [void]$psLlm.AddScript({
            $esito = Invoke-RichiestaOllama -Prompt $SyncLlm.Prompt -Modello $SyncLlm.Modello -Endpoint 'http://localhost:11434'
            [void]$SyncLlm.Finestra.Dispatcher.Invoke(
                [System.Windows.Threading.DispatcherPriority]::Normal,
                $SyncLlm.CallbackFine,
                $esito
            )
        })
        [void]$psLlm.BeginInvoke()
    }

    # --- Verifica connessione e modelli Ollama ---
    $ctrl.BtnVerificaOllama.Add_Click({
        $ctrl.TxtStatoLLM.Text = "Verifica connessione a http://localhost:11434..."
        $statoOllama = Test-ConnessioneOllama -Endpoint 'http://localhost:11434'
        if ($statoOllama.Disponibile) {
            if ($statoOllama.Modelli.Count -gt 0) {
                $ctrl.CmbModelloOllama.Items.Clear()
                foreach ($m in $statoOllama.Modelli) {
                    $itemM = New-Object System.Windows.Controls.ComboBoxItem
                    $itemM.Content = $m
                    [void]$ctrl.CmbModelloOllama.Items.Add($itemM)
                }
                $ctrl.CmbModelloOllama.SelectedIndex = 0
                $ctrl.TxtStatoLLM.Text = "Ollama connesso! Modelli trovati: $($statoOllama.Modelli -join ', ')"
            }
            else {
                $ctrl.TxtStatoLLM.Text = "Ollama attivo ma nessun modello installato. Esegui: ollama pull qwen2.5:0.5b"
            }
        }
        else {
            $ctrl.TxtStatoLLM.Text    = "Ollama non raggiungibile su localhost:11434"
            $ctrl.TxtRispostaLLM.Text = $statoOllama.Errore
            $ctrl.TxtRispostaLLM.Visibility = [System.Windows.Visibility]::Visible
        }
    })

    # --- Spiega controllo selezionato con LLM ---
    $ctrl.BtnSpiegaLLM.Add_Click({
        if ($null -eq $statoUI.ElementoSelezionato) {
            $ctrl.TxtStatoLLM.Text = "Seleziona prima un controllo dalla tabella a sinistra."
            return
        }
        $dettaglio = Format-DettaglioControllo -Elemento $statoUI.ElementoSelezionato -Modalita 'Semplice'
        $promptCtrl = Format-PromptControlloOllama -Dettaglio $dettaglio -Ambiente $Ambiente
        & $avviaRichiestaOllamaAsincrona $promptCtrl "Spiegazione di $($dettaglio.ControlId)"
    })

    # --- Resoconto complessivo della scansione con LLM ---
    $ctrl.BtnResocontoLLM.Add_Click({
        if ($statoUI.ElementiVista.Count -eq 0) {
            $ctrl.TxtStatoLLM.Text = "Esegui prima la scansione per generare il resoconto IA."
            return
        }
        $conteggi = Measure-ConteggiRisultati -Elementi $statoUI.RisultatiGrezzi
        $promptRes = Format-PromptResocontoOllama -ElementiVista $statoUI.ElementiVista -Conteggi $conteggi -Ambiente $Ambiente
        & $avviaRichiestaOllamaAsincrona $promptRes "Generazione Resoconto IA della scansione"
    })

    # --- Avvia scansione in Runspace separato ---
    $ctrl.BtnAvvia.Add_Click({
        if ($statoUI.ScansioneInCorso) { return }

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
        $ctrl.TxtProgresso.Text         = "Avvio scansione..."
        $ctrl.TxtMessaggioGuida.Text    = "Scansione in corso... I risultati compariranno man mano."
        $ctrl.PanelGuidaVuota.Visibility = [System.Windows.Visibility]::Visible
        $ctrl.GridRisultati.ItemsSource = @()
        & $aggiornaConteggiERiepilogo
        & $aggiornaPannelloDettaglio

        # Callback invocato sul thread UI tramite Dispatcher per ogni controllo completato
        $callbackProgresso = [Action[int, int, object]]{
            param([int]$Indice, [int]$Totale, [object]$RisultatoSingolo)

            $statoUI.RisultatiGrezzi += $RisultatoSingolo
            $statoUI.ElementiVista = @(ConvertTo-RisultatiVista -Risultati $statoUI.RisultatiGrezzi -Catalogo $Catalogo)

            $ctrl.ProgressScansione.Maximum = if ($Totale -gt 0) { $Totale } else { 1 }
            $ctrl.ProgressScansione.Value   = $Indice
            $ctrl.TxtProgresso.Text         = "Avanzamento: $Indice/$Totale"

            & $aggiornaConteggiERiepilogo
            & $applicaFiltriTabella
        }

        # Callback invocato sul thread UI al termine (o annullamento) della scansione
        $callbackFine = [Action]{
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
                $ctrl.TxtBannerErrore.Text = "Si e' verificato un problema durante l'esecuzione della scansione. Riprova o esporta il log tecnico."
                $ctrl.BannerErrore.Visibility = [System.Windows.Visibility]::Visible
                $ctrl.TxtProgresso.Text = "Interrotto per errore ($nValutati/$totaleControlli)"
            }
            elseif ($null -ne $statoUI.SyncRunspace -and $statoUI.SyncRunspace.AnnullaRichiesto) {
                $ctrl.TxtProgresso.Text = "Annullata ($nValutati/$totaleControlli)"
                if ($nValutati -eq 0) {
                    $ctrl.TxtMessaggioGuida.Text = "Scansione annullata. Premi 'Avvia scansione' per riprovare."
                }
            }
            else {
                $ctrl.TxtProgresso.Text = "Completata ($nValutati/$nValutati)"
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
        # (consente l'esecuzione anche da singolo file autonomo senza cartella src/)
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
            $ctrl.TxtProgresso.Text = "Annullamento in corso..."
        }
    })

    # --- Export JSON ---
    $ctrl.BtnEsportaJson.Add_Click({
        if ($statoUI.RisultatiGrezzi.Count -eq 0) { return }

        $dialogo = New-Object Microsoft.Win32.SaveFileDialog
        $dialogo.Title      = "Esporta report JSON"
        $dialogo.Filter     = "File JSON (*.json)|*.json"
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

            $ctrl.TxtRiepilogoFooter.Text = "Esportato JSON: $(Split-Path -Leaf $dialogo.FileName)"
        }
    })

    # --- Export HTML ---
    $ctrl.BtnEsportaHtml.Add_Click({
        if ($statoUI.RisultatiGrezzi.Count -eq 0) { return }

        $dialogo = New-Object Microsoft.Win32.SaveFileDialog
        $dialogo.Title      = "Esporta report HTML"
        $dialogo.Filter     = "Pagina HTML (*.html)|*.html"
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

            $ctrl.TxtRiepilogoFooter.Text = "Esportato HTML: $(Split-Path -Leaf $dialogo.FileName)"
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

    # Inizializza pannello dettaglio vuoto
    & $aggiornaPannelloDettaglio

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
        [switch]$Headless,
        [string]$OutFile,
        [string[]]$ControlId
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
