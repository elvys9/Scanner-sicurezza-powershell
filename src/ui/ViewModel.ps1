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
        Restituisce icona testuale, etichetta e priorita' di ordinamento per uno stato (IT o EN).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Stato = 'sconosciuto',

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN')]
        [string]$Lingua = 'IT'
    )

    $statoNorm = if ([string]::IsNullOrWhiteSpace($Stato)) { 'sconosciuto' } else { $Stato.Trim().ToLowerInvariant() }
    $isEn = ($Lingua -eq 'EN')

    switch ($statoNorm) {
        'fallito' {
            $short = if ($isEn) { 'Failed' } else { 'Fallito' }
            return [PSCustomObject]@{ Status = 'fallito'; Icon = '[X]'; ShortLabel = $short; Label = "[X] $short"; Rank = 1 }
        }
        'errore' {
            $short = if ($isEn) { 'Error' } else { 'Errore' }
            return [PSCustomObject]@{ Status = 'errore'; Icon = '[!]'; ShortLabel = $short; Label = "[!] $short"; Rank = 2 }
        }
        'sconosciuto' {
            $short = if ($isEn) { 'Unknown' } else { 'Sconosciuto' }
            return [PSCustomObject]@{ Status = 'sconosciuto'; Icon = '[?]'; ShortLabel = $short; Label = "[?] $short"; Rank = 3 }
        }
        'superato' {
            $short = if ($isEn) { 'Passed' } else { 'Superato' }
            return [PSCustomObject]@{ Status = 'superato'; Icon = '[OK]'; ShortLabel = $short; Label = "[OK] $short"; Rank = 4 }
        }
        'non_applicabile' {
            $short = if ($isEn) { 'N/A' } else { 'Non applicabile' }
            return [PSCustomObject]@{ Status = 'non_applicabile'; Icon = '[-]'; ShortLabel = $short; Label = "[-] $short"; Rank = 5 }
        }
        default {
            $short = if ($isEn) { 'Unknown' } else { 'Sconosciuto' }
            return [PSCustomObject]@{ Status = $statoNorm; Icon = '[?]'; ShortLabel = $short; Label = "[?] $statoNorm"; Rank = 6 }
        }
    }
}

function Get-InfoGravitaVista {
    <#
    .SYNOPSIS
        Restituisce etichetta e priorita' di ordinamento (1 = piu' grave) per la gravita' (IT o EN).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$Gravita = 'medio',

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN')]
        [string]$Lingua = 'IT'
    )

    $gravNorm = if ([string]::IsNullOrWhiteSpace($Gravita)) { 'non_specificata' } else { $Gravita.Trim().ToLowerInvariant() }
    $isEn = ($Lingua -eq 'EN')

    switch ($gravNorm) {
        'critico'     { $lbl = if ($isEn) { 'Critical' } else { 'Critico' };     return [PSCustomObject]@{ Severity = 'critico';     Label = $lbl; Rank = 1 } }
        'alto'        { $lbl = if ($isEn) { 'High' }     else { 'Alto' };        return [PSCustomObject]@{ Severity = 'alto';        Label = $lbl; Rank = 2 } }
        'medio'       { $lbl = if ($isEn) { 'Medium' }   else { 'Medio' };       return [PSCustomObject]@{ Severity = 'medio';       Label = $lbl; Rank = 3 } }
        'basso'       { $lbl = if ($isEn) { 'Low' }      else { 'Basso' };       return [PSCustomObject]@{ Severity = 'basso';       Label = $lbl; Rank = 4 } }
        'informativo' { $lbl = if ($isEn) { 'Info' }     else { 'Informativo' }; return [PSCustomObject]@{ Severity = 'informativo'; Label = $lbl; Rank = 5 } }
        default       { $lbl = if ($isEn) { 'N/A' }      else { 'N/D' };         return [PSCustomObject]@{ Severity = $gravNorm;     Label = $lbl; Rank = 99 } }
    }
}

function Merge-RisultatoConControllo {
    <#
    .SYNOPSIS
        Unisce un singolo risultato del Runner con i metadati del controllo nel catalogo (IT o EN).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Risultato,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [PSCustomObject]$ControlloCatalogo = $null,

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN')]
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
        [ValidateSet('IT', 'EN')]
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
            $elStato      = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'Status' -ValorePredefinito '')
            $elStatoShort = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'StatusShort' -ValorePredefinito '')
            if ($elStato.ToLowerInvariant() -ne $statoNorm -and $elStatoShort.ToLowerInvariant() -ne $statoNorm) {
                continue
            }
        }

        # 2. Filtro Gravita
        if ($gravNorm -ne 'tutte' -and $gravNorm -ne 'tutti' -and $gravNorm -ne 'all') {
            $elGrav    = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'Severity' -ValorePredefinito '')
            $elGravLbl = [string](Get-ValoreProprietaSicuro -Oggetto $el -NomeProprieta 'SeverityLabel' -ValorePredefinito '')
            if ($elGrav.ToLowerInvariant() -ne $gravNorm -and $elGravLbl.ToLowerInvariant() -ne $gravNorm) {
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
        [string]$Modalita = 'Semplice',

        [Parameter(Mandatory = $false)]
        [ValidateSet('IT', 'EN')]
        [string]$Lingua = 'IT'
    )

    $isEn = ($Lingua -eq 'EN')

    if ($null -eq $Elemento) {
        return [PSCustomObject]@{
            Selezionato          = $false
            ControlId            = ''
            Title                = if ($isEn) { 'No control selected' } else { 'Nessun controllo selezionato' }
            Category             = '-'
            SeverityLabel        = '-'
            Status               = 'sconosciuto'
            StatusLabel          = '-'
            Modalita             = $Modalita
            SpiegazioneSemplice  = if ($isEn) { 'Select a control from the table on the left to view its details.' } else { 'Seleziona un controllo dalla tabella per visualizzare i dettagli.' }
            SpiegazioneTecnica   = if ($isEn) { 'Select a control from the table on the left to view technical details.' } else { 'Seleziona un controllo dalla tabella per visualizzare i dettagli tecnici.' }
            TestoSpiegazione     = if ($isEn) { 'Select a control from the table on the left to view its details.' } else { 'Seleziona un controllo dalla tabella per visualizzare i dettagli.' }
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
        $spiegazioneSemplice = if ($isEn) { "No explanation available in the catalog for this control." } else { "Nessuna spiegazione disponibile nel catalogo per questo controllo." }
    }

    if ($isEn -and $script:TraduzioniControlliEN.ContainsKey($id)) {
        $trEn = $script:TraduzioniControlliEN[$id]
        $titolo              = $trEn.title
        $categoria           = $trEn.cat
        $spiegazioneSemplice = $trEn.rat
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

    if ([string]::IsNullOrWhiteSpace([string]$testoRimedio)) {
        $testoRimedio = if ($isEn) { "Manually verify this setting in Windows 11 Settings or Control Panel." } else { "Verifica manualmente questa impostazione nel Pannello di controllo o nelle Impostazioni di sicurezza di Windows 11." }
    }

    if ([string]::IsNullOrWhiteSpace([string]$noteRischi)) {
        $noteRischi = if ($isEn) { "Evaluate the impact before applying manual configuration changes." } else { "Valuta l'impatto prima di applicare modifiche manuali alla configurazione del sistema." }
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
