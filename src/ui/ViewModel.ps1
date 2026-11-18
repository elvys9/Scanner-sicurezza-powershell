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
    'HOME-SEC-004' = [PSCustomObject]@{
        text    = "Abilita la Protezione esecuzione programmi (DEP) per i programmi e servizi di Windows tramite bcdedit."
        command = 'bcdedit.exe /set "{current}" nx OptIn'
        risk    = "Molto basso: OptIn e' la configurazione predefinita sicura di Windows 11."
    }
    'HOME-SEC-005' = [PSCustomObject]@{
        text    = "Disabilita la funzionalita' opzionale obsoleta Windows PowerShell 2.0 per impedire attacchi di downgrade."
        command = 'Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart'
        risk    = "Molto basso: tutti gli script moderni usano PowerShell 5.1 o PowerShell 7."
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
    'HOME-SEC-004' = @{ cat = 'Advanced Security'; title = 'Hardware Data Execution Prevention (DEP) enabled';           rat = 'DEP prevents malicious code execution (buffer overflows/shellcode) from memory pages marked as data-only.'; rem = 'Enable DEP via bcdedit.exe /set "{current}" nx OptIn.'; risk = 'Very low: OptIn is the secure default on Windows 11.' }
    'HOME-SEC-005' = @{ cat = 'Advanced Security'; title = 'Legacy PowerShell v2.0 engine disabled (anti-downgrade)';    rat = 'Attackers run powershell.exe -Version 2 to completely bypass AMSI antivirus inspection and Script Block Logging.'; rem = 'Disable the legacy MicrosoftWindowsPowerShellV2Root optional feature.'; risk = 'Very low: modern scripts run on PowerShell 5.1 or PowerShell 7.' }
}

# Traduzioni complete in Tedesco (DE) per tutti i 50 controlli (Titolo, Categoria, Spiegazione, Rimedio, Rischi)
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
    'HOME-SEC-004' = @{ cat = 'Erweiterte Sicherheit'; title = 'Datenausfuehrungsverhinderung (DEP) aktiviert';                rat = 'DEP verhindert die Ausfuehrung von Schadcode (Buffer Overflows) in Speicherbereichen, die nur fuer Daten vorgesehen sind.'; rem = 'Aktivieren Sie DEP ueber bcdedit.exe /set "{current}" nx OptIn.'; risk = 'Sehr gering: OptIn ist die sichere Standardeinstellung von Windows 11.' }
    'HOME-SEC-005' = @{ cat = 'Erweiterte Sicherheit'; title = 'Veraltete PowerShell v2.0-Engine deaktiviert (Anti-Downgrade)'; rat = 'Angreifer starten powershell.exe -Version 2, um AMSI-Virenpruefung und Script Block Logging komplett zu umgehen.'; rem = 'Deaktivieren Sie das optionale Feature MicrosoftWindowsPowerShellV2Root.'; risk = 'Sehr gering: Moderne Skripte nutzen PowerShell 5.1 oder PowerShell 7.' }
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
