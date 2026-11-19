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
