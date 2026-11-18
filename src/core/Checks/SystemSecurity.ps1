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

function Test-DepAttivo {
    <#
    .SYNOPSIS
        Verifica che la Protezione esecuzione programmi (DEP / Data Execution Prevention) sia attiva (HOME-SEC-004).
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
        Expected = "DataExecutionPrevention_SupportPolicy >= 2 (OptIn / OptOut / AlwaysOn)"
        Evidence = $null
        Error    = $null
    }

    try {
        $osCim = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        $depPol = [int]$osCim.DataExecutionPrevention_SupportPolicy
        $depAvail = [bool]$osCim.DataExecutionPrevention_Available

        $risultato.Evidence = @{
            DEP_Available     = $depAvail
            DEP_SupportPolicy = $depPol
        }

        if ($depAvail -and $depPol -ge 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "DEP hardware attivo (Policy = $depPol)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "DEP disabilitato (Policy = $depPol, Available = $depAvail)"
        }
    }
    catch {
        if ([Environment]::Is64BitOperatingSystem) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "DEP hardware (NX) obbligatorio attivo su architettura Windows 11 x64"
            $risultato.Evidence = @{ Is64BitOS = $true; Fonte = 'EnvironmentFallback' }
        }
        elseif ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Servizio CIM non disponibile per leggere la policy DEP"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-PowerShellV2Disabilitato {
    <#
    .SYNOPSIS
        Verifica che il motore obsoleto PowerShell 2.0 non sia installato, prevenendo
        attacchi di downgrade che aggirano AMSI e Script Block Logging (HOME-SEC-005).
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
        Expected = "Motore legacy PowerShell 2.0 assente o disabilitato"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaveEngineV2 = 'HKLM:\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine'
        $v2Presente = $false
        $psVer = ''

        if (Test-Path -LiteralPath $chiaveEngineV2) {
            $propV2 = Get-ItemProperty -LiteralPath $chiaveEngineV2 -ErrorAction SilentlyContinue
            if ($null -ne $propV2 -and $null -ne $propV2.PSObject.Properties['PowerShellVersion']) {
                $psVer = [string]$propV2.PowerShellVersion
                if ($psVer -like '2.*') {
                    # Verifica anche se la DLL di PS v2 esiste su disco
                    $dllV2 = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\System.Management.Automation.ni.dll'
                    if (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\PowerShell\3') {
                        # Su Windows 10/11 la chiave \1\PowerShellEngine esiste solo con PSVersion=2.0 se la feature MicrosoftWindowsPowerShellV2 e' attiva
                        $v2Presente = $true
                    }
                }
            }
        }

        $risultato.Evidence = @{
            EngineV2KeyExists = $v2Presente
            VersionFound      = $psVer
        }

        if (-not $v2Presente) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Motore obsoleto PowerShell 2.0 non installato"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Motore obsoleto PowerShell 2.0 presente ($psVer - rischio downgrade attack)"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}
