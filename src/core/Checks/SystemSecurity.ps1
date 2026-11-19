<#
.SYNOPSIS
    System security controls: Windows Update, BitLocker, Telemetry, Secure Boot,
    LSA Protection, PowerShell Script Block Logging, Smart App Control, TPM 2.0,
    WSH, ExecutionPolicy, Administrator Protection, and Windows hardening settings.

.DESCRIPTION
    Implements read-only checks for:
    - HOME-UPD-001: Automatic Windows Updates enabled (Test-WindowsUpdateEnabled)
    - HOME-UPD-002: Official Windows Update server (Test-WindowsUpdateAuthenticServer)
    - HOME-ENC-001: BitLocker or Device Encryption active on system drive (Test-BitLockerSystemDrive)
    - HOME-PRV-001: Telemetry set to minimum level (Test-TelemetryMinimum)
    - HOME-SEC-001: UEFI Secure Boot active (Test-SecureBoot)
    - HOME-SEC-002: LSA Protection enabled RunAsPPL (Test-LsaProtection)
    - HOME-SEC-003: PowerShell Script Block Logging enabled (Test-PsScriptBlockLogging)
    - HOME-SYS-001: Known file extensions visible in File Explorer (Test-FileExtensionsVisible)
    - HOME-SYS-002: AutoRun / AutoPlay disabled for removable drives (Test-AutorunDisabled)
    - HOME-SYS-003: Microsoft Defender SmartScreen active (Test-SmartScreenEnabled)
    - HOME-SYS-004: Core Isolation / Memory Integrity HVCI active (Test-MemoryIntegrityEnabled)
    - HOME-SYS-005: Anonymous SAM enumeration restricted (Test-AnonymousSamRestricted)
    - HOME-SYS-006: WDigest cleartext credential caching disabled (Test-WDigestDisabilitato)
    - HOME-SYS-007: Windows Remote Assistance disabled (Test-AssistenzaRemotaDisabilitata)
    - HOME-SYS-008: Remote Registry service disabled (Test-RegistroRemotoDisabilitato)
    - HOME-UAC-002: UAC prompts for elevation on Secure Desktop (Test-UacSecureElevation)
    - HOME-SEC-007: Smart App Control active (Test-SmartAppControl)
    - HOME-SEC-008: Hardware TPM 2.0 present and ready (Test-Tpm20Ready)
    - HOME-SYS-009: Windows Script Host disabled (Test-WshDisabled)
    - HOME-SEC-009: Secure PowerShell ExecutionPolicy (Test-PowerShellExecutionPolicySecure)
    - HOME-UAC-004: Windows 11 Administrator Protection active (Test-AdministratorProtection)
    - HOME-SEC-010: Windows Event Log integrity & Security log clearing check (Test-EventLogIntegrity)
    - HOME-SYS-010: PrintNightmare driver installation protection (Test-PrintNightmareProtection)
    - HOME-SEC-011: Kernel DMA Protection (Test-KernelDmaProtection)
    Never modifies system state.
#>

Set-StrictMode -Version 2

function Test-WindowsUpdateEnabled {
    <#
    .SYNOPSIS
        Verifies that the Windows Update service is not disabled and Group Policy
        does not disable automatic updates.
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
        Expected = "wuauserv service enabled (Start != 4) and NoAutoUpdate policy != 1"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoServizio = 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv'
        $percorsoPolicyAu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

        if (-not (Test-Path -LiteralPath $percorsoServizio)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "wuauserv service registry key not found"
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
            $risultato.Observed = "Windows Update service (wuauserv) is disabled (Start = 4)"
        }
        elseif ($noAutoUpdate -eq 1) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Automatic updates are disabled via policy (NoAutoUpdate = 1)"
        }
        else {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Windows Update enabled (wuauserv Start = $startVal, NoAutoUpdate = $noAutoUpdate)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Access denied to Windows Update configuration"
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
        Verifies that BitLocker or Device Encryption is active on the system drive.
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
        Expected = "BitLocker or Device Encryption active on the system drive"
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
                    Source           = 'Get-BitLockerVolume'
                }

                if ($statoProt -eq 'On' -or $statoProt -eq '1') {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "BitLocker active on $discoSistema (ProtectionStatus = $statoProt)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "BitLocker not active on $discoSistema (ProtectionStatus = $statoProt, VolumeStatus = $statoVol)"
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
                    Source     = 'BitLockerStatusRegistry'
                }
                if ($bootStatus -ge 1) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Boot drive encryption active (BootStatus = $bootStatus)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "BitLocker encryption not active on system drive (BootStatus = 0)"
                }
                return $risultato
            }
        }

        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Unable to determine BitLocker status (run as Administrator)"
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
        Verifies that Windows telemetry level (AllowTelemetry) is set to minimum (<= 1).
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
        Expected = "AllowTelemetry <= 1 (Required diagnostic data / minimum)"
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
            $risultato.Observed = "AllowTelemetry not restricted (default full telemetry level active)"
            $risultato.Evidence = @{ Configured = $false }
            return $risultato
        }

        $risultato.Evidence = @{
            Path           = $chiaveUsata
            AllowTelemetry = $valoreTrovato
        }

        if ($valoreTrovato -le 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "AllowTelemetry = $valoreTrovato (minimum level)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "AllowTelemetry = $valoreTrovato (above minimum level 1)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Access denied to DataCollection registry key"
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
        Verifies that UEFI Secure Boot is enabled.
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
        Expected = "UEFISecureBootEnabled = 1 (Secure Boot enabled)"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoSb = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
        if (-not (Test-Path -LiteralPath $percorsoSb)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Secure Boot state key not present (possible legacy BIOS system)"
            $risultato.Evidence = @{ KeyExists = $false }
            return $risultato
        }

        $propSb = Get-ItemProperty -LiteralPath $percorsoSb -ErrorAction Stop
        if ($null -eq $propSb.PSObject.Properties['UEFISecureBootEnabled']) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "UEFISecureBootEnabled value not found"
            return $risultato
        }

        $sbVal = [int]$propSb.UEFISecureBootEnabled
        $risultato.Evidence = @{
            Path                  = $percorsoSb
            UEFISecureBootEnabled = $sbVal
        }

        if ($sbVal -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Secure Boot enabled (UEFISecureBootEnabled = 1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Secure Boot disabled (UEFISecureBootEnabled = $sbVal)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Access denied to SecureBoot registry key"
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
        Verifies that Local Security Authority (LSA) Protection (RunAsPPL) is enabled.
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
        Expected = "RunAsPPL >= 1 or RunAsPPLBoot >= 1 in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoLsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        if (-not (Test-Path -LiteralPath $percorsoLsa)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "LSA registry key not found"
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
            $risultato.Observed = "LSA Protection active (RunAsPPL = $runAsPpl, RunAsPPLBoot = $runAsPplBoot)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "LSA Protection not active (RunAsPPL = 0)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Access denied to LSA registry key"
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
        Verifies that PowerShell Script Block Logging (EnableScriptBlockLogging) is enabled.
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
            $risultato.Observed = "ScriptBlockLogging policy not configured (logging disabled by default)"
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
            $risultato.Observed = "Script Block Logging enabled (EnableScriptBlockLogging = 1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Script Block Logging disabled (EnableScriptBlockLogging = $valore)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Access denied to ScriptBlockLogging registry key"
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
        Verifies that known file extensions are visible in File Explorer (HideFileExt = 0).
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
        Expected = "HideFileExt = 0 (File extensions always visible)"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoExp = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        if (-not (Test-Path -LiteralPath $percorsoExp)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Explorer Advanced registry key not found"
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
            $risultato.Observed = "File extensions visible (HideFileExt = 0)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "File extensions hidden (HideFileExt = $hideExt, risk of disguised executables)"
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
        Verifies that AutoRun/AutoPlay is disabled for removable drives (NoDriveTypeAutoRun >= 145 or DisableAutoplay = 1).
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
        Expected = "NoDriveTypeAutoRun = 255 or AutoPlay disabled (DisableAutoplay = 1)"
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
            $risultato.Observed = "AutoRun/AutoPlay disabled (NoDriveTypeAutoRun=$noDriveType, DisableAutoplay=$disableAutoplay)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "AutoPlay enabled for removable drives (DisableAutoplay=0, NoDriveTypeAutoRun=$noDriveType)"
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
        Verifies that Microsoft Defender SmartScreen is enabled for downloaded apps and files.
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
        Expected = "SmartScreen enabled (SmartScreenEnabled != 'Off' and EnableWebContentEvaluation = 1)"
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
            $risultato.Observed = "SmartScreen active (SmartScreenEnabled=$ssExplorer, WebEvaluation=$webEval)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "SmartScreen disabled (SmartScreenEnabled=$ssExplorer, WebEvaluation=$webEval)"
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
        Verifies that Core Isolation / Memory Integrity (HVCI) is actively running at runtime
        via Win32_DeviceGuard (VirtualizationBasedSecurityStatus = 2 and SecurityServicesRunning contains 2),
        keeping the registry key as diagnostic evidence and fallback (HOME-SYS-004).
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
        Expected = "VirtualizationBasedSecurityStatus = 2 and SecurityServicesRunning contains 2 (HVCI running)"
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
                    Source                            = 'Win32_DeviceGuard'
                    VirtualizationBasedSecurityStatus = $vbsStatus
                    SecurityServicesRunning           = $serviziRunning
                    RegistryPath                      = $percorsoHvci
                    RegistryEnabled                   = $valoreReg
                }

                if ($vbsStatus -eq 2 -and ($serviziRunning -contains 2)) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Memory Integrity (HVCI) active at runtime (VBS=2, SecurityServicesRunning contains 2)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "HVCI not running at runtime (VBSStatus=$vbsStatus, ServicesRunning=[$($serviziRunning -join ',')], RegEnabled=$valoreReg)"
                }
                return $risultato
            }
        }
        catch {
            # Diagnostic registry fallback if CIM DeviceGuard namespace is unavailable
        }

        if (-not $esisteChiave) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Memory Integrity (HVCI) not configured"
            $risultato.Evidence = @{ Source = 'RegistryFallback'; KeyExists = $false }
            return $risultato
        }

        $risultato.Evidence = @{
            Source          = 'RegistryFallback'
            Path            = $percorsoHvci
            RegistryEnabled = $valoreReg
        }

        if ($valoreReg -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Core Isolation / Memory Integrity enabled in registry (Enabled = 1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Core Isolation / Memory Integrity disabled (Enabled = $valoreReg)"
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
        Verifies that anonymous enumeration of SAM accounts (RestrictAnonymousSAM = 1) is blocked.
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
            $risultato.Observed = "LSA registry key not found"
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
            $risultato.Observed = "Anonymous SAM enumeration blocked (RestrictAnonymousSAM = 1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Anonymous SAM enumeration allowed (RestrictAnonymousSAM = $valore)"
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
        Verifies that Windows Update is not redirected to an unauthorized external WSUS server (WUServer).
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
        Expected = "No unauthorized WSUS server configured in WindowsUpdate policy"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoWu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
        if (-not (Test-Path -LiteralPath $percorsoWu)) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Direct connection to official Microsoft Windows Update servers"
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
            $risultato.Observed = "No custom WSUS server configured"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Windows Update redirected to external server: $wuServer"
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
        Verifies that WDigest cleartext password caching in LSASS memory
        (UseLogonCredential) is disabled (HOME-SYS-006).
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
        Expected = "UseLogonCredential = 0 (or absent) in WDigest"
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
            $risultato.Observed = "WDigest cleartext credential caching disabled (0)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "WARNING: WDigest UseLogonCredential = $valore (cleartext passwords cached in LSASS)"
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
        Verifies that Windows Remote Assistance (fAllowToGetHelp = 0) is disabled (HOME-SYS-007).
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
            $risultato.Observed = "Remote Assistance disabled (fAllowToGetHelp = 0)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Remote Assistance enabled (fAllowToGetHelp = $valore)"
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
        Verifies that the Remote Registry service (RemoteRegistry) is disabled and stopped (HOME-SYS-008).
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
        Expected = "RemoteRegistry service stopped and disabled (Start = 4)"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaveRr = 'HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry'
        if (-not (Test-Path -LiteralPath $chiaveRr)) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "RemoteRegistry service not installed"
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
            $risultato.Observed = "RemoteRegistry service disabled (Start=4) and stopped"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "RemoteRegistry service not disabled (Start=$startVal, Status=$statoSrv)"
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
        Verifies that UAC prompts for elevation consent (ConsentPromptBehaviorAdmin in 1, 2, 5)
        on the Secure Desktop (PromptOnSecureDesktop = 1) (HOME-UAC-002).
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
        Expected = "ConsentPromptBehaviorAdmin in (1, 2, 5) and PromptOnSecureDesktop = 1"
        Evidence = $null
        Error    = $null
    }

    try {
        $chiaveUac = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
        if (-not (Test-Path -LiteralPath $chiaveUac)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "UAC Policies\System registry key not found"
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
            $risultato.Observed = "UAC prompts for consent on Secure Desktop (ConsentPromptBehaviorAdmin=$consent, PromptOnSecureDesktop=1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Weak UAC elevation configuration (ConsentPromptBehaviorAdmin=$consent, PromptOnSecureDesktop=$secureDesk)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Access denied to UAC Policies\System key"
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
        Verifies Smart App Control (SAC) status in HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy
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
        Expected = "VerifiedAndReputablePolicyState = 1 (Enforced) or 2 (Evaluation)"
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
            $risultato.Observed = "Smart App Control active in Enforced mode (1)"
        }
        elseif ($statoSac -eq 2) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Smart App Control active in Evaluation mode (2 - active evaluation)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Smart App Control disabled (VerifiedAndReputablePolicyState = $statoSac)"
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
        Verifies via Get-Tpm (or CIM Win32_Tpm / TPM registry fallback) that hardware TPM 2.0
        is present and ready (TpmPresent = True and TpmReady = True) (HOME-SEC-008).
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
        Expected = "TpmPresent = True and TpmReady = True"
        Evidence = $null
        Error    = $null
    }

    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($null -eq $tpm -or $null -eq $tpm.PSObject.Properties['TpmPresent']) {
            throw "TPM object not returned or requires elevated privileges"
        }
        $present = [bool]$tpm.TpmPresent
        $ready   = [bool]$tpm.TpmReady

        $risultato.Evidence = @{
            Source     = 'Get-Tpm'
            TpmPresent = $present
            TpmReady   = $ready
        }

        if ($present -and $ready) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Hardware TPM 2.0 module present and ready (TpmPresent=True, TpmReady=True)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "TPM not ready or absent (TpmPresent=$present, TpmReady=$ready)"
        }
    }
    catch {
        try {
            $cimTpm = Get-CimInstance -ClassName Win32_Tpm -Namespace 'root\cimv2\Security\MicrosoftTpm' -ErrorAction Stop
            if ($null -ne $cimTpm -and $null -ne $cimTpm.PSObject.Properties['IsEnabled_InitialValue']) {
                $enVal  = [bool]$cimTpm.IsEnabled_InitialValue
                $actVal = [bool]$cimTpm.IsActivated_InitialValue
                $risultato.Evidence = @{
                    Source                   = 'Win32_Tpm'
                    IsEnabled_InitialValue   = $enVal
                    IsActivated_InitialValue = $actVal
                }
                if ($enVal -and $actVal) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Hardware TPM 2.0 module enabled and activated (Win32_Tpm)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "TPM not active (Enabled=$enVal, Activated=$actVal)"
                }
                return $risultato
            }
        }
        catch { }

        # Registry fallback (HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI and Enum - readable without Admin)
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
                        Source              = 'TPMServiceRegistry'
                        DeviceCount         = $enumCount
                        TaskReadyForStorage = $readyStor
                        FirmwareVersion     = $fwVer
                    }
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Hardware TPM 2.0 module present and ready (Firmware $fwVer)"
                    return $risultato
                }
            }
        }
        catch { }

        if ($_.Exception.Message -match 'Administrator|amministratore|Access is denied|Accesso negato|privilegi|privilege|CIM resource') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Administrator privileges required to query TPM 2.0 chip status"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Unable to query TPM status ($($_.Exception.Message))"
            $risultato.Error    = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-WshDisabled {
    <#
    .SYNOPSIS
        Verifies that Windows Script Host (WSH: wscript.exe / cscript.exe for .vbs/.js)
        is disabled (Enabled = 0) (HOME-SYS-009).
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
            $risultato.Observed = "Windows Script Host (WSH) disabled (HKLM=$valLM, HKCU=$valCU)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Windows Script Host (WSH) enabled for .vbs/.js scripts (Enabled = 1)"
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
        Verifies via Get-ExecutionPolicy -List that persistent scopes (MachinePolicy, UserPolicy,
        LocalMachine, CurrentUser) are not set to Unrestricted or Bypass (HOME-SEC-009).
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
        Expected = "No persistent scope set to Unrestricted or Bypass"
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
            $risultato.Observed = "Secure ExecutionPolicy (LocalMachine=$polLM, CurrentUser=$polCU)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Overly permissive ExecutionPolicy detected: $($scopeInsicuri -join ', ')"
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
        Verifies that Windows 11 24H2/25H2/26H2 just-in-time Administrator Protection
        is enabled (TypeOfAdminApprovalMode = 2) (HOME-UAC-004).
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
        Expected = "TypeOfAdminApprovalMode = 2 (Just-in-time Administrator Protection active)"
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
            $risultato.Observed = "UAC Policies\System registry key not found"
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
            $risultato.Observed = "Just-in-time Administrator Protection active (TypeOfAdminApprovalMode = 2)"
        }
        elseif ((-not $haProprieta) -and ($numeroBuild -gt 0 -and $numeroBuild -lt 26100)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Feature available starting in Windows 11 24H2/25H2+ (Detected build: $numeroBuild < 26100)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Legacy UAC mode active; Administrator Protection is not enabled (TypeOfAdminApprovalMode = $valoreMode)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Access denied to UAC Policies\System key"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to check Administrator Protection"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-EventLogIntegrity {
    <#
    .SYNOPSIS
        Verifies Windows Event Log service health and checks for recent Security log clearing events (Event ID 1102) (HOME-SEC-010).
    .DESCRIPTION
        Confirms that the EventLog service is running and not disabled, then queries
        the Security event log for Event ID 1102 over the last 30 days in strict read-only mode.
    .PARAMETER Controllo
        Control object from the security catalog.
    .PARAMETER Ambiente
        Environment object returned by Get-AmbienteSistema.
    .OUTPUTS
        PSCustomObject with properties: Status, Observed, Expected, Evidence, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $result = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "EventLog service running and no Security log clearing events (Event ID 1102) in the last 30 days"
        Evidence = $null
        Error    = $null
    }

    try {
        $eventLogService = $null
        try {
            $eventLogService = Get-Service -Name 'EventLog' -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Message -match 'Cannot find any service|Impossibile trovare alcun servizio') {
                $eventLogService = $null
            }
            else {
                throw
            }
        }

        $serviceStatus = if ($null -ne $eventLogService) { [string]$eventLogService.Status } else { 'Missing' }
        $startType = if ($null -ne $eventLogService -and $null -ne $eventLogService.PSObject.Properties['StartType'] -and $null -ne $eventLogService.StartType) {
            [string]$eventLogService.StartType
        }
        else {
            ''
        }

        if ($null -eq $eventLogService -or $serviceStatus -ne 'Running' -or $startType -eq 'Disabled') {
            $result.Status   = 'fallito'
            $result.Observed = "Windows Event Log service (EventLog) is not running properly (Status=$serviceStatus, StartType=$startType)"
            $result.Evidence = @{
                ServiceStatus = $serviceStatus
                StartType     = $startType
            }
            return $result
        }

        try {
            $startTime   = (Get-Date).AddDays(-30)
            $clearEvents = @(Get-WinEvent -FilterHashtable @{
                LogName   = 'Security'
                Id        = 1102
                StartTime = $startTime
            } -MaxEvents 5 -ErrorAction Stop)

            $timestamps = @()
            foreach ($evt in $clearEvents) {
                if ($null -ne $evt.PSObject.Properties['TimeCreated'] -and $null -ne $evt.TimeCreated) {
                    if ($evt.TimeCreated -is [datetime]) {
                        $timestamps += $evt.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                    }
                    else {
                        $timestamps += [string]$evt.TimeCreated
                    }
                }
            }

            $result.Evidence = @{
                ServiceStatus   = $serviceStatus
                Event1102Count  = $clearEvents.Count
                EventTimestamps = $timestamps
                LookbackDays    = 30
            }

            if ($clearEvents.Count -gt 0) {
                $latestStr       = if ($timestamps.Count -gt 0) { $timestamps[0] } else { 'Unknown timestamp' }
                $result.Status   = 'fallito'
                $result.Observed = "Detected $($clearEvents.Count) Security event log clearing event(s) (Event ID 1102) in the last 30 days (latest: $latestStr)"
            }
            else {
                $result.Status   = 'superato'
                $result.Observed = "EventLog service is running and no Security log clearing events (Event ID 1102) were found in the last 30 days"
            }
        }
        catch {
            if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*' -or
                $_.Exception.Message -match 'No events were found|Nessun evento trovato|Keine Ereignisse gefunden') {
                $result.Status   = 'superato'
                $result.Observed = "EventLog service is running and no Security log clearing events (Event ID 1102) were found in the last 30 days"
                $result.Evidence = @{
                    ServiceStatus  = $serviceStatus
                    Event1102Count = 0
                    LookbackDays   = 30
                }
            }
            elseif ($_.Exception -is [System.UnauthorizedAccessException] -or
                $_.Exception -is [System.Security.SecurityException] -or
                $_.FullyQualifiedErrorId -match 'UnauthorizedAccess|AccessDenied' -or
                $_.Exception.Message -match 'Access is denied|Unauthorized|unauthorized operation|Accesso negato|privileg') {
                $result.Status   = 'sconosciuto'
                $result.Observed = "Administrator privileges are required to inspect the Windows Security event log"
                $result.Evidence = @{
                    ServiceStatus = $serviceStatus
                    RequiresAdmin = $true
                }
                $result.Error = $_.Exception.Message
            }
            elseif ($_.Exception -is [System.Management.Automation.CommandNotFoundException]) {
                $result.Status   = 'sconosciuto'
                $result.Observed = "Cmdlet Get-WinEvent is not available"
                $result.Error    = $_.Exception.Message
            }
            else {
                $result.Status = 'errore'
                $result.Error  = $_.Exception.Message
            }
        }
    }
    catch {
        $result.Status = 'errore'
        $result.Error  = $_.Exception.Message
    }

    return $result
}

function Test-PrintNightmareProtection {
    <#
    .SYNOPSIS
        Verifies PrintNightmare (CVE-2021-34527) Point and Print driver installation restrictions (HOME-SYS-010).
    .DESCRIPTION
        Checks whether the Print Spooler service is disabled/absent, or otherwise ensures that
        RestrictDriverInstallationToAdministrators is not overridden to 0 on Windows 11.
    .PARAMETER Controllo
        Control object from the security catalog.
    .PARAMETER Ambiente
        Environment object returned by Get-AmbienteSistema.
    .OUTPUTS
        PSCustomObject with properties: Status, Observed, Expected, Evidence, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $result = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Print Spooler disabled or RestrictDriverInstallationToAdministrators not set to 0 (admin-only driver installation enforced)"
        Evidence = $null
        Error    = $null
    }

    try {
        $spooler = Get-Service -Name 'Spooler' -ErrorAction SilentlyContinue
        if ($null -eq $spooler) {
            $result.Status   = 'superato'
            $result.Observed = "Print Spooler service is not installed; PrintNightmare attack surface is mitigated"
            $result.Evidence = @{ SpoolerPresent = $false }
            return $result
        }

        $spoolerStatus = [string]$spooler.Status
        $spoolerStartType = if ($null -ne $spooler.PSObject.Properties['StartType'] -and $null -ne $spooler.StartType) {
            [string]$spooler.StartType
        }
        else {
            ''
        }

        if ($spoolerStartType -eq 'Disabled' -or $spoolerStatus -eq 'Disabled') {
            $result.Status   = 'superato'
            $result.Observed = "Print Spooler service is disabled; PrintNightmare attack surface is mitigated"
            $result.Evidence = @{
                SpoolerPresent   = $true
                SpoolerStatus    = $spoolerStatus
                SpoolerStartType = 'Disabled'
            }
            return $result
        }

        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint'
        if (-not (Test-Path -LiteralPath $policyPath -ErrorAction SilentlyContinue)) {
            $result.Status   = 'superato'
            $result.Observed = "Windows 11 default PrintNightmare protection active (PointAndPrint policy absent; admin-only driver installation enforced by default)"
            $result.Evidence = @{
                SpoolerStatus                          = $spoolerStatus
                PolicyKeyExists                        = $false
                RestrictDriverInstallationToAdministrators = $null
            }
            return $result
        }

        $policyProps = Get-ItemProperty -LiteralPath $policyPath -ErrorAction Stop
        $hasValue = (
            $null -ne $policyProps -and
            $null -ne $policyProps.PSObject.Properties['RestrictDriverInstallationToAdministrators'] -and
            $null -ne $policyProps.RestrictDriverInstallationToAdministrators
        )

        if ($hasValue) {
            [int]$restrictVal = $policyProps.RestrictDriverInstallationToAdministrators
            $result.Evidence = @{
                SpoolerStatus                              = $spoolerStatus
                PolicyPath                                 = $policyPath
                RestrictDriverInstallationToAdministrators = $restrictVal
            }

            if ($restrictVal -eq 0) {
                $result.Status   = 'fallito'
                $result.Observed = "Insecure override detected: non-administrators are allowed to install printer drivers (RestrictDriverInstallationToAdministrators = 0)"
            }
            else {
                $result.Status   = 'superato'
                $result.Observed = "Driver installation explicitly restricted to administrators (RestrictDriverInstallationToAdministrators = $restrictVal)"
            }
        }
        else {
            $result.Status   = 'superato'
            $result.Observed = "Windows 11 default PrintNightmare protection active (RestrictDriverInstallationToAdministrators not overridden; admin-only enforced by default)"
            $result.Evidence = @{
                SpoolerStatus                              = $spoolerStatus
                PolicyPath                                 = $policyPath
                RestrictDriverInstallationToAdministrators = $null
            }
        }
    }
    catch [System.Security.SecurityException] {
        $result.Status   = 'sconosciuto'
        $result.Observed = "Access denied while reading PointAndPrint registry policy"
        $result.Error    = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $result.Status   = 'sconosciuto'
        $result.Observed = "Access denied while reading PointAndPrint registry policy"
        $result.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privileg') {
            $result.Status   = 'sconosciuto'
            $result.Observed = "Insufficient privileges to inspect PointAndPrint protection settings"
            $result.Error    = $_.Exception.Message
        }
        else {
            $result.Status = 'errore'
            $result.Error  = $_.Exception.Message
        }
    }

    return $result
}

function Test-KernelDmaProtection {
    <#
    .SYNOPSIS
        Verifies Kernel DMA Protection hardware readiness and Group Policy configuration (HOME-SEC-011).
    .DESCRIPTION
        Inspects Kernel DMA Protection policy settings (DeviceEnumerationPolicy) and queries
        Win32_DeviceGuard AvailableSecurityProperties for value 3 (DMA Protection).
        Returns sconosciuto when hardware or VM does not expose IOMMU/DMA protection.
    .PARAMETER Controllo
        Control object from the security catalog.
    .PARAMETER Ambiente
        Environment object returned by Get-AmbienteSistema.
    .OUTPUTS
        PSCustomObject with properties: Status, Observed, Expected, Evidence, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Controllo,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $result = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = "Kernel DMA Protection active (Win32_DeviceGuard AvailableSecurityProperties contains 3) and not disabled via policy (DeviceEnumerationPolicy != 2)"
        Evidence = $null
        Error    = $null
    }

    try {
        $policyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection'
        $policyVal  = $null
        if (Test-Path -LiteralPath $policyPath -ErrorAction SilentlyContinue) {
            $polProps = Get-ItemProperty -LiteralPath $policyPath -ErrorAction SilentlyContinue
            if ($null -ne $polProps -and $null -ne $polProps.PSObject.Properties['DeviceEnumerationPolicy'] -and $null -ne $polProps.DeviceEnumerationPolicy) {
                $policyVal = [int]$polProps.DeviceEnumerationPolicy
                if ($policyVal -eq 2) {
                    $result.Status   = 'fallito'
                    $result.Observed = "Kernel DMA Protection is explicitly disabled via policy (DeviceEnumerationPolicy = 2 - Allow all)"
                    $result.Evidence = @{
                        PolicyPath              = $policyPath
                        DeviceEnumerationPolicy = 2
                    }
                    return $result
                }
            }
        }

        $dmaKeyPath   = 'HKLM:\SYSTEM\CurrentControlSet\Control\DmaSecurity'
        $dmaKeyExists = (Test-Path -LiteralPath $dmaKeyPath -ErrorAction SilentlyContinue)
        if ($dmaKeyExists) {
            $dmaProps = Get-ItemProperty -LiteralPath $dmaKeyPath -ErrorAction SilentlyContinue
            if ($null -ne $dmaProps -and $null -ne $dmaProps.PSObject.Properties['DeviceEnumerationPolicy'] -and $null -ne $dmaProps.DeviceEnumerationPolicy) {
                [int]$dmaPolicyVal = $dmaProps.DeviceEnumerationPolicy
                if ($null -eq $policyVal) { $policyVal = $dmaPolicyVal }
                if ($dmaPolicyVal -eq 2) {
                    $result.Status   = 'fallito'
                    $result.Observed = "Kernel DMA Protection is explicitly disabled in DmaSecurity configuration (DeviceEnumerationPolicy = 2)"
                    $result.Evidence = @{
                        DmaSecurityPath         = $dmaKeyPath
                        DeviceEnumerationPolicy = 2
                    }
                    return $result
                }
            }
        }

        try {
            $deviceGuard = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction Stop
            $availableProps = @()
            if ($null -ne $deviceGuard -and $null -ne $deviceGuard.PSObject.Properties['AvailableSecurityProperties'] -and $null -ne $deviceGuard.AvailableSecurityProperties) {
                $availableProps = @($deviceGuard.AvailableSecurityProperties | ForEach-Object { [int]$_ })
            }

            $result.Evidence = @{
                Source                        = 'Win32_DeviceGuard'
                AvailableSecurityProperties   = $availableProps
                PolicyDeviceEnumerationPolicy = $policyVal
                DmaSecurityKeyPresent         = $dmaKeyExists
            }

            if ($availableProps -contains 3) {
                $result.Status   = 'superato'
                $result.Observed = "Kernel DMA Protection is active and supported by hardware (AvailableSecurityProperties contains 3)"
            }
            else {
                $result.Status   = 'sconosciuto'
                $result.Observed = "Kernel DMA Protection is not supported or not exposed by this hardware/VM (AvailableSecurityProperties=[$($availableProps -join ',')])"
            }
        }
        catch {
            $result.Status   = 'sconosciuto'
            $result.Observed = "Kernel DMA Protection is not supported or not exposed by this hardware/VM"
            $result.Evidence = @{
                Source                        = 'Win32_DeviceGuard'
                PolicyDeviceEnumerationPolicy = $policyVal
                DmaSecurityKeyPresent         = $dmaKeyExists
            }
            $result.Error = $_.Exception.Message
        }
    }
    catch [System.Security.SecurityException] {
        $result.Status   = 'sconosciuto'
        $result.Observed = "Access denied while checking Kernel DMA Protection settings"
        $result.Error    = $_.Exception.Message
    }
    catch {
        $result.Status = 'errore'
        $result.Error  = $_.Exception.Message
    }

    return $result
}
