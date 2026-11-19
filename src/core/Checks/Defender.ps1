<#
.SYNOPSIS
    Windows Defender Antivirus and threat protection security checks.

.DESCRIPTION
    Implements read-only checks for:
    - HOME-AV-001: Real-time protection active (Test-DefenderRealtime)
    - HOME-AV-002: Antivirus signatures updated within the last 7 days (Test-DefenderSignatures)
    - HOME-AV-003: No active virus or malware threats detected (Test-DefenderNoActiveThreats)
    - HOME-AV-004: Downloaded file scanning (IOAV) and behavior monitoring active (Test-DefenderBehaviorAndIoav)
    - HOME-AV-005: Potentially Unwanted Application (PUA) blocking enabled (Test-DefenderPuaProtection)
    - HOME-AV-006: Tamper Protection and Cloud MAPS active (Test-DefenderTamperAndCloud)
    - HOME-AV-007: Periodic antivirus scan completed within the last 14 days (Test-DefenderRecentScan)
    - HOME-AV-008: No dangerous folder or extension exclusions in Defender (Test-DefenderSafeExclusions)
    - HOME-AV-009: Ransomware protection / Controlled Folder Access active (Test-DefenderRansomwareCartelle)
    - HOME-AV-010: Defender Network Protection active (Test-DefenderNetworkProtection)
    - HOME-AV-011: Attack Surface Reduction (ASR) rules active (Test-DefenderAsrRules)
    Never modifies system state.
#>

Set-StrictMode -Version 2

function Test-DefenderRealtime {
    <#
    .SYNOPSIS
        Verifies that Windows Defender real-time protection is active.
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
        Expected = "AntivirusEnabled = True and RealTimeProtectionEnabled = True"
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
            Source                    = 'Get-MpComputerStatus'
        }

        if ($avAttivo -and $rtAttivo) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Real-time protection and antivirus are active"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "AntivirusEnabled=$avAttivo, RealTimeProtectionEnabled=$rtAttivo"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-MpComputerStatus is not available"
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
                    Source                    = 'RegistryFallback'
                }

                if ($disAv -eq 0 -and $disAs -eq 0 -and $disRt -eq 0) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Real-time protection active (verified via registry fallback)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "Real-time protection disabled in registry (DisableRealtimeMonitoring=$disRt)"
                }
                return $risultato
            }
        }
        catch { }

        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to query Windows Defender"
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
        Verifies that Windows Defender antivirus signatures are up to date (<= 7 days old).
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
        Expected = "Antivirus signature age <= 7 days"
        Evidence = $null
        Error    = $null
    }

    try {
        $statoMp = Get-MpComputerStatus -ErrorAction Stop
        $etaGiorni = [int]$statoMp.AntivirusSignatureAge

        $risultato.Evidence = @{
            AntivirusSignatureAge = $etaGiorni
            Source                = 'Get-MpComputerStatus'
        }

        if ($etaGiorni -le 7) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Signatures up to date ($etaGiorni days old)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Outdated signatures ($etaGiorni days old; max threshold: 7 days)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-MpComputerStatus is not available"
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
                                Source                = 'RegistryFallback'
                            }
                            if ($giorni -le 7) {
                                $risultato.Status   = 'superato'
                                $risultato.Observed = "Signatures up to date ($giorni days old)"
                            }
                            else {
                                $risultato.Status   = 'fallito'
                                $risultato.Observed = "Outdated signatures ($giorni days old)"
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
            $risultato.Observed = "Insufficient privileges to check Windows Defender signatures"
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
        Verifies that Windows Defender has no active or unresolved malware threats.
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
        Expected = "0 active threats detected by Windows Defender"
        Evidence = $null
        Error    = $null
    }

    try {
        $rilevamenti = @(Get-MpThreatDetection -ErrorAction Stop)
        $minacceCat  = @(Get-MpThreat -ErrorAction SilentlyContinue)

        $minacceAttive = @()
        foreach ($m in $minacceCat) {
            if ($null -ne $m.PSObject.Properties['IsActive'] -and $m.IsActive) {
                $nomeMinaccia = if ($null -ne $m.PSObject.Properties['ThreatName']) { [string]$m.ThreatName } else { 'Threat' }
                $minacceAttive += $nomeMinaccia
            }
        }

        $risultato.Evidence = @{
            HistoricalDetectionsCount = $rilevamenti.Count
            ActiveThreatsCount        = $minacceAttive.Count
            ActiveThreats             = $minacceAttive
        }

        if ($minacceAttive.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "No active threats present on the system (0 active threats)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Detected $($minacceAttive.Count) active threats: $($minacceAttive -join ', ')"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-MpThreatDetection is not available"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to query Defender threat catalog"
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
        Verifies that behavior monitoring and downloaded file scanning (IOAV) are active.
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
        Expected = "BehaviorMonitorEnabled = True and IoavProtectionEnabled = True"
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
            $risultato.Observed = "Behavior monitoring and downloaded file scanning (IOAV) are active"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "BehaviorMonitorEnabled=$behav, IoavProtectionEnabled=$ioav"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-MpComputerStatus is not available"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to query Windows Defender"
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
        Verifies that Potentially Unwanted Application blocking (PUAProtection = 1) is enabled.
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
        Expected = "PUAProtection = 1 (Block mode active)"
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
            $risultato.Observed = "PUA protection active in Block mode (PUAProtection = 1)"
        }
        elseif ($pua -eq 2) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "PUA protection in Audit mode only, not blocking files (PUAProtection = 2)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "PUA protection disabled (PUAProtection = $pua)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-MpPreference is not available"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to read Defender PUA preferences"
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
        Verifies that Tamper Protection (IsTamperProtected) and Cloud Protection (MAPSReporting) are enabled.
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
        Expected = "IsTamperProtected = True and MAPSReporting >= 1"
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
            $risultato.Observed = "Tamper Protection active and Cloud MAPS enabled (level $maps)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "IsTamperProtected=$tamper, MAPSReporting=$maps"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Windows Defender cmdlets are not available"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to check Tamper Protection and Cloud MAPS"
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
        Verifies that a Quick or Full antivirus scan has completed within the last 14 days.
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
        Expected = "Quick or Full scan completed within the last 14 days"
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
            $risultato.Observed = "Last scan completed $minAge days ago"
        }
        elseif ($minAge -eq [uint32]::MaxValue) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "No recent periodic scan recorded"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Last scan was $minAge days ago (recommended threshold: <= 14 days)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-MpComputerStatus is not available"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to check last scan age"
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
        Verifies that no dangerous exclusions (e.g., C:\, Downloads, .exe, .ps1) are configured in Windows Defender.
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
        Expected = "No critical folders or executable extensions excluded from Windows Defender"
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

        # When running without admin privileges, Defender returns "N/A: Must be an administrator..."
        if (($paths.Count -gt 0 -and $paths[0] -match 'Must be an administrator|amministratore') -or
            ($exts.Count -gt 0 -and $exts[0] -match 'Must be an administrator|amministratore')) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Administrator privileges required to read Defender exclusions"
            $risultato.Evidence = @{ RequiresAdmin = $true }
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
                $esclusioniPericolose += "Path: $p"
            }
        }

        foreach ($e in $exts) {
            $eNorm = $e.Trim().TrimStart('.').ToLowerInvariant()
            if ($eNorm -in @('exe', 'dll', 'ps1', 'bat', 'cmd', 'vbs', 'js', 'scr', 'hta', 'msi', '*')) {
                $esclusioniPericolose += "Extension: .$eNorm"
            }
        }

        $risultato.Evidence = @{
            ExclusionPathCount      = $paths.Count
            ExclusionExtensionCount = $exts.Count
            DangerousExclusions     = $esclusioniPericolose
        }

        if ($esclusioniPericolose.Count -eq 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "No high-risk exclusions found ($($paths.Count) paths, $($exts.Count) extensions)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "High-risk exclusions detected: $($esclusioniPericolose -join '; ')"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-MpPreference is not available"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to inspect Windows Defender exclusions"
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
        Verifies that Controlled Folder Access (ransomware protection) is enabled (HOME-AV-009).
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
        Expected = "EnableControlledFolderAccess = 1 (Ransomware blocking active)"
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
            $risultato.Observed = "Ransomware protection (Controlled Folder Access) active (1)"
        }
        elseif ($cfa -eq 2) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Controlled Folder Access in Audit mode only (2)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Controlled Folder Access disabled ($cfa)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-MpPreference is not available"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to read EnableControlledFolderAccess"
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
        Verifies that Microsoft Defender Exploit Guard Network Protection (EnableNetworkProtection = 1) is enabled (HOME-AV-010).
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
        Expected = "EnableNetworkProtection = 1 (Malicious domain blocking active)"
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
            $risultato.Observed = "Defender Exploit Guard Network Protection active in Block mode (1)"
        }
        elseif ($netP -eq 2) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Network Protection in Audit mode only (2)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Network Protection disabled ($netP)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-MpPreference is not available"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to read EnableNetworkProtection"
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
        Verifies that Microsoft Defender Attack Surface Reduction (ASR) rules are active
        in Block (1) or Warn (6) mode, including LSASS credential theft and obfuscated script rules (HOME-AV-011).
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
        Expected = "ASR rules active in Block (1) or Warn (6) mode (including LSASS 9e6c4e1f-... and Obfuscated Scripts 5beb7efe-...)"
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
            $risultato.Observed = "Administrator privileges required to read Defender ASR rules"
            $risultato.Evidence = @{ RequiresAdmin = $true }
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
            TotalConfigured  = $ids.Count
            TotalActive      = $regoleAttive.Count
            LsassProtected   = $lsassAttiva
            ScriptsProtected = $scriptAttiva
            ActiveRules      = $regoleAttive
        }

        if ($regoleAttive.Count -gt 0) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "$($regoleAttive.Count) ASR rules active in Block/Warn mode (LSASS=$lsassAttiva, ObfuscatedScripts=$scriptAttiva)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "No Attack Surface Reduction (ASR) rules active in Block/Warn mode ($($ids.Count) configured)"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-MpPreference is not available"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to check Defender ASR rules"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}
