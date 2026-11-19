<#
.SYNOPSIS
    Closed-loop remediation orchestrator for Windows 11 Security Scanner.

.DESCRIPTION
    Applies selected deterministic remediations from RemediationCatalog.ps1 inside an isolated
    backup session, captures pre-change state via BackupManager.ps1, and immediately re-runs
    the corresponding read-only core check via Invoke-Controlli when available.
#>

Set-StrictMode -Version 2

function Test-IsAdministrator {
    <#
    .SYNOPSIS
        Returns $true when the current process runs with local Administrator privileges.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

function Test-IsRdpSession {
    <#
    .SYNOPSIS
        Returns $true when executing inside an active Remote Desktop (RDP) session.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    return (([string]$env:SESSIONNAME) -like 'RDP-*')
}

function Test-IsWinRmSession {
    <#
    .SYNOPSIS
        Returns $true when executing inside a remote PowerShell / WinRM session.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    $senderInfo = Get-Variable -Name 'PSSenderInfo' -ValueOnly -ErrorAction SilentlyContinue
    return (($null -ne $senderInfo) -or ($Host.Name -eq 'ServerRemoteHost'))
}

function Test-HvciSupported {
    <#
    .SYNOPSIS
        Checks whether hardware virtualization / VBS capability is available to support HVCI.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    try {
        $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\Microsoft\Windows\DeviceGuard' -ErrorAction SilentlyContinue
        if ($null -ne $dg -and $null -ne $dg.PSObject.Properties['AvailableSecurityProperties'] -and $null -ne $dg.AvailableSecurityProperties) {
            $props = @($dg.AvailableSecurityProperties | ForEach-Object { [int]$_ })
            if (($props -contains 1) -or ($props -contains 2)) {
                return $true
            }
        }

        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        if ($null -ne $cs -and $null -ne $cs.PSObject.Properties['HypervisorPresent'] -and [bool]$cs.HypervisorPresent) {
            return $true
        }

        return $false
    }
    catch {
        return $false
    }
}

function Test-BuiltInAdminSafeToDisable {
    <#
    .SYNOPSIS
        Verifies at least one other enabled local Administrator exists before disabling SID -500.
    #>
    [CmdletBinding()]
    param()

    try {
        try {
            $currSid = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
            if ($currSid -like '*-500') {
                return [PSCustomObject]@{
                    Safe   = $false
                    Reason = 'Currently signed in as the built-in Administrator (-500) account.'
                }
            }
        }
        catch { }

        $localUsers = @(Get-LocalUser -ErrorAction Stop)
        $disabledSids = @{}
        $disabledNames = @{}
        foreach ($u in $localUsers) {
            if (-not [bool]$u.Enabled) {
                $disabledSids[[string]$u.SID.Value] = $true
                $disabledNames[([string]$u.Name).ToLowerInvariant()] = $true
            }
        }

        $members = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
        $otherEnabledAdmins = 0
        foreach ($m in $members) {
            if ($null -ne $m.PSObject.Properties['ObjectClass'] -and [string]$m.ObjectClass -ne 'User') {
                continue
            }
            $sidVal = if ($null -ne $m.PSObject.Properties['SID'] -and $null -ne $m.SID) { [string]$m.SID.Value } else { '' }
            if ($sidVal -like '*-500') {
                continue
            }
            $shortName = (([string]$m.Name -split '\\')[-1]).ToLowerInvariant()
            if (($sidVal -and $disabledSids.ContainsKey($sidVal)) -or ($shortName -and $disabledNames.ContainsKey($shortName))) {
                continue
            }
            $otherEnabledAdmins++
        }

        if ($otherEnabledAdmins -ge 1) {
            return [PSCustomObject]@{
                Safe   = $true
                Reason = "$otherEnabledAdmins other enabled local Administrator account(s) verified."
            }
        }

        return [PSCustomObject]@{
            Safe   = $false
            Reason = 'No other enabled Administrator account found in S-1-5-32-544.'
        }
    }
    catch {
        return [PSCustomObject]@{
            Safe   = $false
            Reason = "Unable to verify alternate Administrator accounts ($($_.Exception.Message))."
        }
    }
}

function Get-RemediationPreview {
    <#
    .SYNOPSIS
        Returns a read-only preview list describing how each requested Control ID would be handled.

    .PARAMETER ControlIds
        Array or comma-separated list of catalog Control IDs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ControlIds
    )

    $normalizedIds = @()
    foreach ($item in $ControlIds) {
        if ($null -eq $item) { continue }
        foreach ($token in ($item -split ',')) {
            $trimmed = $token.Trim().ToUpperInvariant()
            if ($trimmed -ne '' -and ($normalizedIds -notcontains $trimmed)) {
                $normalizedIds += $trimmed
            }
        }
    }

    $previews = @()
    foreach ($id in $normalizedIds) {
        $def = Get-RemediationDefinition -ControlId $id
        if ($null -eq $def) {
            $previews += [PSCustomObject]@{
                ControlId         = $id
                Supported         = $false
                FixMode           = 'Unsupported'
                RequiresAdmin     = $false
                RequiresReboot    = $false
                RollbackSupported = $false
                Summary           = 'No remediation definition registered for this control.'
                PreviewCommands   = @()
                SettingsUri       = $null
            }
        }
        else {
            $previews += [PSCustomObject]@{
                ControlId         = [string]$def.ControlId
                Supported         = $true
                FixMode           = [string]$def.FixMode
                RequiresAdmin     = [bool]$def.RequiresAdmin
                RequiresReboot    = [bool]$def.RequiresReboot
                RollbackSupported = [bool]$def.RollbackSupported
                Summary           = [string]$def.Summary
                PreviewCommands   = @($def.PreviewCommands)
                SettingsUri       = $def.SettingsUri
            }
        }
    }

    return $previews
}

function Invoke-SecurityRemediation {
    <#
    .SYNOPSIS
        Executes selected security remediations with pre-change backup and closed-loop verification.

    .PARAMETER ControlIds
        One or more catalog Control IDs to remediate (supports comma-separated strings).

    .PARAMETER Catalogo
        Optional catalog object passed through to Invoke-Controlli for post-fix verification.

    .PARAMETER Ambiente
        Optional host environment snapshot passed through to Invoke-Controlli.

    .PARAMETER CartellaChecks
        Optional path to src/core/Checks used by Invoke-Controlli during re-check.

    .PARAMETER ScanResults
        Optional array of latest scan results providing live Evidence for Tier 3 Guided fixes.

    .PARAMETER BackupDirectory
        Optional directory where the rollback_*.json file is written.

    .PARAMETER CreateRestorePoint
        When specified and running as Administrator, creates a Windows System Restore point first.

    .PARAMETER WhatIfMode
        When specified, performs zero system or disk modifications and returns a dry-run preview.

    .PARAMETER OnProgress
        Optional scriptblock called after each control: receives ($CurrentIndex, $Total, $ItemResult).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ControlIds,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Catalogo = $null,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null,

        [Parameter(Mandatory = $false)]
        [string]$CartellaChecks = '',

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [array]$ScanResults = @(),

        [Parameter(Mandatory = $false)]
        [string]$BackupDirectory = '',

        [Parameter(Mandatory = $false)]
        [switch]$CreateRestorePoint,

        [Parameter(Mandatory = $false)]
        [switch]$WhatIfMode,

        [Parameter(Mandatory = $false)]
        [scriptblock]$OnProgress = $null
    )

    $normalizedIds = @()
    foreach ($item in $ControlIds) {
        if ($null -eq $item) { continue }
        foreach ($token in ($item -split ',')) {
            $trimmed = $token.Trim().ToUpperInvariant()
            if ($trimmed -ne '' -and ($normalizedIds -notcontains $trimmed)) {
                $normalizedIds += $trimmed
            }
        }
    }

    $totalRequested = $normalizedIds.Count
    $results = @()

    if ($WhatIfMode) {
        $previews = @(Get-RemediationPreview -ControlIds $normalizedIds)
        $idx = 0
        foreach ($preview in $previews) {
            $idx++
            $status = if (-not $preview.Supported) {
                'Unsupported'
            }
            elseif ($preview.FixMode -eq 'Manual') {
                'ManualOnly'
            }
            else {
                'WhatIf'
            }

            $itemResult = [PSCustomObject]@{
                ControlId         = $preview.ControlId
                Status            = $status
                Verified          = $false
                RequiresAdmin     = $preview.RequiresAdmin
                RequiresReboot    = $preview.RequiresReboot
                RollbackSupported = $preview.RollbackSupported
                SettingsUri       = $preview.SettingsUri
                Message           = $preview.Summary
                PostCheckStatus   = $null
                PostCheckObserved = $null
                Error             = $null
            }
            $results += $itemResult

            if ($null -ne $OnProgress) {
                & $OnProgress $idx $totalRequested $itemResult
            }
        }

        return [PSCustomObject]@{
            SessionId           = $null
            BackupPath          = $null
            RestorePointCreated = $false
            RestorePointMessage = 'Skipped in WhatIf mode.'
            WhatIf              = $true
            TotalRequested      = $totalRequested
            FixedCount          = 0
            AppliedCount        = 0
            RebootRequiredCount = 0
            BlockedCount        = 0
            FailedCount         = 0
            SkippedCount        = 0
            Results             = @($results)
        }
    }

    $session = New-RemediationBackupSession -BackupDirectory $BackupDirectory
    $isAdmin = Test-IsAdministrator

    $restorePointCreated = $false
    $restorePointMessage = 'Not requested.'
    if ($CreateRestorePoint) {
        if ($isAdmin) {
            $rp = New-ScannerRestorePoint
            $restorePointCreated = [bool]$rp.Success
            $restorePointMessage = [string]$rp.Message
            $session.RestorePointCreated = $restorePointCreated
        }
        else {
            $restorePointCreated = $false
            $restorePointMessage = 'Skipped: Administrator privileges are required to create a System Restore point.'
        }
    }

    $fixedCount          = 0
    $appliedCount        = 0
    $rebootRequiredCount = 0
    $blockedCount        = 0
    $failedCount         = 0
    $skippedCount        = 0
    $currentIndex        = 0

    $canRecheck = ($null -ne $Catalogo -and $null -ne $Ambiente -and $null -ne (Get-Command -Name 'Invoke-Controlli' -ErrorAction SilentlyContinue))

    $evidenceById = @{}
    if ($null -ne $ScanResults) {
        foreach ($sr in $ScanResults) {
            if ($null -eq $sr) { continue }
            $srId = if ($null -ne $sr.PSObject.Properties['control_id']) {
                [string]$sr.control_id
            }
            elseif ($null -ne $sr.PSObject.Properties['ControlId']) {
                [string]$sr.ControlId
            }
            else {
                ''
            }
            if ([string]::IsNullOrWhiteSpace($srId)) { continue }

            $srEv = if ($null -ne $sr.PSObject.Properties['evidence']) {
                $sr.evidence
            }
            elseif ($null -ne $sr.PSObject.Properties['Evidence']) {
                $sr.Evidence
            }
            else {
                $null
            }
            if ($null -ne $srEv) {
                $evidenceById[$srId.Trim().ToUpperInvariant()] = $srEv
            }
        }
    }

    foreach ($id in $normalizedIds) {
        $currentIndex++
        $def = Get-RemediationDefinition -ControlId $id
        $itemResult = $null

        if ($null -eq $def) {
            $skippedCount++
            $itemResult = [PSCustomObject]@{
                ControlId         = $id
                Status            = 'Unsupported'
                Verified          = $false
                RequiresAdmin     = $false
                RequiresReboot    = $false
                RollbackSupported = $false
                SettingsUri       = $null
                Message           = 'Control does not have an automated remediation in catalog.'
                PostCheckStatus   = $null
                PostCheckObserved = $null
                Error             = $null
            }
        }
        elseif (($def.FixMode -eq 'Manual') -or ($null -eq $def.Apply)) {
            $skippedCount++
            $itemResult = [PSCustomObject]@{
                ControlId         = $id
                Status            = 'ManualOnly'
                Verified          = $false
                RequiresAdmin     = [bool]$def.RequiresAdmin
                RequiresReboot    = [bool]$def.RequiresReboot
                RollbackSupported = $false
                SettingsUri       = $def.SettingsUri
                Message           = [string]$def.Summary
                PostCheckStatus   = $null
                PostCheckObserved = $null
                Error             = $null
            }
        }
        elseif ([bool]$def.RequiresAdmin -and (-not $isAdmin)) {
            $blockedCount++
            $itemResult = [PSCustomObject]@{
                ControlId         = $id
                Status            = 'RequiresAdmin'
                Verified          = $false
                RequiresAdmin     = $true
                RequiresReboot    = [bool]$def.RequiresReboot
                RollbackSupported = [bool]$def.RollbackSupported
                SettingsUri       = $def.SettingsUri
                Message           = 'Administrator privileges are required to apply this remediation.'
                PostCheckStatus   = $null
                PostCheckObserved = $null
                Error             = $null
            }
        }
        else {
            # Runtime safety guardrails prior to mutating system state
            $guardrailMsg = $null
            if ($id -eq 'HOME-RDP-001' -and (Test-IsRdpSession)) {
                $guardrailMsg = 'Guardrail triggered: cannot disable RDP while connected inside an active RDP session.'
            }
            elseif ($id -eq 'HOME-NET-006' -and (Test-IsWinRmSession)) {
                $guardrailMsg = 'Guardrail triggered: cannot stop WinRM from inside an active WinRM/PowerShell remote session.'
            }
            elseif ($id -eq 'HOME-SYS-004' -and (-not (Test-HvciSupported))) {
                $guardrailMsg = 'Guardrail triggered: hardware virtualization / VBS capability required for HVCI is not supported on this host.'
            }
            elseif ($id -eq 'HOME-ACC-002') {
                $adminGuard = Test-BuiltInAdminSafeToDisable
                if (-not [bool]$adminGuard.Safe) {
                    $guardrailMsg = "Lockout prevention: $($adminGuard.Reason)"
                }
            }

            if ($null -ne $guardrailMsg) {
                $blockedCount++
                $itemResult = [PSCustomObject]@{
                    ControlId         = $id
                    Status            = 'Blocked'
                    Verified          = $false
                    RequiresAdmin     = [bool]$def.RequiresAdmin
                    RequiresReboot    = [bool]$def.RequiresReboot
                    RollbackSupported = [bool]$def.RollbackSupported
                    SettingsUri       = $def.SettingsUri
                    Message           = $guardrailMsg
                    PostCheckStatus   = $null
                    PostCheckObserved = $null
                    Error             = $guardrailMsg
                }
            }
            else {
                try {
                    $ctrlEvidence = if ($evidenceById.ContainsKey($id)) { $evidenceById[$id] } else { $null }
                    if ($null -eq $ctrlEvidence -and $def.FixMode -eq 'Guided' -and $canRecheck) {
                        $preCheckArr = @(Invoke-Controlli -Catalogo $Catalogo -Ambiente $Ambiente -ControlId @($id) -CartellaChecks $CartellaChecks)
                        if ($preCheckArr.Count -gt 0 -and $null -ne $preCheckArr[0].PSObject.Properties['evidence']) {
                            $ctrlEvidence = $preCheckArr[0].evidence
                        }
                    }

                    $context = [PSCustomObject]@{
                        ControlId = $id
                        Ambiente  = $Ambiente
                        Evidence  = $ctrlEvidence
                    }
                    & $def.Apply $session $context

                    if ($canRecheck) {
                        $recheckArr = @(Invoke-Controlli -Catalogo $Catalogo -Ambiente $Ambiente -ControlId @($id) -CartellaChecks $CartellaChecks)
                        $recheck = if ($recheckArr.Count -gt 0) { $recheckArr[0] } else { $null }

                        if ($null -ne $recheck -and $recheck.status -eq 'superato') {
                            $fixedCount++
                            $okMsg = if ([bool]$def.RequiresReboot) {
                                'Remediation applied and compliant (restart Windows to ensure full runtime enforcement).'
                            }
                            else {
                                'Remediation applied and verified as compliant.'
                            }
                            $itemResult = [PSCustomObject]@{
                                ControlId         = $id
                                Status            = 'Fixed'
                                Verified          = $true
                                RequiresAdmin     = [bool]$def.RequiresAdmin
                                RequiresReboot    = [bool]$def.RequiresReboot
                                RollbackSupported = [bool]$def.RollbackSupported
                                SettingsUri       = $def.SettingsUri
                                Message           = $okMsg
                                PostCheckStatus   = [string]$recheck.status
                                PostCheckObserved = $recheck.observed
                                Error             = $null
                            }
                        }
                        elseif ([bool]$def.RequiresReboot) {
                            $rebootRequiredCount++
                            $postStatus = if ($null -ne $recheck) { [string]$recheck.status } else { 'sconosciuto' }
                            $postObs    = if ($null -ne $recheck) { $recheck.observed } else { $null }
                            $itemResult = [PSCustomObject]@{
                                ControlId         = $id
                                Status            = 'RebootRequired'
                                Verified          = $false
                                RequiresAdmin     = [bool]$def.RequiresAdmin
                                RequiresReboot    = $true
                                RollbackSupported = [bool]$def.RollbackSupported
                                SettingsUri       = $def.SettingsUri
                                Message           = 'Remediation applied; restart Windows to activate and verify.'
                                PostCheckStatus   = $postStatus
                                PostCheckObserved = $postObs
                                Error             = $null
                            }
                        }
                        else {
                            $failedCount++
                            $postStatus = if ($null -ne $recheck) { [string]$recheck.status } else { 'sconosciuto' }
                            $postObs    = if ($null -ne $recheck) { $recheck.observed } else { $null }
                            $itemResult = [PSCustomObject]@{
                                ControlId         = $id
                                Status            = 'VerificationFailed'
                                Verified          = $false
                                RequiresAdmin     = [bool]$def.RequiresAdmin
                                RequiresReboot    = $false
                                RollbackSupported = [bool]$def.RollbackSupported
                                SettingsUri       = $def.SettingsUri
                                Message           = "Remediation ran, but post-check returned status '$postStatus'."
                                PostCheckStatus   = $postStatus
                                PostCheckObserved = $postObs
                                Error             = if ($null -ne $recheck) { $recheck.error } else { $null }
                            }
                        }
                    }
                    elseif ([bool]$def.RequiresReboot) {
                        $rebootRequiredCount++
                        $itemResult = [PSCustomObject]@{
                            ControlId         = $id
                            Status            = 'RebootRequired'
                            Verified          = $false
                            RequiresAdmin     = [bool]$def.RequiresAdmin
                            RequiresReboot    = $true
                            RollbackSupported = [bool]$def.RollbackSupported
                            SettingsUri       = $def.SettingsUri
                            Message           = 'Remediation applied; system restart required to verify.'
                            PostCheckStatus   = $null
                            PostCheckObserved = $null
                            Error             = $null
                        }
                    }
                    else {
                        $appliedCount++
                        $itemResult = [PSCustomObject]@{
                            ControlId         = $id
                            Status            = 'Applied'
                            Verified          = $false
                            RequiresAdmin     = [bool]$def.RequiresAdmin
                            RequiresReboot    = $false
                            RollbackSupported = [bool]$def.RollbackSupported
                            SettingsUri       = $def.SettingsUri
                            Message           = 'Remediation applied (post-fix verification skipped: no catalog/environment supplied).'
                            PostCheckStatus   = $null
                            PostCheckObserved = $null
                            Error             = $null
                        }
                    }
                }
                catch {
                    $ex = $_.Exception
                    if ($ex -is [System.Management.Automation.CommandNotFoundException]) {
                        $skippedCount++
                        $itemResult = [PSCustomObject]@{
                            ControlId         = $id
                            Status            = 'Skipped'
                            Verified          = $false
                            RequiresAdmin     = [bool]$def.RequiresAdmin
                            RequiresReboot    = [bool]$def.RequiresReboot
                            RollbackSupported = [bool]$def.RollbackSupported
                            SettingsUri       = $def.SettingsUri
                            Message           = 'Required Windows command or module is unavailable on this host.'
                            PostCheckStatus   = $null
                            PostCheckObserved = $null
                            Error             = $ex.Message
                        }
                    }
                    elseif (
                        ($ex -is [System.UnauthorizedAccessException]) -or
                        ($ex -is [System.Security.SecurityException]) -or
                        ($ex.Message -match '(?i)access.*denied|accesso negato|tamper|group policy|managed by your organization|0x80070005')
                    ) {
                        $blockedCount++
                        $itemResult = [PSCustomObject]@{
                            ControlId         = $id
                            Status            = 'Blocked'
                            Verified          = $false
                            RequiresAdmin     = [bool]$def.RequiresAdmin
                            RequiresReboot    = [bool]$def.RequiresReboot
                            RollbackSupported = [bool]$def.RollbackSupported
                            SettingsUri       = $def.SettingsUri
                            Message           = 'Remediation blocked by Tamper Protection, Group Policy, or system permissions.'
                            PostCheckStatus   = $null
                            PostCheckObserved = $null
                            Error             = $ex.Message
                        }
                    }
                    else {
                        $failedCount++
                        $itemResult = [PSCustomObject]@{
                            ControlId         = $id
                            Status            = 'Failed'
                            Verified          = $false
                            RequiresAdmin     = [bool]$def.RequiresAdmin
                            RequiresReboot    = [bool]$def.RequiresReboot
                            RollbackSupported = [bool]$def.RollbackSupported
                            SettingsUri       = $def.SettingsUri
                            Message           = 'Remediation failed with an unexpected error.'
                            PostCheckStatus   = $null
                            PostCheckObserved = $null
                            Error             = $ex.Message
                        }
                    }
                }
            }
        }

        $results += $itemResult
        if ($null -ne $OnProgress) {
            & $OnProgress $currentIndex $totalRequested $itemResult
        }
    }

    $savedBackupPath = if (@($session.Entries).Count -gt 0) {
        Save-RemediationBackupSession -Session $session
    }
    else {
        $null
    }

    return [PSCustomObject]@{
        SessionId           = [string]$session.SessionId
        BackupPath          = $savedBackupPath
        RestorePointCreated = $restorePointCreated
        RestorePointMessage = $restorePointMessage
        WhatIf              = $false
        TotalRequested      = $totalRequested
        FixedCount          = $fixedCount
        AppliedCount        = $appliedCount
        RebootRequiredCount = $rebootRequiredCount
        BlockedCount        = $blockedCount
        FailedCount         = $failedCount
        SkippedCount        = $skippedCount
        Results             = @($results)
    }
}
