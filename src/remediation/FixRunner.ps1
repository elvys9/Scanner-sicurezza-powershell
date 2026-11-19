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
            try {
                $context = [PSCustomObject]@{
                    ControlId = $id
                    Ambiente  = $Ambiente
                }
                & $def.Apply $session $context

                if ([bool]$def.RequiresReboot) {
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
                elseif ($canRecheck) {
                    $recheckArr = @(Invoke-Controlli -Catalogo $Catalogo -Ambiente $Ambiente -ControlId @($id) -CartellaChecks $CartellaChecks)
                    $recheck = if ($recheckArr.Count -gt 0) { $recheckArr[0] } else { $null }

                    if ($null -ne $recheck -and $recheck.status -eq 'superato') {
                        $fixedCount++
                        $itemResult = [PSCustomObject]@{
                            ControlId         = $id
                            Status            = 'Fixed'
                            Verified          = $true
                            RequiresAdmin     = [bool]$def.RequiresAdmin
                            RequiresReboot    = $false
                            RollbackSupported = [bool]$def.RollbackSupported
                            SettingsUri       = $def.SettingsUri
                            Message           = 'Remediation applied and verified as compliant.'
                            PostCheckStatus   = [string]$recheck.status
                            PostCheckObserved = $recheck.observed
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
