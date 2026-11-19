<#
.SYNOPSIS
    Backup and rollback manager for Windows 11 Security Scanner remediations.

.DESCRIPTION
    Captures pre-remediation state for registry values and Microsoft Defender preferences,
    applies changes atomically via read-before-write backup wrappers, persists timestamped
    JSON rollback sessions, optionally creates a Windows System Restore point, and restores
    original state in reverse chronological order.
#>

Set-StrictMode -Version 2

function Get-DefaultBackupDirectory {
    <#
    .SYNOPSIS
        Returns the default local directory used to store remediation rollback JSON files.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $baseDir = if (-not [string]::IsNullOrWhiteSpace($env:LOCALAPPDATA)) {
        $env:LOCALAPPDATA
    }
    elseif (-not [string]::IsNullOrWhiteSpace($env:TEMP)) {
        $env:TEMP
    }
    else {
        '.'
    }

    return (Join-Path $baseDir 'Win11SecurityScanner\backups')
}

function New-RemediationBackupSession {
    <#
    .SYNOPSIS
        Initializes an in-memory remediation backup session metadata object.

    .PARAMETER BackupDirectory
        Optional directory where the rollback JSON file will be written.

    .PARAMETER SessionId
        Optional explicit session identifier.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$BackupDirectory = '',

        [Parameter(Mandatory = $false)]
        [string]$SessionId = ''
    )

    $resolvedId = if (-not [string]::IsNullOrWhiteSpace($SessionId)) {
        $SessionId.Trim()
    }
    else {
        "$((Get-Date).ToString('yyyyMMdd_HHmmss'))_$([guid]::NewGuid().ToString('N').Substring(0, 6))"
    }

    $resolvedDir = if (-not [string]::IsNullOrWhiteSpace($BackupDirectory)) {
        $BackupDirectory.Trim()
    }
    else {
        Get-DefaultBackupDirectory
    }

    return [PSCustomObject]@{
        SchemaVersion       = '1.0'
        SessionId           = $resolvedId
        CreatedAt           = (Get-Date).ToString('o')
        ComputerName        = [string]$env:COMPUTERNAME
        UserName            = [string]$env:USERNAME
        BackupPath          = (Join-Path $resolvedDir "rollback_$resolvedId.json")
        RestorePointCreated = $false
        Entries             = @()
    }
}

function Backup-RegistryValueState {
    <#
    .SYNOPSIS
        Captures the current existence, registry value kind, and data of a registry value.

    .PARAMETER Path
        PowerShell registry path (e.g., 'HKLM:\SOFTWARE\...').

    .PARAMETER Name
        Registry value name to inspect.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return [PSCustomObject]@{
            Type          = 'RegistryValue'
            Path          = $Path
            Name          = $Name
            KeyExisted    = $false
            ValueExisted  = $false
            ValueType     = $null
            OriginalValue = $null
        }
    }

    $props = Get-ItemProperty -LiteralPath $Path -ErrorAction Stop
    if ($null -ne $props -and $null -ne $props.PSObject.Properties[$Name]) {
        $originalVal = $props.$Name
        $valueType = 'String'

        if ($originalVal -is [int] -or $originalVal -is [uint32] -or $originalVal -is [int64] -or $originalVal -is [bool]) {
            $valueType = 'DWord'
        }
        elseif ($originalVal -is [byte[]]) {
            $valueType = 'Binary'
        }
        elseif ($originalVal -is [string[]]) {
            $valueType = 'MultiString'
        }

        try {
            $regItem = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
            if ($null -ne $regItem -and $null -ne $regItem.PSObject.Methods['GetValueKind']) {
                $kind = $regItem.GetValueKind($Name)
                if ($null -ne $kind) {
                    $valueType = $kind.ToString()
                }
            }
        }
        catch {
            # Keep inferred .NET type when registry provider GetValueKind is unavailable (e.g., mocked objects)
        }

        return [PSCustomObject]@{
            Type          = 'RegistryValue'
            Path          = $Path
            Name          = $Name
            KeyExisted    = $true
            ValueExisted  = $true
            ValueType     = $valueType
            OriginalValue = $originalVal
        }
    }

    return [PSCustomObject]@{
        Type          = 'RegistryValue'
        Path          = $Path
        Name          = $Name
        KeyExisted    = $true
        ValueExisted  = $false
        ValueType     = $null
        OriginalValue = $null
    }
}

function Backup-DefenderPreferenceState {
    <#
    .SYNOPSIS
        Captures the current integer or boolean state of a supported Microsoft Defender preference property.

    .PARAMETER PropertyName
        Name of the preference property on Get-MpPreference output.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    $pref = Get-MpPreference -ErrorAction Stop
    if ($null -eq $pref -or $null -eq $pref.PSObject.Properties[$PropertyName]) {
        throw "Defender preference property '$PropertyName' was not found on Get-MpPreference output."
    }

    $boolProps = @('DisableRealtimeMonitoring', 'DisableBehaviorMonitoring', 'DisableIOAVProtection')
    if ($boolProps -contains $PropertyName) {
        return [PSCustomObject]@{
            Type          = 'DefenderPreference'
            PropertyName  = $PropertyName
            ValueKind     = 'Bool'
            OriginalValue = [bool]$pref.$PropertyName
        }
    }

    return [PSCustomObject]@{
        Type          = 'DefenderPreference'
        PropertyName  = $PropertyName
        ValueKind     = 'Int'
        OriginalValue = [int]$pref.$PropertyName
    }
}

function Add-RemediationBackupEntry {
    <#
    .SYNOPSIS
        Appends a captured state entry to a backup session while deduplicating identical targets.

    .DESCRIPTION
        Preserves the first captured pre-session state if the same registry value, Defender
        preference, service, firewall profile, or user account is modified multiple times within
        a single remediation session.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Session,

        [Parameter(Mandatory = $true)]
        [string]$ControlId,

        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Entry
    )

    $existingEntries = @($Session.Entries)
    foreach ($existing in $existingEntries) {
        if ($existing.Type -ne $Entry.Type) {
            continue
        }

        switch ($Entry.Type) {
            'RegistryValue' {
                if (($existing.Path -eq $Entry.Path) -and ($existing.Name -eq $Entry.Name)) { return }
            }
            'DefenderPreference' {
                if ($existing.PropertyName -eq $Entry.PropertyName) { return }
            }
            'DefenderAsrRules' { return }
            'FirewallProfile' {
                if ($existing.ProfileName -eq $Entry.ProfileName) { return }
            }
            'ServiceConfig' {
                if ($existing.ServiceName -eq $Entry.ServiceName) { return }
            }
            'ExecutionPolicy' {
                if ($existing.Scope -eq $Entry.Scope) { return }
            }
            'OptionalFeature' {
                if ($existing.FeatureName -eq $Entry.FeatureName) { return }
            }
            'AccountLockoutPolicy' { return }
            'LocalUser' {
                $matchSid  = ($existing.SID -and $Entry.SID -and ($existing.SID -eq $Entry.SID))
                $matchName = ($existing.Name -and $Entry.Name -and ($existing.Name -eq $Entry.Name))
                if ($matchSid -or $matchName) { return }
            }
            'WifiAutoConnect' {
                if ($existing.ProfileName -eq $Entry.ProfileName) { return }
            }
        }
    }

    $cloned = [PSCustomObject]@{}
    foreach ($prop in $Entry.PSObject.Properties) {
        Add-Member -InputObject $cloned -MemberType NoteProperty -Name $prop.Name -Value $prop.Value
    }
    Add-Member -InputObject $cloned -MemberType NoteProperty -Name 'ControlId' -Value $ControlId -Force
    Add-Member -InputObject $cloned -MemberType NoteProperty -Name 'CapturedAt' -Value ((Get-Date).ToString('o')) -Force

    $Session.Entries = @($existingEntries) + @($cloned)
}

function Set-RegistryValueWithBackup {
    <#
    .SYNOPSIS
        Safely creates missing parent registry keys, records original state, and sets a registry value.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $false)]
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord')]
        [string]$PropertyType = 'DWord',

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$BackupSession = $null,

        [Parameter(Mandatory = $false)]
        [string]$ControlId = ''
    )

    if ($null -ne $BackupSession) {
        $snapshot = Backup-RegistryValueState -Path $Path -Name $Name
        Add-RemediationBackupEntry -Session $BackupSession -ControlId $ControlId -Entry $snapshot
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force -ErrorAction Stop | Out-Null
    }

    New-ItemProperty -LiteralPath $Path -Name $Name -Value $Value -PropertyType $PropertyType -Force -ErrorAction Stop | Out-Null
}

function Set-DefenderPreferenceWithBackup {
    <#
    .SYNOPSIS
        Records the original Microsoft Defender preference state and applies a supported target mode.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet(
            'PUAProtection',
            'EnableNetworkProtection',
            'EnableControlledFolderAccess',
            'DisableRealtimeMonitoring',
            'DisableBehaviorMonitoring',
            'DisableIOAVProtection'
        )]
        [string]$PropertyName,

        [Parameter(Mandatory = $true)]
        [object]$TargetValue,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$BackupSession = $null,

        [Parameter(Mandatory = $false)]
        [string]$ControlId = ''
    )

    if ($null -ne $BackupSession) {
        $snapshot = Backup-DefenderPreferenceState -PropertyName $PropertyName
        Add-RemediationBackupEntry -Session $BackupSession -ControlId $ControlId -Entry $snapshot
    }

    switch ($PropertyName) {
        'PUAProtection'                { Set-MpPreference -PUAProtection ([string]$TargetValue) -ErrorAction Stop }
        'EnableNetworkProtection'      { Set-MpPreference -EnableNetworkProtection ([string]$TargetValue) -ErrorAction Stop }
        'EnableControlledFolderAccess' { Set-MpPreference -EnableControlledFolderAccess ([string]$TargetValue) -ErrorAction Stop }
        'DisableRealtimeMonitoring'    { Set-MpPreference -DisableRealtimeMonitoring ([bool]$TargetValue) -ErrorAction Stop }
        'DisableBehaviorMonitoring'    { Set-MpPreference -DisableBehaviorMonitoring ([bool]$TargetValue) -ErrorAction Stop }
        'DisableIOAVProtection'        { Set-MpPreference -DisableIOAVProtection ([bool]$TargetValue) -ErrorAction Stop }
    }
}

function Set-DefenderAsrRulesWithBackup {
    <#
    .SYNOPSIS
        Backs up current Attack Surface Reduction (ASR) rules and enables the specified ASR rule IDs.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$RuleIds,

        [Parameter(Mandatory = $true)]
        [string[]]$Actions,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$BackupSession = $null,

        [Parameter(Mandatory = $false)]
        [string]$ControlId = ''
    )

    if ($null -ne $BackupSession) {
        $pref = Get-MpPreference -ErrorAction Stop
        $origIds = @(if ($null -ne $pref -and $null -ne $pref.PSObject.Properties['AttackSurfaceReductionRules_Ids'] -and $null -ne $pref.AttackSurfaceReductionRules_Ids) {
            $pref.AttackSurfaceReductionRules_Ids | ForEach-Object { [string]$_ }
        })
        $origActs = @(if ($null -ne $pref -and $null -ne $pref.PSObject.Properties['AttackSurfaceReductionRules_Actions'] -and $null -ne $pref.AttackSurfaceReductionRules_Actions) {
            $pref.AttackSurfaceReductionRules_Actions | ForEach-Object { [string]$_ }
        })

        Add-RemediationBackupEntry -Session $BackupSession -ControlId $ControlId -Entry ([PSCustomObject]@{
            Type            = 'DefenderAsrRules'
            OriginalIds     = @($origIds)
            OriginalActions = @($origActs)
            AppliedIds      = @($RuleIds)
        })
    }

    Add-MpPreference -AttackSurfaceReductionRules_Ids $RuleIds -AttackSurfaceReductionRules_Actions $Actions -ErrorAction Stop
}

function Invoke-NetAccounts {
    <#
    .SYNOPSIS
        Thin wrapper around net.exe accounts to allow clean Pester mocking without calling external binaries in unit tests.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$Arguments = @()
    )

    $output = & net.exe accounts @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "net.exe accounts exited with code ${LASTEXITCODE}: $($output -join ' ')"
    }
    return $output
}

function Invoke-NetshWlan {
    <#
    .SYNOPSIS
        Thin wrapper around netsh.exe to allow clean Pester mocking for WLAN profile remediation and rollback.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $output = & netsh.exe @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "netsh.exe failed with exit code ${LASTEXITCODE}: $($output -join ' ')"
    }
    return $output
}

function Set-FirewallProfileWithBackup {
    <#
    .SYNOPSIS
        Captures original firewall profile states and enforces Enabled + DefaultInboundAction per profile.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string[]]$Profiles = @('Domain', 'Private', 'Public'),

        [Parameter(Mandatory = $false)]
        [string]$Enabled = 'True',

        [Parameter(Mandatory = $false)]
        [string]$DefaultInboundAction = 'Block',

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$BackupSession = $null,

        [Parameter(Mandatory = $false)]
        [string]$ControlId = ''
    )

    foreach ($profName in $Profiles) {
        if ($null -ne $BackupSession) {
            $cur = Get-NetFirewallProfile -Name $profName -ErrorAction Stop
            $origEnabled = if ($cur.Enabled -is [bool]) { [string]$cur.Enabled } else { [string]$cur.Enabled }
            $origInbound = if ($null -ne $cur.PSObject.Properties['DefaultInboundAction'] -and $null -ne $cur.DefaultInboundAction) {
                [string]$cur.DefaultInboundAction
            }
            else {
                'NotConfigured'
            }

            Add-RemediationBackupEntry -Session $BackupSession -ControlId $ControlId -Entry ([PSCustomObject]@{
                Type                        = 'FirewallProfile'
                ProfileName                 = $profName
                OriginalEnabled             = $origEnabled
                OriginalDefaultInboundAction = $origInbound
            })
        }

        Set-NetFirewallProfile -Name $profName -Enabled $Enabled -DefaultInboundAction $DefaultInboundAction -ErrorAction Stop
    }
}

function Set-ServiceStartupWithBackup {
    <#
    .SYNOPSIS
        Records a Windows service Start registry value and runtime status, then sets target Start mode and state.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServiceName,

        [Parameter(Mandatory = $true)]
        [ValidateSet(2, 3, 4)]
        [int]$TargetStart,

        [Parameter(Mandatory = $false)]
        [switch]$StopService,

        [Parameter(Mandatory = $false)]
        [switch]$StartService,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$BackupSession = $null,

        [Parameter(Mandatory = $false)]
        [string]$ControlId = ''
    )

    $svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"
    if (-not (Test-Path -LiteralPath $svcRegPath)) {
        throw "Service registry key not found: $svcRegPath"
    }

    $props = Get-ItemProperty -LiteralPath $svcRegPath -ErrorAction Stop
    $origStart = if ($null -ne $props -and $null -ne $props.PSObject.Properties['Start'] -and $null -ne $props.Start) {
        [int]$props.Start
    }
    else {
        3
    }

    $svcObj = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    $origStatus = if ($null -ne $svcObj) { [string]$svcObj.Status } else { 'Stopped' }

    if ($null -ne $BackupSession) {
        Add-RemediationBackupEntry -Session $BackupSession -ControlId $ControlId -Entry ([PSCustomObject]@{
            Type           = 'ServiceConfig'
            ServiceName    = $ServiceName
            RegistryPath   = $svcRegPath
            OriginalStart  = $origStart
            OriginalStatus = $origStatus
        })
    }

    New-ItemProperty -LiteralPath $svcRegPath -Name 'Start' -Value $TargetStart -PropertyType 'DWord' -Force -ErrorAction Stop | Out-Null

    if ($StopService -and $null -ne $svcObj -and [string]$svcObj.Status -eq 'Running') {
        Stop-Service -Name $ServiceName -Force -ErrorAction Stop
    }
    elseif ($StartService -and $null -ne $svcObj -and [string]$svcObj.Status -ne 'Running') {
        Start-Service -Name $ServiceName -ErrorAction Stop
    }
}

function Set-ExecutionPolicyWithBackup {
    <#
    .SYNOPSIS
        Captures the current PowerShell ExecutionPolicy for a scope and applies the target policy.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$Scope,

        [Parameter(Mandatory = $true)]
        [string]$ExecutionPolicy,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$BackupSession = $null,

        [Parameter(Mandatory = $false)]
        [string]$ControlId = ''
    )

    if ($null -ne $BackupSession) {
        $list = @(Get-ExecutionPolicy -List -ErrorAction Stop)
        $origPolicy = 'Undefined'
        foreach ($entry in $list) {
            if ([string]$entry.Scope -eq $Scope) {
                $origPolicy = [string]$entry.ExecutionPolicy
                break
            }
        }

        Add-RemediationBackupEntry -Session $BackupSession -ControlId $ControlId -Entry ([PSCustomObject]@{
            Type           = 'ExecutionPolicy'
            Scope          = $Scope
            OriginalPolicy = $origPolicy
        })
    }

    Set-ExecutionPolicy -Scope $Scope -ExecutionPolicy $ExecutionPolicy -Force -ErrorAction Stop
}

function Disable-OptionalFeatureWithBackup {
    <#
    .SYNOPSIS
        Captures the current DISM optional feature state and disables the feature when enabled.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FeatureName,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$BackupSession = $null,

        [Parameter(Mandatory = $false)]
        [string]$ControlId = ''
    )

    if ($null -eq (Get-Command -Name 'Get-WindowsOptionalFeature' -ErrorAction SilentlyContinue)) {
        return
    }

    $feature = Get-WindowsOptionalFeature -Online -FeatureName $FeatureName -ErrorAction Stop
    if ($null -eq $feature) {
        return
    }

    $stateStr = [string]$feature.State
    if ($null -ne $BackupSession) {
        Add-RemediationBackupEntry -Session $BackupSession -ControlId $ControlId -Entry ([PSCustomObject]@{
            Type          = 'OptionalFeature'
            FeatureName   = $FeatureName
            OriginalState = $stateStr
        })
    }

    if ($stateStr -eq 'Enabled') {
        Disable-WindowsOptionalFeature -Online -FeatureName $FeatureName -NoRestart -ErrorAction Stop | Out-Null
    }
}

function Set-AccountLockoutPolicyWithBackup {
    <#
    .SYNOPSIS
        Captures current net accounts lockout thresholds and applies brute-force protection limits.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [int]$Threshold = 5,

        [Parameter(Mandatory = $false)]
        [int]$Duration = 15,

        [Parameter(Mandatory = $false)]
        [int]$Window = 15,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$BackupSession = $null,

        [Parameter(Mandatory = $false)]
        [string]$ControlId = ''
    )

    if ($null -ne $BackupSession) {
        $lines = @(Invoke-NetAccounts -Arguments @())
        $origThreshold = 0
        $origDuration  = 0
        $origWindow    = 0

        foreach ($line in $lines) {
            if ($line -match '(?i)(Lockout threshold|Soglia di blocco|Kontosperrungsschwelle)\s*:\s*(.+)$') {
                $valTxt = $Matches[2].Trim()
                if ($valTxt -match '^\d+$') { $origThreshold = [int]$valTxt }
            }
            elseif ($line -match '(?i)(Lockout duration|Durata del blocco|Sperrdauer)\s*:\s*(\d+)') {
                $origDuration = [int]$Matches[2]
            }
            elseif ($line -match '(?i)(Lockout observation window|Finestra di osservazione|Beobachtungsfenster)\s*:\s*(\d+)') {
                $origWindow = [int]$Matches[2]
            }
        }

        Add-RemediationBackupEntry -Session $BackupSession -ControlId $ControlId -Entry ([PSCustomObject]@{
            Type              = 'AccountLockoutPolicy'
            OriginalThreshold = $origThreshold
            OriginalDuration  = $origDuration
            OriginalWindow    = $origWindow
        })
    }

    [void](Invoke-NetAccounts -Arguments @("/lockoutthreshold:$Threshold", "/lockoutduration:$Duration", "/lockoutwindow:$Window"))
}

function Disable-LocalUserWithBackup {
    <#
    .SYNOPSIS
        Captures the enabled state of a local user matching the specified SID suffix and disables it.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SidSuffix,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$BackupSession = $null,

        [Parameter(Mandatory = $false)]
        [string]$ControlId = ''
    )

    $user = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -like "*$SidSuffix" } | Select-Object -First 1
    if ($null -eq $user) {
        throw "No local user account matching SID suffix '$SidSuffix' was found."
    }

    if ($null -ne $BackupSession) {
        Add-RemediationBackupEntry -Session $BackupSession -ControlId $ControlId -Entry ([PSCustomObject]@{
            Type            = 'LocalUser'
            Name            = [string]$user.Name
            SID             = [string]$user.SID.Value
            OriginalEnabled = [bool]$user.Enabled
        })
    }

    if ([bool]$user.Enabled) {
        Disable-LocalUser -SID $user.SID.Value -ErrorAction Stop
    }
}

function Set-WifiProfileManualWithBackup {
    <#
    .SYNOPSIS
        Validates a WLAN profile SSID strictly, records its AutoConnect state, and switches it to manual.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ProfileName,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$BackupSession = $null,

        [Parameter(Mandatory = $false)]
        [string]$ControlId = ''
    )

    if ([string]::IsNullOrWhiteSpace($ProfileName)) {
        throw 'Wi-Fi profile name cannot be empty.'
    }

    $cleanName = $ProfileName.Trim()
    if ($cleanName -match '["''`;|&<>$\x00-\x1F\x7F]') {
        throw "Rejected unsafe characters in Wi-Fi profile name: '$cleanName'."
    }

    if ($null -ne $BackupSession) {
        Add-RemediationBackupEntry -Session $BackupSession -ControlId $ControlId -Entry ([PSCustomObject]@{
            Type                   = 'WifiAutoConnect'
            ProfileName            = $cleanName
            OriginalConnectionMode = 'auto'
        })
    }

    [void](Invoke-NetshWlan -Arguments @('wlan', 'set', 'profileparameter', "name=$cleanName", 'connectionmode=manual'))
}

function ConvertTo-QuotedServicePath {
    <#
    .SYNOPSIS
        Wraps an unquoted Windows service executable path containing spaces in double quotes
        while preserving any trailing command-line arguments outside the quotes.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$PathName = ''
    )

    if ([string]::IsNullOrWhiteSpace($PathName)) {
        return $null
    }

    $trimmed = $PathName.Trim()
    if ($trimmed.StartsWith('"')) {
        return $null
    }

    if ($trimmed -match '^(?i)(.+?\.exe)(\s+.*)?$') {
        $exePart  = $Matches[1].Trim()
        $argsPart = if ($null -ne $Matches[2]) { $Matches[2] } else { '' }
        if ($exePart -notmatch '\s') {
            return $null
        }
        return ('"' + $exePart + '"' + $argsPart)
    }

    return $null
}

function Save-RemediationBackupSession {
    <#
    .SYNOPSIS
        Persists a remediation backup session object to disk as UTF-8 JSON.

    .PARAMETER Session
        Backup session object returned by New-RemediationBackupSession.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Session
    )

    $parentDir = [System.IO.Path]::GetDirectoryName($Session.BackupPath)
    if (-not [string]::IsNullOrWhiteSpace($parentDir) -and (-not ([System.IO.Directory]::Exists($parentDir)))) {
        [System.IO.Directory]::CreateDirectory($parentDir) | Out-Null
    }

    $json = $Session | ConvertTo-Json -Depth 10
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Session.BackupPath, $json, $utf8NoBom)

    return $Session.BackupPath
}

function New-ScannerRestorePoint {
    <#
    .SYNOPSIS
        Attempts to create a Windows System Restore point prior to applying remediations.

    .PARAMETER Description
        Restore point description shown in Windows System Restore.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Description = 'Win11SecurityScanner Pre-Remediation Snapshot'
    )

    try {
        Checkpoint-Computer -Description $Description -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
        return [PSCustomObject]@{
            Success = $true
            Message = "System Restore point '$Description' created successfully."
        }
    }
    catch {
        return [PSCustomObject]@{
            Success = $false
            Message = $_.Exception.Message
        }
    }
}

function Restore-RemediationBackup {
    <#
    .SYNOPSIS
        Rolls back system settings from a saved remediation JSON backup file in reverse order.

    .PARAMETER BackupPath
        Path to a rollback_*.json file written by Save-RemediationBackupSession.

    .PARAMETER ControlId
        Optional subset of control IDs to restore; when omitted, restores all entries in the file.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BackupPath,

        [Parameter(Mandatory = $false)]
        [string[]]$ControlId = @()
    )

    if (-not ([System.IO.File]::Exists($BackupPath))) {
        throw "Backup file not found: $BackupPath"
    }

    $rawJson = [System.IO.File]::ReadAllText($BackupPath, [System.Text.Encoding]::UTF8)
    $data = $rawJson | ConvertFrom-Json

    $sessionId = if ($null -ne $data.PSObject.Properties['SessionId'] -and $null -ne $data.SessionId) {
        [string]$data.SessionId
    }
    else {
        ''
    }

    $rawEntries = @(if ($null -ne $data.PSObject.Properties['Entries'] -and $null -ne $data.Entries) {
        $data.Entries
    })

    $filterIds = @()
    if ($null -ne $ControlId) {
        foreach ($item in $ControlId) {
            if ($null -eq $item) { continue }
            foreach ($token in ($item -split ',')) {
                $trimmed = $token.Trim()
                if ($trimmed -ne '') {
                    $filterIds += $trimmed
                }
            }
        }
    }

    $selectedEntries = @(if ($filterIds.Count -gt 0) {
        @($rawEntries | Where-Object { $filterIds -contains $_.ControlId })
    }
    else {
        $rawEntries
    })

    # Iterate in reverse order to cleanly unwind multi-step changes
    $orderedEntries = @()
    for ($idx = $selectedEntries.Count - 1; $idx -ge 0; $idx--) {
        $orderedEntries += $selectedEntries[$idx]
    }

    $results = @()
    $restoredCount = 0
    $failedCount = 0

    $defenderIntMap = @{
        0 = 'Disabled'
        1 = 'Enabled'
        2 = 'AuditMode'
    }

    $asrCodeMap = @{
        '0' = 'Disabled'
        '1' = 'Enabled'
        '2' = 'AuditMode'
        '6' = 'Warn'
    }

    foreach ($entry in $orderedEntries) {
        $entryControlId = if ($null -ne $entry.PSObject.Properties['ControlId']) { [string]$entry.ControlId } else { '' }
        $entryType = if ($null -ne $entry.PSObject.Properties['Type']) { [string]$entry.Type } else { '' }
        $targetDesc = $entryType

        try {
            if ($entryType -eq 'RegistryValue') {
                $targetDesc = "$($entry.Path)\$($entry.Name)"
                $valueExisted = ($null -ne $entry.PSObject.Properties['ValueExisted'] -and [bool]$entry.ValueExisted)
                if ($valueExisted) {
                    if (-not (Test-Path -LiteralPath $entry.Path)) {
                        New-Item -Path $entry.Path -Force -ErrorAction Stop | Out-Null
                    }

                    $propType = if ($null -ne $entry.PSObject.Properties['ValueType'] -and -not [string]::IsNullOrWhiteSpace([string]$entry.ValueType)) {
                        [string]$entry.ValueType
                    }
                    else {
                        'DWord'
                    }

                    New-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -Value $entry.OriginalValue -PropertyType $propType -Force -ErrorAction Stop | Out-Null
                }
                else {
                    if (Test-Path -LiteralPath $entry.Path) {
                        Remove-ItemProperty -LiteralPath $entry.Path -Name $entry.Name -ErrorAction SilentlyContinue
                    }
                }
            }
            elseif ($entryType -eq 'DefenderPreference') {
                $targetDesc = [string]$entry.PropertyName
                $isBool = ($null -ne $entry.PSObject.Properties['ValueKind'] -and [string]$entry.ValueKind -eq 'Bool') -or ($entry.OriginalValue -is [bool])

                if ($isBool) {
                    $origBool = [bool]$entry.OriginalValue
                    switch ($entry.PropertyName) {
                        'DisableRealtimeMonitoring' { Set-MpPreference -DisableRealtimeMonitoring $origBool -ErrorAction Stop }
                        'DisableBehaviorMonitoring' { Set-MpPreference -DisableBehaviorMonitoring $origBool -ErrorAction Stop }
                        'DisableIOAVProtection'     { Set-MpPreference -DisableIOAVProtection $origBool -ErrorAction Stop }
                        default { throw "Unsupported boolean Defender preference property: $($entry.PropertyName)" }
                    }
                }
                else {
                    $origInt = [int]$entry.OriginalValue
                    if (-not $defenderIntMap.ContainsKey($origInt)) {
                        throw "Unsupported original Defender value '$origInt' for property '$($entry.PropertyName)'."
                    }
                    $targetMode = $defenderIntMap[$origInt]

                    switch ($entry.PropertyName) {
                        'PUAProtection'                { Set-MpPreference -PUAProtection $targetMode -ErrorAction Stop }
                        'EnableNetworkProtection'      { Set-MpPreference -EnableNetworkProtection $targetMode -ErrorAction Stop }
                        'EnableControlledFolderAccess' { Set-MpPreference -EnableControlledFolderAccess $targetMode -ErrorAction Stop }
                        default { throw "Unsupported Defender preference property for rollback: $($entry.PropertyName)" }
                    }
                }
            }
            elseif ($entryType -eq 'DefenderAsrRules') {
                $targetDesc = 'AttackSurfaceReductionRules'
                $origIds = @(if ($null -ne $entry.PSObject.Properties['OriginalIds'] -and $null -ne $entry.OriginalIds) {
                    $entry.OriginalIds | ForEach-Object { [string]$_ }
                })

                $origActs = @(if ($null -ne $entry.PSObject.Properties['OriginalActions'] -and $null -ne $entry.OriginalActions) {
                    $entry.OriginalActions | ForEach-Object {
                        $s = [string]$_
                        if ($asrCodeMap.ContainsKey($s)) { $asrCodeMap[$s] } else { $s }
                    }
                })

                if ($origIds.Count -gt 0 -and $origIds.Count -eq $origActs.Count) {
                    Set-MpPreference -AttackSurfaceReductionRules_Ids $origIds -AttackSurfaceReductionRules_Actions $origActs -ErrorAction Stop
                }
                elseif ($null -ne $entry.PSObject.Properties['AppliedIds'] -and $null -ne $entry.AppliedIds) {
                    $appliedIdList = @($entry.AppliedIds | ForEach-Object { [string]$_ })
                    if ($appliedIdList.Count -gt 0) {
                        Remove-MpPreference -AttackSurfaceReductionRules_Ids $appliedIdList -ErrorAction Stop
                    }
                }
            }
            elseif ($entryType -eq 'FirewallProfile') {
                $targetDesc = "Firewall:$($entry.ProfileName)"
                $origIn = if ($null -ne $entry.PSObject.Properties['OriginalDefaultInboundAction'] -and -not [string]::IsNullOrWhiteSpace([string]$entry.OriginalDefaultInboundAction)) {
                    [string]$entry.OriginalDefaultInboundAction
                }
                else { 'NotConfigured' }
                Set-NetFirewallProfile -Name ([string]$entry.ProfileName) -Enabled ([string]$entry.OriginalEnabled) -DefaultInboundAction $origIn -ErrorAction Stop
            }
            elseif ($entryType -eq 'ServiceConfig') {
                $targetDesc = "Service:$($entry.ServiceName)"
                $svcRegPath = [string]$entry.RegistryPath
                if (Test-Path -LiteralPath $svcRegPath) {
                    New-ItemProperty -LiteralPath $svcRegPath -Name 'Start' -Value ([int]$entry.OriginalStart) -PropertyType 'DWord' -Force -ErrorAction Stop | Out-Null
                }
                $origStat = if ($null -ne $entry.PSObject.Properties['OriginalStatus']) { [string]$entry.OriginalStatus } else { '' }
                if ($origStat -eq 'Running') {
                    Start-Service -Name ([string]$entry.ServiceName) -ErrorAction SilentlyContinue
                }
                elseif ($origStat -eq 'Stopped') {
                    Stop-Service -Name ([string]$entry.ServiceName) -Force -ErrorAction SilentlyContinue
                }
            }
            elseif ($entryType -eq 'ExecutionPolicy') {
                $targetDesc = "ExecutionPolicy:$($entry.Scope)"
                Set-ExecutionPolicy -Scope ([string]$entry.Scope) -ExecutionPolicy ([string]$entry.OriginalPolicy) -Force -ErrorAction Stop
            }
            elseif ($entryType -eq 'OptionalFeature') {
                $targetDesc = "OptionalFeature:$($entry.FeatureName)"
                if ([string]$entry.OriginalState -eq 'Enabled' -and $null -ne (Get-Command -Name 'Enable-WindowsOptionalFeature' -ErrorAction SilentlyContinue)) {
                    Enable-WindowsOptionalFeature -Online -FeatureName ([string]$entry.FeatureName) -NoRestart -ErrorAction Stop | Out-Null
                }
            }
            elseif ($entryType -eq 'AccountLockoutPolicy') {
                $targetDesc = 'AccountLockoutPolicy'
                $origT = [int]$entry.OriginalThreshold
                if ($origT -le 0) {
                    [void](Invoke-NetAccounts -Arguments @('/lockoutthreshold:0'))
                }
                else {
                    $rbArgs = @("/lockoutthreshold:$origT")
                    $origD = if ($null -ne $entry.PSObject.Properties['OriginalDuration']) { [int]$entry.OriginalDuration } else { 0 }
                    $origW = if ($null -ne $entry.PSObject.Properties['OriginalWindow'])   { [int]$entry.OriginalWindow }   else { 0 }
                    if ($origD -gt 0) { $rbArgs += "/lockoutduration:$origD" }
                    if ($origW -gt 0) { $rbArgs += "/lockoutwindow:$origW" }
                    [void](Invoke-NetAccounts -Arguments $rbArgs)
                }
            }
            elseif ($entryType -eq 'LocalUser') {
                $targetDesc = "LocalUser:$($entry.Name)"
                if ([bool]$entry.OriginalEnabled) {
                    Enable-LocalUser -SID ([string]$entry.SID) -ErrorAction Stop
                }
            }
            elseif ($entryType -eq 'WifiAutoConnect') {
                $targetDesc = "Wifi:$($entry.ProfileName)"
                $origMode = if ($null -ne $entry.PSObject.Properties['OriginalConnectionMode'] -and -not [string]::IsNullOrWhiteSpace([string]$entry.OriginalConnectionMode)) {
                    [string]$entry.OriginalConnectionMode
                }
                else { 'auto' }
                [void](Invoke-NetshWlan -Arguments @('wlan', 'set', 'profileparameter', "name=$($entry.ProfileName)", "connectionmode=$origMode"))
            }
            else {
                throw "Unsupported backup entry type: '$entryType'"
            }

            $restoredCount++
            $results += [PSCustomObject]@{
                ControlId = $entryControlId
                Type      = $entryType
                Target    = $targetDesc
                Restored  = $true
                Error     = $null
            }
        }
        catch {
            $failedCount++
            $results += [PSCustomObject]@{
                ControlId = $entryControlId
                Type      = $entryType
                Target    = $targetDesc
                Restored  = $false
                Error     = $_.Exception.Message
            }
        }
    }

    return [PSCustomObject]@{
        BackupPath    = $BackupPath
        SessionId     = $sessionId
        TotalEntries  = $orderedEntries.Count
        RestoredCount = $restoredCount
        FailedCount   = $failedCount
        Results       = @($results)
    }
}
