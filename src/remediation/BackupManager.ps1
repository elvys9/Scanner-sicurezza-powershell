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
            if ($null -ne $regItem -and $null -ne ($regItem | Get-Member -Name 'GetValueKind' -MemberType Method -ErrorAction SilentlyContinue)) {
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
        Captures the current integer state of a supported Microsoft Defender preference property.

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

    return [PSCustomObject]@{
        Type          = 'DefenderPreference'
        PropertyName  = $PropertyName
        OriginalValue = [int]$pref.$PropertyName
    }
}

function Add-RemediationBackupEntry {
    <#
    .SYNOPSIS
        Appends a captured state entry to a backup session while deduplicating identical targets.

    .DESCRIPTION
        Preserves the first captured pre-session state if the same registry value or Defender
        preference is modified multiple times within a single remediation session.
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

        if ($Entry.Type -eq 'RegistryValue') {
            if (($existing.Path -eq $Entry.Path) -and ($existing.Name -eq $Entry.Name)) {
                return
            }
        }
        elseif ($Entry.Type -eq 'DefenderPreference') {
            if ($existing.PropertyName -eq $Entry.PropertyName) {
                return
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

    .PARAMETER Path
        Target PowerShell registry path.

    .PARAMETER Name
        Target registry value name.

    .PARAMETER Value
        Desired value data.

    .PARAMETER PropertyType
        Registry value type (defaults to DWord).

    .PARAMETER BackupSession
        Optional backup session object where pre-change state is captured.

    .PARAMETER ControlId
        Catalog control ID associated with this change.
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

    .PARAMETER PropertyName
        Supported Defender preference name (PUAProtection or EnableNetworkProtection).

    .PARAMETER TargetValue
        Desired Defender setting value (e.g., 'Enabled').

    .PARAMETER BackupSession
        Optional backup session object where pre-change state is captured.

    .PARAMETER ControlId
        Catalog control ID associated with this change.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('PUAProtection', 'EnableNetworkProtection')]
        [string]$PropertyName,

        [Parameter(Mandatory = $true)]
        [string]$TargetValue,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$BackupSession = $null,

        [Parameter(Mandatory = $false)]
        [string]$ControlId = ''
    )

    if ($null -ne $BackupSession) {
        $snapshot = Backup-DefenderPreferenceState -PropertyName $PropertyName
        Add-RemediationBackupEntry -Session $BackupSession -ControlId $ControlId -Entry $snapshot
    }

    if ($PropertyName -eq 'PUAProtection') {
        Set-MpPreference -PUAProtection $TargetValue -ErrorAction Stop
    }
    elseif ($PropertyName -eq 'EnableNetworkProtection') {
        Set-MpPreference -EnableNetworkProtection $TargetValue -ErrorAction Stop
    }
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

    $rawEntries = if ($null -ne $data.PSObject.Properties['Entries'] -and $null -ne $data.Entries) {
        @($data.Entries)
    }
    else {
        @()
    }

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

    foreach ($entry in $orderedEntries) {
        $entryControlId = if ($null -ne $entry.PSObject.Properties['ControlId']) { [string]$entry.ControlId } else { '' }
        $entryType = if ($null -ne $entry.PSObject.Properties['Type']) { [string]$entry.Type } else { '' }

        try {
            if ($entryType -eq 'RegistryValue') {
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

                $restoredCount++
                $results += [PSCustomObject]@{
                    ControlId = $entryControlId
                    Type      = $entryType
                    Target    = "$($entry.Path)\$($entry.Name)"
                    Restored  = $true
                    Error     = $null
                }
            }
            elseif ($entryType -eq 'DefenderPreference') {
                $origInt = [int]$entry.OriginalValue
                if (-not $defenderIntMap.ContainsKey($origInt)) {
                    throw "Unsupported original Defender value '$origInt' for property '$($entry.PropertyName)'."
                }
                $targetMode = $defenderIntMap[$origInt]

                if ($entry.PropertyName -eq 'PUAProtection') {
                    Set-MpPreference -PUAProtection $targetMode -ErrorAction Stop
                }
                elseif ($entry.PropertyName -eq 'EnableNetworkProtection') {
                    Set-MpPreference -EnableNetworkProtection $targetMode -ErrorAction Stop
                }
                else {
                    throw "Unsupported Defender preference property for rollback: $($entry.PropertyName)"
                }

                $restoredCount++
                $results += [PSCustomObject]@{
                    ControlId = $entryControlId
                    Type      = $entryType
                    Target    = [string]$entry.PropertyName
                    Restored  = $true
                    Error     = $null
                }
            }
            else {
                throw "Unsupported backup entry type: '$entryType'"
            }
        }
        catch {
            $failedCount++
            $results += [PSCustomObject]@{
                ControlId = $entryControlId
                Type      = $entryType
                Target    = if ($entryType -eq 'RegistryValue') { "$($entry.Path)\$($entry.Name)" } else { [string]$entry.PropertyName }
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
