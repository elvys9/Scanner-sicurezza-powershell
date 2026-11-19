<#
.SYNOPSIS
    Detects execution environment metadata.

.DESCRIPTION
    Collects Windows edition, build and UBR, OS display language,
    administrator privilege status, and PowerShell version.
    Never modifies system state.
#>

Set-StrictMode -Version 2

function Get-AmbienteSistema {
    <#
    .SYNOPSIS
        Returns an object with system environment details.
    .OUTPUTS
        PSCustomObject with properties: Edition, EditionId, Build, Language, IsAdmin, PsVersion
    #>
    [CmdletBinding()]
    param()

    # Edition: EditionID from registry (e.g., "Core" = Home, "Professional" = Pro)
    $editionId = $null
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $editionId = (Get-ItemProperty -Path $regPath -Name 'EditionID' -ErrorAction Stop).EditionID
    }
    catch {
        $editionId = 'Unknown'
    }

    # Map EditionID to catalog edition names
    $editionMap = @{
        'Core'               = 'Home'
        'CoreSingleLanguage' = 'Home'
        'Professional'       = 'Pro'
        'Education'          = 'Pro'   # treated as Pro for control applicability
        'Enterprise'         = 'Pro'   # treated as Pro for control applicability
    }
    $editionName = $editionId
    if ($editionMap.ContainsKey($editionId)) {
        $editionName = $editionMap[$editionId]
    }

    # Build and UBR
    $build = $null
    $ubr = $null
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $ntVer = Get-ItemProperty -Path $regPath -ErrorAction Stop
        if ($ntVer.PSObject.Properties['CurrentBuildNumber']) {
            $build = $ntVer.CurrentBuildNumber
        }
        else {
            $build = 'Unknown'
        }
        if ($ntVer.PSObject.Properties['UBR']) {
            $ubr = $ntVer.UBR
        }
    }
    catch {
        $build = 'Unknown'
        $ubr = $null
    }

    $buildString = $build
    if ($null -ne $ubr) {
        $buildString = "$build.$ubr"
    }

    # System UI language (culture name, e.g., "en-US", "it-IT")
    $language = $null
    try {
        $culture = [System.Globalization.CultureInfo]::InstalledUICulture
        $language = $culture.Name
    }
    catch {
        $language = 'Unknown'
    }

    # Administrator privilege check
    $isAdmin = $false
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        $isAdmin = $false
    }

    # PowerShell version
    $psVersion = $PSVersionTable.PSVersion.ToString()

    # Build result object
    $ambiente = [PSCustomObject]@{
        Edition   = $editionName
        EditionId = $editionId
        Build     = $buildString
        Language  = $language
        IsAdmin   = $isAdmin
        PsVersion = $psVersion
    }

    return $ambiente
}
