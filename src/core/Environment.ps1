<#
.SYNOPSIS
    Rileva le informazioni sull'ambiente di esecuzione.

.DESCRIPTION
    Raccoglie edizione di Windows, build e UBR, lingua di sistema,
    stato di amministratore e versione di PowerShell.
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Get-AmbienteSistema {
    <#
    .SYNOPSIS
        Restituisce un oggetto con le informazioni sull'ambiente.
    .OUTPUTS
        PSCustomObject con proprieta': Edition, Build, Language, IsAdmin, PsVersion
    #>
    [CmdletBinding()]
    param()

    # Edizione: EditionID dal registro (es. "Core" = Home, "Professional" = Pro)
    $editionId = $null
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $editionId = (Get-ItemProperty -Path $regPath -Name 'EditionID' -ErrorAction Stop).EditionID
    }
    catch {
        $editionId = 'Sconosciuta'
    }

    # Mappa EditionID ai nomi usati nel catalogo
    $editionMap = @{
        'Core'              = 'Home'
        'CoreSingleLanguage'= 'Home'
        'Professional'      = 'Pro'
        'Education'         = 'Pro'   # trattata come Pro per i controlli
        'Enterprise'        = 'Pro'   # trattata come Pro per i controlli
    }
    $editionName = $editionId
    if ($editionMap.ContainsKey($editionId)) {
        $editionName = $editionMap[$editionId]
    }

    # Build e UBR
    $build = $null
    $ubr = $null
    try {
        $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $ntVer = Get-ItemProperty -Path $regPath -ErrorAction Stop
        if ($ntVer.PSObject.Properties['CurrentBuildNumber']) {
            $build = $ntVer.CurrentBuildNumber
        }
        else {
            $build = 'Sconosciuto'
        }
        if ($ntVer.PSObject.Properties['UBR']) {
            $ubr = $ntVer.UBR
        }
    }
    catch {
        $build = 'Sconosciuto'
        $ubr = $null
    }

    $buildString = $build
    if ($null -ne $ubr) {
        $buildString = "$build.$ubr"
    }

    # Lingua di sistema (codice LCID -> nome cultura)
    $language = $null
    try {
        $culture = [System.Globalization.CultureInfo]::InstalledUICulture
        $language = $culture.Name  # es. "it-IT", "en-US"
    }
    catch {
        $language = 'Sconosciuta'
    }

    # Stato di amministratore
    $isAdmin = $false
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        $isAdmin = $false
    }

    # Versione PowerShell
    $psVersion = $PSVersionTable.PSVersion.ToString()

    # Costruisci l'oggetto risultato
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
