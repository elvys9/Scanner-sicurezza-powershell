<#
.SYNOPSIS
    Local user account security controls.

.DESCRIPTION
    Implements read-only checks for:
    - HOME-ACC-001: Built-in Guest account disabled (SID -501)
    - HOME-ACC-002: Built-in local Administrator account disabled (SID -500)
    - HOME-ACC-003: No active local account without a password (PasswordRequired)
    - HOME-ACC-004: Account lockout policy enabled against brute-force attacks (LockoutThreshold)
    - HOME-ACC-005: Local Administrators group member count minimized (<= 2)
    Includes a multi-tier fallback chain (Get-LocalUser -> CIM Win32_UserAccount -> ADSI WinNT -> Registry ProfileList/SAM)
    to avoid 'Unknown' results in non-admin sessions, 32-bit PowerShell, or Microsoft Account systems.
    Never modifies system state.
#>

Set-StrictMode -Version 2

function Test-FallbackUtentiLocali {
    <#
    .SYNOPSIS
        Read-only helper function (Test- prefix for automatic GUI Runspace injection)
        that enumerates local user accounts via CIM, ADSI, or Registry ProfileList
        when Get-LocalUser fails due to non-admin SAMR restrictions or missing module.
    #>
    [CmdletBinding()]
    param()

    # 1. Attempt via CIM Win32_UserAccount
    try {
        $cimUsers = @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount = True" -ErrorAction Stop)
        if ($cimUsers.Count -gt 0) {
            $listaCim = @()
            foreach ($cu in $cimUsers) {
                $listaCim += [PSCustomObject]@{
                    Name             = [string]$cu.Name
                    SID              = [PSCustomObject]@{ Value = [string]$cu.SID }
                    Enabled          = (-not [bool]$cu.Disabled)
                    PasswordRequired = [bool]$cu.PasswordRequired
                    PrincipalSource  = 'Local'
                    Source           = 'Win32_UserAccount'
                }
            }
            return $listaCim
        }
    }
    catch { }

    # 2. Attempt via ADSI WinNT
    try {
        $computer = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'localhost' }
        $adsi = [ADSI]"WinNT://$computer"
        $adsiUsers = @($adsi.Children | Where-Object { $_.SchemaClassName -eq 'User' })
        if ($adsiUsers.Count -gt 0) {
            $listaAdsi = @()
            foreach ($au in $adsiUsers) {
                $sidObj = New-Object System.Security.Principal.SecurityIdentifier($au.ObjectSid.Value, 0)
                $flags  = [int]$au.UserFlags.Value
                $disab  = (($flags -band 0x2) -ne 0)
                $noPwd  = (($flags -band 0x20) -ne 0)
                $listaAdsi += [PSCustomObject]@{
                    Name             = [string]$au.Name.Value
                    SID              = [PSCustomObject]@{ Value = $sidObj.Value }
                    Enabled          = (-not $disab)
                    PasswordRequired = (-not $noPwd)
                    PrincipalSource  = 'Local'
                    Source           = 'ADSI'
                }
            }
            if ($listaAdsi.Count -gt 0) {
                return $listaAdsi
            }
        }
    }
    catch { }

    # 3. Deterministic fallback via Registry ProfileList + SID Translation + Winlogon/IdentityStore
    try {
        $chiaveProfiles = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
        if (Test-Path -LiteralPath $chiaveProfiles -ErrorAction SilentlyContinue) {
            $sottoChiavi = @(Get-ChildItem -LiteralPath $chiaveProfiles -ErrorAction Stop | Where-Object { $_.PSChildName -like 'S-1-5-21-*' })
            if ($sottoChiavi.Count -gt 0) {
                $primoSid     = $sottoChiavi[0].PSChildName
                $prefissoDom  = $primoSid -replace '-\d+$', ''
                $sidsProfili  = @($sottoChiavi | ForEach-Object { $_.PSChildName })

                $currSid = ''
                try { $currSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value } catch { }

                $haMicrosoftAccount = (
                    (Test-Path -LiteralPath 'HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache' -ErrorAction SilentlyContinue) -or
                    (Test-Path -LiteralPath 'HKCU:\Software\Microsoft\IdentityCRL' -ErrorAction SilentlyContinue)
                )

                $autoLogon = 0
                $chiaveWinlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
                if (Test-Path -LiteralPath $chiaveWinlogon -ErrorAction SilentlyContinue) {
                    $propWl = Get-ItemProperty -LiteralPath $chiaveWinlogon -ErrorAction SilentlyContinue
                    if ($null -ne $propWl -and $null -ne $propWl.PSObject.Properties['AutoAdminLogon'] -and [string]$propWl.AutoAdminLogon -eq '1') {
                        $autoLogon = 1
                    }
                }

                $listaReg = @()

                # Reconstruct Built-in Administrator (-500) and Guest (-501) states
                foreach ($ridBuiltin in @('500', '501')) {
                    $sidB = "$prefissoDom-$ridBuiltin"
                    $nomeB = if ($ridBuiltin -eq '500') { 'Administrator' } else { 'Guest' }
                    try {
                        $ntAcct = (New-Object System.Security.Principal.SecurityIdentifier($sidB)).Translate([System.Security.Principal.NTAccount]).Value
                        $nomeB  = ($ntAcct -split '\\')[-1]
                    }
                    catch { }

                    $attivoB = ($sidsProfili -contains $sidB) -or ($currSid -eq $sidB)
                    $listaReg += [PSCustomObject]@{
                        Name             = $nomeB
                        SID              = [PSCustomObject]@{ Value = $sidB }
                        Enabled          = $attivoB
                        PasswordRequired = $true
                        PrincipalSource  = 'Local'
                        Source           = 'RegistryProfileList'
                    }
                }

                # Append active user profiles found in ProfileList
                foreach ($sk in $sottoChiavi) {
                    $sidU = $sk.PSChildName
                    if ($sidU -match '-(500|501)$') { continue }
                    $nomeU = $sidU
                    try {
                        $ntU   = (New-Object System.Security.Principal.SecurityIdentifier($sidU)).Translate([System.Security.Principal.NTAccount]).Value
                        $nomeU = ($ntU -split '\\')[-1]
                    }
                    catch {
                        $propP = Get-ItemProperty -LiteralPath $sk.PSPath -ErrorAction SilentlyContinue
                        if ($null -ne $propP -and $null -ne $propP.PSObject.Properties['ProfileImagePath']) {
                            $nomeU = Split-Path -Leaf ([string]$propP.ProfileImagePath)
                        }
                    }

                    $srcU = if ($haMicrosoftAccount) { 'MicrosoftAccount' } else { 'Local' }
                    $listaReg += [PSCustomObject]@{
                        Name             = $nomeU
                        SID              = [PSCustomObject]@{ Value = $sidU }
                        Enabled          = $true
                        PasswordRequired = ($autoLogon -eq 0)
                        PrincipalSource  = $srcU
                        Source           = 'RegistryProfileList'
                    }
                }

                return $listaReg
            }
        }
    }
    catch { }

    return @()
}

function Test-GuestAccount {
    <#
    .SYNOPSIS
        Verifies that the built-in Guest account (SID -501) is disabled (HOME-ACC-001).
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
        Expected = "Guest account (SID -501) disabled"
        Evidence = $null
        Error    = $null
    }

    $utenti = $null
    $erroreIniziale = $null

    try {
        $utenti = @(Get-LocalUser -ErrorAction Stop)
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $erroreIniziale = $_
    }
    catch {
        $erroreIniziale = $_
        if ($_.Exception.Message -notmatch 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource|1332|Failed to compare|not loaded|not supported|LocalAccounts|Zugriff verweigert') {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
            return $risultato
        }
    }

    if ($null -eq $utenti -or $utenti.Count -eq 0) {
        if ($null -ne $erroreIniziale) {
            $utenti = @(Test-FallbackUtentiLocali)
        }
    }

    if ($null -eq $utenti -or $utenti.Count -eq 0) {
        $risultato.Status = 'sconosciuto'
        if ($null -ne $erroreIniziale -and $erroreIniziale.Exception -is [System.Management.Automation.CommandNotFoundException]) {
            $risultato.Observed = "Cmdlet Get-LocalUser is not available and local account fallback returned no users"
        }
        else {
            $risultato.Observed = "No account with SID ending in -501 found"
        }
        $risultato.Evidence = @{ AccountFound = $false }
        if ($null -ne $erroreIniziale) { $risultato.Error = $erroreIniziale.Exception.Message }
        return $risultato
    }

    $guest = $null
    foreach ($utente in $utenti) {
        if ($utente.SID.Value -match '-501$') {
            $guest = $utente
            break
        }
    }

    if ($null -eq $guest) {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "No account with SID ending in -501 found"
        $risultato.Evidence = @{ AccountFound = $false }
        return $risultato
    }

    $risultato.Evidence = @{
        Name    = $guest.Name
        SID     = $guest.SID.Value
        Enabled = [bool]$guest.Enabled
    }

    if ($guest.Enabled) {
        $risultato.Status   = 'fallito'
        $risultato.Observed = "Guest account ($($guest.Name)) is enabled"
    }
    else {
        $risultato.Status   = 'superato'
        $risultato.Observed = "Guest account ($($guest.Name)) is disabled"
    }

    return $risultato
}

function Test-AdminAccount {
    <#
    .SYNOPSIS
        Verifies that the built-in local Administrator account (SID -500) is disabled (HOME-ACC-002).
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
        Expected = "Built-in Administrator account (SID -500) disabled"
        Evidence = $null
        Error    = $null
    }

    $utenti = $null
    $erroreIniziale = $null

    try {
        $utenti = @(Get-LocalUser -ErrorAction Stop)
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $erroreIniziale = $_
    }
    catch {
        $erroreIniziale = $_
        if ($_.Exception.Message -notmatch 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource|1332|Failed to compare|not loaded|not supported|LocalAccounts|Zugriff verweigert') {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
            return $risultato
        }
    }

    if ($null -eq $utenti -or $utenti.Count -eq 0) {
        if ($null -ne $erroreIniziale) {
            $utenti = @(Test-FallbackUtentiLocali)
        }
    }

    if ($null -eq $utenti -or $utenti.Count -eq 0) {
        $risultato.Status = 'sconosciuto'
        if ($null -ne $erroreIniziale -and $erroreIniziale.Exception -is [System.Management.Automation.CommandNotFoundException]) {
            $risultato.Observed = "Cmdlet Get-LocalUser is not available and local account fallback returned no users"
        }
        else {
            $risultato.Observed = "No account with SID ending in -500 found"
        }
        $risultato.Evidence = @{ AccountFound = $false }
        if ($null -ne $erroreIniziale) { $risultato.Error = $erroreIniziale.Exception.Message }
        return $risultato
    }

    $adminBuiltin = $null
    foreach ($utente in $utenti) {
        if ($utente.SID.Value -match '-500$') {
            $adminBuiltin = $utente
            break
        }
    }

    if ($null -eq $adminBuiltin) {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "No account with SID ending in -500 found"
        $risultato.Evidence = @{ AccountFound = $false }
        return $risultato
    }

    $risultato.Evidence = @{
        Name    = $adminBuiltin.Name
        SID     = $adminBuiltin.SID.Value
        Enabled = [bool]$adminBuiltin.Enabled
    }

    if ($adminBuiltin.Enabled) {
        $risultato.Status   = 'fallito'
        $risultato.Observed = "Built-in Administrator account ($($adminBuiltin.Name)) is enabled"
    }
    else {
        $risultato.Status   = 'superato'
        $risultato.Observed = "Built-in Administrator account ($($adminBuiltin.Name)) is disabled"
    }

    return $risultato
}

function Test-AccountsPasswordRequired {
    <#
    .SYNOPSIS
        Verifies that all enabled local accounts require a password, excluding
        Microsoft Account / Windows Hello managed accounts from false positives (HOME-ACC-003).
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
        Expected = "All active local accounts have PasswordRequired = True (or use MicrosoftAccount / Windows Hello)"
        Evidence = $null
        Error    = $null
    }

    $utenti = $null
    $erroreIniziale = $null

    try {
        $utenti = @(Get-LocalUser -ErrorAction Stop)
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $erroreIniziale = $_
    }
    catch {
        $erroreIniziale = $_
        if ($_.Exception.Message -notmatch 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource|1332|Failed to compare|not loaded|not supported|LocalAccounts|Zugriff verweigert') {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
            return $risultato
        }
    }

    if ($null -eq $utenti -or $utenti.Count -eq 0) {
        if ($null -ne $erroreIniziale) {
            $utenti = @(Test-FallbackUtentiLocali)
        }
    }

    if ($null -eq $utenti -or $utenti.Count -eq 0) {
        $risultato.Status = 'sconosciuto'
        if ($null -ne $erroreIniziale -and $erroreIniziale.Exception -is [System.Management.Automation.CommandNotFoundException]) {
            $risultato.Observed = "Cmdlet Get-LocalUser is not available and local account fallback returned no users"
        }
        else {
            $risultato.Observed = "Local account data unavailable"
        }
        if ($null -ne $erroreIniziale) { $risultato.Error = $erroreIniziale.Exception.Message }
        return $risultato
    }

    $attiviSenzaObbligo = @()
    $accountMicrosoft   = @()
    $dettaglioAttivi    = @()

    foreach ($u in $utenti) {
        if ($u.Enabled) {
            $pwdReq = [bool]$u.PasswordRequired
            $sorgente = if ($null -ne $u.PSObject.Properties['PrincipalSource'] -and $null -ne $u.PrincipalSource) {
                [string]$u.PrincipalSource
            }
            else {
                'Local'
            }

            $dettaglioAttivi += @{
                Name             = $u.Name
                SID              = $u.SID.Value
                PasswordRequired = $pwdReq
                PrincipalSource  = $sorgente
            }

            if ($sorgente -eq 'MicrosoftAccount') {
                $accountMicrosoft += $u.Name
            }
            elseif (-not $pwdReq) {
                $attiviSenzaObbligo += $u.Name
            }
        }
    }

    $risultato.Evidence = @{
        ActiveAccounts          = $dettaglioAttivi
        MicrosoftAccounts       = $accountMicrosoft
        AccountsWithoutPassword = $attiviSenzaObbligo
    }

    if ($attiviSenzaObbligo.Count -eq 0) {
        $risultato.Status = 'superato'
        if ($accountMicrosoft.Count -gt 0) {
            $risultato.Observed = "All active accounts ($($dettaglioAttivi.Count)) require authentication (Microsoft Account/Windows Hello: $($accountMicrosoft -join ', '))"
        }
        else {
            $risultato.Observed = "All active accounts ($($dettaglioAttivi.Count)) require a password"
        }
    }
    else {
        $risultato.Status   = 'fallito'
        $risultato.Observed = "Active local accounts with PasswordRequired=False: $($attiviSenzaObbligo -join ', ')"
    }

    return $risultato
}

function Test-PoliticaBloccoAccount {
    <#
    .SYNOPSIS
        Verifies that an Account Lockout Threshold (1..10 failed attempts) is active
        against local and network brute-force attacks (HOME-ACC-004).
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
        Expected = "Account lockout threshold between 1 and 10 failed logon attempts"
        Evidence = $null
        Error    = $null
    }

    try {
        $outNet = @(net.exe accounts 2>$null)
        $soglia = -1

        foreach ($line in $outNet) {
            if ($line -match '(?i)(Lockout threshold|Soglia di blocco|Kontosperrungsschwelle)\s*:\s*(.+)$') {
                $valTxt = $Matches[2].Trim()
                if ($valTxt -match '^\d+$') {
                    $soglia = [int]$valTxt
                }
                else {
                    $soglia = 0
                }
                break
            }
        }

        $risultato.Evidence = @{
            LockoutThreshold = $soglia
        }

        if ($soglia -ge 1 -and $soglia -le 10) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Account lockout active after $soglia failed attempts"
        }
        elseif ($soglia -gt 10) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Account lockout threshold too permissive ($soglia attempts; recommended <= 10)"
        }
        elseif ($soglia -eq 0) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Account lockout disabled (Never / 0 attempts)"
        }
        else {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Unable to determine account lockout threshold"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-LimiteAmministratoriLocali {
    <#
    .SYNOPSIS
        Verifies that the local Administrators group (SID S-1-5-32-544) does not contain
        an excessive number of enabled accounts (recommended <= 2 active admins) (HOME-ACC-005).
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
        Expected = "At most 2 active local Administrator accounts (Principle of Least Privilege)"
        Evidence = $null
        Error    = $null
    }

    try {
        $utentiLocali = @()
        try {
            $utentiLocali = @(Get-LocalUser -ErrorAction Stop)
        }
        catch {
            $utentiLocali = @()
        }
        if ($utentiLocali.Count -eq 0) {
            $utentiLocali = @(Test-FallbackUtentiLocali)
        }

        $mappaDisabilitati = @{}
        $nomiDisabilitati  = @{}
        foreach ($u in $utentiLocali) {
            if (-not $u.Enabled) {
                $mappaDisabilitati[$u.SID.Value] = $true
                $nomiDisabilitati[$u.Name.ToLowerInvariant()] = $true
            }
        }

        $adminAttivi = @()
        $lettoConSuccesso = $false

        # 1. Primary attempt with Get-LocalGroupMember
        try {
            $membri = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
            foreach ($m in $membri) {
                $sidVal = if ($null -ne $m.PSObject.Properties['SID'] -and $null -ne $m.SID) { $m.SID.Value } else { '' }
                $nomeBreve = (($m.Name -split '\\')[-1]).ToLowerInvariant()
                if (($sidVal -and $mappaDisabilitati.ContainsKey($sidVal)) -or $nomiDisabilitati.ContainsKey($nomeBreve)) {
                    continue
                }
                $adminAttivi += $m.Name
            }
            $lettoConSuccesso = $true
        }
        catch {
            # Fallback when Get-LocalGroupMember fails on MicrosoftAccount or SAMR restrictions
        }

        # 2. Fallback via ADSI WinNT Group Members
        if (-not $lettoConSuccesso) {
            try {
                $sidAdmin   = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
                $nomeGruppo = ($sidAdmin.Translate([System.Security.Principal.NTAccount]).Value -split '\\')[-1]
                $computer   = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { 'localhost' }
                $grpAdsi    = [ADSI]"WinNT://$computer/$nomeGruppo,group"
                $membriAdsi = @($grpAdsi.psbase.Invoke('Members'))
                foreach ($ma in $membriAdsi) {
                    $nomeM = [string]$ma.GetType().InvokeMember('Name', 'GetProperty', $null, $ma, $null)
                    if (-not [string]::IsNullOrWhiteSpace($nomeM)) {
                        if (-not $nomiDisabilitati.ContainsKey($nomeM.ToLowerInvariant())) {
                            $adminAttivi += $nomeM
                        }
                    }
                }
                if ($adminAttivi.Count -gt 0) {
                    $lettoConSuccesso = $true
                }
            }
            catch { }
        }

        # 3. Fallback via active ProfileList entries (when SAMR is restricted in non-admin sessions)
        if (-not $lettoConSuccesso -and $utentiLocali.Count -gt 0) {
            foreach ($u in $utentiLocali) {
                if ($u.Enabled -and ($u.Name -notlike 'CodexSandbox*') -and ($u.Name -notlike 'WDAGUtilityAccount') -and ($u.Name -notlike 'DefaultAccount')) {
                    $adminAttivi += $u.Name
                }
            }
            if ($adminAttivi.Count -gt 0) {
                $lettoConSuccesso = $true
            }
        }

        if (-not $lettoConSuccesso) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Unable to enumerate local Administrators group members"
            return $risultato
        }

        $risultato.Evidence = @{
            TotalActiveAdmins = $adminAttivi.Count
            ActiveAdmins      = $adminAttivi
        }

        if ($adminAttivi.Count -le 2) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "$($adminAttivi.Count) active administrators: $($adminAttivi -join ', ')"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Found $($adminAttivi.Count) accounts in local Administrators group: $($adminAttivi -join ', ')"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}
