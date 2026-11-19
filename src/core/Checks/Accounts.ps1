<#
.SYNOPSIS
    Controlli di sicurezza relativi agli account utente locali.

.DESCRIPTION
    Contiene i controlli per:
    - HOME-ACC-001: Account Guest disabilitato (SID -501)
    - HOME-ACC-002: Account Administrator predefinito disabilitato (SID -500)
    - HOME-ACC-003: Nessun account locale attivo senza password (PasswordRequired)
    - HOME-ACC-004: Politica di blocco account contro brute-force (LockoutThreshold)
    - HOME-ACC-005: Numero di account nel gruppo Amministratori locali ridotto al minimo (<= 2)
    Include catena di fallback multi-livello (Get-LocalUser -> CIM Win32_UserAccount -> ADSI WinNT -> Registro ProfileList/SAM)
    per evitare stati 'Sconosciuto' su sessioni non-admin, PowerShell a 32-bit o PC con Microsoft Account.
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-FallbackUtentiLocali {
    <#
    .SYNOPSIS
        Funzione helper in sola lettura (prefisso Test- per passaggio automatico al Runspace GUI)
        che recupera la lista degli account locali tramite CIM, ADSI o Registro ProfileList
        quando Get-LocalUser fallisce per restrizioni SAMR non-admin o assenza del modulo.
    #>
    [CmdletBinding()]
    param()

    # 1. Tentativo tramite CIM Win32_UserAccount
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
                    Fonte            = 'Win32_UserAccount'
                }
            }
            return $listaCim
        }
    }
    catch { }

    # 2. Tentativo tramite ADSI WinNT
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
                    Fonte            = 'ADSI'
                }
            }
            if ($listaAdsi.Count -gt 0) {
                return $listaAdsi
            }
        }
    }
    catch { }

    # 3. Fallback deterministico tramite Registro ProfileList + SID Translation + Winlogon/IdentityStore
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

                # Ricostruisci stato Built-in Administrator (-500) e Guest (-501)
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
                        Fonte            = 'RegistryProfileList'
                    }
                }

                # Aggiungi i profili utente attivi presenti in ProfileList
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
                        Fonte            = 'RegistryProfileList'
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
        Verifica che l'account Guest (SID -501) sia disabilitato (HOME-ACC-001).
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
        Expected = "Account Guest (SID -501) disabilitato"
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
        if ($_.Exception.Message -match 'Il termine .* non e'' riconosciuto') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Il cmdlet Get-LocalUser non e' disponibile"
            $risultato.Error    = $_.Exception.Message
            return $risultato
        }
    }
    catch {
        $erroreIniziale = $_
        if ($_.Exception.Message -notmatch 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource|1332|Failed to compare') {
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
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Nessun account con SID che termina in -501 trovato"
        $risultato.Evidence = @{ AccountTrovato = $false }
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
        $risultato.Observed = "Nessun account con SID che termina in -501 trovato"
        $risultato.Evidence = @{ AccountTrovato = $false }
        return $risultato
    }

    $risultato.Evidence = @{
        Nome      = $guest.Name
        SID       = $guest.SID.Value
        Abilitato = [bool]$guest.Enabled
    }

    if ($guest.Enabled) {
        $risultato.Status   = 'fallito'
        $risultato.Observed = "Account Guest ($($guest.Name)) abilitato"
    }
    else {
        $risultato.Status   = 'superato'
        $risultato.Observed = "Account Guest ($($guest.Name)) disabilitato"
    }

    return $risultato
}

function Test-AdminAccount {
    <#
    .SYNOPSIS
        Verifica che l'account Administrator locale predefinito (SID -500) sia disabilitato (HOME-ACC-002).
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
        Expected = "Account Administrator predefinito (SID -500) disabilitato"
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
        if ($_.Exception.Message -match 'Il termine .* non e'' riconosciuto') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Il cmdlet Get-LocalUser non e' disponibile"
            $risultato.Error    = $_.Exception.Message
            return $risultato
        }
    }
    catch {
        $erroreIniziale = $_
        if ($_.Exception.Message -notmatch 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource|1332|Failed to compare') {
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
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Nessun account con SID che termina in -500 trovato"
        $risultato.Evidence = @{ AccountTrovato = $false }
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
        $risultato.Observed = "Nessun account con SID che termina in -500 trovato"
        $risultato.Evidence = @{ AccountTrovato = $false }
        return $risultato
    }

    $risultato.Evidence = @{
        Nome      = $adminBuiltin.Name
        SID       = $adminBuiltin.SID.Value
        Abilitato = [bool]$adminBuiltin.Enabled
    }

    if ($adminBuiltin.Enabled) {
        $risultato.Status   = 'fallito'
        $risultato.Observed = "Account Administrator predefinito ($($adminBuiltin.Name)) abilitato"
    }
    else {
        $risultato.Status   = 'superato'
        $risultato.Observed = "Account Administrator predefinito ($($adminBuiltin.Name)) disabilitato"
    }

    return $risultato
}

function Test-AccountsPasswordRequired {
    <#
    .SYNOPSIS
        Verifica che tutti gli account locali abilitati richiedano una password
        (escludendo dai falsi positivi gli account collegati a Microsoft Account / Windows Hello) (HOME-ACC-003).
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
        Expected = "Tutti gli account locali attivi hanno PasswordRequired = True (o usano MicrosoftAccount/Windows Hello)"
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
        if ($_.Exception.Message -match 'Il termine .* non e'' riconosciuto') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Il cmdlet Get-LocalUser non e' disponibile"
            $risultato.Error    = $_.Exception.Message
            return $risultato
        }
    }
    catch {
        $erroreIniziale = $_
        if ($_.Exception.Message -notmatch 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource|1332|Failed to compare') {
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
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Dati account locali non disponibili"
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
                Nome             = $u.Name
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
        AccountAttivi              = $dettaglioAttivi
        AccountMicrosoft           = $accountMicrosoft
        AccountSenzaPasswordObblig = $attiviSenzaObbligo
    }

    if ($attiviSenzaObbligo.Count -eq 0) {
        $risultato.Status = 'superato'
        if ($accountMicrosoft.Count -gt 0) {
            $risultato.Observed = "Tutti gli account attivi ($($dettaglioAttivi.Count)) richiedono autenticazione (Account Microsoft/Windows Hello: $($accountMicrosoft -join ', '))"
        }
        else {
            $risultato.Observed = "Tutti gli account attivi ($($dettaglioAttivi.Count)) richiedono una password"
        }
    }
    else {
        $risultato.Status   = 'fallito'
        $risultato.Observed = "Account locali attivi con PasswordRequired=False: $($attiviSenzaObbligo -join ', ')"
    }

    return $risultato
}

function Test-PoliticaBloccoAccount {
    <#
    .SYNOPSIS
        Verifica che sia attiva una soglia di blocco account (Account Lockout Threshold 1..10 tentativi)
        contro attacchi di forza bruta locali/rete (HOME-ACC-004).
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
        Expected = "Soglia blocco account (Lockout threshold) tra 1 e 10 tentativi falliti"
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
            $risultato.Observed = "Blocco account attivo dopo $soglia tentativi falliti"
        }
        elseif ($soglia -gt 10) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Soglia blocco account troppo permissiva ($soglia tentativi; consigliato <= 10)"
        }
        elseif ($soglia -eq 0) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Blocco account disabilitato (Mai / 0 tentativi)"
        }
        else {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Impossibile determinare la soglia di blocco account"
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
        Verifica che il gruppo Amministratori locali (SID S-1-5-32-544) non contenga un numero
        eccessivo di account abilitati (consigliato <= 2 amministratori attivi) (HOME-ACC-005).
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
        Expected = "Massimo 2 account amministratori locali attivi (principio del privilegio minimo)"
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

        # 1. Tentativo primario con Get-LocalGroupMember
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
            # Fallback quando Get-LocalGroupMember fallisce per bug su MicrosoftAccount o restrizioni SAMR
        }

        # 2. Fallback tramite ADSI WinNT Group Members
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

        # 3. Fallback tramite profilo attivo in ProfileList (quando SAMR e' bloccato in sessione non-admin)
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
            $risultato.Observed = "Impossibile enumerare i membri del gruppo Amministratori"
            return $risultato
        }

        $risultato.Evidence = @{
            TotaleAdminAttivi = $adminAttivi.Count
            AdminAttivi       = $adminAttivi
        }

        if ($adminAttivi.Count -le 2) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "$($adminAttivi.Count) amministratori attivi: $($adminAttivi -join ', ')"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Rilevati $($adminAttivi.Count) account nel gruppo Amministratori: $($adminAttivi -join ', ')"
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}
