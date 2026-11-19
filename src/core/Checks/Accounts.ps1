<#
.SYNOPSIS
    Controlli di sicurezza relativi agli account utente locali.

.DESCRIPTION
    Contiene i controlli per:
    - HOME-ACC-001: Account Guest disabilitato (SID -501)
    - HOME-ACC-002: Account Administrator predefinito disabilitato (SID -500)
    - HOME-ACC-003: Nessun account locale attivo senza password (PasswordRequired)
    Usa i SID e le proprieta' degli oggetti, mai nomi localizzati.
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-GuestAccount {
    <#
    .SYNOPSIS
        Verifica che l'account Guest (SID -501) sia disabilitato.
    .PARAMETER Controllo
        L'oggetto controllo dal catalogo.
    .PARAMETER Ambiente
        L'oggetto ambiente (da Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject con proprieta': Status, Observed, Expected, Evidence, Error.
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

    try {
        $utenti = Get-LocalUser -ErrorAction Stop
        $guest = $null

        foreach ($utente in $utenti) {
            if ($utente.SID.Value -match '-501$') {
                $guest = $utente
                break
            }
        }

        if ($null -eq $guest) {
            $risultato.Status = 'sconosciuto'
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
            $risultato.Status = 'fallito'
            $risultato.Observed = "Account Guest ($($guest.Name)) abilitato"
        }
        else {
            $risultato.Status = 'superato'
            $risultato.Observed = "Account Guest ($($guest.Name)) disabilitato"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-LocalUser non e' disponibile"
        $risultato.Error = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Privilegi insufficienti per accedere agli account locali"
        $risultato.Error = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource') {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Dati account locali non disponibili o privilegi insufficienti"
            $risultato.Error = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-AdminAccount {
    <#
    .SYNOPSIS
        Verifica che l'account Administrator locale predefinito (SID -500) sia disabilitato.
    .PARAMETER Controllo
        L'oggetto controllo dal catalogo.
    .PARAMETER Ambiente
        L'oggetto ambiente (da Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject con proprieta': Status, Observed, Expected, Evidence, Error.
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

    try {
        $utenti = Get-LocalUser -ErrorAction Stop
        $adminBuiltin = $null

        foreach ($utente in $utenti) {
            if ($utente.SID.Value -match '-500$') {
                $adminBuiltin = $utente
                break
            }
        }

        if ($null -eq $adminBuiltin) {
            $risultato.Status = 'sconosciuto'
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
            $risultato.Status = 'fallito'
            $risultato.Observed = "Account Administrator predefinito ($($adminBuiltin.Name)) abilitato"
        }
        else {
            $risultato.Status = 'superato'
            $risultato.Observed = "Account Administrator predefinito ($($adminBuiltin.Name)) disabilitato"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-LocalUser non e' disponibile"
        $risultato.Error = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Privilegi insufficienti per accedere agli account locali"
        $risultato.Error = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource') {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Dati account locali non disponibili o privilegi insufficienti"
            $risultato.Error = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error = $_.Exception.Message
        }
    }

    return $risultato
}

function Test-AccountsPasswordRequired {
    <#
    .SYNOPSIS
        Verifica che tutti gli account locali abilitati richiedano una password.
    .PARAMETER Controllo
        L'oggetto controllo dal catalogo.
    .PARAMETER Ambiente
        L'oggetto ambiente (da Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject con proprieta': Status, Observed, Expected, Evidence, Error.
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
        Expected = "Tutti gli account locali attivi hanno PasswordRequired = True"
        Evidence = $null
        Error    = $null
    }

    try {
        $utenti = @(Get-LocalUser -ErrorAction Stop)
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
            $risultato.Status = 'fallito'
            $risultato.Observed = "Account locali attivi con PasswordRequired=False: $($attiviSenzaObbligo -join ', ')"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-LocalUser non e' disponibile"
        $risultato.Error = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Privilegi insufficienti per accedere agli account locali"
        $risultato.Error = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource') {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Dati account locali non disponibili o privilegi insufficienti"
            $risultato.Error = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error = $_.Exception.Message
        }
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
        $membri = @(Get-LocalGroupMember -SID 'S-1-5-32-544' -ErrorAction Stop)
        $utentiLocali = @(Get-LocalUser -ErrorAction SilentlyContinue)
        $mappaDisabilitati = @{}
        foreach ($u in $utentiLocali) {
            if (-not $u.Enabled) {
                $mappaDisabilitati[$u.SID.Value] = $true
            }
        }

        $adminAttivi = @()
        foreach ($m in $membri) {
            $sidVal = if ($null -ne $m.PSObject.Properties['SID'] -and $null -ne $m.SID) { $m.SID.Value } else { '' }
            if ($sidVal -and $mappaDisabilitati.ContainsKey($sidVal)) {
                continue
            }
            $adminAttivi += $m.Name
        }

        $risultato.Evidence = @{
            TotaleMembriGruppo = $membri.Count
            AdminAttivi        = $adminAttivi
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
    catch [System.Management.Automation.CommandNotFoundException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-LocalGroupMember non disponibile"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        if ($_.Exception.Message -match 'Access is denied|Accesso negato|privilegi|privilege|Object reference|CIM resource') {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti o account Microsoft/Cloud presente nel gruppo Amministratori"
            $risultato.Error    = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error  = $_.Exception.Message
        }
    }

    return $risultato
}
