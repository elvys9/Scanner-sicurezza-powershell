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
        $dettaglioAttivi = @()

        foreach ($u in $utenti) {
            if ($u.Enabled) {
                $pwdReq = [bool]$u.PasswordRequired
                $dettaglioAttivi += @{
                    Nome             = $u.Name
                    SID              = $u.SID.Value
                    PasswordRequired = $pwdReq
                }
                if (-not $pwdReq) {
                    $attiviSenzaObbligo += $u.Name
                }
            }
        }

        $risultato.Evidence = @{
            AccountAttivi              = $dettaglioAttivi
            AccountSenzaPasswordObblig = $attiviSenzaObbligo
        }

        if ($attiviSenzaObbligo.Count -eq 0) {
            $risultato.Status = 'superato'
            $risultato.Observed = "Tutti gli account attivi ($($dettaglioAttivi.Count)) richiedono una password"
        }
        else {
            $risultato.Status = 'fallito'
            $risultato.Observed = "Account attivi con PasswordRequired=False: $($attiviSenzaObbligo -join ', ')"
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
