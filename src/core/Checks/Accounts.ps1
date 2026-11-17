<#
.SYNOPSIS
    Controllo dello stato dell'account Guest.

.DESCRIPTION
    Verifica che l'account locale con SID che termina in -501 (Guest)
    sia disabilitato. Usa il SID, non il nome localizzato.
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
        # Cerca l'account locale con SID che termina in -501
        $utenti = Get-LocalUser -ErrorAction Stop
        $guest = $null

        foreach ($utente in $utenti) {
            if ($utente.SID.Value -match '-501$') {
                $guest = $utente
                break
            }
        }

        if ($null -eq $guest) {
            # L'account non esiste: sconosciuto, non fallito
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Nessun account con SID che termina in -501 trovato"
            $risultato.Evidence = @{ AccountTrovato = $false }
            return $risultato
        }

        $risultato.Evidence = @{
            Nome       = $guest.Name
            SID        = $guest.SID.Value
            Abilitato  = $guest.Enabled
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
        # Get-LocalUser non disponibile (modulo Microsoft.PowerShell.LocalAccounts)
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
        # Se mancano privilegi o Get-LocalUser fallisce per restrizioni account/ambiente
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
