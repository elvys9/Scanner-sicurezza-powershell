<#
.SYNOPSIS
    Controllo dello stato del firewall di Windows.

.DESCRIPTION
    Verifica che Windows Defender Firewall sia attivo sui tre profili:
    Domain, Private, Public.
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-FirewallProfiles {
    <#
    .SYNOPSIS
        Verifica che tutti i profili del firewall siano attivi.
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
        Expected = "Tutti i profili firewall attivi (Domain, Private, Public)"
        Evidence = $null
        Error    = $null
    }

    try {
        # Get-NetFirewallProfile restituisce lo stato dei profili
        $profili = Get-NetFirewallProfile -ErrorAction Stop

        $evidenza = @{}
        $tuttiAttivi = $true

        foreach ($profilo in $profili) {
            $nomeNormalizzato = $profilo.Name
            $attivo = [bool]$profilo.Enabled
            $evidenza[$nomeNormalizzato] = $attivo

            if (-not $attivo) {
                $tuttiAttivi = $false
            }
        }

        $risultato.Evidence = $evidenza

        if ($tuttiAttivi) {
            $risultato.Status = 'superato'
            $risultato.Observed = "Tutti i profili attivi"
        }
        else {
            $risultato.Status = 'fallito'
            $profiliDisattivi = @()
            foreach ($chiave in $evidenza.Keys) {
                if (-not $evidenza[$chiave]) {
                    $profiliDisattivi += $chiave
                }
            }
            $risultato.Observed = "Profili disattivi: $($profiliDisattivi -join ', ')"
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        # Get-NetFirewallProfile non disponibile
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Il cmdlet Get-NetFirewallProfile non e' disponibile"
        $risultato.Error = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Privilegi insufficienti per accedere al firewall di Windows"
        $risultato.Error = $_.Exception.Message
    }
    catch {
        # Se l'errore e' legato a privilegi mancanti o accesso CIM negato
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Privilegi insufficienti per accedere al firewall di Windows"
            $risultato.Error = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error = $_.Exception.Message
        }
    }

    return $risultato
}
