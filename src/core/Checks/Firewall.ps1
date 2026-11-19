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
        Expected = "Tutti i profili firewall attivi (Domain, Private, Public) con DefaultInboundAction != Allow"
        Evidence = $null
        Error    = $null
    }

    try {
        # Get-NetFirewallProfile restituisce lo stato dei profili
        $profili = Get-NetFirewallProfile -ErrorAction Stop

        $evidenza = @{}
        $tuttiAttivi = $true
        $profiliDisattivi = @()
        $profiliInboundAllow = @()

        foreach ($profilo in $profili) {
            $nomeNormalizzato = [string]$profilo.Name
            $attivo = [bool]$profilo.Enabled
            $inboundAct = if ($null -ne $profilo.PSObject.Properties['DefaultInboundAction'] -and $null -ne $profilo.DefaultInboundAction) {
                [string]$profilo.DefaultInboundAction
            }
            else {
                'NotConfigured'
            }

            $evidenza[$nomeNormalizzato] = @{
                Enabled              = $attivo
                DefaultInboundAction = $inboundAct
            }

            if (-not $attivo) {
                $tuttiAttivi = $false
                $profiliDisattivi += $nomeNormalizzato
            }
            if ($inboundAct -eq 'Allow') {
                $tuttiAttivi = $false
                $profiliInboundAllow += "$nomeNormalizzato (DefaultInboundAction=Allow)"
            }
        }

        $risultato.Evidence = $evidenza

        if ($tuttiAttivi) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Tutti i profili attivi con traffico in ingresso bloccato per impostazione predefinita"
        }
        else {
            $risultato.Status = 'fallito'
            $motivi = @()
            if ($profiliDisattivi.Count -gt 0) {
                $motivi += "Profili disattivi: $($profiliDisattivi -join ', ')"
            }
            if ($profiliInboundAllow.Count -gt 0) {
                $motivi += "Profili che consentono traffico in ingresso: $($profiliInboundAllow -join ', ')"
            }
            $risultato.Observed = ($motivi -join '; ')
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
