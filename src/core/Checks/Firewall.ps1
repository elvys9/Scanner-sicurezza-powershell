<#
.SYNOPSIS
    Windows Defender Firewall profile status check.

.DESCRIPTION
    Verifies that Windows Defender Firewall is enabled across all three profiles
    (Domain, Private, Public) and that DefaultInboundAction is not set to Allow.
    Never modifies system state.
#>

Set-StrictMode -Version 2

function Test-FirewallProfiles {
    <#
    .SYNOPSIS
        Verifies that all firewall profiles are enabled with default inbound blocking.
    .PARAMETER Controllo
        Control object from the catalog.
    .PARAMETER Ambiente
        Environment object (from Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject with properties: Status, Observed, Expected, Evidence, Error.
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
        Expected = "All firewall profiles enabled (Domain, Private, Public) with DefaultInboundAction != Allow"
        Evidence = $null
        Error    = $null
    }

    try {
        # Retrieve Windows Defender Firewall profile states
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
            $risultato.Observed = "All profiles active with inbound traffic blocked by default"
        }
        else {
            $risultato.Status = 'fallito'
            $motivi = @()
            if ($profiliDisattivi.Count -gt 0) {
                $motivi += "Disabled profiles: $($profiliDisattivi -join ', ')"
            }
            if ($profiliInboundAllow.Count -gt 0) {
                $motivi += "Profiles allowing inbound traffic: $($profiliInboundAllow -join ', ')"
            }
            $risultato.Observed = ($motivi -join '; ')
        }
    }
    catch [System.Management.Automation.CommandNotFoundException] {
        # Get-NetFirewallProfile unavailable
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Cmdlet Get-NetFirewallProfile is not available"
        $risultato.Error = $_.Exception.Message
    }
    catch [System.UnauthorizedAccessException] {
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Insufficient privileges to query Windows Firewall"
        $risultato.Error = $_.Exception.Message
    }
    catch {
        # Handle missing privileges or CIM access denied errors
        if ($_.Exception.Message -match 'CIM resource|Access is denied|Accesso negato|privilegi|privilege') {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Insufficient privileges to query Windows Firewall"
            $risultato.Error = $_.Exception.Message
        }
        else {
            $risultato.Status = 'errore'
            $risultato.Error = $_.Exception.Message
        }
    }

    return $risultato
}
