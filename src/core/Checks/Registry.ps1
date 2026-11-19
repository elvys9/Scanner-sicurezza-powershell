<#
.SYNOPSIS
    Generic evaluator for Windows Registry-based security controls.

.DESCRIPTION
    Reads a Windows Registry value and compares it against the expected value
    using the operator defined in the catalog.
    Never modifies system state.
#>

Set-StrictMode -Version 2

function Test-RegistryValue {
    <#
    .SYNOPSIS
        Evaluates a Windows Registry value against catalog parameters.
    .PARAMETER RegistryCheck
        Object with properties: path, name, operator, value.
    .PARAMETER Ambiente
        Environment object (from Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject with properties: Status, Observed, Expected, Evidence, Error.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RegistryCheck,

        [Parameter(Mandatory = $false)]
        [PSCustomObject]$Ambiente = $null
    )

    $risultato = [PSCustomObject]@{
        Status   = 'sconosciuto'
        Observed = $null
        Expected = $null
        Evidence = $null
        Error    = $null
    }

    $percorso = $RegistryCheck.path
    $nome = $RegistryCheck.name
    $operatore = $RegistryCheck.operator
    $atteso = $RegistryCheck.value

    $risultato.Expected = "$nome $operatore $atteso"

    try {
        # Check whether the registry key exists
        if (-not (Test-Path -LiteralPath $percorso)) {
            if ($operatore -eq 'notexists') {
                $risultato.Status = 'superato'
                $risultato.Observed = "Registry key not present"
                $risultato.Evidence = @{ Path = $percorso; Exists = $false }
            }
            elseif ($operatore -eq 'exists') {
                $risultato.Status = 'fallito'
                $risultato.Observed = "Registry key not present"
                $risultato.Evidence = @{ Path = $percorso; Exists = $false }
            }
            else {
                $risultato.Status = 'sconosciuto'
                $risultato.Observed = "Registry key not found: $percorso"
                $risultato.Evidence = @{ Path = $percorso; Exists = $false }
            }
            return $risultato
        }

        # Read the registry value
        $prop = Get-ItemProperty -LiteralPath $percorso -Name $nome -ErrorAction Stop
        if (-not $prop.PSObject.Properties[$nome]) {
            throw [System.Management.Automation.PSArgumentException]::new("Registry value not found: $nome")
        }
        $valoreCorrente = $prop.$nome

        $risultato.Observed = $valoreCorrente
        $risultato.Evidence = @{
            Path  = $percorso
            Name  = $nome
            Value = $valoreCorrente
        }

        # Compare using the specified operator
        $superato = $false
        switch ($operatore) {
            'eq'        { $superato = ($valoreCorrente -eq $atteso) }
            'ne'        { $superato = ($valoreCorrente -ne $atteso) }
            'ge'        { $superato = ($valoreCorrente -ge $atteso) }
            'le'        { $superato = ($valoreCorrente -le $atteso) }
            'exists'    { $superato = $true }  # Value exists
            'notexists' { $superato = $false } # Value exists (should not)
            default     {
                $risultato.Status = 'errore'
                $risultato.Error = "Unsupported operator: $operatore"
                return $risultato
            }
        }

        if ($superato) {
            $risultato.Status = 'superato'
        }
        else {
            $risultato.Status = 'fallito'
        }
    }
    catch [System.Security.SecurityException] {
        # Access denied: data unavailable, not a control failure
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Access denied to registry key"
        $risultato.Error = $_.Exception.Message
    }
    catch [System.Management.Automation.PSArgumentException] {
        # The requested value does not exist in the key
        if ($operatore -eq 'notexists') {
            $risultato.Status = 'superato'
            $risultato.Observed = "Registry value not present"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
        elseif ($operatore -eq 'exists') {
            $risultato.Status = 'fallito'
            $risultato.Observed = "Registry value not present"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
        else {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Registry value not found: $nome"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        # The requested value does not exist in the key
        if ($operatore -eq 'notexists') {
            $risultato.Status = 'superato'
            $risultato.Observed = "Registry value not present"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
        elseif ($operatore -eq 'exists') {
            $risultato.Status = 'fallito'
            $risultato.Observed = "Registry value not present"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
        else {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Registry value not found: $nome"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error = $_.Exception.Message
    }

    return $risultato
}
