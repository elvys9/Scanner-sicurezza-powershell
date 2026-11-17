<#
.SYNOPSIS
    Valutatore generico per i controlli basati su registro di Windows.

.DESCRIPTION
    Legge un valore dal registro di Windows e lo confronta con il valore
    atteso usando l'operatore specificato nel catalogo.
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-RegistryValue {
    <#
    .SYNOPSIS
        Verifica un valore nel registro confrontandolo con i parametri del catalogo.
    .PARAMETER RegistryCheck
        Oggetto con proprieta': Path, Name, Operator, Value.
    .PARAMETER Ambiente
        Oggetto ambiente (da Get-AmbienteSistema).
    .OUTPUTS
        PSCustomObject con proprieta': Status, Observed, Expected, Evidence, Error.
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
        # Verifica se la chiave esiste
        if (-not (Test-Path -LiteralPath $percorso)) {
            if ($operatore -eq 'notexists') {
                $risultato.Status = 'superato'
                $risultato.Observed = "Chiave non presente"
                $risultato.Evidence = @{ Path = $percorso; Exists = $false }
            }
            elseif ($operatore -eq 'exists') {
                $risultato.Status = 'fallito'
                $risultato.Observed = "Chiave non presente"
                $risultato.Evidence = @{ Path = $percorso; Exists = $false }
            }
            else {
                $risultato.Status = 'sconosciuto'
                $risultato.Observed = "Chiave di registro non trovata: $percorso"
                $risultato.Evidence = @{ Path = $percorso; Exists = $false }
            }
            return $risultato
        }

        # Leggi il valore
        $prop = Get-ItemProperty -LiteralPath $percorso -Name $nome -ErrorAction Stop
        if (-not $prop.PSObject.Properties[$nome]) {
            throw [System.Management.Automation.PSArgumentException]::new("Valore di registro non trovato: $nome")
        }
        $valoreCorrente = $prop.$nome

        $risultato.Observed = $valoreCorrente
        $risultato.Evidence = @{
            Path  = $percorso
            Name  = $nome
            Value = $valoreCorrente
        }

        # Confronto con l'operatore specificato
        $superato = $false
        switch ($operatore) {
            'eq'        { $superato = ($valoreCorrente -eq $atteso) }
            'ne'        { $superato = ($valoreCorrente -ne $atteso) }
            'ge'        { $superato = ($valoreCorrente -ge $atteso) }
            'le'        { $superato = ($valoreCorrente -le $atteso) }
            'exists'    { $superato = $true }  # Se siamo qui, il valore esiste
            'notexists' { $superato = $false } # Se siamo qui, il valore esiste (non dovrebbe)
            default     {
                $risultato.Status = 'errore'
                $risultato.Error = "Operatore non supportato: $operatore"
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
        # Accesso negato: il dato non e' disponibile, non e' un fallimento del controllo
        $risultato.Status = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave di registro"
        $risultato.Error = $_.Exception.Message
    }
    catch [System.Management.Automation.PSArgumentException] {
        # Il valore specifico non esiste nella chiave
        if ($operatore -eq 'notexists') {
            $risultato.Status = 'superato'
            $risultato.Observed = "Valore non presente"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
        elseif ($operatore -eq 'exists') {
            $risultato.Status = 'fallito'
            $risultato.Observed = "Valore non presente"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
        else {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Valore di registro non trovato: $nome"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
    }
    catch [System.Management.Automation.ItemNotFoundException] {
        # Il valore specifico non esiste nella chiave
        if ($operatore -eq 'notexists') {
            $risultato.Status = 'superato'
            $risultato.Observed = "Valore non presente"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
        elseif ($operatore -eq 'exists') {
            $risultato.Status = 'fallito'
            $risultato.Observed = "Valore non presente"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
        else {
            $risultato.Status = 'sconosciuto'
            $risultato.Observed = "Valore di registro non trovato: $nome"
            $risultato.Evidence = @{ Path = $percorso; Name = $nome; Exists = $false }
        }
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error = $_.Exception.Message
    }

    return $risultato
}
