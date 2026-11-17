<#
.SYNOPSIS
    Controlli di sicurezza di sistema: Windows Update, BitLocker, Telemetria,
    Secure Boot, Protezione LSA e PowerShell Script Block Logging.

.DESCRIPTION
    Contiene i controlli per:
    - HOME-UPD-001: Aggiornamenti automatici abilitati (Test-WindowsUpdateEnabled)
    - HOME-ENC-001: BitLocker attivo sul disco di sistema (Test-BitLockerSystemDrive)
    - HOME-PRV-001: Telemetria impostata al livello minimo (Test-TelemetryMinimum)
    - HOME-SEC-001: Avvio protetto Secure Boot attivo (Test-SecureBoot)
    - HOME-SEC-002: Protezione LSA abilitata RunAsPPL (Test-LsaProtection)
    - HOME-SEC-003: PowerShell Script Block Logging abilitato (Test-PsScriptBlockLogging)
    Non modifica mai lo stato del sistema.
#>

Set-StrictMode -Version 2

function Test-WindowsUpdateEnabled {
    <#
    .SYNOPSIS
        Verifica che il servizio Windows Update non sia disabilitato e che le policy
        non disattivino gli aggiornamenti automatici.
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
        Expected = "Servizio wuauserv abilitato (Start != 4) e policy NoAutoUpdate != 1"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoServizio = 'HKLM:\SYSTEM\CurrentControlSet\Services\wuauserv'
        $percorsoPolicyAu = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'

        if (-not (Test-Path -LiteralPath $percorsoServizio)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Chiave del servizio wuauserv non trovata"
            return $risultato
        }

        $propSvc = Get-ItemProperty -LiteralPath $percorsoServizio -ErrorAction Stop
        $startVal = if ($null -ne $propSvc.PSObject.Properties['Start']) { [int]$propSvc.Start } else { 3 }

        $noAutoUpdate = 0
        if (Test-Path -LiteralPath $percorsoPolicyAu) {
            $propAu = Get-ItemProperty -LiteralPath $percorsoPolicyAu -ErrorAction SilentlyContinue
            if ($null -ne $propAu -and $null -ne $propAu.PSObject.Properties['NoAutoUpdate'] -and $null -ne $propAu.NoAutoUpdate) {
                $noAutoUpdate = [int]$propAu.NoAutoUpdate
            }
        }

        $risultato.Evidence = @{
            WuauservStart = $startVal
            NoAutoUpdate  = $noAutoUpdate
        }

        # Start = 4 significa Disabled
        if ($startVal -eq 4) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Il servizio Windows Update (wuauserv) e' disabilitato (Start = 4)"
        }
        elseif ($noAutoUpdate -eq 1) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Gli aggiornamenti automatici sono disabilitati tramite policy (NoAutoUpdate = 1)"
        }
        else {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Windows Update abilitato (wuauserv Start = $startVal, NoAutoUpdate = $noAutoUpdate)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla configurazione di Windows Update"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-BitLockerSystemDrive {
    <#
    .SYNOPSIS
        Verifica che BitLocker sia attivo sulla partizione di sistema.
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
        Expected = "Crittografia BitLocker attiva sul disco di sistema"
        Evidence = $null
        Error    = $null
    }

    $discoSistema = if ($env:SystemDrive) { $env:SystemDrive } else { 'C:' }

    try {
        # Tenta prima con Get-BitLockerVolume (richiede privilegi di amministratore)
        if (Get-Command -Name 'Get-BitLockerVolume' -ErrorAction SilentlyContinue) {
            try {
                $vol = Get-BitLockerVolume -MountPoint $discoSistema -ErrorAction Stop
                $statoProt = [string]$vol.ProtectionStatus
                $statoVol  = [string]$vol.VolumeStatus

                $risultato.Evidence = @{
                    MountPoint       = $discoSistema
                    ProtectionStatus = $statoProt
                    VolumeStatus     = $statoVol
                    Fonte            = 'Get-BitLockerVolume'
                }

                if ($statoProt -eq 'On' -or $statoProt -eq '1') {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "BitLocker attivo su $discoSistema (ProtectionStatus = $statoProt)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "BitLocker non attivo su $discoSistema (ProtectionStatus = $statoProt, VolumeStatus = $statoVol)"
                }
                return $risultato
            }
            catch {
                # Se fallisce per permessi non-admin, prosegue col controllo registro BitLockerStatus
            }
        }

        # Lettura da registro HKLM:\SYSTEM\CurrentControlSet\Control\BitLockerStatus (accessibile anche senza admin)
        $percorsoBl = 'HKLM:\SYSTEM\CurrentControlSet\Control\BitLockerStatus'
        if (Test-Path -LiteralPath $percorsoBl) {
            $propBl = Get-ItemProperty -LiteralPath $percorsoBl -ErrorAction Stop
            if ($null -ne $propBl.PSObject.Properties['BootStatus'] -and $null -ne $propBl.BootStatus) {
                $bootStatus = [int]$propBl.BootStatus
                $risultato.Evidence = @{
                    MountPoint = $discoSistema
                    BootStatus = $bootStatus
                    Fonte      = 'BitLockerStatusRegistry'
                }
                if ($bootStatus -ge 1) {
                    $risultato.Status   = 'superato'
                    $risultato.Observed = "Crittografia disco di avvio attiva (BootStatus = $bootStatus)"
                }
                else {
                    $risultato.Status   = 'fallito'
                    $risultato.Observed = "Crittografia BitLocker non attiva sul disco di sistema (BootStatus = 0)"
                }
                return $risultato
            }
        }

        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Stato BitLocker non determinabile (eseguire come amministratore)"
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-TelemetryMinimum {
    <#
    .SYNOPSIS
        Verifica che il livello di telemetria di Windows (AllowTelemetry) sia impostato al minimo (<= 1).
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
        Expected = "AllowTelemetry <= 1 (Dati diagnostici obbligatori / minimo)"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoPolicy  = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        $percorsoDefault = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'

        $valoreTrovato = $null
        $chiaveUsata   = $null

        if (Test-Path -LiteralPath $percorsoPolicy) {
            $propPol = Get-ItemProperty -LiteralPath $percorsoPolicy -ErrorAction SilentlyContinue
            if ($null -ne $propPol -and $null -ne $propPol.PSObject.Properties['AllowTelemetry'] -and $null -ne $propPol.AllowTelemetry) {
                $valoreTrovato = [int]$propPol.AllowTelemetry
                $chiaveUsata   = $percorsoPolicy
            }
        }

        if ($null -eq $valoreTrovato -and (Test-Path -LiteralPath $percorsoDefault)) {
            $propDef = Get-ItemProperty -LiteralPath $percorsoDefault -ErrorAction SilentlyContinue
            if ($null -ne $propDef -and $null -ne $propDef.PSObject.Properties['AllowTelemetry'] -and $null -ne $propDef.AllowTelemetry) {
                $valoreTrovato = [int]$propDef.AllowTelemetry
                $chiaveUsata   = $percorsoDefault
            }
        }

        if ($null -eq $valoreTrovato) {
            # Se AllowTelemetry non e' configurato, Windows usa il livello predefinito (3 = Full/Optional)
            $risultato.Status   = 'fallito'
            $risultato.Observed = "AllowTelemetry non limitato (livello predefinito completo attivo)"
            $risultato.Evidence = @{ Configured = $false }
            return $risultato
        }

        $risultato.Evidence = @{
            Path           = $chiaveUsata
            AllowTelemetry = $valoreTrovato
        }

        if ($valoreTrovato -le 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "AllowTelemetry = $valoreTrovato (livello minimo)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "AllowTelemetry = $valoreTrovato (superiore al livello minimo 1)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave di registro DataCollection"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-SecureBoot {
    <#
    .SYNOPSIS
        Verifica che l'avvio protetto UEFI (Secure Boot) sia abilitato.
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
        Expected = "UEFISecureBootEnabled = 1 (Secure Boot attivo)"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoSb = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State'
        if (-not (Test-Path -LiteralPath $percorsoSb)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Stato Secure Boot non presente (possibile sistema BIOS legacy)"
            $risultato.Evidence = @{ KeyExists = $false }
            return $risultato
        }

        $propSb = Get-ItemProperty -LiteralPath $percorsoSb -ErrorAction Stop
        if ($null -eq $propSb.PSObject.Properties['UEFISecureBootEnabled']) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Valore UEFISecureBootEnabled non trovato"
            return $risultato
        }

        $sbVal = [int]$propSb.UEFISecureBootEnabled
        $risultato.Evidence = @{
            Path                  = $percorsoSb
            UEFISecureBootEnabled = $sbVal
        }

        if ($sbVal -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Secure Boot attivo (UEFISecureBootEnabled = 1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Secure Boot disattivato (UEFISecureBootEnabled = $sbVal)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave SecureBoot"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-LsaProtection {
    <#
    .SYNOPSIS
        Verifica che la protezione del processo LSA (RunAsPPL) sia abilitata.
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
        Expected = "RunAsPPL >= 1 oppure RunAsPPLBoot >= 1 in HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoLsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
        if (-not (Test-Path -LiteralPath $percorsoLsa)) {
            $risultato.Status   = 'sconosciuto'
            $risultato.Observed = "Chiave di registro LSA non trovata"
            return $risultato
        }

        $propLsa = Get-ItemProperty -LiteralPath $percorsoLsa -ErrorAction Stop
        $runAsPpl = if ($null -ne $propLsa.PSObject.Properties['RunAsPPL'] -and $null -ne $propLsa.RunAsPPL) {
            [int]$propLsa.RunAsPPL
        }
        else {
            0
        }

        $runAsPplBoot = if ($null -ne $propLsa.PSObject.Properties['RunAsPPLBoot'] -and $null -ne $propLsa.RunAsPPLBoot) {
            [int]$propLsa.RunAsPPLBoot
        }
        else {
            0
        }

        $risultato.Evidence = @{
            Path         = $percorsoLsa
            RunAsPPL     = $runAsPpl
            RunAsPPLBoot = $runAsPplBoot
        }

        if ($runAsPpl -ge 1 -or $runAsPplBoot -ge 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Protezione LSA attiva (RunAsPPL = $runAsPpl, RunAsPPLBoot = $runAsPplBoot)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Protezione LSA non attiva (RunAsPPL = 0)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave di registro LSA"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}

function Test-PsScriptBlockLogging {
    <#
    .SYNOPSIS
        Verifica che il logging degli script block di PowerShell (EnableScriptBlockLogging) sia abilitato.
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
        Expected = "EnableScriptBlockLogging = 1 in HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
        Evidence = $null
        Error    = $null
    }

    try {
        $percorsoSbl = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
        if (-not (Test-Path -LiteralPath $percorsoSbl)) {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Policy ScriptBlockLogging non configurata (logging disabilitato per impostazione predefinita)"
            $risultato.Evidence = @{ Path = $percorsoSbl; KeyExists = $false }
            return $risultato
        }

        $propSbl = Get-ItemProperty -LiteralPath $percorsoSbl -ErrorAction Stop
        $valore = if ($null -ne $propSbl.PSObject.Properties['EnableScriptBlockLogging'] -and $null -ne $propSbl.EnableScriptBlockLogging) {
            [int]$propSbl.EnableScriptBlockLogging
        }
        else {
            0
        }

        $risultato.Evidence = @{
            Path                     = $percorsoSbl
            EnableScriptBlockLogging = $valore
        }

        if ($valore -eq 1) {
            $risultato.Status   = 'superato'
            $risultato.Observed = "Script Block Logging abilitato (EnableScriptBlockLogging = 1)"
        }
        else {
            $risultato.Status   = 'fallito'
            $risultato.Observed = "Script Block Logging disabilitato (EnableScriptBlockLogging = $valore)"
        }
    }
    catch [System.Security.SecurityException] {
        $risultato.Status   = 'sconosciuto'
        $risultato.Observed = "Accesso negato alla chiave di registro ScriptBlockLogging"
        $risultato.Error    = $_.Exception.Message
    }
    catch {
        $risultato.Status = 'errore'
        $risultato.Error  = $_.Exception.Message
    }

    return $risultato
}
