<#
.SYNOPSIS
    Test Pester 5 — Test di integrazione end-to-end.

.DESCRIPTION
    Esegue lo scanner completo e verifica il JSON di output:
    - Lo schema del risultato e' rispettato
    - Il file e' UTF-8 senza BOM
    - Il riepilogo corrisponde ai risultati
#>

Set-StrictMode -Version 2

Describe 'Integrazione: JSON di output' {

    BeforeAll {
        $percorsoCore = Join-Path $PSScriptRoot '..\src\core'
        . (Join-Path $percorsoCore 'Environment.ps1')
        . (Join-Path $percorsoCore 'Catalog.ps1')
        . (Join-Path $percorsoCore 'Runner.ps1')
        . (Join-Path $percorsoCore 'Report.ps1')
        . (Join-Path $percorsoCore 'Checks\Registry.ps1')
        . (Join-Path $percorsoCore 'Checks\Firewall.ps1')
        . (Join-Path $percorsoCore 'Checks\Accounts.ps1')

        $percorsoChecks = Join-Path $PSScriptRoot '..\src\core\Checks'

        # Mock per rendere i test riproducibili
        Mock Get-NetFirewallProfile {
            return @(
                [PSCustomObject]@{ Name = 'Domain';  Enabled = $true }
                [PSCustomObject]@{ Name = 'Private'; Enabled = $true }
                [PSCustomObject]@{ Name = 'Public';  Enabled = $true }
            )
        }
        Mock Get-LocalUser {
            return @(
                [PSCustomObject]@{
                    Name    = 'Guest'
                    SID     = [PSCustomObject]@{ Value = 'S-1-5-21-123-456-789-501' }
                    Enabled = $false
                }
            )
        }
        Mock Test-Path {
            if ($LiteralPath -eq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System') {
                return $true
            }
            return ([System.IO.File]::Exists($LiteralPath) -or [System.IO.Directory]::Exists($LiteralPath))
        }
        Mock Get-ItemProperty {
            return [PSCustomObject]@{ EnableLUA = 1 }
        } -ParameterFilter {
            $LiteralPath -eq 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -and $Name -eq 'EnableLUA'
        }
    }

    It 'Genera un JSON valido conforme al contratto' {
        $ambiente = [PSCustomObject]@{
            Edition   = 'Home'
            EditionId = 'Core'
            Build     = '22631.1234'
            Language  = 'it-IT'
            IsAdmin   = $true
            PsVersion = '5.1.22621.1234'
        }

        $catalogo = [PSCustomObject]@{
            schema_version = '0.2'
            controls = @(
                [PSCustomObject]@{
                    id = 'HOME-FW-001'
                    title = 'Firewall'
                    editions = @('Home', 'Pro')
                    check = [PSCustomObject]@{ command_ref = 'Firewall.ps1#Test-FirewallProfiles' }
                }
                [PSCustomObject]@{
                    id = 'HOME-UAC-001'
                    title = 'UAC'
                    editions = @('Home', 'Pro')
                    check = [PSCustomObject]@{
                        registry = [PSCustomObject]@{
                            path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                            name = 'EnableLUA'
                            operator = 'eq'
                            value = 1
                        }
                    }
                }
                [PSCustomObject]@{
                    id = 'HOME-ACC-001'
                    title = 'Guest'
                    editions = @('Home', 'Pro')
                    check = [PSCustomObject]@{ command_ref = 'Accounts.ps1#Test-GuestAccount' }
                }
            )
        }

        $risultati = Invoke-Controlli -Catalogo $catalogo -Ambiente $ambiente -CartellaChecks $percorsoChecks
        $report = New-Report -Risultati $risultati -Ambiente $ambiente -Catalogo $catalogo

        $percorsoFile = Join-Path $TestDrive 'integrazione.json'
        Export-ReportJson -Report $report -PercorsoFile $percorsoFile

        # 1. Il file esiste
        Test-Path -LiteralPath $percorsoFile | Should -Be $true

        # 2. E' JSON valido
        $contenuto = Get-Content -LiteralPath $percorsoFile -Raw -Encoding UTF8
        $json = $contenuto | ConvertFrom-Json

        # 3. Campi obbligatori del contratto
        $json.schema_version | Should -Be '0.1'
        $json.run_id | Should -Not -BeNullOrEmpty
        $json.timestamp | Should -Not -BeNullOrEmpty
        $json.tool_version | Should -Not -BeNullOrEmpty
        $json.catalog_version | Should -Not -BeNullOrEmpty
        $json.environment | Should -Not -BeNullOrEmpty
        $json.results | Should -Not -BeNullOrEmpty
        $json.summary | Should -Not -BeNullOrEmpty

        # 4. Tre risultati
        @($json.results).Count | Should -Be 3

        # 5. Ogni risultato ha i campi obbligatori
        foreach ($r in $json.results) {
            $r.PSObject.Properties.Name | Should -Contain 'control_id'
            $r.PSObject.Properties.Name | Should -Contain 'status'
            $r.PSObject.Properties.Name | Should -Contain 'observed'
            $r.PSObject.Properties.Name | Should -Contain 'expected'
            $r.PSObject.Properties.Name | Should -Contain 'evidence'
            $r.PSObject.Properties.Name | Should -Contain 'error'
            $r.PSObject.Properties.Name | Should -Contain 'duration_ms'
            $r.status | Should -BeIn @('superato', 'fallito', 'non_applicabile', 'sconosciuto', 'errore')
        }

        # 6. Il riepilogo corrisponde ai risultati
        $statiPossibili = @('superato', 'fallito', 'non_applicabile', 'sconosciuto', 'errore')
        foreach ($stato in $statiPossibili) {
            $conteggioRisultati = @($json.results | Where-Object { $_.status -eq $stato }).Count
            $conteggioSummary = $json.summary.$stato
            $conteggioSummary | Should -Be $conteggioRisultati -Because "Il riepilogo per '$stato' deve corrispondere ai risultati"
        }
    }

    It 'Il file JSON e in UTF-8 senza BOM' {
        $ambiente = [PSCustomObject]@{
            Edition = 'Home'; EditionId = 'Core'; Build = '22631.1'; Language = 'it-IT'; IsAdmin = $true; PsVersion = '5.1'
        }
        $catalogo = [PSCustomObject]@{
            schema_version = '0.2'
            controls = @(
                [PSCustomObject]@{
                    id = 'HOME-FW-001'; title = 'FW'; editions = @('Home', 'Pro')
                    check = [PSCustomObject]@{ command_ref = 'Firewall.ps1#Test-FirewallProfiles' }
                }
            )
        }

        $risultati = Invoke-Controlli -Catalogo $catalogo -Ambiente $ambiente -CartellaChecks $percorsoChecks
        $report = New-Report -Risultati $risultati -Ambiente $ambiente -Catalogo $catalogo

        $percorsoFile = Join-Path $TestDrive 'bom_test.json'
        Export-ReportJson -Report $report -PercorsoFile $percorsoFile

        $bytes = [System.IO.File]::ReadAllBytes($percorsoFile)
        if ($bytes.Length -ge 3) {
            $haBom = ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
            $haBom | Should -Be $false -Because "Il JSON di output deve essere UTF-8 senza BOM"
        }
    }

    It 'I tre ID della fetta sono presenti nei risultati' {
        $ambiente = [PSCustomObject]@{
            Edition = 'Home'; EditionId = 'Core'; Build = '22631.1'; Language = 'it-IT'; IsAdmin = $true; PsVersion = '5.1'
        }
        $catalogo = [PSCustomObject]@{
            schema_version = '0.2'
            controls = @(
                [PSCustomObject]@{
                    id = 'HOME-FW-001'; title = 'FW'; editions = @('Home', 'Pro')
                    check = [PSCustomObject]@{ command_ref = 'Firewall.ps1#Test-FirewallProfiles' }
                }
                [PSCustomObject]@{
                    id = 'HOME-UAC-001'; title = 'UAC'; editions = @('Home', 'Pro')
                    check = [PSCustomObject]@{
                        registry = [PSCustomObject]@{
                            path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
                            name = 'EnableLUA'; operator = 'eq'; value = 1
                        }
                    }
                }
                [PSCustomObject]@{
                    id = 'HOME-ACC-001'; title = 'Guest'; editions = @('Home', 'Pro')
                    check = [PSCustomObject]@{ command_ref = 'Accounts.ps1#Test-GuestAccount' }
                }
            )
        }

        $risultati = Invoke-Controlli -Catalogo $catalogo -Ambiente $ambiente -CartellaChecks $percorsoChecks
        $report = New-Report -Risultati $risultati -Ambiente $ambiente -Catalogo $catalogo

        $percorsoFile = Join-Path $TestDrive 'tre_id.json'
        Export-ReportJson -Report $report -PercorsoFile $percorsoFile

        $json = Get-Content -LiteralPath $percorsoFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $ids = @($json.results | ForEach-Object { $_.control_id })

        $ids | Should -Contain 'HOME-FW-001'
        $ids | Should -Contain 'HOME-UAC-001'
        $ids | Should -Contain 'HOME-ACC-001'
    }
}
