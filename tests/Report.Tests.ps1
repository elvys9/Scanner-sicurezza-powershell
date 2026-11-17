<#
.SYNOPSIS
    Test Pester 5 per il modulo Report.
#>

Set-StrictMode -Version 2

Describe 'New-Report' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Report.ps1'
        . $percorsoModulo

        $ambienteFittizio = [PSCustomObject]@{
            Edition   = 'Home'
            EditionId = 'Core'
            Build     = '22631.1234'
            Language  = 'it-IT'
            IsAdmin   = $true
            PsVersion = '5.1.22621.1234'
        }

        $catalogoFittizio = [PSCustomObject]@{
            schema_version = '0.2'
        }
    }

    Context 'Generazione report' {

        It 'Genera un report con la struttura corretta' {
            $risultati = @(
                [PSCustomObject]@{ control_id = 'HOME-FW-001'; status = 'superato'; observed = 'ok'; expected = 'ok'; evidence = $null; error = $null; duration_ms = 10 }
                [PSCustomObject]@{ control_id = 'HOME-UAC-001'; status = 'fallito'; observed = '0'; expected = '1'; evidence = $null; error = $null; duration_ms = 5 }
                [PSCustomObject]@{ control_id = 'HOME-ACC-001'; status = 'sconosciuto'; observed = $null; expected = $null; evidence = $null; error = 'errore test'; duration_ms = 2 }
            )

            $report = New-Report -Risultati $risultati -Ambiente $ambienteFittizio -Catalogo $catalogoFittizio

            $report.schema_version | Should -Be '0.1'
            $report.run_id | Should -Not -BeNullOrEmpty
            $report.timestamp | Should -Not -BeNullOrEmpty
            $report.tool_version | Should -Not -BeNullOrEmpty
            $report.catalog_version | Should -Be '0.2'
            $report.environment | Should -Not -BeNullOrEmpty
            $report.results.Count | Should -Be 3
            $report.summary | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Riepilogo calcolato correttamente' {

        It 'Conta correttamente gli stati' {
            $risultati = @(
                [PSCustomObject]@{ control_id = 'A'; status = 'superato'; observed = $null; expected = $null; evidence = $null; error = $null; duration_ms = 0 }
                [PSCustomObject]@{ control_id = 'B'; status = 'superato'; observed = $null; expected = $null; evidence = $null; error = $null; duration_ms = 0 }
                [PSCustomObject]@{ control_id = 'C'; status = 'fallito'; observed = $null; expected = $null; evidence = $null; error = $null; duration_ms = 0 }
                [PSCustomObject]@{ control_id = 'D'; status = 'non_applicabile'; observed = $null; expected = $null; evidence = $null; error = $null; duration_ms = 0 }
                [PSCustomObject]@{ control_id = 'E'; status = 'errore'; observed = $null; expected = $null; evidence = $null; error = 'err'; duration_ms = 0 }
            )

            $report = New-Report -Risultati $risultati -Ambiente $ambienteFittizio -Catalogo $catalogoFittizio

            $report.summary.superato | Should -Be 2
            $report.summary.fallito | Should -Be 1
            $report.summary.non_applicabile | Should -Be 1
            $report.summary.sconosciuto | Should -Be 0
            $report.summary.errore | Should -Be 1
        }
    }

    Context 'Ambiente nel report' {

        It 'Contiene le informazioni ambiente corrette' {
            $risultati = @()
            $report = New-Report -Risultati $risultati -Ambiente $ambienteFittizio -Catalogo $catalogoFittizio

            $report.environment.edition | Should -Be 'Home'
            $report.environment.build | Should -Be '22631.1234'
            $report.environment.language | Should -Be 'it-IT'
            $report.environment.is_admin | Should -Be $true
            $report.environment.ps_version | Should -Be '5.1.22621.1234'
        }
    }
}

Describe 'Export-ReportJson' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Report.ps1'
        . $percorsoModulo
    }

    It 'Scrive un file JSON valido in UTF-8 senza BOM' {
        $risultati = @(
            [PSCustomObject]@{ control_id = 'TEST-001'; status = 'superato'; observed = 'ok'; expected = 'ok'; evidence = $null; error = $null; duration_ms = 1 }
        )
        $ambiente = [PSCustomObject]@{
            Edition = 'Home'; EditionId = 'Core'; Build = '22631.1'; Language = 'it-IT'; IsAdmin = $true; PsVersion = '5.1'
        }
        $catalogo = [PSCustomObject]@{ schema_version = '0.2' }

        $report = New-Report -Risultati $risultati -Ambiente $ambiente -Catalogo $catalogo

        $percorsoFile = Join-Path $TestDrive 'test_output.json'
        Export-ReportJson -Report $report -PercorsoFile $percorsoFile

        # Verifica che il file esiste
        Test-Path -LiteralPath $percorsoFile | Should -Be $true

        # Verifica che e' JSON valido
        $contenuto = Get-Content -LiteralPath $percorsoFile -Raw -Encoding UTF8
        $json = $contenuto | ConvertFrom-Json
        $json.schema_version | Should -Be '0.1'

        # Verifica UTF-8 senza BOM
        $bytes = [System.IO.File]::ReadAllBytes($percorsoFile)
        # BOM UTF-8 = 0xEF 0xBB 0xBF
        if ($bytes.Length -ge 3) {
            $haBom = ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF)
            $haBom | Should -Be $false
        }
    }

    It 'Il riepilogo corrisponde ai risultati' {
        $risultati = @(
            [PSCustomObject]@{ control_id = 'A'; status = 'superato'; observed = $null; expected = $null; evidence = $null; error = $null; duration_ms = 0 }
            [PSCustomObject]@{ control_id = 'B'; status = 'fallito'; observed = $null; expected = $null; evidence = $null; error = $null; duration_ms = 0 }
        )
        $ambiente = [PSCustomObject]@{
            Edition = 'Pro'; EditionId = 'Professional'; Build = '22631.1'; Language = 'en-US'; IsAdmin = $false; PsVersion = '5.1'
        }
        $catalogo = [PSCustomObject]@{ schema_version = '0.2' }

        $report = New-Report -Risultati $risultati -Ambiente $ambiente -Catalogo $catalogo

        $percorsoFile = Join-Path $TestDrive 'riepilogo.json'
        Export-ReportJson -Report $report -PercorsoFile $percorsoFile

        $json = Get-Content -LiteralPath $percorsoFile -Raw -Encoding UTF8 | ConvertFrom-Json

        # Conta manualmente
        $conteggioSuperato = @($json.results | Where-Object { $_.status -eq 'superato' }).Count
        $conteggioFallito = @($json.results | Where-Object { $_.status -eq 'fallito' }).Count

        $json.summary.superato | Should -Be $conteggioSuperato
        $json.summary.fallito | Should -Be $conteggioFallito
    }
}
