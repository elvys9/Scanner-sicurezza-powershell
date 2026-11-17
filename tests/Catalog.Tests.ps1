<#
.SYNOPSIS
    Test Pester 5 per il modulo Catalog.
#>

Set-StrictMode -Version 2

Describe 'Import-Catalogo' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Catalog.ps1'
        . $percorsoModulo

        # Crea un catalogo di test valido
        $catalogoValido = @{
            schema_version = '0.2'
            profile = @{
                name = 'test'
                description = 'Profilo di test'
                target_os = 'Windows 11'
            }
            controls = @(
                @{
                    id = 'TEST-001'
                    title = 'Test'
                    category = 'Test'
                    severity = 'medio'
                    editions = @('Home', 'Pro')
                    description = 'Test'
                    rationale = 'Test'
                    check = @{}
                }
            )
        }

        $percorsoTemp = Join-Path $TestDrive 'catalogo_valido.json'
        $catalogoValido | ConvertTo-Json -Depth 10 | Out-File -FilePath $percorsoTemp -Encoding UTF8
    }

    It 'Carica un catalogo JSON valido' {
        $percorsoTemp = Join-Path $TestDrive 'catalogo_valido.json'
        $catalogo = Import-Catalogo -PercorsoCatalogo $percorsoTemp
        $catalogo | Should -Not -BeNullOrEmpty
        $catalogo.schema_version | Should -Be '0.2'
    }

    It 'Lancia eccezione se il file non esiste' {
        { Import-Catalogo -PercorsoCatalogo 'C:\inesistente\catalogo.json' } | Should -Throw '*non esiste*'
    }

    It 'Lancia eccezione per JSON non valido' {
        $percorsoInvalido = Join-Path $TestDrive 'invalido.json'
        'questo non e json' | Out-File -FilePath $percorsoInvalido -Encoding UTF8
        { Import-Catalogo -PercorsoCatalogo $percorsoInvalido } | Should -Throw '*JSON*'
    }

    It 'Lancia eccezione per ID duplicati' {
        $catalogoDuplicati = @{
            schema_version = '0.2'
            profile = @{ name = 'test'; description = 'Test'; target_os = 'Win11' }
            controls = @(
                @{ id = 'DUP-001'; title = 'A'; category = 'Test'; severity = 'medio'; editions = @('Home'); description = 'x'; rationale = 'x'; check = @{} }
                @{ id = 'DUP-001'; title = 'B'; category = 'Test'; severity = 'medio'; editions = @('Home'); description = 'x'; rationale = 'x'; check = @{} }
            )
        }
        $percorsoDup = Join-Path $TestDrive 'duplicati.json'
        $catalogoDuplicati | ConvertTo-Json -Depth 10 | Out-File -FilePath $percorsoDup -Encoding UTF8
        { Import-Catalogo -PercorsoCatalogo $percorsoDup } | Should -Throw '*duplicato*'
    }

    It 'Lancia eccezione per schema_version non supportata' {
        $catalogoVecchio = @{
            schema_version = '99.0'
            profile = @{ name = 'test'; description = 'Test'; target_os = 'Win11' }
            controls = @(
                @{ id = 'OLD-001'; title = 'Old'; category = 'Test'; severity = 'medio'; editions = @('Home'); description = 'x'; rationale = 'x'; check = @{} }
            )
        }
        $percorsoVecchio = Join-Path $TestDrive 'vecchio.json'
        $catalogoVecchio | ConvertTo-Json -Depth 10 | Out-File -FilePath $percorsoVecchio -Encoding UTF8
        { Import-Catalogo -PercorsoCatalogo $percorsoVecchio } | Should -Throw '*non supportata*'
    }

    It 'Carica il catalogo reale del progetto' {
        $percorsoReale = Join-Path $PSScriptRoot '..\catalog\home_profile.json'
        if (Test-Path $percorsoReale) {
            $catalogo = Import-Catalogo -PercorsoCatalogo $percorsoReale
            $catalogo.controls.Count | Should -BeGreaterThan 0
        }
        else {
            Set-ItResult -Skipped -Because "Il file home_profile.json non esiste (eseguire yaml_to_json.py)"
        }
    }
}
