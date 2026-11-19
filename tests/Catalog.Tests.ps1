<#
.SYNOPSIS
    Pester 5 tests for the Catalog module.
#>

Set-StrictMode -Version 2

Describe 'Import-Catalogo' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Catalog.ps1'
        . $percorsoModulo

        # Create a valid test catalog
        $catalogoValido = @{
            schema_version = '0.2'
            profile = @{
                name = 'test'
                description = 'Test profile'
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

        $percorsoTemp = Join-Path $TestDrive 'valid_catalog.json'
        $catalogoValido | ConvertTo-Json -Depth 10 | Out-File -FilePath $percorsoTemp -Encoding UTF8
    }

    It 'Loads a valid JSON catalog' {
        $percorsoTemp = Join-Path $TestDrive 'valid_catalog.json'
        $catalogo = Import-Catalogo -PercorsoCatalogo $percorsoTemp
        $catalogo | Should -Not -BeNullOrEmpty
        $catalogo.schema_version | Should -Be '0.2'
    }

    It 'Throws when the catalog file does not exist' {
        { Import-Catalogo -PercorsoCatalogo 'C:\nonexistent\catalog.json' } | Should -Throw '*not found*'
    }

    It 'Throws on invalid JSON content' {
        $percorsoInvalido = Join-Path $TestDrive 'invalid.json'
        'this is not json' | Out-File -FilePath $percorsoInvalido -Encoding UTF8
        { Import-Catalogo -PercorsoCatalogo $percorsoInvalido } | Should -Throw '*JSON*'
    }

    It 'Throws on duplicate control IDs' {
        $catalogoDuplicati = @{
            schema_version = '0.2'
            profile = @{ name = 'test'; description = 'Test'; target_os = 'Win11' }
            controls = @(
                @{ id = 'DUP-001'; title = 'A'; category = 'Test'; severity = 'medio'; editions = @('Home'); description = 'x'; rationale = 'x'; check = @{} }
                @{ id = 'DUP-001'; title = 'B'; category = 'Test'; severity = 'medio'; editions = @('Home'); description = 'x'; rationale = 'x'; check = @{} }
            )
        }
        $percorsoDup = Join-Path $TestDrive 'duplicates.json'
        $catalogoDuplicati | ConvertTo-Json -Depth 10 | Out-File -FilePath $percorsoDup -Encoding UTF8
        { Import-Catalogo -PercorsoCatalogo $percorsoDup } | Should -Throw '*Duplicate*'
    }

    It 'Throws on unsupported schema_version' {
        $catalogoVecchio = @{
            schema_version = '99.0'
            profile = @{ name = 'test'; description = 'Test'; target_os = 'Win11' }
            controls = @(
                @{ id = 'OLD-001'; title = 'Old'; category = 'Test'; severity = 'medio'; editions = @('Home'); description = 'x'; rationale = 'x'; check = @{} }
            )
        }
        $percorsoVecchio = Join-Path $TestDrive 'old.json'
        $catalogoVecchio | ConvertTo-Json -Depth 10 | Out-File -FilePath $percorsoVecchio -Encoding UTF8
        { Import-Catalogo -PercorsoCatalogo $percorsoVecchio } | Should -Throw '*Unsupported*'
    }

    It 'Loads the real project catalog' {
        $percorsoReale = Join-Path $PSScriptRoot '..\catalog\home_profile.json'
        if (Test-Path $percorsoReale) {
            $catalogo = Import-Catalogo -PercorsoCatalogo $percorsoReale
            $catalogo.controls.Count | Should -BeGreaterThan 0
        }
        else {
            Set-ItResult -Skipped -Because "home_profile.json does not exist (run tools/yaml_to_json.py)"
        }
    }
}
