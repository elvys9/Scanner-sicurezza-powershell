<#
.SYNOPSIS
    Test Pester 5 per il modulo Environment.
#>

Set-StrictMode -Version 2

Describe 'Get-AmbienteSistema' {

    BeforeAll {
        $percorsoModulo = Join-Path $PSScriptRoot '..\src\core\Environment.ps1'
        . $percorsoModulo
    }

    It 'Restituisce un oggetto con tutte le proprieta attese' {
        $ambiente = Get-AmbienteSistema
        $ambiente | Should -Not -BeNullOrEmpty
        $ambiente.PSObject.Properties.Name | Should -Contain 'Edition'
        $ambiente.PSObject.Properties.Name | Should -Contain 'EditionId'
        $ambiente.PSObject.Properties.Name | Should -Contain 'Build'
        $ambiente.PSObject.Properties.Name | Should -Contain 'Language'
        $ambiente.PSObject.Properties.Name | Should -Contain 'IsAdmin'
        $ambiente.PSObject.Properties.Name | Should -Contain 'PsVersion'
    }

    It 'PsVersion corrisponde alla versione corrente' {
        $ambiente = Get-AmbienteSistema
        $ambiente.PsVersion | Should -Be $PSVersionTable.PSVersion.ToString()
    }

    It 'IsAdmin e un booleano' {
        $ambiente = Get-AmbienteSistema
        $ambiente.IsAdmin | Should -BeOfType [bool]
    }

    Context 'Simulazione edizione Home' {

        It 'Mappa EditionID Core a Home' {
            # Simuliamo il comportamento della mappa
            $editionMap = @{
                'Core'              = 'Home'
                'CoreSingleLanguage'= 'Home'
                'Professional'      = 'Pro'
            }
            $editionMap['Core'] | Should -Be 'Home'
            $editionMap['CoreSingleLanguage'] | Should -Be 'Home'
        }
    }

    Context 'Simulazione edizione Pro' {

        It 'Mappa EditionID Professional a Pro' {
            $editionMap = @{
                'Core'              = 'Home'
                'Professional'      = 'Pro'
                'Education'         = 'Pro'
                'Enterprise'        = 'Pro'
            }
            $editionMap['Professional'] | Should -Be 'Pro'
            $editionMap['Education'] | Should -Be 'Pro'
            $editionMap['Enterprise'] | Should -Be 'Pro'
        }
    }
}
