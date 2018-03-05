<#
.DESCRIPTION
Displays the settings for a Windows customization configuration file.
#>
[CmdletBinding()]
param(
    [Parameter(HelpMessage='Configuration file to load')]
    [string]$Configuration = (Join-Path $PSScriptRoot 'config.json')
)

begin {
    try {
        $Definitions = Get-Content 'definitions.json' | ConvertFrom-Json
        $Definitions = $Definitions | Sort-Object -Property 'Group'
    }
    catch {
        throw 'Unable to load the definitions.json file!'
    }

    # Create a hash of lookup values (minus any 'skip' options)
    $DefinitionLookup = @{}
    Foreach ($Def in $Definitions) {
        $Def.Choices | ForEach-Object {
            if ($_ -ne '&Skip') {
                $key = ($_ -replace '&','')
                Write-Verbose "Adding Definition: $Key"
                Write-Verbose "       Group: $($Def.Group)"
                Write-Verbose "       Description: $($Def.Description)"
                $DefinitionLookup[$key] = @($Def.Group, $Def.Description)
            }
        }
    }
    
    try {
        $Config = Get-Content $Configuration | ConvertFrom-Json 
    }
    catch {
        throw "Unable to load the configuration file: $Configuration"
    }

    $Config | ForEach-Object {
        Write-Verbose "Action = $_"
        New-Object -TypeName psobject -Property @{
            'Action' = $_
            'Category' = $DefinitionLookup[$_][0]
            'Description' = $DefinitionLookup[$_][1]
        }
    }
}