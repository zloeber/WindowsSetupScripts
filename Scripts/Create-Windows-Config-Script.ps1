<#
.SYNOPSIS
Creates a Windows 10 or Server 2016 Initial Setup Script.
.DESCRIPTION
Creates a Windows 10 or Server 2016 Initial Setup Script.
.PARAMETER OutputScript
Script file output file.
.EXAMPLE
.\Configure-Windows-Config-Script.ps1
.NOTES
Author: Zachary Loeber

Requires the following files:
- Boostrap-Config-Template.ps1
- definitions.json
.LINK
https://github.com/Disassembler0/Win10-Initial-Setup-Script
.LINK
https://github.com/zloeber/WindowsSetupScripts
#>
[CmdletBinding()]
param(
    [string]$OutputScript = 'Bootstrap-WindowsConfig.ps1'
)

begin {
    $tweaks = @()
    function Read-Choice {     
        Param(
            [Parameter(Position = 0)]
            [System.String]$Message, 
         
            [Parameter(Position = 1)]
            [ValidateNotNullOrEmpty()]
            [System.String[]]$Choices = @('&Yes', '&No', 'Yes to &All', 'No &to All'),
         
            [Parameter(Position = 2)]
            [System.Int32]$DefaultChoice = 0, 
         
            [Parameter(Position = 3)]
            [System.String]$Title = [string]::Empty 
        )        
        [System.Management.Automation.Host.ChoiceDescription[]]$Poss = $Choices | ForEach-Object {            
            New-Object System.Management.Automation.Host.ChoiceDescription "$($_)", "Sets $_ as an answer."      
        }       
        $Host.UI.PromptForChoice( $Title, $Message, $Poss, $DefaultChoice )
    }
}
process {}
end {
    Write-Output 'Starting interactive prompting for configuration settings..'
    Write-Output ''
    try {
        $tweakDefinitions = Get-Content 'definitions.json' | ConvertFrom-Json
    }
    catch {
        throw 'Unable to find the definitions.json file required for interactive prompting'
    }
    Write-Host -ForegroundColor Yellow "No configuration file specified, starting interactive mode."
    $tweakDefinitions | Group-Object Group | ForEach-Object {
        Write-Host ''
        Write-Host '** Prompting for ' -NoNewline -Foregroundcolor:Cyan
        Write-Host  $_.Name -NoNewline -ForegroundColor:Green 
        Write-Host ' Settings**' -Foregroundcolor:Cyan
        $_.Group | ForEach-Object {
            $Choices = $_.Choices
            if ($Choices -notcontains '&Skip') {
                $Choices += '&Skip'
            }
            $Choice = Read-Choice -Message $_.Description -Choices $Choices
            $Setting = $_.Choices[$Choice] -replace '&', ''
            if ($Setting -ne 'Skip') {
                $tweaks += $Setting
            }
        }
    }

    try {
        $tweakdata = $tweaks | ConvertTo-Json
        $Template = (Get-Content -Path .\Bootstrap-Config-Template.ps1 -Raw) -replace '<%WindowsSettings%>',$tweakdata
        $Template | Out-File -FilePath $OutputScript -Encoding:utf8 -Force
        Write-Output ''
        Write-Output "Configuration file has been saved to $OutputScript"
    }
    catch {
        throw 'Unable to save configuration file!'
    }

}