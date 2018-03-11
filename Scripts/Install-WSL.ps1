<#
.SYNOPSIS
Installs Windows subsystem for linux (WSL) as well as downloads, starts the distro setup. Supports ubuntu, sles, and opensuse 
.DESCRIPTION
Installs Windows subsystem for linux (WSL) as well as downloads, starts the distro setup. Supports ubuntu, sles, and opensuse 
.PARAMETER InstallPath
Path to save and install WSL distro to
.PARAMETER Distro
Distro to attempt to download and install
.EXAMPLE
.\Install-WSL.ps1

Configures the WSL feature if required then attempts to install the ubuntu wsl distrobution to C:\WSLDistros\Ubuntu
.NOTES
Author: Zachary Loeber

I've only really tested the ubuntu installer.
.LINK
https://github.com/zloeber/WindowsSetupScripts
.LINK
https://docs.microsoft.com/en-us/windows/wsl/install-on-server
#>
[CmdletBinding()]
param(
    [Parameter(HelpMessage = 'Path to save and install WSL distro to.')]
    [string]$InstallPath = 'C:\WSLDistros\Ubuntu',
    [Parameter(HelpMessage = 'Distro to attempt to download and install')]
    [ValidateSet('ubuntu','opensuse','sles')]
    [string]$Distro = 'ubuntu'
)

Begin {
    $WSLDownloadPath = Join-Path $ENV:TEMP "$Distro.zip"

    $DistroURI = @{
        'ubuntu' = 'https://aka.ms/wsl-ubuntu-1604'
        'sles' = 'https://aka.ms/wsl-sles-12'
        'opensuse' = 'https://aka.ms/wsl-opensuse-42'
    }
    $DistroEXE = @{
        'ubuntu' = 'ubuntu.exe'
        'sles' = 'sles.exe'
        'opensuse' = 'opensuse.exe'
    }

    function Start-Proc {
        param([string]$Exe = $(Throw "An executable must be specified"),
            [string]$Arguments,
            [switch]$Hidden,
            [switch]$waitforexit)

        $startinfo = New-Object System.Diagnostics.ProcessStartInfo
        $startinfo.FileName = $Exe
        $startinfo.Arguments = $Arguments
        if ($Hidden) {
            $startinfo.WindowStyle = 'Hidden'
            $startinfo.CreateNoWindow = $True
        }
        $process = [System.Diagnostics.Process]::Start($startinfo)
        if ($waitforexit) { $process.WaitForExit() }
    }

    Function ReRunScriptElevated {
        if ( -not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator') ) {
            Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $PSCommandArgs" -WorkingDirectory $pwd -Verb RunAs
            Exit
        }
    }

    ReRunScriptElevated
}
end {
    if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State -ne 'Enabled') {
        try {
            Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
        }
        catch {
            Write-Warning 'Unable to install the WSL feature!'
        }
    }
    else {
        Write-Output 'Windows subsystem for Linux optional feature already installed!'
    }

    $InstalledWSLDistros = @((Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction:SilentlyContinue | ForEach-Object { Get-ItemProperty $_.pspath }).DistributionName)

    $WSLExe = Join-Path $InstallPath $DistroEXE[$Distro]

    if ($InstalledWSLDistros -notcontains $Distro) {
        Write-Output "WSL distro $Distro is not found to be installed on this system, attempting to download and install it now..."    

        if (-not (Test-Path $WSLDownloadPath)) {
            Invoke-WebRequest -Uri $DistroURI[$Distro] -OutFile $WSLDownloadPath -UseBasicParsing
        }
        else {
            Write-Warning "The $Distro zip file appears to already be downloaded."
        }
        
        Expand-Archive $WSLDownloadPath $InstallPath -Force

        if (Test-Path $WSLExe) {
            Start-Proc -Exe $WSLExe -waitforexit
        }
        else {
            Write-Warning "  $WSLExe was not found for whatever reason"
        }

        # Run distro specific updates and such
        switch ($Distro) {
            'ubuntu' {
                Write-Output 'Assuming that the install worked, attempting to run updates against it now. If prompted for a password please supply the one provided for the ubuntu install.'
            
                & $WSLExe run 'sudo apt-get update && sudo apt-get upgrade -y'
            }
            'sles' {
                # NA
            }
            'opensuse' {
                # NA
            }
        }
    }
    else {
        Write-Warning "Found $Distro is already installed on this system. Enter it simply by typing bash.exe"
    }
}