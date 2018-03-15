Function Install-WSL {
    <#
    .SYNOPSIS
    Installs Windows subsystem for linux (WSL) as well as downloads, starts the distro setup. Supports ubuntu, sles, and opensuse 
    .DESCRIPTION
    Installs Windows subsystem for linux (WSL) as well as downloads, starts the distro setup. Supports ubuntu, sles, and opensuse.
    .PARAMETER InstallPath
    Path to save and install WSL distro to
    .PARAMETER Distro
    Distro to attempt to download and install
    .EXAMPLE
    .\Install-WSL.ps1

    Configures the WSL feature if required then attempts to install the ubuntu wsl distrobution to C:\WSLDistros\Ubuntu
    .NOTES
    Author: Zachary Loeber

    - I've only really tested the ubuntu installer. This is the only distro that is currently setup to autoupdate after the initial installation.
    - The downloads are skipped if already found in the $env:temp directory. 
    - The installer process may fail without a reboot inbetween the feature install and the distro installer running.
    - Unregister or manage the default distro install via wslconfig.exe
    .LINK
    https://docs.microsoft.com/en-us/windows/wsl/install-on-server
    #>
    [CmdletBinding()]
    param(
        [Parameter(HelpMessage = 'Path to save and install WSL distro to.')]
        [string]$InstallPath = 'C:\WSLDistros\Ubuntu',
        [Parameter(HelpMessage = 'Distro to attempt to download and install')]
        [ValidateSet('ubuntu', 'opensuse', 'sles')]
        [string]$Distro = 'ubuntu'
    )

    Begin {
        $WSLDownloadPath = Join-Path $ENV:TEMP "$Distro.zip"
        $DistroURI = @{
            'ubuntu'   = 'https://aka.ms/wsl-ubuntu-1604'
            'sles'     = 'https://aka.ms/wsl-sles-12'
            'opensuse' = 'https://aka.ms/wsl-opensuse-42'
        }
        $DistroEXE = @{
            'ubuntu'   = 'ubuntu.exe'
            'sles'     = 'SLES-12.exe'
            'opensuse' = 'openSUSE-42.exe'
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
        }
        else {
            Write-Warning "Found $Distro is already installed on this system. Enter it simply by typing bash.exe"
        }
    }
}

Function Test-WSLFeatureInstalled {
    <#
    .SYNOPSIS
    Validates if the WSL feature is installed or not. Only works when run elevated.
    .DESCRIPTION
    Validates if the WSL feature is installed or not. Only works when run elevated.
    .EXAMPLE
    Test-WSLFeatureInstalled
    .NOTES
    Author: Zachary Loeber
        If not elevated this function returns $null

    .LINK
    TBD
    .LINK
    https://docs.microsoft.com/en-us/windows/wsl/install-on-server
    #>

    try {
        if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State -ne 'Enabled') {
            return $FALSE
        }
        else {
            return $TRUE
        }
    }
    catch {}
}

Function Get-CanonicalPath {
    # Used to ensure that we fix any case-sensitivity issues
    [CmdletBinding()]
    param (
        [string]$Path
    )
    begin {
        Function Get-RecurseCN ([string]$Path) {
            if ( -not [string]::IsNullOrEmpty($Path) ) {
                try {
                    $CurrPath = Get-Item -Path $Path
                }
                catch {
                    throw
                }
                if ($CurrPath -is [System.IO.DirectoryInfo]) {
                    # this is a directory
                    Write-Verbose "Processing Directory: $($CurrPath.ToString())"
                    if ($null -ne $CurrPath.Parent) {
                        # we are not at a root directory
                        $ThisPath = $Currpath.Parent
                        $ThisLeafPath = Split-Path $CurrPath.ToString() -leaf
                        Write-Verbose "...Leaf Path: $ThisLeafPath"
                        Get-CanonicalPath $ThisPath.FullName.ToString()
                        return $ThisPath.GetDirectories($ThisLeafPath).Name
                    }
                    else {
                        # We are at a drive or base location, return it lowercase to align with WSL mounting
                        return $CurrPath.ToString().ToLower()
                    }
                }
                elseif ($CurrPath -is [System.IO.FileInfo]) {
                    # this is a file
                    Write-Verbose "Processing File: $($CurrPath.ToString())"
                    $Base = Get-Item (Get-CanonicalPath (Split-Path $CurrPath.ToString()))
                    $LeafPath = Split-Path $CurrPath.ToString() -Leaf
                    return $Base.GetFiles($LeafPath).FullName
                }
                else {
                    # this is something else
                    throw
                }
            }
        }

        ((Get-RecurseCN $Path) -join '\') -replace "\\\\",'\'
    }
}

Function ConvertTo-WSLPath {
    <#
    .SYNOPSIS
    Converts a Windows path to a WSL linux path.
    .DESCRIPTION
    Converts a Windows path to a WSL linux path.
    .PARAMETER Path
    The Windows path to convert.
    .EXAMPLE
    ConvertTo-WSLPath -Path 'C:\'

    Returns /mnt/c
    .NOTES
    Author: Zachary Loeber

    For this to work 
    .LINK
    TBD
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path
    )
    begin {
        try {
            $SourcePath = Get-Item -Path $Path
        }
        catch {
            throw 'Unable to find the source script path!'
        }
        $LinuxPath = (Get-CanonicalPath $SourcePath.toString()) -replace [regex]::Escape($SourcePath.psdrive.root), '' -replace '\\', '/'
        
        "/mnt/$(($SourcePath.PSDrive.Name).ToLower())/$LinuxPath"
    }
}

Function Invoke-CopyStartWSLScript {
    <#
    .SYNOPSIS
    Copies over, makes executable, and runs a shell script on WSL Linux servers.
    .DESCRIPTION
    Copies over, makes executable, and runs a shell script on WSL Linux servers.
    .PARAMETER Path
    Local path to the shell file (ie. c:\temp\setup.sh)
    .PARAMETER Destination
    Linux destination path. Default is /tmp
    .PARAMETER Sudo
    Run file as sudo user (prompts for password)
    .PARAMETER Distro
    Distribution to target.
    .EXAMPLE
    TBD
    .NOTES
    Author: Zachary Loeber
    .LINK
    https://github.com/zloeber/WindowsSetupScripts
    .LINK
    https://docs.microsoft.com/en-us/windows/wsl/install-on-server
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path,
        [Parameter()]
        [string]$Destination = '/tmp',
        [Parameter()]
        [switch]$Sudo,
        [Parameter()]
        [ValidateSet('Ubuntu', 'Opensuse', 'SLES')]
        [string]$Distro = 'Ubuntu'
    )

    Begin {
        try {
            $scriptpath = Get-ChildItem -Path $Path
        }
        catch {
            throw 'Unable to find the source script path!'
        }
        $LinuxPath = ConvertTo-WSLPath $Path

        $LinuxDestScript = (Join-Path -Path $Destination -ChildPath (Split-Path -Path $scriptpath -Leaf)) -replace '\\', '/'
    }
    end {
        Invoke-WSLCommand "cp $LinuxPath $LinuxDestScript" -Distro:$Distro
        Invoke-WSLCommand "chmod +x $LinuxDestScript" -Distro:$Distro

        if ($Sudo) {
            Write-Output "Running sudo $LinuxDestScript"
            Invoke-WSLCommand "sudo $LinuxDestScript" -Distro:$Distro
        }
        else {
            Write-Output "Running $LinuxDestScript"
            Invoke-WSLCommand "$LinuxDestScript" -Distro:$Distro
        }
    }
}

Function Copy-WSLFile {
    <#
    .SYNOPSIS
    Copies a file to a WSL Linux instance.
    .DESCRIPTION
    Copies a file to a WSL Linux instance.
    .PARAMETER Path
    Local path to the shell file (ie. c:\temp\setup.sh)
    .PARAMETER Destination
    Linux destination path.
    .PARAMETER Distro
    Distribution to target.
    .EXAMPLE
    TBD
    .NOTES
    Author: Zachary Loeber
    .LINK
    https://github.com/zloeber/WindowsSetupScripts
    .LINK
    https://docs.microsoft.com/en-us/windows/wsl/install-on-server
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Path,
        [Parameter()]
        [string]$Destination = '/tmp',
        [Parameter()]
        [ValidateSet('Ubuntu', 'Opensuse', 'SLES')]
        [string]$Distro = 'Ubuntu'
    )

    Begin {
        try {
            $scriptpath = Get-ChildItem -Path $Path
        }
        catch {
            throw 'Unable to find the source script path!'
        }
        $LinuxPath = ConvertTo-WSLPath $Path
        $LinuxDestScript = (Join-Path -Path $Destination -ChildPath (Split-Path -Path $scriptpath -Leaf)) -replace '\\', '/'
    }
    end {
        Invoke-WSLCommand "cp $LinuxPath $LinuxDestScript" -Distro:$Distro
    }
}

Function Invoke-WSLCommand {
    <#
    .SYNOPSIS
    Runs a Linux command within the WSL instance.
    .DESCRIPTION
    Runs a Linux command within the WSL instance.
    .PARAMETER Command
    Command to run
    .PARAMETER Distro
    Distribution to run command against. Only tested against ubuntu.
    .EXAMPLE
    TBD
    .NOTES
    Author: Zachary Loeber
    .LINK
    TBD
    .LINK
    https://docs.microsoft.com/en-us/windows/wsl/install-on-server
    #>
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Command,
        [Parameter()]
        [ValidateSet('Ubuntu', 'Opensuse', 'SLES')]
        [string]$Distro = 'Ubuntu'
    )

    Begin {
        $DistroEXE = @{
            'Ubuntu'   = 'ubuntu.exe'
            'SLES'     = 'SLES-12.exe'
            'Opensuse' = 'openSUSE-42.exe'
        }
        if (Test-WSLFeatureInstalled -eq $FALSE) {
            throw 'WSL optional feature is not installed!'
        }
    }
    end {
        $InstalledWSLDistros = @{}
        (Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss' -ErrorAction:SilentlyContinue | ForEach-Object { Get-ItemProperty $_.pspath }) | ForEach-Object {
            $InstalledWSLDistros.($_.DistributionName) = $_.BasePath
        }

        if ($InstalledWSLDistros.Keys -contains $Distro) {
            $WSLExe = Join-Path $InstalledWSLDistros[$Distro] $DistroEXE[$Distro]
            Write-Verbose "WSL distro $Distro found, setting exe path to $WSLExe"

            # Run distro specific updates and such
            switch ($Distro) {
                default {
                    Write-Output "Executing command: $Command"
                    try {
                        & $WSLExe run $Command
                    }
                    catch {
                        throw
                    }
                }
            }
        }
        else {
            Write-Warning "$Distro not installed on this system!"
        }
    }
}