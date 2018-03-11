# DesktopReinstall

A set of PowerShell scripts to configure applications and settings the way you want them on a new workstation. This combines boxcutter, a large set of custom functions, and interactive prompting to create customization files.

## Installation
Download this github project and extract to any directory and run via powershell.

## Features

- Ability to tweak several dozen Windows settings (privacy, taskbar, explorer, et cetera..)
- Can install chocolatey based applications
- Can install GitReleases based applications
- Can find and install recent versions of Hashicorp applications
- Can download and kick off installation of custom intallations based on URL
- Can run windows updates (based on boxstarter)
- Can install vscode plugins
- Can setup a custom PowerShell profile
- Is largely idempotent
- Can be stored as a gist and launched via boxstarter

Read on to see how to use some of these features.

## Scripts

There are a handful of scripts make up this mini-project. One script can be used to create another script that could be used as a gist for your own boxstarter customization. Another can be used stand-alone by generating an external json config file with all appropriate settings to setup a new system to suit your specific needs.

*Create-Windows-Config-Script.ps1* - Creates a Windows 10 or Server 2016 Initial Setup Script to be used with boxstarter.

*Configure-Windows.ps1* - Post intall Windows configuration script. This is meant to be run manually and can be used in conjunction with a config.json file (that this script can also create). To create a boxstarter version of this script use the create-windows-config.ps1 script with this project instead.

*Install-Extras.ps1* - Installs additional software from chocolatey and other sources. Also used to setup different application settings, a powershell profile, and install PowerShell modules. This is meant to be heavily customized to suit your needs and run manually after running your configuration scripts. It would not be hard to move a good deal of this to a boxstarter script as well.

*Show-Config.ps1* - Use this to view all the settings in a saved config.json file in a nice readable format. This compliments the Configure-Windows.ps1 script.

## Other Information

- The configuration generation script just pulls in a definitions.json file and prompts for options that represent functions that will be called during the script processing. This makes it pretty easy to add or remove settings.
- The default option is the first listed when prompted for configuration settings. I've attempted to make all default options pretty sane but they should all be closely reviewed to ensure you have what you want.
- If a 'Skip' option does not appear in the definition.json entry for an option it is automatically added at the end.
- The scripts attempt to restart as admin and other trickery which is pretty neat I think.
- Enabling defender protected folders will prevent you from writing a custom powershell profile file!

**Author:** Zachary Loeber

**Website:** https://www.github.com/zloeber/DesktopReInstall
