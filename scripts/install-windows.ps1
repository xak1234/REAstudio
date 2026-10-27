[CmdletBinding()]
param([string]$Destination = (Join-Path $env:LOCALAPPDATA 'Programs\QuixiDesk'))
$ErrorActionPreference = 'Stop'
if (Test-Path $Destination) { throw "Destination already exists: $Destination. Choose a new path or update the existing installation after closing QuixiDesk." }
New-Item $Destination -ItemType Directory -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot '*') $Destination -Recurse
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'QuixiDesk.lnk'))
$link.TargetPath = Join-Path $Destination 'QuixiDesk.exe'
$link.WorkingDirectory = $Destination
$link.Description = 'QuixiDesk coding and reverse engineering playground'
$link.Save()
Write-Host "Installed to $Destination. Start QuixiDesk from your desktop."
