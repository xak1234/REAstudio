[CmdletBinding()]
param([string]$Destination = (Join-Path $env:LOCALAPPDATA 'Programs\REA Studio'))
$ErrorActionPreference = 'Stop'
if (Test-Path $Destination) { throw "Destination already exists: $Destination. Choose a new path or update the existing installation after closing REA Studio." }
New-Item $Destination -ItemType Directory -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot '*') $Destination -Recurse
$shell = New-Object -ComObject WScript.Shell
$link = $shell.CreateShortcut((Join-Path ([Environment]::GetFolderPath('Desktop')) 'REA Studio.lnk'))
$link.TargetPath = Join-Path $Destination 'REAStudio.exe'
$link.WorkingDirectory = $Destination
$link.Description = 'REA Studio coding and reverse engineering playground'
$link.Save()
Write-Host "Installed to $Destination. Start REA Studio from your desktop."
