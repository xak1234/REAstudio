[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Destination)
$ErrorActionPreference = 'Stop'
if (Test-Path $Destination) { throw 'Choose a new empty fixture directory.' }
if (!(Get-Command cl.exe -ErrorAction SilentlyContinue)) { throw 'Run this script from an x64 Visual Studio Developer PowerShell.' }
New-Item $Destination -ItemType Directory -Force | Out-Null
Copy-Item (Join-Path $PSScriptRoot 'fixtures\quixi-fixture.c') (Join-Path $Destination 'native.c')
Set-Content (Join-Path $Destination 'README.md') '# QuixiDesk test project' -Encoding utf8
Set-Content (Join-Path $Destination 'app.js') 'function add(a, b) { return a + b; } module.exports = { add };' -Encoding utf8
Push-Location $Destination
try {
    & cl.exe /nologo /Od native.c /Fe:quixi-fixture.exe
    if ($LASTEXITCODE -ne 0) { throw 'Fixture compilation failed.' }
    & git init
    if ($LASTEXITCODE -ne 0) { throw 'Fixture Git initialisation failed.' }
    & git add README.md app.js native.c
    & git -c user.name=QuixiDesk-Test -c user.email=test@example.invalid commit -m 'Test fixture'
    if ($LASTEXITCODE -ne 0) { throw 'Fixture commit failed.' }
    Write-Host "Fixture ready: $Destination"
} finally { Pop-Location }
