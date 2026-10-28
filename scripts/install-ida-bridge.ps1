[CmdletBinding()]
param([string]$PythonExecutable = '', [string]$IdaDirectory = '', [string]$Destination = '')
# App-local headless IDA (idalib) MCP bridge. Requires your own licensed IDA Pro 9.x with idalib.
# Nothing global is changed: no global pip packages, PATH, MCP-client registrations, IDA install
# directory or IDA user plugins. The idalib activation script writes its configuration into this
# bridge folder instead of %APPDATA%; the registration passes IDADIR to the server explicitly.
$ErrorActionPreference = 'Stop'
$Commit = 'c133c3853faa111a9b00ee615c013b720d0c4acd'
$TomliW = '1.2.0'
$base = if (Test-Path (Join-Path $PSScriptRoot 'resources\toolchain.json')) { $PSScriptRoot } else { Split-Path $PSScriptRoot -Parent }
if (!$Destination) { $Destination = Join-Path $base 'resources\toolchain\ida-headless' }
$Destination = [IO.Path]::GetFullPath($Destination)

if (!$PythonExecutable) {
    $candidate = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($candidate -and $candidate.Source -notmatch 'WindowsApps') { $PythonExecutable = $candidate.Source }
    if (!$PythonExecutable) {
        $candidate = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python3*\python.exe') -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if ($candidate) { $PythonExecutable = $candidate.FullName }
    }
}
if (!$PythonExecutable -or !(Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) { throw 'Supply -PythonExecutable with a Python 3.11+ interpreter (not a Microsoft Store alias).' }
& $PythonExecutable -c 'import sys; sys.exit(0 if (3,11) <= sys.version_info[:2] < (4,0) else 1)'
if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 or newer is required by ida-pro-mcp.' }

if (!$IdaDirectory) {
    $found = Get-ChildItem (Join-Path $env:ProgramFiles 'IDA Professional *') -Directory -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'idalib.dll') } |
        Sort-Object { [version](($_.Name -replace '^IDA Professional\s+', '') -replace '[^0-9.].*$', '') } -Descending |
        Select-Object -First 1
    if (!$found) { throw 'No "IDA Professional *" installation with idalib.dll was found. Supply -IdaDirectory.' }
    $IdaDirectory = $found.FullName
}
$IdaDirectory = [IO.Path]::GetFullPath($IdaDirectory).TrimEnd('\')
if (!(Test-Path -LiteralPath (Join-Path $IdaDirectory 'idalib.dll'))) { throw "IDA directory has no idalib.dll (idalib requires IDA Pro 9.0+): $IdaDirectory" }
$wheel = Get-ChildItem (Join-Path $IdaDirectory 'idalib\python\idapro-*.whl') -File -ErrorAction SilentlyContinue | Sort-Object Name -Descending | Select-Object -First 1
$activate = Join-Path $IdaDirectory 'idalib\python\py-activate-idalib.py'
if (!$wheel -or !(Test-Path -LiteralPath $activate)) { throw "IDA's idalib Python package or activation script is missing under $IdaDirectory\idalib\python." }

$venv = Join-Path $Destination 'venv'
$python = Join-Path $venv 'Scripts\python.exe'
$server = Join-Path $venv 'Scripts\idalib-mcp.exe'
$manifestPath = Join-Path $Destination 'rea-ida-install.json'
$registrationPath = Join-Path $Destination 'rea-headless-registration.json'
$idausr = Join-Path $Destination 'idausr'
if (Test-Path -LiteralPath $Destination) {
    $existing = @(Get-ChildItem -LiteralPath $Destination -Force)
    if ($existing.Count -gt 0) {
        # Only re-verify an installation created by this script with the same pinned commit.
        if (!(Test-Path -LiteralPath $manifestPath) -or !(Test-Path -LiteralPath $python)) { throw "Destination is not empty and is not an IDA bridge installation: $Destination. Choose another destination." }
        $previous = Get-Content -Raw -LiteralPath $manifestPath | ConvertFrom-Json
        if ($previous.commit -ne $Commit) { throw "Existing bridge uses ida-pro-mcp $($previous.commit). Preserve it and choose another destination." }
        $unexpected = $existing | Where-Object { $_.Name -notin @('venv', 'idausr', 'rea-ida-install.json', 'rea-headless-registration.json', 'installed-requirements.txt') }
        if ($unexpected) { throw "Destination contains unexpected files ($($unexpected.Name -join ', ')). Choose another destination." }
    }
}
New-Item $Destination -ItemType Directory -Force | Out-Null
if (!(Test-Path -LiteralPath $python)) {
    & $PythonExecutable -m venv $venv
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the app-local Python environment.' }
    # The vendor wheel matches the installed idalib; ida-pro-mcp only uses open_database,
    # close_database and enable_console_messages from it. Its other dependency is pinned.
    & $python -m pip install --disable-pip-version-check $wheel.FullName "tomli-w==$TomliW"
    if ($LASTEXITCODE -ne 0) { throw "Could not install IDA's idapro package." }
    & $python -m pip install --disable-pip-version-check --no-deps "git+https://github.com/mrexodia/ida-pro-mcp@$Commit"
    if ($LASTEXITCODE -ne 0) { throw 'Could not install ida-pro-mcp at the pinned commit (git is required).' }
}
if (!(Test-Path -LiteralPath $server)) { throw "The idalib-mcp entry point is missing: $server" }

# Keep idalib's activation record app-local (IDAUSR) instead of the user's IDA profile.
New-Item $idausr -ItemType Directory -Force | Out-Null
$savedIdausr = $env:IDAUSR; $savedIdadir = $env:IDADIR
try {
    $env:IDAUSR = $idausr
    & $python $activate -d $IdaDirectory | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'idalib activation failed.' }
    $env:IDAUSR = $savedIdausr
    $env:IDADIR = $IdaDirectory
    & $python -c 'import importlib.metadata as m, idapro; print(m.version("idapro"))' | Tee-Object -Variable idaproVersion | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'import idapro failed: the IDA library could not be loaded. Check the IDA installation and its license.' }
    & $server --help | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'idalib-mcp --help failed.' }
} finally { $env:IDAUSR = $savedIdausr; $env:IDADIR = $savedIdadir }
$pythonVersion = (& $python -c 'import platform; print(platform.python_version())').Trim()
$mcpVersion = (& $python -c 'import importlib.metadata as m; print(m.version("ida-pro-mcp"))').Trim()
& $python -m pip freeze --disable-pip-version-check | Set-Content (Join-Path $Destination 'installed-requirements.txt') -Encoding utf8

$registration = [ordered]@{ command = $server; args = @('--stdio', '--max-workers', '1'); mode = 'headless'; env = [ordered]@{ IDADIR = $IdaDirectory } }
$utf8 = New-Object System.Text.UTF8Encoding($false)  # No BOM: REA parses this file with JSON.parse.
[IO.File]::WriteAllText($registrationPath, ($registration | ConvertTo-Json -Depth 4), $utf8)
$manifest = [ordered]@{
    package = 'ida-pro-mcp'; version = $mcpVersion; source = 'https://github.com/mrexodia/ida-pro-mcp'; commit = $Commit
    idapro = "$idaproVersion".Trim(); idaproWheel = $wheel.Name; tomliW = $TomliW; python = $pythonVersion
    idaDirectory = $IdaDirectory; server = $server; registration = $registrationPath; installed = (Get-Date).ToUniversalTime().ToString('o')
}
[IO.File]::WriteAllText($manifestPath, ($manifest | ConvertTo-Json), $utf8)

Write-Host "Headless IDA bridge ready: $server"
Write-Host "REA-compatible registration: $registrationPath"
Write-Host 'Next: refresh Toolchain in REA Studio, then enable the IDA bridge (headless) in Reverse engineering.'
Write-Host 'Optional: use "Register for REA" to point REA''s IDA provider at this headless profile; reconnect REA afterwards.'
Write-Host 'No IDA database or target was opened. Global Python, PATH, IDA plugins and MCP-client registrations were not changed.'
