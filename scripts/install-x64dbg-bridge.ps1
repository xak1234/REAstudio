[CmdletBinding()]
param([string]$PythonExecutable = '', [string]$Destination = '')
$ErrorActionPreference = 'Stop'
$base = if (Test-Path (Join-Path $PSScriptRoot 'resources\toolchain.json')) { $PSScriptRoot } else { Split-Path $PSScriptRoot -Parent }
if (!$Destination) { $Destination = Join-Path $base 'resources\toolchain' }
$Destination = [IO.Path]::GetFullPath($Destination)
if (!$PythonExecutable) {
    $candidate = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($candidate -and $candidate.Source -notmatch 'WindowsApps') { $PythonExecutable = $candidate.Source }
    if (!$PythonExecutable) {
        $candidate = Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Programs\Python\Python*\python.exe') -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if ($candidate) { $PythonExecutable = $candidate.FullName }
    }
}
if (!$PythonExecutable -or !(Test-Path -LiteralPath $PythonExecutable -PathType Leaf)) { throw 'Supply -PythonExecutable with a Python 3.10+ interpreter (not a Microsoft Store alias).' }
& $PythonExecutable -c 'import sys; sys.exit(0 if (3,10) <= sys.version_info[:2] < (4,0) else 1)'
if ($LASTEXITCODE -ne 0) { throw 'Python 3.10 or newer is required.' }
$debuggerRoot = Join-Path $Destination 'x64dbg'
if (!(Test-Path -LiteralPath $debuggerRoot)) {
    $installer = if (Test-Path (Join-Path $PSScriptRoot 'Install-Toolchain.ps1')) { Join-Path $PSScriptRoot 'Install-Toolchain.ps1' } else { Join-Path $PSScriptRoot 'install-toolchain.ps1' }
    & $installer -Tool x64dbg -Destination $Destination
}
$launcher = Get-ChildItem -LiteralPath $debuggerRoot -Filter x96dbg.exe -Recurse -File | Select-Object -First 1
if (!$launcher) { throw 'The portable x64dbg installation has no x96dbg.exe launcher.' }
$bridge = Join-Path $Destination 'x64dbg-bridge'
$python = Join-Path $bridge 'Scripts\python.exe'
if (!(Test-Path -LiteralPath $bridge)) {
    & $PythonExecutable -m venv $bridge
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the app-local Python environment.' }
    & $python -m pip install 'x64dbg_automate[mcp]==0.9.2' --disable-pip-version-check
    if ($LASTEXITCODE -ne 0) { throw 'Could not install the x64dbg MCP client.' }
} else {
    if (!(Test-Path -LiteralPath $python)) { throw "Existing bridge folder is incomplete: $bridge. Choose another destination." }
    & $python -c 'import importlib.metadata, mcp; assert importlib.metadata.version("x64dbg_automate") == "0.9.2"'
    if ($LASTEXITCODE -ne 0) { throw 'Existing bridge has a different/incomplete client. Preserve it and choose another destination.' }
}
$cache = Join-Path ([IO.Path]::GetTempPath()) 'rea-studio-x64dbg-automate'
New-Item $cache -ItemType Directory -Force | Out-Null
$components = @(
    @{Bits='64'; Hash='942cd81d2dd02141deacb848846b8a8a26b5f4de1731142a4df6f44581b0597b'},
    @{Bits='32'; Hash='9e7e64aa7cdfde5783c7414cf6bc42f97e7ec7d012c894ca5c7f1756f44e7d9a'}
)
foreach ($component in $components) {
    $file = "release$($component.Bits)-0.8.1-ghost_fungus.zip"
    $archive = Join-Path $cache $file
    $url = "https://github.com/dariushoule/x64dbg-automate/releases/download/v0.8.1-ghost_fungus/$file"
    if (!(Test-Path -LiteralPath $archive) -or (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $component.Hash) {
        Invoke-WebRequest $url -OutFile $archive
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $component.Hash) { throw "Plugin checksum mismatch: $file" }
    $unpack = Join-Path $cache ([guid]::NewGuid().ToString())
    try {
        Expand-Archive -LiteralPath $archive -DestinationPath $unpack
        $plugin = Get-ChildItem -LiteralPath $unpack -Recurse -Filter "*.dp$($component.Bits)" -File | Select-Object -First 1
        if (!$plugin) { throw "No plugin in $file" }
        $output = Join-Path $launcher.DirectoryName "x$($component.Bits)\plugins"
        New-Item $output -ItemType Directory -Force | Out-Null
        foreach ($item in Get-ChildItem -LiteralPath $plugin.DirectoryName -File) {
            $target = Join-Path $output $item.Name
            if (Test-Path -LiteralPath $target) {
                if ((Get-FileHash $target -Algorithm SHA256).Hash -ne (Get-FileHash $item.FullName -Algorithm SHA256).Hash) { throw "Preserving a different existing plugin file: $target" }
            } else { Copy-Item -LiteralPath $item.FullName -Destination $target }
        }
    } finally { if (Test-Path -LiteralPath $unpack) { Remove-Item -LiteralPath $unpack -Recurse -Force } }
}
& $python -m pip freeze | Set-Content (Join-Path $bridge 'installed-requirements.txt') -Encoding utf8
[pscustomobject]@{client='0.9.2';plugin='0.8.1-ghost_fungus';debugger=$launcher.FullName;server=(Join-Path $bridge 'Scripts\x64dbg-automate-mcp.exe');components=$components} | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $bridge 'rea-install.json') -Encoding utf8
Write-Host 'x64dbg and its bridge are ready for a connection check. Refresh installed tools in REA Studio, select x64dbg, and enable its connection. No debugger or target was started.'
Write-Host 'The rea-unpack tool (rea-unpack.ps1 at the install root) uses this bridge to live-dump packed PEs; see the unpack-packed-binary skill.'
