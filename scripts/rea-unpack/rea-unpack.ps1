<#
  rea-unpack launcher: run the live-dump unpacker ELEVATED on a trusted packed PE.

  Elevation is required so x64dbg can launch admin-manifest targets. Because an
  elevated process cannot redirect stdio to a caller-owned file, this script
  relaunches itself elevated via a self-logging cmd shim and reports the result
  back on stdout, so a non-elevated caller (e.g. Studio's studio_command) still
  gets the JSON.

  Paths resolve relative to the install (this launcher ships at the package root,
  beside Install-X64dbg-Bridge.ps1, so resources\toolchain sits next to it). Pass
  -X64dbgRoot / -BridgePython to override.

  Usage:
    powershell -ExecutionPolicy Bypass -File rea-unpack.ps1 -Target <exe> [-Output <exe>] -Trusted
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][Alias('Input')][string]$Target,
  [string]$Output = '',
  [switch]$Trusted,
  [double]$Timeout = 90,
  [string]$BridgePython = '',
  [string]$X64dbgRoot = ''
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$unpack = Join-Path $here 'unpack.py'

# Resolve the toolchain relative to the install when not supplied. The launcher
# ships at the package root, so resources\toolchain sits beside it; when run from
# the dev tree (scripts\rea-unpack), fall back to the known Studio install.
if (!$X64dbgRoot) {
  $cand = Join-Path $here 'resources\toolchain\x64dbg'
  if (!(Test-Path $cand)) { $cand = Join-Path (Split-Path $here -Parent) 'resources\toolchain\x64dbg' }
  if (!(Test-Path $cand)) { $cand = 'E:\tools\REA-Studio\resources\toolchain\x64dbg' }
  $X64dbgRoot = $cand
}
if (!$BridgePython) {
  $BridgePython = Join-Path (Split-Path $X64dbgRoot -Parent) 'x64dbg-bridge\Scripts\python.exe'
}

if (!(Test-Path $BridgePython)) { throw "x64dbg bridge python missing: $BridgePython (run Install-X64dbg-Bridge.ps1)" }
if (!$Trusted) { throw 'Refused: unpacking EXECUTES the target. Pass -Trusted only for binaries you trust.' }
if (!$Output) { $Output = [IO.Path]::ChangeExtension($Target, $null).TrimEnd('.') + '_unpacked.exe' }

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)

$pyArgs = @("`"$unpack`"", '--input', "`"$Target`"", '--output', "`"$Output`"",
            '--x64dbg-root', "`"$X64dbgRoot`"", '--timeout', $Timeout, '--trusted')

if ($elevated) {
  & $BridgePython @pyArgs
  exit $LASTEXITCODE
}

# relaunch elevated via a self-logging cmd shim, then relay its JSON
$log  = Join-Path ([IO.Path]::GetTempPath()) ("rea-unpack-" + [guid]::NewGuid().ToString('N') + '.log')
$shim = Join-Path ([IO.Path]::GetTempPath()) ("rea-unpack-" + [guid]::NewGuid().ToString('N') + '.cmd')
$cmdline = '"' + $BridgePython + '" ' + ($pyArgs -join ' ') + ' > "' + $log + '" 2>&1'
Set-Content -LiteralPath $shim -Value "@echo off`r`n$cmdline`r`nexit /b %ERRORLEVEL%" -Encoding ascii
try {
  $p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', "`"$shim`"" -Verb RunAs -PassThru -WindowStyle Hidden
  $p.WaitForExit()
  if (Test-Path $log) { Get-Content -LiteralPath $log -Raw }
  exit $p.ExitCode
}
finally {
  Remove-Item -LiteralPath $shim -ErrorAction SilentlyContinue
  Remove-Item -LiteralPath $log  -ErrorAction SilentlyContinue
}
