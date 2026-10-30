<#
.SYNOPSIS
Capture a trusted PE and reconstruct reviewed imports, or rebuild a saved plan.
.DESCRIPTION
Live mode executes the selected EXE and requires -Trusted. Supply a reviewed
entry point and IAT ranges to rebuild in the same capture. Without them the
driver saves analysis evidence and a review plan (exit code 3). Offline mode
does not execute a target. Existing files are never overwritten.

For a target that requires administrator access, run from an elevated terminal
or supply -Elevate to request UAC. Ordinary captures do not need elevation.
.EXAMPLE
.\rea-unpack.ps1 -Target C:\analysis\app.exe -Trusted -OepRva 0x5252 -IatRange 0x12000:0x100
.EXAMPLE
.\rea-unpack.ps1 -RebuildPlan C:\analysis\capture.exe.imports.json -Output C:\analysis\repaired.exe
#>
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Live')][Alias('Input')][string]$Target,
    [Parameter(Mandatory = $true, ParameterSetName = 'Offline')][string]$RebuildPlan,
    [string]$Output = '',
    [Parameter(ParameterSetName = 'Live')][switch]$Trusted,
    [Parameter(ParameterSetName = 'Live')][string]$OepRva = '',
    [Parameter(ParameterSetName = 'Live')][string]$OepVa = '',
    [Parameter(ParameterSetName = 'Live')][string[]]$IatRange = @(),
    [Parameter(ParameterSetName = 'Live')][string[]]$IatDll = @(),
    [Parameter(ParameterSetName = 'Live')][switch]$AnalysisOnly,
    [Parameter(ParameterSetName = 'Live')][ValidateRange(1, 1800)][double]$Timeout = 90,
    [Parameter(ParameterSetName = 'Live')][ValidateRange(1, 100000)][int]$MaxRounds = 2000,
    [Parameter(ParameterSetName = 'Live')][switch]$Elevate,
    [string]$BridgePython = '',
    [string]$X64dbgRoot = '',
    [Parameter(DontShow = $true)][string]$ResultPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)

function ConvertTo-NativeArgument([AllowEmptyString()][string]$Value) {
    if ($Value -ne '' -and $Value -notmatch '[\s"]') { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-UnpackPython([string]$Executable, [string[]]$Arguments) {
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = ($Arguments | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (!$process.Start()) { throw 'Could not start the unpack driver' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()
        $text = $stdout.GetAwaiter().GetResult()
        $errors = $stderr.GetAwaiter().GetResult()
        if ($errors) { [Console]::Error.Write($errors) }
        if (!$text.Trim()) { throw "Driver returned no JSON (exit $($process.ExitCode)): $errors" }
        # Validate the output before reporting it as the driver's structured result.
        $null = $text | ConvertFrom-Json
        return [pscustomobject]@{text=$text;exitCode=$process.ExitCode}
    } finally { $process.Dispose() }
}

$code = 1
$resultText = ''
try {
    $roots = @()
    $current = $PSScriptRoot
    for ($depth = 0; $depth -le 3 -and $current; $depth++) {
        $roots += $current
        $current = Split-Path $current -Parent
    }
    $unpack = Join-Path $PSScriptRoot 'unpack.py'
    if (!(Test-Path -LiteralPath $unpack -PathType Leaf)) {
        $unpack = Join-Path $PSScriptRoot 'resources\toolchain\rea-unpack\unpack.py'
    }
    if (!(Test-Path -LiteralPath $unpack -PathType Leaf)) { throw 'The packaged unpack.py module is missing.' }
    if (!$X64dbgRoot) {
        if ($env:REA_X64DBG_ROOT) { $X64dbgRoot = $env:REA_X64DBG_ROOT }
        else {
            foreach ($root in $roots) {
                $candidate = Join-Path $root 'resources\toolchain\x64dbg'
                if (Test-Path -LiteralPath $candidate -PathType Container) { $X64dbgRoot = $candidate; break }
            }
        }
    }
    if (!$BridgePython) {
        if ($X64dbgRoot) {
            $candidate = Join-Path (Split-Path $X64dbgRoot -Parent) 'x64dbg-bridge\Scripts\python.exe'
            if (Test-Path -LiteralPath $candidate -PathType Leaf) { $BridgePython = $candidate }
        }
        if (!$BridgePython -and $PSCmdlet.ParameterSetName -eq 'Offline') {
            $pythonCommand = Get-Command python.exe -ErrorAction SilentlyContinue
            if ($pythonCommand -and $pythonCommand.Source -notmatch 'WindowsApps') { $BridgePython = $pythonCommand.Source }
        }
    }
    if (!$BridgePython -or !(Test-Path -LiteralPath $BridgePython -PathType Leaf)) {
        throw 'Supply -BridgePython with Python 3.10+ (the installed x64dbg bridge Python is required for live capture).'
    }
    $BridgePython = (Resolve-Path -LiteralPath $BridgePython).Path
    $pythonArgs = @($unpack)
    if ($PSCmdlet.ParameterSetName -eq 'Offline') {
        if (!$Output) { throw 'Offline rebuilding requires an explicit new -Output path.' }
        $RebuildPlan = (Resolve-Path -LiteralPath $RebuildPlan).Path
        $pythonArgs += @('--rebuild-plan', $RebuildPlan, '--output', [IO.Path]::GetFullPath($Output))
    } else {
        if (!$Trusted) { throw 'Live capture executes the selected EXE. Pass -Trusted only when execution is authorized.' }
        if (!$X64dbgRoot -or !(Test-Path -LiteralPath $X64dbgRoot)) { throw 'Supply -X64dbgRoot or install the optional x64dbg bridge.' }
        if ($OepRva -and $OepVa) { throw 'Select -OepRva or -OepVa, not both.' }
        $Target = (Resolve-Path -LiteralPath $Target).Path
        if (!$Output) { $Output = Join-Path (Split-Path $Target -Parent) ([IO.Path]::GetFileNameWithoutExtension($Target) + '_unpacked.exe') }
        $Output = [IO.Path]::GetFullPath($Output)
        $X64dbgRoot = (Resolve-Path -LiteralPath $X64dbgRoot).Path
        $elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
        if ($Elevate -and !$elevated) {
            $relay = Join-Path ([IO.Path]::GetTempPath()) ('rea-unpack-' + [guid]::NewGuid().ToString('N') + '.json')
            $shell = Join-Path $PSHOME 'powershell.exe'
            if (!(Test-Path -LiteralPath $shell)) { $shell = Join-Path $PSHOME 'pwsh.exe' }
            $relayArgs = @('-NoProfile','-ExecutionPolicy','Bypass','-File',$PSCommandPath,
                '-Target',$Target,'-Output',$Output,'-Trusted','-BridgePython',$BridgePython,
                '-X64dbgRoot',$X64dbgRoot,'-Timeout',$Timeout.ToString([Globalization.CultureInfo]::InvariantCulture),
                '-MaxRounds',[string]$MaxRounds,'-ResultPath',$relay)
            if ($OepRva) { $relayArgs += @('-OepRva',$OepRva) }
            if ($OepVa) { $relayArgs += @('-OepVa',$OepVa) }
            # PowerShell -File cannot reliably bind an array from separate native
            # arguments. Keep complex capture selections in a normal elevated
            # PowerShell invocation, rather than reinterpreting them as code.
            if ($IatRange.Count -gt 1 -or $IatDll.Count -gt 1) {
                throw 'For multiple IAT ranges/DLL selections, run this command in an elevated PowerShell terminal.'
            }
            if ($IatRange.Count) { $relayArgs += @('-IatRange',$IatRange[0]) }
            if ($IatDll.Count) { $relayArgs += @('-IatDll',$IatDll[0]) }
            if ($AnalysisOnly) { $relayArgs += '-AnalysisOnly' }
            try {
                $arguments = ($relayArgs | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' '
                $child = Start-Process -FilePath $shell -ArgumentList $arguments -Verb RunAs -PassThru -Wait -WindowStyle Hidden
                try { $code = $child.ExitCode } finally { $child.Dispose() }
                if (!(Test-Path -LiteralPath $relay -PathType Leaf)) { throw 'The elevated driver returned no report.' }
                $resultText = [IO.File]::ReadAllText($relay)
                $null = $resultText | ConvertFrom-Json
            } finally { if (Test-Path -LiteralPath $relay) { Remove-Item -LiteralPath $relay } }
        } else {
            $pythonArgs += @('--input',$Target,'--output',$Output,'--trusted','--x64dbg-root',$X64dbgRoot,
                '--timeout',$Timeout.ToString([Globalization.CultureInfo]::InvariantCulture),'--max-rounds',[string]$MaxRounds)
            if ($OepRva) { $pythonArgs += @('--oep-rva',$OepRva) }
            if ($OepVa) { $pythonArgs += @('--oep-va',$OepVa) }
            foreach ($range in $IatRange) { $pythonArgs += @('--iat-range',$range) }
            foreach ($hint in $IatDll) { $pythonArgs += @('--iat-dll',$hint) }
            if ($AnalysisOnly) { $pythonArgs += '--analysis-only' }
        }
    }
    if (!$resultText) {
        $result = Invoke-UnpackPython -Executable $BridgePython -Arguments $pythonArgs
        $code = $result.exitCode
        $resultText = $result.text
    }
} catch {
    $code = 1
    $resultText = [ordered]@{ok=$false;imports_rebuilt=$false;status='failed';error=$_.Exception.Message} | ConvertTo-Json
}
if ($ResultPath) { [IO.File]::WriteAllText($ResultPath, $resultText, $utf8) }
else { [Console]::Out.WriteLine($resultText) }
exit $code
