<#
.SYNOPSIS
Build and execute owned x86/x64 PE fixtures through the real IAT rebuild driver.
.DESCRIPTION
Requires Windows, Visual Studio C++ Build Tools with a Windows SDK, and the
installed x64dbg Automate bridge. No model, application profile, third-party
target, or production app is used. Output is one JSON receipt; logs and generated
fixtures stay in a new output folder. A missing dependency or skipped live lane
is a failure, never a successful test.
.EXAMPLE
.\scripts\test-rea-unpack-windows.ps1 -BridgePython C:\tools\bridge\Scripts\python.exe -X64dbgRoot C:\tools\x64dbg
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$BridgePython,
    [Parameter(Mandatory = $true)][string]$X64dbgRoot,
    [string]$OutputDirectory = '',
    [ValidateSet('x86', 'x64')][string[]]$Architecture = @('x86', 'x64'),
    [ValidateRange(15, 600)][int]$Timeout = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$unpack = Join-Path $PSScriptRoot 'rea-unpack\unpack.py'
$launcher = Join-Path $PSScriptRoot 'rea-unpack\rea-unpack.ps1'
$verifier = Join-Path $PSScriptRoot 'rea-unpack\tests\windows_verify.py'
$fixtureSource = Join-Path $PSScriptRoot 'rea-unpack\tests\fixtures\iat_probe.c'
$fixtureResource = Join-Path $PSScriptRoot 'rea-unpack\tests\fixtures\iat_probe.rc'
$utf8 = New-Object System.Text.UTF8Encoding($false)

function ConvertTo-NativeArgument {
    param([AllowEmptyString()][string]$Value)
    if ($Value -ne '' -and $Value -notmatch '[\s"]') { return $Value }
    $escaped = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $escaped = [regex]::Replace($escaped, '(\\+)$', '$1$1')
    return '"' + $escaped + '"'
}

function Invoke-LoggedProcess {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$WorkingDirectory,
        [string]$LogPrefix,
        [int]$TimeoutSeconds = 120,
        [hashtable]$Environment = @{}
    )
    $start = New-Object System.Diagnostics.ProcessStartInfo
    $start.FileName = $FilePath
    $start.Arguments = ($ArgumentList | ForEach-Object { ConvertTo-NativeArgument $_ }) -join ' '
    $start.WorkingDirectory = $WorkingDirectory
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($key in $Environment.Keys) { $start.EnvironmentVariables[$key] = [string]$Environment[$key] }
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (!$process.Start()) { throw "Could not start $FilePath" }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (!$process.WaitForExit($TimeoutSeconds * 1000)) {
            # This PID belongs to the process this function just created.
            # Terminate only that owned process tree, never by executable name.
            $stop = New-Object System.Diagnostics.ProcessStartInfo
            $stop.FileName = Join-Path $env:SystemRoot 'System32\taskkill.exe'
            $stop.Arguments = '/PID ' + $process.Id + ' /T /F'
            $stop.UseShellExecute = $false
            $stop.CreateNoWindow = $true
            $stop.RedirectStandardOutput = $true
            $stop.RedirectStandardError = $true
            $stopProcess = [System.Diagnostics.Process]::Start($stop)
            try { [void]$stopProcess.WaitForExit(10000) } finally { $stopProcess.Dispose() }
            throw "Timed out after $TimeoutSeconds seconds: $FilePath. Output folder: $WorkingDirectory"
        }
        if (!$stdoutTask.Wait(5000) -or !$stderrTask.Wait(5000)) {
            throw "Process exited but its output streams did not close: $FilePath"
        }
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        [IO.File]::WriteAllText($LogPrefix + '.stdout.log', $stdout, $utf8)
        [IO.File]::WriteAllText($LogPrefix + '.stderr.log', $stderr, $utf8)
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Stdout = $stdout; Stderr = $stderr }
    }
    finally { $process.Dispose() }
}

$receipt = [ordered]@{
    passed = $false
    started_at = [DateTimeOffset]::UtcNow.ToString('o')
    output_directory = $null
    results = @()
    limitations = @(
        'Compiled fixed-base fixtures only; this does not prove arbitrary packer recovery.',
        'ASLR, TLS, Load Config and complete application behaviour are outside this runtime check.'
    )
}
$exitCode = 1
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { throw 'This live test requires Windows.' }
    foreach ($required in @($BridgePython, $unpack, $launcher, $verifier, $fixtureSource, $fixtureResource)) {
        if (!(Test-Path -LiteralPath $required -PathType Leaf)) { throw "Required file missing: $required" }
    }
    if (!(Test-Path -LiteralPath $X64dbgRoot -PathType Container)) { throw "Debugger root missing: $X64dbgRoot" }
    $BridgePython = (Resolve-Path -LiteralPath $BridgePython).Path
    $X64dbgRoot = (Resolve-Path -LiteralPath $X64dbgRoot).Path
    if (!$OutputDirectory) {
        $OutputDirectory = Join-Path ([IO.Path]::GetTempPath()) ('rea-iat-live-' + [guid]::NewGuid().ToString('N'))
    }
    $OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
    if (Test-Path -LiteralPath $OutputDirectory) { throw "Output directory must be new: $OutputDirectory" }
    [void][IO.Directory]::CreateDirectory($OutputDirectory)
    $receipt.output_directory = $OutputDirectory
    $receipt.source_sha256 = (Get-FileHash -LiteralPath $fixtureSource -Algorithm SHA256).Hash.ToLowerInvariant()
    $receipt.resource_source_sha256 = (Get-FileHash -LiteralPath $fixtureResource -Algorithm SHA256).Hash.ToLowerInvariant()
    $receipt.driver_sha256 = (Get-FileHash -LiteralPath $unpack -Algorithm SHA256).Hash.ToLowerInvariant()
    $receipt.launcher_sha256 = (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash.ToLowerInvariant()
    $receipt.modules = @(Get-ChildItem -LiteralPath (Split-Path $unpack -Parent) -Filter '*.py' -File | ForEach-Object {
        [pscustomobject]@{name=$_.Name;sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()}
    })

    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (!(Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        $found = Get-Command vswhere.exe -ErrorAction SilentlyContinue
        if ($null -eq $found) { throw 'Visual Studio vswhere.exe was not found.' }
        $vswhere = $found.Source
    }
    $discovery = Invoke-LoggedProcess -FilePath $vswhere -ArgumentList @(
        '-latest', '-products', '*', '-requires', 'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
        '-property', 'installationPath'
    ) -WorkingDirectory $OutputDirectory -LogPrefix (Join-Path $OutputDirectory 'vswhere') -TimeoutSeconds 30
    if ($discovery.ExitCode -ne 0 -or !$discovery.Stdout.Trim()) { throw 'Visual Studio C++ x86/x64 Build Tools were not found.' }
    $vcvars = Join-Path $discovery.Stdout.Trim() 'VC\Auxiliary\Build\vcvarsall.bat'
    if (!(Test-Path -LiteralPath $vcvars -PathType Leaf)) { throw "vcvarsall.bat missing: $vcvars" }
    # CALL performs a second CMD expansion; avoid ambiguous percent expansion.
    if ($vcvars -match '[%"\r\n]') { throw 'Unsupported character in Visual Studio installation path.' }
    $receipt.compiler_setup = $vcvars

    foreach ($arch in ($Architecture | Select-Object -Unique)) {
        $item = [ordered]@{ architecture = $arch; passed = $false }
        try {
            [Console]::Error.WriteLine("[rea-iat-test] Building and checking $arch fixture")
            $folder = Join-Path $OutputDirectory $arch
            [void][IO.Directory]::CreateDirectory($folder)
            $original = Join-Path $folder 'iat-probe.exe'
            $rebuilt = Join-Path $folder 'iat-probe-rebuilt.exe'
            $captureOutput = $rebuilt
            $buildScript = Join-Path $folder 'build-fixture.cmd'
            # LINK adds the leading x86 underscore to the supplied entry name.
            $entry = if ($arch -eq 'x86') { 'entry@0' } else { 'entry' }
            $buildCommands = @'
@echo off
setlocal DisableDelayedExpansion
call "%REA_IAT_VCVARS%" %REA_IAT_ARCH%
if errorlevel 1 exit /b %errorlevel%
rc /nologo /fo"%REA_IAT_RES%" "%REA_IAT_RC%"
if errorlevel 1 exit /b %errorlevel%
cl /nologo /TC /W4 /WX /O1 /GS- /Zl /Fo"%REA_IAT_OBJ%" /Fe"%REA_IAT_EXE%" "%REA_IAT_SOURCE%" /link "%REA_IAT_RES%" /NODEFAULTLIB /ENTRY:%REA_IAT_ENTRY% /SUBSYSTEM:CONSOLE /INCREMENTAL:NO /DYNAMICBASE:NO /FIXED /MANIFEST:NO kernel32.lib
exit /b %errorlevel%
'@
            [IO.File]::WriteAllText($buildScript, $buildCommands, $utf8)
            $buildEnvironment = @{
                REA_IAT_VCVARS = $vcvars
                REA_IAT_ARCH = $arch
                REA_IAT_SOURCE = $fixtureSource
                REA_IAT_RC = $fixtureResource
                REA_IAT_RES = (Join-Path $folder 'iat-probe.res')
                REA_IAT_OBJ = (Join-Path $folder 'iat-probe.obj')
                REA_IAT_EXE = $original
                REA_IAT_ENTRY = $entry
                CL = ''; _CL_ = ''; LINK = ''; _LINK_ = ''
            }
            $build = Invoke-LoggedProcess -FilePath $env:ComSpec -ArgumentList @('/d', '/c', 'build-fixture.cmd') `
                -WorkingDirectory $folder -LogPrefix (Join-Path $folder 'build') -Environment $buildEnvironment
            if ($build.ExitCode -ne 0) { throw "Compiler failed ($($build.ExitCode)); see $folder\build.stdout.log" }

            $baselineRun = Invoke-LoggedProcess -FilePath $BridgePython -ArgumentList @($verifier, 'inspect', $original) `
                -WorkingDirectory $folder -LogPrefix (Join-Path $folder 'baseline') -TimeoutSeconds 30
            if ($baselineRun.ExitCode -ne 0) { throw "Fixture baseline failed: $($baselineRun.Stdout) $($baselineRun.Stderr)" }
            $baseline = $baselineRun.Stdout | ConvertFrom-Json
            $baselineFile = Join-Path $folder 'baseline.json'
            [IO.File]::WriteAllText($baselineFile, $baselineRun.Stdout, $utf8)
            if ($baseline.arch -ne $arch) { throw 'Compiler produced the wrong architecture.' }
            $driverArguments = @(
                $unpack, '--input', $original, '--output', $rebuilt, '--trusted',
                '--x64dbg-root', $X64dbgRoot, '--timeout', [string]$Timeout,
                '--oep-rva', ('0x{0:x}' -f [long]$baseline.entry_rva)
            )
            foreach ($range in $baseline.iat_ranges) {
                $driverArguments += @('--iat-range', ('0x{0:x}:0x{1:x}' -f [long]$range.rva, [long]$range.size))
            }
            $driver = Invoke-LoggedProcess -FilePath $BridgePython -ArgumentList $driverArguments `
                -WorkingDirectory $folder -LogPrefix (Join-Path $folder 'unpack') -TimeoutSeconds ($Timeout + 90)
            if ($driver.ExitCode -notin @(0, 3)) { throw "Unpack failed ($($driver.ExitCode)); see $folder\unpack.stdout.log and unpack.stderr.log" }
            $driverJson = $driver.Stdout | ConvertFrom-Json
            $item.live_exit_code = $driver.ExitCode
            $item.capture_report = $captureOutput + '.report.json'
            foreach ($artifact in @($captureOutput, ($captureOutput + '.report.json'), ($captureOutput + '.capture.json'), ($captureOutput + '.memory.bin'), ($captureOutput + '.imports.json'))) {
                if (!(Test-Path -LiteralPath $artifact -PathType Leaf) -or (Get-Item -LiteralPath $artifact).Length -eq 0) {
                    throw "Driver artifact missing or empty: $artifact"
                }
            }
            if ($driver.ExitCode -eq 3) {
                # Equal-address export aliases need independent evidence. Only
                # this owned fixture's original import identities supply it.
                $capture = Get-Content -LiteralPath ($captureOutput + '.capture.json') -Raw | ConvertFrom-Json
                if ($capture.memory.complete -ne $true -or $capture.process.identity_stable -ne $true -or
                    $capture.oep.explicit -ne $true -or $capture.oep.reached -ne $true -or
                    $capture.oep.rva -ne $baseline.entry_rva -or $capture.source.sha256 -cne $baseline.sha256 -or
                    $capture.iat.unresolved_count -ne 0 -or $capture.iat.ambiguous_count -le 0 -or
                    @($capture.iat.layout_errors).Count -ne 0 -or @($driverJson.review_reasons).Count -ne 1) {
                    throw 'Review-required capture has a problem other than source-known export aliases.'
                }
                $plan = Get-Content -LiteralPath ($captureOutput + '.imports.json') -Raw | ConvertFrom-Json
                if (@($plan.imports).Count -ne @($baseline.imports).Count) { throw 'Review plan differs from fixture import coverage.' }
                foreach ($expected in $baseline.imports) {
                    $selected = @($plan.imports | Where-Object { $_.rva -eq $expected.iat_rva })
                    if ($selected.Count -ne 1) { throw 'Fixture import slot is missing or duplicated in the review plan.' }
                    $candidates = @($selected[0].candidates | Where-Object {
                        $_.dll -ieq $expected.dll -and $_.name -ceq $expected.name -and $_.ordinal -eq $expected.ordinal
                    })
                    if ($candidates.Count -ne 1) { throw 'Original fixture import identity is not a unique captured candidate.' }
                    $selected[0].dll = $candidates[0].dll
                    $selected[0].name = $candidates[0].name
                    $selected[0].ordinal = $candidates[0].ordinal
                }
                $plan.reviewed = $true
                $plan.review_note = 'Reviewed only against this source-owned fixture original import table: ' + $baseline.sha256
                $reviewedPlan = Join-Path $folder 'reviewed imports.json'
                [IO.File]::WriteAllText($reviewedPlan, ($plan | ConvertTo-Json -Depth 16), $utf8)
                $rebuilt = Join-Path $folder 'iat probe reviewed.exe'
                # Exercise the application-root launcher layout and paths with
                # spaces, using the same modules selected by release packaging.
                $packageRoot = Join-Path $folder 'packaged launcher'
                $packageModules = Join-Path $packageRoot 'resources\toolchain\rea-unpack'
                [void][IO.Directory]::CreateDirectory($packageModules)
                Copy-Item -LiteralPath $launcher -Destination (Join-Path $packageRoot 'rea-unpack.ps1')
                Get-ChildItem -LiteralPath (Split-Path $unpack -Parent) -Filter '*.py' -File | Copy-Item -Destination $packageModules
                $shell = Join-Path $PSHOME 'powershell.exe'
                if (!(Test-Path -LiteralPath $shell)) { $shell = Join-Path $PSHOME 'pwsh.exe' }
                $offline = Invoke-LoggedProcess -FilePath $shell -ArgumentList @(
                    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $packageRoot 'rea-unpack.ps1'),
                    '-RebuildPlan', $reviewedPlan, '-Output', $rebuilt, '-BridgePython', $BridgePython
                ) -WorkingDirectory $folder -LogPrefix (Join-Path $folder 'offline') -TimeoutSeconds 30
                if ($offline.ExitCode -ne 0) { throw "Reviewed offline rebuild failed: $($offline.Stdout) $($offline.Stderr)" }
                $driverJson = $offline.Stdout | ConvertFrom-Json
                $item.reviewed_plan = $reviewedPlan
                $item.reviewed_plan_sha256 = (Get-FileHash -LiteralPath $reviewedPlan -Algorithm SHA256).Hash.ToLowerInvariant()
                $item.review_basis = 'Exact original fixture import identity present in captured candidates.'
                $item.offline_launcher_exit_code = $offline.ExitCode
            }
            if ($driverJson.ok -ne $true -or $driverJson.imports_rebuilt -ne $true) { throw 'Driver did not confirm a completed import rebuild.' }
            $check = Invoke-LoggedProcess -FilePath $BridgePython -ArgumentList @(
                $verifier, 'verify', '--original', $original, '--rebuilt', $rebuilt,
                '--baseline', $baselineFile, '--driver-report', ($rebuilt + '.report.json'), '--execute-owned-fixtures'
            ) -WorkingDirectory $folder -LogPrefix (Join-Path $folder 'verification') -TimeoutSeconds 45
            if ($check.ExitCode -ne 0) { throw "Independent verification failed: $($check.Stdout) $($check.Stderr)" }
            $verified = $check.Stdout | ConvertFrom-Json
            if ($verified.passed -ne $true -or $verified.runtime_verified -ne $true) { throw 'Independent verifier did not complete the runtime checks.' }
            $item.verification = $verified
            $item.driver_report = $rebuilt + '.report.json'
            $item.passed = $true
        }
        catch { $item.error = $_.Exception.Message }
        $receipt.results += [pscustomobject]$item
    }
    $receipt.passed = @($receipt.results).Count -gt 0 -and @($receipt.results | Where-Object { !$_.passed }).Count -eq 0
    if ($receipt.passed) { $exitCode = 0 }
}
catch { $receipt.error = $_.Exception.Message }
finally {
    $receipt.finished_at = [DateTimeOffset]::UtcNow.ToString('o')
    $json = $receipt | ConvertTo-Json -Depth 16
    if ($receipt.output_directory) {
        [IO.File]::WriteAllText((Join-Path $receipt.output_directory 'receipt.json'), $json, $utf8)
    }
    [Console]::Out.WriteLine($json)
}
exit $exitCode
