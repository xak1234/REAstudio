[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $env:TEMP ('rea-validation-' + [guid]::NewGuid())),
    [switch]$Windows,
    [switch]$Mcp,
    [switch]$Controls,
    [switch]$Ida,
    [switch]$Debugger,
    [switch]$Specialist,
    [switch]$Complex,
    [switch]$ComplexRuntime,
    [switch]$Investigations,
    [switch]$Scale,
    [switch]$ScaleRuntime,
    [switch]$NativeClose
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$node = (Get-Command node -ErrorAction Stop).Source
$out = [IO.Path]::GetFullPath($OutputDirectory)
New-Item $out -ItemType Directory -Force | Out-Null
$checks = [Collections.Generic.List[object]]::new()
$started = [DateTime]::UtcNow
$previousReport = $env:REA_STUDIO_BENCHMARK_REPORT
$previousRuntime = $env:REA_STUDIO_COMPLEX_RUNTIME
$previousScaleReport = $env:REA_STUDIO_SCALE_REPORT
$previousScaleRuntime = $env:REA_STUDIO_SCALE_RUNTIME
$previousInvestigationReport = $env:REA_STUDIO_INVESTIGATION_REPORT
$previousNativeCloseReport = $env:REA_STUDIO_NATIVE_CLOSE_REPORT
$previousCdp = $env:REA_STUDIO_TEST_CDP
function Invoke-NodeCheck {
    param([string]$Name, [string[]]$Arguments, [bool]$Selected = $true, [string[]]$RequiredEnvironment = @())
    $row = [ordered]@{name=$Name;status='skipped';durationMs=0;reason='Not selected; no integration was executed.'}
    if (!$Selected) { $checks.Add([pscustomobject]$row); return }
    $missing = @($RequiredEnvironment | Where-Object { [string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($_)) })
    if ($missing.Count -gt 0) {
        $row.status='failed'; $row.reason='Requested check is missing environment: ' + ($missing -join ', ')
        $checks.Add([pscustomobject]$row); Write-Warning $row.reason; return
    }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $log = Join-Path $out ($Name + '.log')
    $savedErrorPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $lines = @(& $node @Arguments 2>&1)
        $code = $LASTEXITCODE
        $ErrorActionPreference = $savedErrorPreference
        [IO.File]::WriteAllLines($log, [string[]]@($lines | ForEach-Object { [string]$_ }), [Text.UTF8Encoding]::new($false))
        $row.status = if ($code -eq 0) { 'passed' } else { 'failed' }
        $row.reason = if ($code -eq 0) { 'Executed successfully.' } else { 'Check exited with an error; inspect the log.' }
        $row.exitCode = $code; $row.log = $log
        $lastJson = @($lines | Where-Object { [string]$_ -match '^\{' } | Select-Object -Last 1)
        if ($lastJson.Count) { try { $row.result = ([string]$lastJson[0] | ConvertFrom-Json) } catch { } }
    } catch {
        $row.status='failed'; $row.reason=$_.Exception.Message
    } finally {
        $ErrorActionPreference = $savedErrorPreference
        $clock.Stop(); $row.durationMs = [Math]::Round($clock.Elapsed.TotalMilliseconds)
        $checks.Add([pscustomobject]$row); Write-Host ($Name + ': ' + $row.status)
    }
}
Push-Location $repo
try {
    Invoke-NodeCheck 'version' @('scripts/check-version.mjs')
    Invoke-NodeCheck 'analysis-contract' @('scripts/check-analysis.cjs')
    Invoke-NodeCheck 'reconstruction-contract' @('scripts/check-reconstruction.cjs')
    $syntaxFiles = @('resources/playground/app.js','resources/playground/analysis.js','resources/playground/reconstruction.js','resources/playground/close-guard.js','resources/playground/investigations.js','scripts/fixtures/scale/generate.cjs')
    $syntaxFiles += @(Get-ChildItem (Join-Path $PSScriptRoot '*.cjs') -File | ForEach-Object { 'scripts/' + $_.Name })
    foreach ($file in $syntaxFiles) { Invoke-NodeCheck ('syntax-' + [IO.Path]::GetFileNameWithoutExtension($file)) @('--check', $file) }
    $uiEnvironment = @('QUIXI_TEST_PLAYWRIGHT_MODULE','QUIXI_SMOKE_ROOT','REA_STUDIO_TEST_DATA','REA_STUDIO_TEST_CDP')
    Invoke-NodeCheck 'native-ui-ghidra' @('scripts/smoke-windows.cjs') $Windows.IsPresent $uiEnvironment
    Invoke-NodeCheck 'controls' @('scripts/smoke-controls.cjs') $Controls.IsPresent $uiEnvironment
    Invoke-NodeCheck 'mcp' @('scripts/smoke-mcp.cjs') $Mcp.IsPresent ($uiEnvironment + @('REA_STUDIO_TEST_SDK','REA_STUDIO_TEST_EXPECTED_ENV_KEY'))
    Invoke-NodeCheck 'ida-bridge' @('scripts/smoke-ida-bridge.cjs') $Ida.IsPresent ($uiEnvironment + @('REA_STUDIO_TEST_SDK'))
    Invoke-NodeCheck 'debugger' @('scripts/smoke-debugger.cjs') $Debugger.IsPresent ($uiEnvironment + @('REA_STUDIO_TEST_SDK'))
    Invoke-NodeCheck 'specialist' @('scripts/smoke-specialist.cjs') $Specialist.IsPresent ($uiEnvironment + @('REA_STUDIO_TEST_SDK','REA_STUDIO_PROVIDER_CONFIG','REA_STUDIO_SPECIALIST_MODEL'))
    $env:REA_STUDIO_BENCHMARK_REPORT = Join-Path $out 'complex-benchmark.json'
    $env:REA_STUDIO_COMPLEX_RUNTIME = if ($ComplexRuntime) { '1' } else { '0' }
    if ($Complex) {
        Invoke-NodeCheck 'complex-static' @('scripts/smoke-complex.cjs') $true ($uiEnvironment + @('REA_STUDIO_COMPLEX_ROOT'))
    } else {
        Invoke-NodeCheck 'complex-static' @('scripts/smoke-complex.cjs') $false
        Invoke-NodeCheck 'complex-runtime' @('scripts/smoke-complex.cjs','--runtime-only') $ComplexRuntime.IsPresent @('REA_STUDIO_COMPLEX_ROOT')
    }
    $dedicatedUiEnvironment = @('QUIXI_TEST_PLAYWRIGHT_MODULE','REA_STUDIO_TEST_DATA','REA_STUDIO_TEST_CDP')
    $env:REA_STUDIO_INVESTIGATION_REPORT = Join-Path $out 'investigation-report.json'
    Invoke-NodeCheck 'investigations' @('scripts/smoke-investigations.cjs') $Investigations.IsPresent ($dedicatedUiEnvironment + @('REA_STUDIO_TEST_SDK','REA_STUDIO_COMPLEX_ROOT'))
    $env:REA_STUDIO_SCALE_REPORT = Join-Path $out 'scale-benchmark.json'
    $env:REA_STUDIO_SCALE_RUNTIME = if ($ScaleRuntime) { '1' } else { '0' }
    if ($Scale) {
        Invoke-NodeCheck 'scale-static' @('scripts/smoke-scale.cjs') $true ($dedicatedUiEnvironment + @('REA_STUDIO_SCALE_ROOT'))
    } else {
        Invoke-NodeCheck 'scale-static' @('scripts/smoke-scale.cjs') $false
        Invoke-NodeCheck 'scale-runtime' @('scripts/smoke-scale.cjs','--runtime-only') $ScaleRuntime.IsPresent @('REA_STUDIO_SCALE_ROOT')
    }
    $env:REA_STUDIO_NATIVE_CLOSE_REPORT = Join-Path $out 'native-close-report.json'
    # This test owns its app processes and requires an unused CDP endpoint.
    $env:REA_STUDIO_TEST_CDP = if ($env:REA_STUDIO_NATIVE_CLOSE_CDP) { $env:REA_STUDIO_NATIVE_CLOSE_CDP } else { 'http://127.0.0.1:9326' }
    Invoke-NodeCheck 'native-close' @('scripts/smoke-native-close.cjs') $NativeClose.IsPresent @('QUIXI_TEST_PLAYWRIGHT_MODULE','REA_STUDIO_TEST_EXE','REA_STUDIO_TEST_RESOURCES','REA_STUDIO_TEST_DATA')
} finally {
    Pop-Location
    $env:REA_STUDIO_BENCHMARK_REPORT = $previousReport
    $env:REA_STUDIO_COMPLEX_RUNTIME = $previousRuntime
    $env:REA_STUDIO_SCALE_REPORT = $previousScaleReport
    $env:REA_STUDIO_SCALE_RUNTIME = $previousScaleRuntime
    $env:REA_STUDIO_INVESTIGATION_REPORT = $previousInvestigationReport
    $env:REA_STUDIO_NATIVE_CLOSE_REPORT = $previousNativeCloseReport
    $env:REA_STUDIO_TEST_CDP = $previousCdp
    $finished = [DateTime]::UtcNow
    $result = [ordered]@{
        version=1;startedAt=$started.ToString('o');finishedAt=$finished.ToString('o');durationMs=[Math]::Round(($finished-$started).TotalMilliseconds)
        passed=@($checks | Where-Object status -eq 'passed').Count
        failed=@($checks | Where-Object status -eq 'failed').Count
        skipped=@($checks | Where-Object status -eq 'skipped').Count
        checks=@($checks.ToArray())
        scope='Source checks plus explicitly selected live integrations. Skipped checks are not passes. A static fixture result does not establish runtime/reconstruction equivalence.'
    }
    [IO.File]::WriteAllText((Join-Path $out 'validation.json'), ($result | ConvertTo-Json -Depth 40), [Text.UTF8Encoding]::new($false))
    Write-Host ('Validation report: ' + (Join-Path $out 'validation.json'))
}
if ($result.failed -gt 0) { exit 1 }
