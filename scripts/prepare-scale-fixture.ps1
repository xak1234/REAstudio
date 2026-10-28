[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Destination)
$ErrorActionPreference='Stop'
if(Test-Path -LiteralPath $Destination){throw 'Choose a new fixture directory; existing files are never overwritten.'}
if(!(Get-Command cl.exe -ErrorAction SilentlyContinue)){throw 'Run from an x64 Visual Studio Developer PowerShell.'}
$node=(Get-Command node -ErrorAction Stop).Source
$repo=Split-Path -Parent $PSScriptRoot
$source=Join-Path $PSScriptRoot 'fixtures\scale'
$destinationPath=[IO.Path]::GetFullPath($Destination)
New-Item $destinationPath -ItemType Directory | Out-Null
& $node (Join-Path $source 'generate.cjs') (Join-Path $destinationPath 'scale_fixture.cpp')
if($LASTEXITCODE -ne 0){throw 'Fixture source generation failed.'}
Push-Location $destinationPath
try {
    & cl.exe /nologo /std:c++17 /O2 /EHsc /W4 /WX /Gy /MT scale_fixture.cpp /Fe:rea-scale-fixture.exe /link /INCREMENTAL:NO /OPT:REF /OPT:ICF /DEBUG:NONE
    if($LASTEXITCODE -ne 0){throw 'Optimized scale fixture compilation failed.'}
    $strippedText=& $node (Join-Path $source 'generate.cjs') --strip-linker-metadata (Join-Path $destinationPath 'rea-scale-fixture.exe')
    if($LASTEXITCODE -ne 0){throw 'Fixture-only linker metadata cleanup failed.'}
    $peText=& $node (Join-Path $source 'generate.cjs') --inspect (Join-Path $destinationPath 'rea-scale-fixture.exe')
    if($LASTEXITCODE -ne 0){throw 'Compiled PE contains unexpected symbols/debug metadata or has the wrong architecture.'}
    if(Get-ChildItem -LiteralPath $destinationPath -Filter '*.pdb' -File){throw 'A PDB was emitted; choose a clean build configuration.'}
    $sources=@('scripts/fixtures/scale/generate.cjs','scripts/fixtures/scale/expected.json','scripts/prepare-scale-fixture.ps1')
    $manifest=[ordered]@{
        version=1;builtAt=[DateTime]::UtcNow.ToString('o');generatedFunctions=2304
        compiler=(Get-Command cl.exe).Source;flags='/std:c++17 /O2 /EHsc /W4 /WX /Gy /MT /INCREMENTAL:NO /OPT:REF /OPT:ICF /DEBUG:NONE'
        sources=@($sources|ForEach-Object {@{file=$_;sha256=(Get-FileHash (Join-Path $repo $_) -Algorithm SHA256).Hash.ToLowerInvariant()}})
        generated=@{file='scale_fixture.cpp';sha256=(Get-FileHash 'scale_fixture.cpp' -Algorithm SHA256).Hash.ToLowerInvariant()}
        binary=@{file='rea-scale-fixture.exe';sha256=(Get-FileHash 'rea-scale-fixture.exe' -Algorithm SHA256).Hash.ToLowerInvariant()}
        pe=($peText|ConvertFrom-Json)
        metadataCleanup=($strippedText|ConvertFrom-Json)
        scope='Synthetic paging and unnamed-function discovery fixture, not representative large-application coverage.'
    }
    [IO.File]::WriteAllText((Join-Path $destinationPath 'build.json'),($manifest|ConvertTo-Json -Depth 10),[Text.UTF8Encoding]::new($false))
    Write-Host ('Scale fixture ready: '+$destinationPath)
} finally {Pop-Location}
