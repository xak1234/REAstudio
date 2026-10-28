[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$Destination, [switch]$IncludeComplex)
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
    if ($IncludeComplex) {
        $complex = Join-Path (Get-Location).Path 'complex'
        New-Item $complex -ItemType Directory | Out-Null
        Copy-Item (Join-Path $PSScriptRoot 'fixtures\complex\*') $complex
        Push-Location $complex
        try {
            & cl.exe /nologo /std:c++17 /O2 /EHsc /W4 /WX /DREA_FIXTURE_BUILD /LD pricing.cpp storage.cpp /Fe:rea-fixture-core.dll /link /INCREMENTAL:NO /OPT:REF /OPT:ICF
            if ($LASTEXITCODE -ne 0) { throw 'Optimized fixture DLL compilation failed.' }
            & cl.exe /nologo /std:c++17 /O2 /EHsc /W4 /WX main.cpp rea-fixture-core.lib /Fe:rea-complex-fixture.exe /link /INCREMENTAL:NO /OPT:REF /OPT:ICF
            if ($LASTEXITCODE -ne 0) { throw 'Optimized fixture EXE compilation failed.' }
            $manifest = [ordered]@{
                version=1;builtAt=[DateTime]::UtcNow.ToString('o')
                compiler=(Get-Command cl.exe).Source;flags='/std:c++17 /O2 /EHsc /W4 /WX; no PDB'
                sources=@(Get-ChildItem -File | Where-Object { $_.Extension -in @('.cpp','.h','.json') } | ForEach-Object { @{file=$_.Name;sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()} })
                modules=@(Get-ChildItem -File | Where-Object { $_.Extension -in @('.exe','.dll') } | ForEach-Object { @{file=$_.Name;sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant();bytes=$_.Length} })
            }
            [IO.File]::WriteAllText((Join-Path $complex 'build.json'), ($manifest | ConvertTo-Json -Depth 8), [Text.UTF8Encoding]::new($false))
        } finally { Pop-Location }
    }
    & git init
    if ($LASTEXITCODE -ne 0) { throw 'Fixture Git initialisation failed.' }
    & git add README.md app.js native.c
    & git -c user.name=QuixiDesk-Test -c user.email=test@example.invalid commit -m 'Test fixture'
    if ($LASTEXITCODE -ne 0) { throw 'Fixture commit failed.' }
    Write-Host "Fixture ready: $Destination"
} finally { Pop-Location }
